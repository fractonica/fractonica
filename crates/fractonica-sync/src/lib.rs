#![forbid(unsafe_code)]
//! Bounded background synchronization for native Fractonica clients.
//!
//! The worker never decides whether a local write succeeded. It consumes
//! durable delivery leases and incremental pull cursors after local commits.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fractonica_application::{OperationChangePage, StoredOperation};
use fractonica_client_content::{ClientContentError, ClientContentStore, MAX_DOWNLOAD_CHUNK_BYTES};
use fractonica_client_sqlite::{
    ClientSqliteStore, ClientStoreError, DeliveryLeaseId, MAX_ERROR_BYTES,
    MAX_RESOURCE_TRANSFER_BATCH, PeerConfig, PeerReadMode, ResourceTransferDirection,
    ResourceTransferItem, ResourceTransferLeaseId, SyncCounts, SyncTarget,
};
use fractonica_content::{ContentDescriptor, ContentId, ResourceRef};
use fractonica_data_model::{NodeId, OperationEnvelope};
use fractonica_peer::{
    MAX_PEER_CHANGE_LIMIT, MAX_REQUEST_LIFETIME_MS, PeerReadChangesFields, PeerReadChangesProof,
    PeerRequestNonce,
};
use reqwest::{Client, StatusCode, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;
use tokio::{io::AsyncReadExt, io::AsyncSeekExt};

#[derive(Clone, Debug)]
pub struct SyncConfig {
    pub push_batch_size: usize,
    pub pull_page_size: u16,
    pub max_peers_per_cycle: usize,
    pub idle_interval: Duration,
    pub caught_up_poll_interval: Duration,
    pub lease_duration: Duration,
    pub request_lifetime: Duration,
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
    pub resource_scan_size: usize,
    pub resource_transfers_per_cycle: usize,
    pub content_chunk_bytes: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            push_batch_size: 32,
            pull_page_size: 100,
            max_peers_per_cycle: 32,
            idle_interval: Duration::from_secs(2),
            caught_up_poll_interval: Duration::from_secs(5),
            lease_duration: Duration::from_secs(30),
            request_lifetime: Duration::from_secs(10),
            initial_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(5 * 60),
            resource_scan_size: 100,
            resource_transfers_per_cycle: 8,
            content_chunk_bytes: 256 * 1_024,
        }
    }
}

impl SyncConfig {
    pub fn validate(&self) -> Result<(), SyncError> {
        if !(1..=100).contains(&self.push_batch_size)
            || !(1..=MAX_PEER_CHANGE_LIMIT).contains(&self.pull_page_size)
            || !(1..=100).contains(&self.max_peers_per_cycle)
            || self.idle_interval.is_zero()
            || self.caught_up_poll_interval.is_zero()
            || self.lease_duration.is_zero()
            || self.initial_backoff.is_zero()
            || self.maximum_backoff < self.initial_backoff
            || self.request_lifetime.as_millis() > MAX_REQUEST_LIFETIME_MS as u128
            || self.request_lifetime.as_millis() < 1_000
            || !(1..=MAX_RESOURCE_TRANSFER_BATCH).contains(&self.resource_scan_size)
            || !(1..=MAX_RESOURCE_TRANSFER_BATCH).contains(&self.resource_transfers_per_cycle)
            || self.content_chunk_bytes == 0
            || self.content_chunk_bytes > MAX_DOWNLOAD_CHUNK_BYTES
        {
            return Err(SyncError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CycleReport {
    pub pushed: u64,
    pub pulled: u64,
    pub retried: u64,
    pub rejected: u64,
    pub pull_failures: u64,
    pub resource_upload_bytes: u64,
    pub resource_download_bytes: u64,
    pub resource_uploads_completed: u64,
    pub resource_downloads_completed: u64,
    pub resource_retried: u64,
    pub resource_rejected: u64,
    pub resource_waiting_local: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncStatus {
    pub running: bool,
    pub cycle: u64,
    pub last_cycle_at_unix_ms: Option<i64>,
    pub last_report: CycleReport,
    pub counts: Option<SyncCounts>,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureKind {
    Retryable,
    Permanent,
    LocalContentUnavailable,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{detail}")]
pub struct TransportError {
    pub kind: TransportFailureKind,
    pub detail: String,
}

impl TransportError {
    #[must_use]
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self {
            kind: TransportFailureKind::Retryable,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            kind: TransportFailureKind::Permanent,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn local_content_unavailable(detail: impl Into<String>) -> Self {
        Self {
            kind: TransportFailureKind::LocalContentUnavailable,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PulledPage {
    pub operations: Vec<OperationEnvelope>,
    pub next_after: u64,
    pub has_more: bool,
}

#[async_trait]
pub trait SyncTransport: Send + Sync + 'static {
    async fn push(
        &self,
        peer: &PeerConfig,
        operation: &OperationEnvelope,
    ) -> Result<(), TransportError>;

    async fn pull(
        &self,
        target: &SyncTarget,
        limit: u16,
        now_unix_ms: i64,
        request_lifetime: Duration,
    ) -> Result<PulledPage, TransportError>;
}

#[async_trait]
pub trait ContentSyncTransport: Send + Sync + 'static {
    async fn content_availability(
        &self,
        peer: &PeerConfig,
        content_ids: &[ContentId],
    ) -> Result<BlobAvailability, TransportError>;

    async fn create_content_upload(
        &self,
        peer: &PeerConfig,
        resource: &ResourceRef,
    ) -> Result<UploadChunkResult, TransportError>;

    async fn content_upload_status(
        &self,
        peer: &PeerConfig,
        upload_url: Url,
    ) -> Result<UploadChunkResult, TransportError>;

    async fn upload_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        upload: RemoteUpload,
        maximum_chunk_bytes: usize,
    ) -> Result<UploadChunkResult, TransportError>;

    async fn download_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        maximum_chunk_bytes: usize,
    ) -> Result<fractonica_client_content::AppendResult, TransportError>;
}

pub trait SyncClock: Send + Sync + 'static {
    fn now_unix_ms(&self) -> Result<i64, SyncError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSyncClock;

impl SyncClock for SystemSyncClock {
    fn now_unix_ms(&self) -> Result<i64, SyncError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SyncError::Clock)?
            .as_millis();
        i64::try_from(millis).map_err(|_| SyncError::Clock)
    }
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("invalid synchronization configuration")]
    InvalidConfiguration,
    #[error("system clock is unavailable")]
    Clock,
    #[error("client store operation failed: {0}")]
    Store(#[from] ClientStoreError),
    #[error("synchronization task join failed: {0}")]
    Join(String),
}

pub struct SyncWorker<T, C = SystemSyncClock> {
    store: ClientSqliteStore,
    content: ClientContentStore,
    transport: Arc<T>,
    clock: C,
    config: SyncConfig,
    status: watch::Sender<SyncStatus>,
}

impl<T> SyncWorker<T, SystemSyncClock>
where
    T: SyncTransport + ContentSyncTransport,
{
    pub fn new(
        store: ClientSqliteStore,
        content: ClientContentStore,
        transport: T,
        config: SyncConfig,
    ) -> Result<(Self, watch::Receiver<SyncStatus>), SyncError> {
        Self::with_clock(store, content, transport, SystemSyncClock, config)
    }
}

impl<T, C> SyncWorker<T, C>
where
    T: SyncTransport + ContentSyncTransport,
    C: SyncClock,
{
    pub fn with_clock(
        store: ClientSqliteStore,
        content: ClientContentStore,
        transport: T,
        clock: C,
        config: SyncConfig,
    ) -> Result<(Self, watch::Receiver<SyncStatus>), SyncError> {
        config.validate()?;
        let (status, receiver) = watch::channel(SyncStatus::default());
        Ok((
            Self {
                store,
                content,
                transport: Arc::new(transport),
                clock,
                config,
                status,
            },
            receiver,
        ))
    }

    pub async fn run_cycle(&self) -> Result<CycleReport, SyncError> {
        let mut report = CycleReport::default();
        let peers = blocking({
            let store = self.store.clone();
            let limit = self.config.max_peers_per_cycle;
            move || store.enabled_peers(limit)
        })
        .await?;
        for peer in peers {
            let lease_time = self.clock.now_unix_ms()?;
            let lease_id = DeliveryLeaseId::new();
            let deliveries = blocking({
                let store = self.store.clone();
                let peer_id = peer.peer_id;
                let lease_duration = self.config.lease_duration;
                let limit = self.config.push_batch_size;
                move || store.lease_due(peer_id, lease_time, lease_duration, limit, lease_id)
            })
            .await?;
            for delivery in deliveries {
                match self.transport.push(&peer, &delivery.operation).await {
                    Ok(()) => {
                        let completed_at = self.clock.now_unix_ms()?;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = peer.peer_id;
                            let operation_id = delivery.operation.operation_id;
                            move || store.acknowledge(peer_id, operation_id, lease_id, completed_at)
                        })
                        .await?;
                        report.pushed += 1;
                    }
                    Err(error) if error.kind == TransportFailureKind::Permanent => {
                        let completed_at = self.clock.now_unix_ms()?;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = peer.peer_id;
                            let operation_id = delivery.operation.operation_id;
                            let detail = bounded_detail(error.detail);
                            move || {
                                store.reject(peer_id, operation_id, lease_id, completed_at, &detail)
                            }
                        })
                        .await?;
                        report.rejected += 1;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = peer.peer_id;
                            move || store.release_lease(peer_id, lease_id).map(|_| ())
                        })
                        .await?;
                        // A rejected prefix may authorize or causally precede
                        // the remaining batch, so do not cascade misleading
                        // permanent rejections through its suffix.
                        break;
                    }
                    Err(error) => {
                        let completed_at = self.clock.now_unix_ms()?;
                        let next =
                            add_duration(completed_at, self.backoff(delivery.attempt_count))?;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = peer.peer_id;
                            let operation_id = delivery.operation.operation_id;
                            let detail = bounded_detail(error.detail);
                            move || store.retry(peer_id, operation_id, lease_id, next, &detail)
                        })
                        .await?;
                        report.retried += 1;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = peer.peer_id;
                            move || store.release_lease(peer_id, lease_id).map(|_| ())
                        })
                        .await?;
                        // Delivery order is causal order. If an earlier
                        // operation (notably a capability grant) could not be
                        // accepted yet, pushing later dependent operations in
                        // this cycle would turn a temporary gap into permanent
                        // missing-authorization rejections at the peer.
                        break;
                    }
                }
            }
        }

        let pull_scan_time = self.clock.now_unix_ms()?;
        let targets = blocking({
            let store = self.store.clone();
            let limit = self.config.max_peers_per_cycle;
            move || store.due_sync_targets(pull_scan_time, limit)
        })
        .await?;
        for target in targets {
            let pull_time = self.clock.now_unix_ms()?;
            match self
                .transport
                .pull(
                    &target,
                    self.config.pull_page_size,
                    pull_time,
                    self.config.request_lifetime,
                )
                .await
            {
                Ok(page) => {
                    for operation in &page.operations {
                        blocking({
                            let store = self.store.clone();
                            let operation = operation.clone();
                            let peer_id = target.peer_id;
                            move || store.commit_from_peer(&operation, pull_time, peer_id)
                        })
                        .await?;
                    }
                    let next_pull = if page.has_more {
                        pull_time
                    } else {
                        add_duration(pull_time, self.config.caught_up_poll_interval)?
                    };
                    blocking({
                        let store = self.store.clone();
                        let target = target.clone();
                        move || {
                            store.advance_pull_cursor(
                                target.peer_id,
                                target.space_id,
                                target.after,
                                page.next_after,
                                pull_time,
                                next_pull,
                            )
                        }
                    })
                    .await?;
                    report.pulled = report
                        .pulled
                        .saturating_add(u64::try_from(page.operations.len()).unwrap_or(u64::MAX));
                }
                Err(error) => {
                    let failed_at = self.clock.now_unix_ms()?;
                    let attempt = target.pull_failure_count.saturating_add(1);
                    let next = add_duration(failed_at, self.backoff(attempt))?;
                    blocking({
                        let store = self.store.clone();
                        let target = target.clone();
                        let detail = bounded_detail(error.detail);
                        move || {
                            store.record_pull_failure(
                                target.peer_id,
                                target.space_id,
                                target.after,
                                next,
                                &detail,
                            )
                        }
                    })
                    .await?;
                    report.pull_failures += 1;
                }
            }
        }

        let candidates = blocking({
            let store = self.store.clone();
            let limit = self.config.resource_scan_size;
            move || store.resource_scan_candidates(limit)
        })
        .await?;
        for descriptor in candidates {
            let content = self.content.clone();
            let verified = tokio::task::spawn_blocking(move || content.blob(descriptor))
                .await
                .map_err(|error| SyncError::Join(error.to_string()))?;
            match verified {
                Ok(Some(_)) => {
                    let verified_at = self.clock.now_unix_ms()?;
                    blocking({
                        let store = self.store.clone();
                        move || store.mark_resource_local(descriptor, verified_at)
                    })
                    .await?;
                }
                Ok(None) | Err(_) => {
                    report.resource_waiting_local = report.resource_waiting_local.saturating_add(1);
                }
            }
        }

        let resource_lease = ResourceTransferLeaseId::new();
        let resource_lease_time = self.clock.now_unix_ms()?;
        let transfers = blocking({
            let store = self.store.clone();
            let duration = self.config.lease_duration;
            let limit = self.config.resource_transfers_per_cycle;
            move || store.lease_due_resources(resource_lease_time, duration, limit, resource_lease)
        })
        .await?;
        for transfer in transfers {
            match self
                .advance_resource_transfer(transfer, resource_lease)
                .await?
            {
                ResourceStep::Progress { direction, bytes } => match direction {
                    ResourceTransferDirection::Upload => {
                        report.resource_upload_bytes =
                            report.resource_upload_bytes.saturating_add(bytes);
                    }
                    ResourceTransferDirection::Download => {
                        report.resource_download_bytes =
                            report.resource_download_bytes.saturating_add(bytes);
                    }
                },
                ResourceStep::Complete { direction, bytes } => match direction {
                    ResourceTransferDirection::Upload => {
                        report.resource_upload_bytes =
                            report.resource_upload_bytes.saturating_add(bytes);
                        report.resource_uploads_completed =
                            report.resource_uploads_completed.saturating_add(1);
                    }
                    ResourceTransferDirection::Download => {
                        report.resource_download_bytes =
                            report.resource_download_bytes.saturating_add(bytes);
                        report.resource_downloads_completed =
                            report.resource_downloads_completed.saturating_add(1);
                    }
                },
                ResourceStep::Retried => {
                    report.resource_retried = report.resource_retried.saturating_add(1);
                }
                ResourceStep::Rejected => {
                    report.resource_rejected = report.resource_rejected.saturating_add(1);
                }
                ResourceStep::WaitingLocal => {
                    report.resource_waiting_local = report.resource_waiting_local.saturating_add(1);
                }
            }
        }
        Ok(report)
    }

    async fn advance_resource_transfer(
        &self,
        transfer: ResourceTransferItem,
        lease_id: ResourceTransferLeaseId,
    ) -> Result<ResourceStep, SyncError> {
        match self.execute_resource_transfer(&transfer, lease_id).await {
            Ok(step) => Ok(step),
            Err(ResourceExecutionError::Sync(error)) => Err(error),
            Err(ResourceExecutionError::Transport(error)) => {
                let failed_at = self.clock.now_unix_ms()?;
                let detail = bounded_detail(error.detail);
                match error.kind {
                    TransportFailureKind::LocalContentUnavailable
                        if transfer.direction == ResourceTransferDirection::Upload =>
                    {
                        blocking({
                            let store = self.store.clone();
                            let peer_id = transfer.peer.peer_id;
                            let content_id = transfer.resource.content_id;
                            let next =
                                add_duration(failed_at, self.backoff(transfer.attempt_count))?;
                            move || {
                                store.wait_for_local_resource(
                                    peer_id, content_id, lease_id, next, &detail,
                                )
                            }
                        })
                        .await?;
                        Ok(ResourceStep::WaitingLocal)
                    }
                    TransportFailureKind::Retryable
                    | TransportFailureKind::LocalContentUnavailable => {
                        let next = add_duration(failed_at, self.backoff(transfer.attempt_count))?;
                        blocking({
                            let store = self.store.clone();
                            let peer_id = transfer.peer.peer_id;
                            let content_id = transfer.resource.content_id;
                            let direction = transfer.direction;
                            move || {
                                store.retry_resource_transfer(
                                    peer_id, content_id, direction, lease_id, next, &detail,
                                )
                            }
                        })
                        .await?;
                        Ok(ResourceStep::Retried)
                    }
                    TransportFailureKind::Permanent => {
                        blocking({
                            let store = self.store.clone();
                            let peer_id = transfer.peer.peer_id;
                            let content_id = transfer.resource.content_id;
                            let direction = transfer.direction;
                            move || {
                                store.reject_resource_transfer(
                                    peer_id, content_id, direction, lease_id, failed_at, &detail,
                                )
                            }
                        })
                        .await?;
                        Ok(ResourceStep::Rejected)
                    }
                }
            }
        }
    }

    async fn execute_resource_transfer(
        &self,
        transfer: &ResourceTransferItem,
        lease_id: ResourceTransferLeaseId,
    ) -> Result<ResourceStep, ResourceExecutionError> {
        let descriptor = transfer.resource.descriptor();
        let availability = self
            .transport
            .content_availability(&transfer.peer, &[descriptor.content_id])
            .await?;
        let remote = availability_descriptor(&availability, descriptor.content_id)?;
        match transfer.direction {
            ResourceTransferDirection::Upload => {
                if let Some(remote) = remote {
                    if remote != descriptor {
                        return Err(TransportError::permanent(
                            "peer content length conflicts with the referenced descriptor",
                        )
                        .into());
                    }
                    self.complete_transfer(transfer, lease_id).await?;
                    return Ok(ResourceStep::Complete {
                        direction: transfer.direction,
                        bytes: 0,
                    });
                }
                let upload = if let Some(url) = &transfer.remote_upload_url {
                    let url = Url::parse(url).map_err(|error| {
                        TransportError::permanent(format!("stored upload URL is invalid: {error}"))
                    })?;
                    self.transport
                        .content_upload_status(&transfer.peer, url)
                        .await?
                } else {
                    self.transport
                        .create_content_upload(&transfer.peer, &transfer.resource)
                        .await?
                };
                if upload.upload.length != descriptor.byte_length {
                    return Err(TransportError::permanent(
                        "peer upload length conflicts with the referenced descriptor",
                    )
                    .into());
                }
                self.persist_transfer_progress(
                    transfer,
                    lease_id,
                    upload.upload.offset,
                    Some(upload.upload.url.as_str()),
                )
                .await?;
                if upload.complete {
                    self.complete_transfer(transfer, lease_id).await?;
                    return Ok(ResourceStep::Complete {
                        direction: transfer.direction,
                        bytes: 0,
                    });
                }
                let before = upload.upload.offset;
                let uploaded = self
                    .transport
                    .upload_content_chunk(
                        &transfer.peer,
                        &self.content,
                        descriptor,
                        upload.upload,
                        self.config.content_chunk_bytes,
                    )
                    .await?;
                self.persist_transfer_progress(
                    transfer,
                    lease_id,
                    uploaded.upload.offset,
                    Some(uploaded.upload.url.as_str()),
                )
                .await?;
                let bytes = uploaded.upload.offset.saturating_sub(before);
                if uploaded.complete {
                    self.complete_transfer(transfer, lease_id).await?;
                    Ok(ResourceStep::Complete {
                        direction: transfer.direction,
                        bytes,
                    })
                } else {
                    self.release_transfer_for_next_chunk(transfer, lease_id)
                        .await?;
                    Ok(ResourceStep::Progress {
                        direction: transfer.direction,
                        bytes,
                    })
                }
            }
            ResourceTransferDirection::Download => {
                let Some(remote) = remote else {
                    return Err(TransportError::retryable(
                        "the selected peer does not currently have this content",
                    )
                    .into());
                };
                if remote != descriptor {
                    return Err(TransportError::permanent(
                        "peer content length conflicts with the referenced descriptor",
                    )
                    .into());
                }
                let before = transfer.transferred_bytes;
                let downloaded = self
                    .transport
                    .download_content_chunk(
                        &transfer.peer,
                        &self.content,
                        descriptor,
                        self.config.content_chunk_bytes,
                    )
                    .await?;
                self.persist_transfer_progress(transfer, lease_id, downloaded.offset, None)
                    .await?;
                let bytes = downloaded.offset.saturating_sub(before);
                if downloaded.complete {
                    self.complete_transfer(transfer, lease_id).await?;
                    Ok(ResourceStep::Complete {
                        direction: transfer.direction,
                        bytes,
                    })
                } else {
                    self.release_transfer_for_next_chunk(transfer, lease_id)
                        .await?;
                    Ok(ResourceStep::Progress {
                        direction: transfer.direction,
                        bytes,
                    })
                }
            }
        }
    }

    async fn persist_transfer_progress(
        &self,
        transfer: &ResourceTransferItem,
        lease_id: ResourceTransferLeaseId,
        offset: u64,
        upload_url: Option<&str>,
    ) -> Result<(), SyncError> {
        let store = self.store.clone();
        let peer_id = transfer.peer.peer_id;
        let content_id = transfer.resource.content_id;
        let direction = transfer.direction;
        let upload_url = upload_url.map(ToOwned::to_owned);
        blocking(move || {
            store.record_resource_progress(
                peer_id,
                content_id,
                direction,
                lease_id,
                offset,
                upload_url.as_deref(),
            )
        })
        .await
    }

    async fn complete_transfer(
        &self,
        transfer: &ResourceTransferItem,
        lease_id: ResourceTransferLeaseId,
    ) -> Result<(), SyncError> {
        let completed_at = self.clock.now_unix_ms()?;
        let store = self.store.clone();
        let peer_id = transfer.peer.peer_id;
        let content_id = transfer.resource.content_id;
        let direction = transfer.direction;
        blocking(move || {
            store.complete_resource_transfer(peer_id, content_id, direction, lease_id, completed_at)
        })
        .await
    }

    async fn release_transfer_for_next_chunk(
        &self,
        transfer: &ResourceTransferItem,
        lease_id: ResourceTransferLeaseId,
    ) -> Result<(), SyncError> {
        let next = self.clock.now_unix_ms()?;
        let store = self.store.clone();
        let peer_id = transfer.peer.peer_id;
        let content_id = transfer.resource.content_id;
        let direction = transfer.direction;
        blocking(move || {
            store.continue_resource_transfer(peer_id, content_id, direction, lease_id, next)
        })
        .await
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut status = SyncStatus {
            running: true,
            ..SyncStatus::default()
        };
        self.status.send_replace(status.clone());
        loop {
            if *shutdown.borrow() {
                break;
            }
            let now = self.clock.now_unix_ms().ok();
            match self.run_cycle().await {
                Ok(report) => {
                    status.last_report = report;
                    status.last_error = None;
                }
                Err(error) => status.last_error = Some(error.to_string()),
            }
            status.cycle = status.cycle.saturating_add(1);
            status.last_cycle_at_unix_ms = now;
            status.counts = if let Some(value) = now {
                blocking({
                    let store = self.store.clone();
                    move || store.sync_counts(value)
                })
                .await
                .ok()
            } else {
                None
            };
            self.status.send_replace(status.clone());
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                () = tokio::time::sleep(self.config.idle_interval) => {}
            }
        }
        status.running = false;
        self.status.send_replace(status);
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(31);
        self.config
            .initial_backoff
            .saturating_mul(1_u32 << shift)
            .min(self.config.maximum_backoff)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceStep {
    Progress {
        direction: ResourceTransferDirection,
        bytes: u64,
    },
    Complete {
        direction: ResourceTransferDirection,
        bytes: u64,
    },
    Retried,
    Rejected,
    WaitingLocal,
}

enum ResourceExecutionError {
    Transport(TransportError),
    Sync(SyncError),
}

impl From<TransportError> for ResourceExecutionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<SyncError> for ResourceExecutionError {
    fn from(error: SyncError) -> Self {
        Self::Sync(error)
    }
}

fn availability_descriptor(
    availability: &BlobAvailability,
    content_id: ContentId,
) -> Result<Option<ContentDescriptor>, TransportError> {
    let available = availability
        .available
        .iter()
        .filter(|value| value.content_id == content_id)
        .copied()
        .collect::<Vec<_>>();
    let missing = availability
        .missing
        .iter()
        .filter(|value| **value == content_id)
        .count();
    match (available.as_slice(), missing) {
        ([descriptor], 0) => Ok(Some(*descriptor)),
        ([], 1) => Ok(None),
        _ => Err(TransportError::permanent(
            "availability response did not partition the requested content ID exactly once",
        )),
    }
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ClientStoreError> + Send + 'static,
) -> Result<T, SyncError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| SyncError::Join(error.to_string()))?
        .map_err(SyncError::from)
}

fn add_duration(time: i64, duration: Duration) -> Result<i64, SyncError> {
    let millis = i64::try_from(duration.as_millis()).map_err(|_| SyncError::Clock)?;
    time.checked_add(millis).ok_or(SyncError::Clock)
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() <= MAX_ERROR_BYTES {
        return detail;
    }
    let mut boundary = MAX_ERROR_BYTES;
    while !detail.is_char_boundary(boundary) {
        boundary -= 1;
    }
    detail.truncate(boundary);
    detail
}

pub trait PeerProofCustody: Send + Sync + 'static {
    fn sign_read(
        &self,
        fields: PeerReadChangesFields,
    ) -> Result<PeerReadChangesProof, TransportError>;
}

pub struct SoftwarePeerProofCustody {
    node_key: fractonica_data_model::SigningKey,
    actor_key: fractonica_data_model::SigningKey,
}

impl SoftwarePeerProofCustody {
    #[must_use]
    pub const fn new(
        node_key: fractonica_data_model::SigningKey,
        actor_key: fractonica_data_model::SigningKey,
    ) -> Self {
        Self {
            node_key,
            actor_key,
        }
    }
}

impl PeerProofCustody for SoftwarePeerProofCustody {
    fn sign_read(
        &self,
        fields: PeerReadChangesFields,
    ) -> Result<PeerReadChangesProof, TransportError> {
        PeerReadChangesProof::sign(fields, &self.node_key, &self.actor_key)
            .map_err(|error| TransportError::permanent(error.to_string()))
    }
}

pub struct NodeHttpTransport<C> {
    client: Client,
    custody: C,
    bearer_tokens: BTreeMap<NodeId, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteUpload {
    pub url: Url,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadChunkResult {
    pub upload: RemoteUpload,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobAvailability {
    pub available: Vec<ContentDescriptor>,
    pub missing: Vec<ContentId>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AvailabilityRequest<'a> {
    content_ids: &'a [ContentId],
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AvailabilityResponse {
    available: Vec<ContentDescriptor>,
    missing: Vec<ContentId>,
}

impl<C> NodeHttpTransport<C> {
    pub fn new(
        custody: C,
        bearer_tokens: BTreeMap<NodeId, String>,
    ) -> Result<Self, TransportError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| TransportError::permanent(error.to_string()))?;
        Ok(Self {
            client,
            custody,
            bearer_tokens,
        })
    }

    pub async fn content_availability(
        &self,
        peer: &PeerConfig,
        content_ids: &[ContentId],
    ) -> Result<BlobAvailability, TransportError> {
        if content_ids.is_empty() || content_ids.len() > 256 {
            return Err(TransportError::permanent(
                "availability requires 1-256 content IDs",
            ));
        }
        let mut unique = content_ids.to_vec();
        unique.sort_unstable();
        unique.dedup();
        if unique.len() != content_ids.len() {
            return Err(TransportError::permanent(
                "availability content IDs must be unique",
            ));
        }
        let url = node_url(&peer.endpoint, "api/blobs/availability")?;
        let response = self
            .authorize(peer, self.client.post(url))
            .json(&AvailabilityRequest { content_ids })
            .send()
            .await
            .map_err(network_error)?;
        if !response.status().is_success() {
            return Err(http_failure(response.status()).await);
        }
        let response: AvailabilityResponse = response
            .json()
            .await
            .map_err(|error| TransportError::retryable(format!("invalid availability: {error}")))?;
        let mut observed = BTreeMap::new();
        for descriptor in &response.available {
            descriptor.validate().map_err(|error| {
                TransportError::permanent(format!("invalid available descriptor: {error}"))
            })?;
            if unique.binary_search(&descriptor.content_id).is_err()
                || observed.insert(descriptor.content_id, ()).is_some()
            {
                return Err(TransportError::permanent(
                    "availability returned an unknown or duplicate content ID",
                ));
            }
        }
        for content_id in &response.missing {
            if unique.binary_search(content_id).is_err()
                || observed.insert(*content_id, ()).is_some()
            {
                return Err(TransportError::permanent(
                    "availability returned an unknown or duplicate content ID",
                ));
            }
        }
        if observed.len() != unique.len() {
            return Err(TransportError::permanent(
                "availability omitted a requested content ID",
            ));
        }
        Ok(BlobAvailability {
            available: response.available,
            missing: response.missing,
        })
    }

    pub async fn create_content_upload(
        &self,
        peer: &PeerConfig,
        resource: &ResourceRef,
    ) -> Result<UploadChunkResult, TransportError> {
        let base = node_url(&peer.endpoint, "api/uploads")?;
        let metadata = upload_metadata(resource);
        let response = self
            .authorize(peer, self.client.post(base.clone()))
            .header("tus-resumable", "1.0.0")
            .header("upload-length", resource.byte_length)
            .header("upload-metadata", metadata)
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::CREATED {
            return Err(http_failure(response.status()).await);
        }
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| TransportError::permanent("upload response omitted Location"))?;
        let url = base.join(location).map_err(|error| {
            TransportError::permanent(format!("invalid upload location: {error}"))
        })?;
        require_upload_url(&base, &url)?;
        let offset = required_u64_header(response.headers(), "upload-offset")?;
        if offset > resource.byte_length {
            return Err(TransportError::permanent(
                "upload offset exceeds declared length",
            ));
        }
        Ok(UploadChunkResult {
            upload: RemoteUpload {
                url,
                offset,
                length: resource.byte_length,
            },
            complete: offset == resource.byte_length,
        })
    }

    pub async fn content_upload_status(
        &self,
        peer: &PeerConfig,
        upload_url: Url,
    ) -> Result<UploadChunkResult, TransportError> {
        let base = node_url(&peer.endpoint, "api/uploads")?;
        require_upload_url(&base, &upload_url)?;
        let response = self
            .authorize(peer, self.client.head(upload_url.clone()))
            .header("tus-resumable", "1.0.0")
            .send()
            .await
            .map_err(network_error)?;
        if !response.status().is_success() {
            return Err(http_failure(response.status()).await);
        }
        let offset = required_u64_header(response.headers(), "upload-offset")?;
        let length = required_u64_header(response.headers(), "upload-length")?;
        if offset > length {
            return Err(TransportError::permanent(
                "upload status offset exceeds length",
            ));
        }
        Ok(UploadChunkResult {
            upload: RemoteUpload {
                url: upload_url,
                offset,
                length,
            },
            complete: offset == length,
        })
    }

    pub async fn upload_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        upload: RemoteUpload,
        maximum_chunk_bytes: usize,
    ) -> Result<UploadChunkResult, TransportError> {
        if maximum_chunk_bytes == 0 || maximum_chunk_bytes > MAX_DOWNLOAD_CHUNK_BYTES {
            return Err(TransportError::permanent(
                "content chunk size must be between 1 and 4 MiB",
            ));
        }
        if upload.length != descriptor.byte_length || upload.offset > upload.length {
            return Err(TransportError::permanent(
                "upload state does not match the local descriptor",
            ));
        }
        if upload.offset == upload.length {
            return Ok(UploadChunkResult {
                upload,
                complete: true,
            });
        }
        let content = content.clone();
        let blob = tokio::task::spawn_blocking(move || content.blob(descriptor))
            .await
            .map_err(|error| TransportError::retryable(format!("content task failed: {error}")))?
            .map_err(content_error)?
            .ok_or_else(|| TransportError::local_content_unavailable("local content is missing"))?;
        let remaining = upload.length - upload.offset;
        let length = usize::try_from(remaining.min(maximum_chunk_bytes as u64))
            .map_err(|_| TransportError::permanent("content chunk length overflows"))?;
        let mut file = tokio::fs::File::open(blob.path)
            .await
            .map_err(|error| TransportError::retryable(error.to_string()))?;
        file.seek(std::io::SeekFrom::Start(upload.offset))
            .await
            .map_err(|error| TransportError::retryable(error.to_string()))?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)
            .await
            .map_err(|error| TransportError::retryable(error.to_string()))?;
        let checksum = STANDARD.encode(Sha256::digest(&bytes));
        let base = node_url(&peer.endpoint, "api/uploads")?;
        require_upload_url(&base, &upload.url)?;
        let response = self
            .authorize(peer, self.client.patch(upload.url.clone()))
            .header("tus-resumable", "1.0.0")
            .header("content-type", "application/offset+octet-stream")
            .header("upload-offset", upload.offset)
            .header("upload-checksum", format!("sha256 {checksum}"))
            .body(bytes)
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(http_failure(response.status()).await);
        }
        let offset = required_u64_header(response.headers(), "upload-offset")?;
        if offset <= upload.offset || offset > upload.length {
            return Err(TransportError::permanent(
                "upload PATCH returned an invalid offset",
            ));
        }
        Ok(UploadChunkResult {
            upload: RemoteUpload { offset, ..upload },
            complete: offset == descriptor.byte_length,
        })
    }

    pub async fn download_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        maximum_chunk_bytes: usize,
    ) -> Result<fractonica_client_content::AppendResult, TransportError> {
        if maximum_chunk_bytes == 0 || maximum_chunk_bytes > MAX_DOWNLOAD_CHUNK_BYTES {
            return Err(TransportError::permanent(
                "content chunk size must be between 1 and 4 MiB",
            ));
        }
        let content_for_offset = content.clone();
        let offset =
            tokio::task::spawn_blocking(move || content_for_offset.partial_offset(descriptor))
                .await
                .map_err(|error| {
                    TransportError::retryable(format!("content task failed: {error}"))
                })?
                .map_err(content_error)?;
        if offset == descriptor.byte_length {
            return Ok(fractonica_client_content::AppendResult {
                offset,
                complete: true,
            });
        }
        let end = offset
            .saturating_add(maximum_chunk_bytes as u64)
            .min(descriptor.byte_length)
            - 1;
        let url = node_url(
            &peer.endpoint,
            &format!("api/blobs/{}", descriptor.content_id),
        )?;
        let mut response = self
            .authorize(peer, self.client.get(url))
            .header("range", format!("bytes={offset}-{end}"))
            .send()
            .await
            .map_err(network_error)?;
        if response.status() != StatusCode::PARTIAL_CONTENT
            && !(offset == 0 && response.status() == StatusCode::OK)
        {
            return Err(http_failure(response.status()).await);
        }
        let expected = usize::try_from(end - offset + 1)
            .map_err(|_| TransportError::permanent("download range overflows"))?;
        let mut bytes = Vec::with_capacity(expected);
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if bytes.len().saturating_add(chunk.len()) > expected {
                return Err(TransportError::permanent(
                    "blob response exceeded the requested range",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != expected {
            return Err(TransportError::retryable(
                "blob response ended before the requested range",
            ));
        }
        let content = content.clone();
        tokio::task::spawn_blocking(move || {
            content.append_download_chunk(descriptor, offset, &bytes)
        })
        .await
        .map_err(|error| TransportError::retryable(format!("content task failed: {error}")))?
        .map_err(content_error)
    }

    fn authorize(
        &self,
        peer: &PeerConfig,
        mut request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        if let Some(token) = self.bearer_tokens.get(&peer.peer_id) {
            request = request.bearer_auth(token);
        } else if let Some(credential) = &peer.peer_transport_credential {
            request = request.header("authorization", format!("Fractonica-Peer {credential}"));
        }
        request
    }
}

#[async_trait]
impl<C> SyncTransport for NodeHttpTransport<C>
where
    C: PeerProofCustody,
{
    async fn push(
        &self,
        peer: &PeerConfig,
        operation: &OperationEnvelope,
    ) -> Result<(), TransportError> {
        let url = node_url(
            &peer.endpoint,
            &format!("api/spaces/{}/operations", operation.space_id),
        )?;
        let mut request = self.client.post(url).json(operation);
        request = self.authorize(peer, request);
        let response = request
            .send()
            .await
            .map_err(|error| TransportError::retryable(error.to_string()))?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(http_failure(response.status()).await)
    }

    async fn pull(
        &self,
        target: &SyncTarget,
        limit: u16,
        now_unix_ms: i64,
        request_lifetime: Duration,
    ) -> Result<PulledPage, TransportError> {
        if target.read_mode == PeerReadMode::SupervisorBearer {
            let token = self.bearer_tokens.get(&target.peer_id).ok_or_else(|| {
                TransportError::permanent("supervised-node reads require a configured bearer token")
            })?;
            let mut url = node_url(
                &target.endpoint,
                &format!("api/spaces/{}/changes", target.space_id),
            )?;
            url.query_pairs_mut()
                .append_pair("after", &target.after.to_string())
                .append_pair("limit", &limit.to_string());
            let response = self
                .client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(network_error)?;
            return decode_change_page(response, target).await;
        }
        let PeerReadMode::Paired {
            session_id,
            grant_operation_id,
        } = &target.read_mode
        else {
            unreachable!("supervisor mode returned above")
        };
        let expires_at_unix_ms = now_unix_ms
            .checked_add(i64::try_from(request_lifetime.as_millis()).map_err(|_| {
                TransportError::permanent("request lifetime exceeds signed milliseconds")
            })?)
            .ok_or_else(|| TransportError::permanent("request expiry overflows"))?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| TransportError::retryable(format!("entropy unavailable: {error}")))?;
        let proof = self.custody.sign_read(PeerReadChangesFields {
            session_id: *session_id,
            space_id: target.space_id,
            grant_operation_id: *grant_operation_id,
            after: target.after,
            limit,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            nonce: PeerRequestNonce::from_bytes(nonce),
        })?;
        let url = node_url(
            &target.endpoint,
            &format!("api/peer/spaces/{}/changes", target.space_id),
        )?;
        let response = self
            .client
            .post(url)
            .json(&PeerReadBody::from(proof))
            .send()
            .await
            .map_err(|error| TransportError::retryable(error.to_string()))?;
        decode_change_page(response, target).await
    }
}

async fn decode_change_page(
    response: reqwest::Response,
    target: &SyncTarget,
) -> Result<PulledPage, TransportError> {
    if !response.status().is_success() {
        return Err(http_failure(response.status()).await);
    }
    let page: OperationChangePage = response
        .json()
        .await
        .map_err(|error| TransportError::retryable(format!("invalid change page: {error}")))?;
    if page.space_id != target.space_id || page.next_after < target.after {
        return Err(TransportError::permanent(
            "change page identity or cursor is invalid",
        ));
    }
    Ok(PulledPage {
        operations: page
            .operations
            .into_iter()
            .map(|stored: StoredOperation| stored.operation)
            .collect(),
        next_after: page.next_after,
        has_more: page.has_more,
    })
}

#[async_trait]
impl<C> ContentSyncTransport for NodeHttpTransport<C>
where
    C: PeerProofCustody,
{
    async fn content_availability(
        &self,
        peer: &PeerConfig,
        content_ids: &[ContentId],
    ) -> Result<BlobAvailability, TransportError> {
        NodeHttpTransport::content_availability(self, peer, content_ids).await
    }

    async fn create_content_upload(
        &self,
        peer: &PeerConfig,
        resource: &ResourceRef,
    ) -> Result<UploadChunkResult, TransportError> {
        NodeHttpTransport::create_content_upload(self, peer, resource).await
    }

    async fn content_upload_status(
        &self,
        peer: &PeerConfig,
        upload_url: Url,
    ) -> Result<UploadChunkResult, TransportError> {
        NodeHttpTransport::content_upload_status(self, peer, upload_url).await
    }

    async fn upload_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        upload: RemoteUpload,
        maximum_chunk_bytes: usize,
    ) -> Result<UploadChunkResult, TransportError> {
        NodeHttpTransport::upload_content_chunk(
            self,
            peer,
            content,
            descriptor,
            upload,
            maximum_chunk_bytes,
        )
        .await
    }

    async fn download_content_chunk(
        &self,
        peer: &PeerConfig,
        content: &ClientContentStore,
        descriptor: ContentDescriptor,
        maximum_chunk_bytes: usize,
    ) -> Result<fractonica_client_content::AppendResult, TransportError> {
        NodeHttpTransport::download_content_chunk(
            self,
            peer,
            content,
            descriptor,
            maximum_chunk_bytes,
        )
        .await
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerReadBody {
    protocol_version: u8,
    session_id: String,
    node_id: String,
    actor_id: String,
    grant_operation_id: String,
    after: u64,
    limit: u16,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    nonce: String,
    node_signature: String,
    actor_signature: String,
}

impl From<PeerReadChangesProof> for PeerReadBody {
    fn from(proof: PeerReadChangesProof) -> Self {
        Self {
            protocol_version: proof.protocol_version,
            session_id: proof.session_id.to_string(),
            node_id: proof.node_id.to_string(),
            actor_id: proof.actor_id.to_string(),
            grant_operation_id: proof.grant_operation_id.to_string(),
            after: proof.after,
            limit: proof.limit,
            issued_at_unix_ms: proof.issued_at_unix_ms,
            expires_at_unix_ms: proof.expires_at_unix_ms,
            nonce: proof.nonce.to_string(),
            node_signature: proof.node_signature_hex(),
            actor_signature: proof.actor_signature_hex(),
        }
    }
}

fn node_url(endpoint: &str, path: &str) -> Result<Url, TransportError> {
    let mut url = Url::parse(endpoint)
        .map_err(|error| TransportError::permanent(format!("invalid peer endpoint: {error}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(TransportError::permanent(
            "peer endpoint must be an HTTP(S) origin",
        ));
    }
    url.set_path(path);
    Ok(url)
}

fn require_upload_url(base: &Url, upload: &Url) -> Result<(), TransportError> {
    let same_origin = base.scheme() == upload.scheme()
        && base.host_str() == upload.host_str()
        && base.port_or_known_default() == upload.port_or_known_default();
    if !same_origin
        || !upload.username().is_empty()
        || upload.password().is_some()
        || upload.query().is_some()
        || upload.fragment().is_some()
        || !upload.path().starts_with("/api/uploads/")
    {
        return Err(TransportError::permanent(
            "upload URL escaped the configured node origin",
        ));
    }
    Ok(())
}

fn required_u64_header(
    headers: &reqwest::header::HeaderMap,
    name: &'static str,
) -> Result<u64, TransportError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| TransportError::permanent(format!("response omitted valid {name}")))
}

fn upload_metadata(resource: &ResourceRef) -> String {
    let mut values = vec![
        format!(
            "contentId {}",
            STANDARD.encode(resource.content_id.to_string().as_bytes())
        ),
        format!(
            "mediaType {}",
            STANDARD.encode(resource.media_type.as_bytes())
        ),
    ];
    if let Some(name) = &resource.original_name {
        values.push(format!("filename {}", STANDARD.encode(name.as_bytes())));
    }
    values.join(",")
}

fn network_error(error: reqwest::Error) -> TransportError {
    TransportError::retryable(error.to_string())
}

fn content_error(error: ClientContentError) -> TransportError {
    match error {
        ClientContentError::Io(ref source)
            if matches!(
                source.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            ) =>
        {
            TransportError::retryable(error.to_string())
        }
        _ => TransportError::permanent(error.to_string()),
    }
}

async fn http_failure(status: StatusCode) -> TransportError {
    let detail = format!("node returned HTTP {status}");
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        TransportError::retryable(detail)
    } else {
        TransportError::permanent(detail)
    }
}

#[cfg(test)]
mod tests;
