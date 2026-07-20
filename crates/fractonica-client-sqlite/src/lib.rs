#![forbid(unsafe_code)]
//! Durable local operation storage and per-peer delivery queues.
//!
//! A successful [`ClientSqliteStore::commit_local`] is the client write
//! boundary. Network delivery happens later through bounded, expiring leases.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use fractonica_data_model::{
    EntityId, EntitySchema, MAX_CAUSAL_PARENTS, NodeId, OperationBody, OperationEnvelope,
    OperationId, ProtectedDocument, SpaceId, Visibility,
};
use fractonica_peer::PeerSessionId;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub const CLIENT_SCHEMA_VERSION: u32 = 1;
pub const MAX_OUTBOX_BATCH: usize = 100;
pub const MAX_ERROR_BYTES: usize = 2_048;
pub const MAX_ENDPOINT_BYTES: usize = 2_048;

const MIGRATION: &str = include_str!("../migrations/0001_client_store.sql");

#[derive(Clone)]
pub struct ClientSqliteStore {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitSource {
    Local,
    Remote,
    Peer(NodeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitResult {
    pub local_sequence: u64,
    pub operation_id: OperationId,
    pub replayed: bool,
    pub queued_peers: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    pub peer_id: NodeId,
    pub endpoint: String,
    pub enabled: bool,
    pub added_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSpaceConfig {
    pub peer_id: NodeId,
    pub space_id: SpaceId,
    pub session_id: PeerSessionId,
    pub grant_operation_id: OperationId,
    pub start_after: u64,
    pub next_pull_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncTarget {
    pub peer_id: NodeId,
    pub endpoint: String,
    pub space_id: SpaceId,
    pub session_id: PeerSessionId,
    pub grant_operation_id: OperationId,
    pub after: u64,
    pub pull_failure_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeliveryLeaseId(Uuid);

impl DeliveryLeaseId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DeliveryLeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeliveryLeaseId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryItem {
    pub operation: OperationEnvelope,
    pub attempt_count: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalEntity {
    pub space_id: SpaceId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: u64,
    pub heads: Vec<OperationEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEntitySummary {
    pub operation_id: OperationId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub visibility: Visibility,
    pub conflicted: bool,
    pub tombstone: bool,
    pub start_at_unix_ms: Option<i64>,
    pub end_at_unix_ms: Option<i64>,
    pub sort_text: Option<String>,
    pub resource_count: u64,
    pub media_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxCounts {
    pub pending: u64,
    pub leased: u64,
    pub acknowledged: u64,
    pub rejected: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCounts {
    pub enabled_peers: u64,
    pub spaces: u64,
    pub pending_deliveries: u64,
    pub leased_deliveries: u64,
    pub rejected_deliveries: u64,
    pub due_pulls: u64,
}

#[derive(Debug, Error)]
pub enum ClientStoreError {
    #[error("failed to prepare the client database: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite client store failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("signed operation is invalid: {0}")]
    InvalidOperation(String),
    #[error("client database uses schema {found}, but this binary supports {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("client database lock was poisoned")]
    LockPoisoned,
    #[error("stored client data is corrupt: {0}")]
    Corrupt(String),
    #[error("operation {0} conflicts with already stored bytes")]
    OperationConflict(OperationId),
    #[error("operation parent {0} is missing locally")]
    MissingParent(OperationId),
    #[error("authorization operation {0} is missing locally")]
    MissingAuthorization(OperationId),
    #[error("operation parent {0} belongs to another entity or schema")]
    ParentMismatch(OperationId),
    #[error("entity already exists and a new root operation is not allowed")]
    EntityAlreadyExists,
    #[error("an entity cannot begin with a tombstone")]
    InitialTombstone,
    #[error("operation would exceed the {MAX_CAUSAL_PARENTS}-head limit")]
    TooManyHeads,
    #[error("timestamp must be nonnegative")]
    NegativeTimestamp,
    #[error("peer endpoint must be nonempty and no larger than {MAX_ENDPOINT_BYTES} bytes")]
    InvalidPeerEndpoint,
    #[error("peer {0} is not configured")]
    UnknownPeer(NodeId),
    #[error("outbox limit must be between 1 and {MAX_OUTBOX_BATCH}")]
    InvalidOutboxLimit,
    #[error("lease duration must be positive")]
    InvalidLeaseDuration,
    #[error("delivery item is not owned by the supplied active lease")]
    LeaseMismatch,
    #[error("delivery error must be no larger than {MAX_ERROR_BYTES} bytes")]
    DeliveryErrorTooLong,
    #[error("entity query limit must be between 1 and 200")]
    InvalidEntityLimit,
    #[error("sync target limit must be between 1 and 100")]
    InvalidSyncTargetLimit,
    #[error("pull cursor does not match the worker's observed cursor")]
    PullCursorMismatch,
    #[error("pull cursor cannot move backwards or exceed signed 64-bit storage")]
    InvalidPullCursor,
}

impl ClientSqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ClientStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(&path)?;
        configure(&connection, true)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(path),
        })
    }

    pub fn open_in_memory() -> Result<Self, ClientStoreError> {
        let mut connection = Connection::open_in_memory()?;
        configure(&connection, false)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(PathBuf::from(":memory:")),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn commit_local(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(operation, stored_at_unix_ms, CommitSource::Local)
    }

    pub fn commit_remote(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(operation, stored_at_unix_ms, CommitSource::Remote)
    }

    /// Stores an operation received from one configured peer and queues it for
    /// every other enabled peer. The source is recorded as acknowledged.
    pub fn commit_from_peer(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
        source_peer: NodeId,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(
            operation,
            stored_at_unix_ms,
            CommitSource::Peer(source_peer),
        )
    }

    pub fn commit(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
        source: CommitSource,
    ) -> Result<CommitResult, ClientStoreError> {
        operation
            .verify()
            .map_err(|error| ClientStoreError::InvalidOperation(error.to_string()))?;
        if stored_at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let projection_json = serde_json::to_string(operation)
            .map_err(|error| ClientStoreError::InvalidOperation(error.to_string()))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((sequence, existing)) =
            load_operation_row(&transaction, operation.operation_id)?
        {
            if existing != *operation {
                return Err(ClientStoreError::OperationConflict(operation.operation_id));
            }
            apply_delivery_source(
                &transaction,
                operation.operation_id,
                stored_at_unix_ms,
                source,
            )?;
            let queued_peers = delivery_count(&transaction, operation.operation_id)?;
            transaction.commit()?;
            return Ok(CommitResult {
                local_sequence: sequence,
                operation_id: operation.operation_id,
                replayed: true,
                queued_peers,
            });
        }
        validate_references(&transaction, operation)?;
        validate_topology(&transaction, operation)?;
        transaction.execute(
            "INSERT INTO client_operations (
                operation_id, space_id, entity_id, schema_id, actor_id,
                occurred_at_unix_ms, stored_at_unix_ms, locally_authored, projection_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                operation.operation_id.to_string(),
                operation.space_id.to_string(),
                operation.entity_id.to_string(),
                operation.schema.as_str(),
                operation.actor_id.to_string(),
                operation.occurred_at_unix_ms,
                stored_at_unix_ms,
                i64::from(matches!(source, CommitSource::Local)),
                projection_json,
            ],
        )?;
        let local_sequence = positive_u64(transaction.last_insert_rowid())?;
        insert_graph(&transaction, operation)?;
        insert_projection(&transaction, operation)?;
        apply_delivery_source(
            &transaction,
            operation.operation_id,
            stored_at_unix_ms,
            source,
        )?;
        let queued_peers = delivery_count(&transaction, operation.operation_id)?;
        transaction.commit()?;
        Ok(CommitResult {
            local_sequence,
            operation_id: operation.operation_id,
            replayed: false,
            queued_peers,
        })
    }

    pub fn upsert_peer(&self, peer: &PeerConfig) -> Result<(), ClientStoreError> {
        validate_peer(peer)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO client_peers (peer_id, endpoint, enabled, added_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_id) DO UPDATE SET endpoint = excluded.endpoint, enabled = excluded.enabled",
            params![
                peer.peer_id.to_string(),
                peer.endpoint,
                i64::from(peer.enabled),
                peer.added_at_unix_ms,
            ],
        )?;
        if peer.enabled {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT ?1, operation_id, 'pending', ?2 FROM client_operations
                   WHERE schema_id <> 'space.genesis'",
                params![peer.peer_id.to_string(), peer.added_at_unix_ms],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn set_peer_enabled(&self, peer_id: NodeId, enabled: bool) -> Result<(), ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE client_peers SET enabled = ?2 WHERE peer_id = ?1",
            params![peer_id.to_string(), i64::from(enabled)],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::UnknownPeer(peer_id));
        }
        if enabled {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT ?1, operation_id, 'pending', stored_at_unix_ms
                   FROM client_operations WHERE schema_id <> 'space.genesis'",
                params![peer_id.to_string()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn enabled_peers(&self, limit: usize) -> Result<Vec<PeerConfig>, ClientStoreError> {
        if !(1..=100).contains(&limit) {
            return Err(ClientStoreError::InvalidSyncTargetLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT peer_id, endpoint, enabled, added_at_unix_ms
             FROM client_peers WHERE enabled = 1 ORDER BY peer_id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit_i64(limit)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        rows.map(|row| {
            let row = row?;
            Ok(PeerConfig {
                peer_id: row
                    .0
                    .parse()
                    .map_err(|error| corrupt(format!("invalid peer ID: {error}")))?,
                endpoint: row.1,
                enabled: row.2,
                added_at_unix_ms: row.3,
            })
        })
        .collect()
    }

    pub fn configure_peer_space(&self, config: &PeerSpaceConfig) -> Result<(), ClientStoreError> {
        if config.next_pull_at_unix_ms < 0 || config.start_after > i64::MAX as u64 {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        let connection = self.lock()?;
        let configured = connection
            .query_row(
                "SELECT 1 FROM client_peers WHERE peer_id = ?1",
                params![config.peer_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !configured {
            return Err(ClientStoreError::UnknownPeer(config.peer_id));
        }
        connection.execute(
            "INSERT INTO client_peer_spaces (
                peer_id, space_id, session_id, grant_operation_id,
                pull_after, next_pull_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(peer_id, space_id) DO UPDATE SET
                session_id = excluded.session_id,
                grant_operation_id = excluded.grant_operation_id",
            params![
                config.peer_id.to_string(),
                config.space_id.to_string(),
                config.session_id.to_string(),
                config.grant_operation_id.to_string(),
                i64::try_from(config.start_after)
                    .map_err(|_| ClientStoreError::InvalidPullCursor)?,
                config.next_pull_at_unix_ms,
            ],
        )?;
        Ok(())
    }

    pub fn due_sync_targets(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<SyncTarget>, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if !(1..=100).contains(&limit) {
            return Err(ClientStoreError::InvalidSyncTargetLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT p.peer_id, p.endpoint, s.space_id, s.session_id,
                    s.grant_operation_id, s.pull_after, s.pull_failure_count
             FROM client_peer_spaces s
             JOIN client_peers p ON p.peer_id = s.peer_id
             WHERE p.enabled = 1 AND s.next_pull_at_unix_ms <= ?1
             ORDER BY s.next_pull_at_unix_ms, p.peer_id, s.space_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_unix_ms, limit_i64(limit)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        rows.map(|row| {
            let row = row?;
            Ok(SyncTarget {
                peer_id: row
                    .0
                    .parse()
                    .map_err(|error| corrupt(format!("invalid peer ID: {error}")))?,
                endpoint: row.1,
                space_id: row
                    .2
                    .parse()
                    .map_err(|error| corrupt(format!("invalid space ID: {error}")))?,
                session_id: row
                    .3
                    .parse()
                    .map_err(|error| corrupt(format!("invalid session ID: {error}")))?,
                grant_operation_id: row
                    .4
                    .parse()
                    .map_err(|error| corrupt(format!("invalid grant ID: {error}")))?,
                after: nonnegative_u64(row.5)?,
                pull_failure_count: u32::try_from(row.6)
                    .map_err(|_| corrupt("pull failure count overflow"))?,
            })
        })
        .collect()
    }

    pub fn advance_pull_cursor(
        &self,
        peer_id: NodeId,
        space_id: SpaceId,
        expected_after: u64,
        next_after: u64,
        pulled_at_unix_ms: i64,
        next_pull_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        if pulled_at_unix_ms < 0
            || next_pull_at_unix_ms < 0
            || expected_after > i64::MAX as u64
            || next_after > i64::MAX as u64
            || next_after < expected_after
        {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_peer_spaces SET
                pull_after = ?4, next_pull_at_unix_ms = ?6,
                pull_failure_count = 0, last_pull_error = NULL,
                last_pull_at_unix_ms = ?5
             WHERE peer_id = ?1 AND space_id = ?2 AND pull_after = ?3",
            params![
                peer_id.to_string(),
                space_id.to_string(),
                i64::try_from(expected_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                i64::try_from(next_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                pulled_at_unix_ms,
                next_pull_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::PullCursorMismatch);
        }
        Ok(())
    }

    pub fn record_pull_failure(
        &self,
        peer_id: NodeId,
        space_id: SpaceId,
        expected_after: u64,
        next_pull_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        if next_pull_at_unix_ms < 0 || expected_after > i64::MAX as u64 {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        if error.len() > MAX_ERROR_BYTES {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_peer_spaces SET
                next_pull_at_unix_ms = ?4,
                pull_failure_count = pull_failure_count + 1,
                last_pull_error = ?5
             WHERE peer_id = ?1 AND space_id = ?2 AND pull_after = ?3",
            params![
                peer_id.to_string(),
                space_id.to_string(),
                i64::try_from(expected_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                next_pull_at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::PullCursorMismatch);
        }
        Ok(())
    }

    pub fn sync_counts(&self, now_unix_ms: i64) -> Result<SyncCounts, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let connection = self.lock()?;
        let values: (i64, i64, i64, i64, i64, i64) = connection.query_row(
            "SELECT
                (SELECT count(*) FROM client_peers WHERE enabled = 1),
                (SELECT count(*) FROM client_peer_spaces),
                (SELECT count(*) FROM client_deliveries WHERE state = 'pending'),
                (SELECT count(*) FROM client_deliveries WHERE state = 'leased'),
                (SELECT count(*) FROM client_deliveries WHERE state = 'rejected'),
                (SELECT count(*) FROM client_peer_spaces s JOIN client_peers p USING(peer_id)
                 WHERE p.enabled = 1 AND s.next_pull_at_unix_ms <= ?1)",
            params![now_unix_ms],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        Ok(SyncCounts {
            enabled_peers: nonnegative_u64(values.0)?,
            spaces: nonnegative_u64(values.1)?,
            pending_deliveries: nonnegative_u64(values.2)?,
            leased_deliveries: nonnegative_u64(values.3)?,
            rejected_deliveries: nonnegative_u64(values.4)?,
            due_pulls: nonnegative_u64(values.5)?,
        })
    }

    pub fn lease_due(
        &self,
        peer_id: NodeId,
        now_unix_ms: i64,
        lease_duration: Duration,
        limit: usize,
        lease_id: DeliveryLeaseId,
    ) -> Result<Vec<DeliveryItem>, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if !(1..=MAX_OUTBOX_BATCH).contains(&limit) {
            return Err(ClientStoreError::InvalidOutboxLimit);
        }
        let lease_ms = i64::try_from(lease_duration.as_millis())
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let expires = now_unix_ms
            .checked_add(lease_ms)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = {
            let mut statement = transaction.prepare(
                "SELECT d.operation_id
                 FROM client_deliveries d
                 JOIN client_peers p ON p.peer_id = d.peer_id
                 JOIN client_operations o ON o.operation_id = d.operation_id
                 WHERE d.peer_id = ?1 AND p.enabled = 1 AND (
                    (d.state = 'pending' AND d.next_attempt_at_unix_ms <= ?2) OR
                    (d.state = 'leased' AND d.lease_expires_at_unix_ms <= ?2)
                 )
                 ORDER BY o.local_sequence LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![peer_id.to_string(), now_unix_ms, limit_i64(limit)?],
                |row| row.get::<_, String>(0),
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            let changed = transaction.execute(
                "UPDATE client_deliveries
                 SET state = 'leased', attempt_count = attempt_count + 1,
                     lease_id = ?3, lease_expires_at_unix_ms = ?4
                 WHERE peer_id = ?1 AND operation_id = ?2",
                params![peer_id.to_string(), id, lease_id.to_string(), expires],
            )?;
            if changed != 1 {
                return Err(corrupt("selected delivery disappeared"));
            }
            let operation_id =
                OperationId::parse(&id).map_err(|error| corrupt(error.to_string()))?;
            let (_, operation) = load_operation_row(&transaction, operation_id)?
                .ok_or_else(|| corrupt("delivery references a missing operation"))?;
            let attempts = transaction.query_row(
                "SELECT attempt_count FROM client_deliveries WHERE peer_id = ?1 AND operation_id = ?2",
                params![peer_id.to_string(), id],
                |row| row.get::<_, i64>(0),
            )?;
            items.push(DeliveryItem {
                operation,
                attempt_count: u32::try_from(attempts)
                    .map_err(|_| corrupt("attempt count overflow"))?,
            });
        }
        transaction.commit()?;
        Ok(items)
    }

    pub fn acknowledge(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        acknowledged_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "acknowledged",
            acknowledged_at_unix_ms,
            None,
        )
    }

    pub fn retry(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        next_attempt_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "pending",
            next_attempt_at_unix_ms,
            Some(error),
        )
    }

    pub fn reject(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        rejected_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "rejected",
            rejected_at_unix_ms,
            Some(error),
        )
    }

    fn finish_delivery(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        state: &'static str,
        at_unix_ms: i64,
        error: Option<&str>,
    ) -> Result<(), ClientStoreError> {
        if at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if error.is_some_and(|value| value.len() > MAX_ERROR_BYTES) {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_deliveries SET
                state = ?4, next_attempt_at_unix_ms = ?5,
                lease_id = NULL, lease_expires_at_unix_ms = NULL,
                acknowledged_at_unix_ms = CASE WHEN ?4 = 'acknowledged' THEN ?5 ELSE NULL END,
                last_error = ?6
             WHERE peer_id = ?1 AND operation_id = ?2
               AND state = 'leased' AND lease_id = ?3",
            params![
                peer_id.to_string(),
                operation_id.to_string(),
                lease_id.to_string(),
                state,
                at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::LeaseMismatch);
        }
        Ok(())
    }

    pub fn outbox_counts(&self, peer_id: NodeId) -> Result<OutboxCounts, ClientStoreError> {
        let connection = self.lock()?;
        let values = connection.query_row(
            "SELECT
                count(CASE WHEN state = 'pending' THEN 1 END),
                count(CASE WHEN state = 'leased' THEN 1 END),
                count(CASE WHEN state = 'acknowledged' THEN 1 END),
                count(CASE WHEN state = 'rejected' THEN 1 END)
             FROM client_deliveries WHERE peer_id = ?1",
            params![peer_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        Ok(OutboxCounts {
            pending: nonnegative_u64(values.0)?,
            leased: nonnegative_u64(values.1)?,
            acknowledged: nonnegative_u64(values.2)?,
            rejected: nonnegative_u64(values.3)?,
        })
    }

    pub fn entity(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
    ) -> Result<Option<LocalEntity>, ClientStoreError> {
        let connection = self.lock()?;
        let summary = connection.query_row(
            "SELECT min(schema_id), count(*), count(DISTINCT schema_id)
             FROM client_operations WHERE space_id = ?1 AND entity_id = ?2",
            params![space_id.to_string(), entity_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        let Some(schema) = summary.0 else {
            return Ok(None);
        };
        if summary.2 != 1 {
            return Err(corrupt("entity history contains multiple schemas"));
        }
        let schema = EntitySchema::parse(&schema).map_err(|error| corrupt(error.to_string()))?;
        let mut statement = connection.prepare(
            "SELECT o.projection_json FROM client_operations o
             JOIN client_entity_heads h ON h.operation_id = o.operation_id
             WHERE h.space_id = ?1 AND h.entity_id = ?2 ORDER BY o.operation_id",
        )?;
        let rows = statement.query_map(
            params![space_id.to_string(), entity_id.to_string()],
            |row| row.get::<_, String>(0),
        )?;
        let heads = rows
            .map(|row| decode_operation(&row?))
            .collect::<Result<Vec<_>, _>>()?;
        if heads.is_empty() {
            return Err(corrupt("entity history has no heads"));
        }
        Ok(Some(LocalEntity {
            space_id,
            entity_id,
            schema,
            operation_count: positive_u64(summary.1)?,
            heads,
        }))
    }

    pub fn list_entities(
        &self,
        space_id: SpaceId,
        schema: EntitySchema,
        limit: usize,
    ) -> Result<Vec<LocalEntitySummary>, ClientStoreError> {
        if !(1..=200).contains(&limit) {
            return Err(ClientStoreError::InvalidEntityLimit);
        }
        if !is_client_schema(schema) {
            return Ok(Vec::new());
        }
        let temporal = matches!(schema, EntitySchema::Record | EntitySchema::Event);
        let order = if temporal {
            "coalesce(p.start_at_unix_ms, -1) DESC, p.entity_id, p.operation_id"
        } else {
            "coalesce(p.sort_text, ''), p.entity_id, p.operation_id"
        };
        let sql = format!(
            "SELECT p.operation_id, p.entity_id, p.visibility, p.tombstone,
                    p.start_at_unix_ms, p.end_at_unix_ms, p.sort_text,
                    p.resource_count, p.media_bytes,
                    (SELECT count(*) FROM client_entity_heads h2
                     WHERE h2.space_id = p.space_id AND h2.entity_id = p.entity_id) > 1
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = ?2 AND p.tombstone = 0
             ORDER BY {order} LIMIT ?3"
        );
        let connection = self.lock()?;
        let mut statement = connection.prepare(&sql)?;
        let rows = statement.query_map(
            params![space_id.to_string(), schema.as_str(), limit_i64(limit)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, bool>(9)?,
                ))
            },
        )?;
        rows.map(|row| {
            let row = row?;
            Ok(LocalEntitySummary {
                operation_id: OperationId::parse(&row.0)
                    .map_err(|error| corrupt(error.to_string()))?,
                entity_id: EntityId::parse(&row.1).map_err(|error| corrupt(error.to_string()))?,
                schema,
                visibility: parse_visibility(&row.2)?,
                tombstone: row.3,
                start_at_unix_ms: row.4,
                end_at_unix_ms: row.5,
                sort_text: row.6,
                resource_count: nonnegative_u64(row.7)?,
                media_bytes: nonnegative_u64(row.8)?,
                conflicted: row.9,
            })
        })
        .collect()
    }

    /// Rebuilds every entity head and client projection from immutable local
    /// operations. Delivery state is not touched.
    pub fn rebuild_derived_state(&self) -> Result<u64, ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operations = {
            let mut statement = transaction
                .prepare("SELECT projection_json FROM client_operations ORDER BY local_sequence")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|row| decode_operation(&row?))
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.execute("DELETE FROM client_projections", [])?;
        transaction.execute("DELETE FROM client_entity_visibility", [])?;
        transaction.execute("DELETE FROM client_entity_heads", [])?;
        transaction.execute("DELETE FROM client_operation_authorizations", [])?;
        transaction.execute("DELETE FROM client_operation_parents", [])?;
        for operation in &operations {
            insert_graph(&transaction, operation)?;
            insert_projection(&transaction, operation)?;
        }
        transaction.commit()?;
        u64::try_from(operations.len()).map_err(|_| corrupt("operation count overflow"))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ClientStoreError> {
        self.connection
            .lock()
            .map_err(|_| ClientStoreError::LockPoisoned)
    }
}

fn configure(connection: &Connection, persistent: bool) -> Result<(), ClientStoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(Duration::from_secs(5))?;
    if persistent {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), ClientStoreError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > CLIENT_SCHEMA_VERSION {
        return Err(ClientStoreError::UnsupportedSchema {
            found: version,
            supported: CLIENT_SCHEMA_VERSION,
        });
    }
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATION)?;
        transaction.commit()?;
    }
    Ok(())
}

fn validate_peer(peer: &PeerConfig) -> Result<(), ClientStoreError> {
    if peer.added_at_unix_ms < 0 {
        return Err(ClientStoreError::NegativeTimestamp);
    }
    if peer.endpoint.is_empty() || peer.endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(ClientStoreError::InvalidPeerEndpoint);
    }
    Ok(())
}

fn apply_delivery_source(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    at_unix_ms: i64,
    source: CommitSource,
) -> Result<(), ClientStoreError> {
    let schema: String = transaction.query_row(
        "SELECT schema_id FROM client_operations WHERE operation_id = ?1",
        params![operation_id.to_string()],
        |row| row.get(0),
    )?;
    if schema == EntitySchema::SpaceGenesis.as_str() {
        return Ok(());
    }
    if let CommitSource::Peer(peer_id) = source {
        let configured = transaction
            .query_row(
                "SELECT 1 FROM client_peers WHERE peer_id = ?1",
                params![peer_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !configured {
            return Err(ClientStoreError::UnknownPeer(peer_id));
        }
    }
    match source {
        CommitSource::Remote => return Ok(()),
        CommitSource::Local | CommitSource::Peer(_) => {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT peer_id, ?1, 'pending', ?2 FROM client_peers
                   WHERE enabled = 1 AND (?3 IS NULL OR peer_id <> ?3)",
                params![
                    operation_id.to_string(),
                    at_unix_ms,
                    match source {
                        CommitSource::Peer(peer_id) => Some(peer_id.to_string()),
                        _ => None,
                    },
                ],
            )?;
        }
    }
    if let CommitSource::Peer(peer_id) = source {
        let changed = transaction.execute(
            "INSERT INTO client_deliveries (
                peer_id, operation_id, state, next_attempt_at_unix_ms, acknowledged_at_unix_ms
             ) VALUES (?1, ?2, 'acknowledged', ?3, ?3)
             ON CONFLICT(peer_id, operation_id) DO UPDATE SET
                state = 'acknowledged', lease_id = NULL, lease_expires_at_unix_ms = NULL,
                acknowledged_at_unix_ms = excluded.acknowledged_at_unix_ms, last_error = NULL",
            params![peer_id.to_string(), operation_id.to_string(), at_unix_ms],
        )?;
        if changed != 1 {
            return Err(corrupt("source peer delivery state was not recorded"));
        }
    }
    Ok(())
}

fn validate_references(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for parent in &operation.causal_parents {
        if load_operation_row(transaction, *parent)?.is_none() {
            return Err(ClientStoreError::MissingParent(*parent));
        }
    }
    for authorization in &operation.authorization {
        if load_operation_row(transaction, *authorization)?.is_none() {
            return Err(ClientStoreError::MissingAuthorization(*authorization));
        }
    }
    Ok(())
}

fn validate_topology(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for parent in &operation.causal_parents {
        let (entity, schema): (String, String) = transaction.query_row(
            "SELECT entity_id, schema_id FROM client_operations WHERE operation_id = ?1",
            params![parent.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if entity != operation.entity_id.to_string() || schema != operation.schema.as_str() {
            return Err(ClientStoreError::ParentMismatch(*parent));
        }
    }
    let (history, heads): (i64, i64) = transaction.query_row(
        "SELECT
            (SELECT count(*) FROM client_operations WHERE space_id = ?1 AND entity_id = ?2),
            (SELECT count(*) FROM client_entity_heads WHERE space_id = ?1 AND entity_id = ?2)",
        params![
            operation.space_id.to_string(),
            operation.entity_id.to_string()
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if history > 0 && heads == 0 {
        return Err(corrupt("entity history has no current heads"));
    }
    if history > 0 && operation.causal_parents.is_empty() {
        return Err(ClientStoreError::EntityAlreadyExists);
    }
    if history == 0 && matches!(operation.body, OperationBody::Tombstone) {
        return Err(ClientStoreError::InitialTombstone);
    }
    let consumed = operation
        .causal_parents
        .iter()
        .try_fold(0_i64, |count, parent| {
            let present: i64 = transaction.query_row(
                "SELECT count(*) FROM client_entity_heads WHERE operation_id = ?1",
                params![parent.to_string()],
                |row| row.get(0),
            )?;
            Ok::<_, rusqlite::Error>(count + present)
        })?;
    if heads - consumed + 1 > i64::try_from(MAX_CAUSAL_PARENTS).unwrap_or(i64::MAX) {
        return Err(ClientStoreError::TooManyHeads);
    }
    Ok(())
}

fn insert_graph(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for (position, parent) in operation.causal_parents.iter().enumerate() {
        transaction.execute(
            "INSERT INTO client_operation_parents (operation_id, parent_operation_id, position)
             VALUES (?1, ?2, ?3)",
            params![
                operation.operation_id.to_string(),
                parent.to_string(),
                limit_i64(position)?
            ],
        )?;
        transaction.execute(
            "DELETE FROM client_entity_heads WHERE operation_id = ?1",
            params![parent.to_string()],
        )?;
    }
    for (position, authorization) in operation.authorization.iter().enumerate() {
        transaction.execute(
            "INSERT INTO client_operation_authorizations (
                operation_id, authorization_operation_id, position
             ) VALUES (?1, ?2, ?3)",
            params![
                operation.operation_id.to_string(),
                authorization.to_string(),
                limit_i64(position)?
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO client_entity_heads (space_id, entity_id, schema_id, operation_id)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            operation.space_id.to_string(),
            operation.entity_id.to_string(),
            operation.schema.as_str(),
            operation.operation_id.to_string(),
        ],
    )?;
    Ok(())
}

fn insert_projection(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    let (start, end, sort_text) = match &operation.body {
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public { document },
        } => (
            Some(document.start_at_unix_ms),
            document.end_at_unix_ms,
            None,
        ),
        OperationBody::PutEvent {
            payload: ProtectedDocument::Public { document },
        } => (
            Some(document.start_at_unix_ms),
            document.end_at_unix_ms,
            Some(document.label.to_lowercase()),
        ),
        OperationBody::PutTag {
            payload: ProtectedDocument::Public { document },
        } => (None, None, Some(document.name.to_lowercase())),
        OperationBody::PutProfile { document } => (None, None, Some(document.handle.clone())),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Private { .. },
        }
        | OperationBody::PutTag {
            payload: ProtectedDocument::Private { .. },
        }
        | OperationBody::PutEvent {
            payload: ProtectedDocument::Private { .. },
        }
        | OperationBody::Tombstone
            if is_client_schema(operation.schema) =>
        {
            (None, None, None)
        }
        _ => return Ok(()),
    };
    let visibility = if let Some(value) = operation.body.declared_visibility() {
        let value = visibility_key(value).to_owned();
        if operation.causal_parents.is_empty() {
            transaction.execute(
                "INSERT INTO client_entity_visibility (space_id, entity_id, schema_id, visibility)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.entity_id.to_string(),
                    operation.schema.as_str(),
                    value
                ],
            )?;
        } else {
            let existing: String = transaction.query_row(
                "SELECT visibility FROM client_entity_visibility WHERE space_id = ?1 AND entity_id = ?2",
                params![operation.space_id.to_string(), operation.entity_id.to_string()],
                |row| row.get(0),
            )?;
            if existing != value {
                return Err(ClientStoreError::InvalidOperation(
                    "entity visibility is immutable".into(),
                ));
            }
        }
        value
    } else {
        transaction.query_row(
            "SELECT visibility FROM client_entity_visibility WHERE space_id = ?1 AND entity_id = ?2",
            params![operation.space_id.to_string(), operation.entity_id.to_string()],
            |row| row.get::<_, String>(0),
        )?
    };
    let resources = operation.body.resources();
    let resource_count =
        i64::try_from(resources.len()).map_err(|_| corrupt("resource count overflow"))?;
    let media_bytes = resources.iter().try_fold(0_i64, |total, resource| {
        let bytes = i64::try_from(resource.byte_length)
            .map_err(|_| corrupt("media byte count overflow"))?;
        total
            .checked_add(bytes)
            .ok_or_else(|| corrupt("media byte total overflow"))
    })?;
    transaction.execute(
        "INSERT INTO client_projections (
            operation_id, space_id, entity_id, schema_id, visibility, tombstone,
            start_at_unix_ms, end_at_unix_ms, sort_text, resource_count, media_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            operation.operation_id.to_string(),
            operation.space_id.to_string(),
            operation.entity_id.to_string(),
            operation.schema.as_str(),
            visibility,
            i64::from(matches!(operation.body, OperationBody::Tombstone)),
            start,
            end,
            sort_text,
            resource_count,
            media_bytes,
        ],
    )?;
    Ok(())
}

fn load_operation_row(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<(u64, OperationEnvelope)>, ClientStoreError> {
    connection
        .query_row(
            "SELECT local_sequence, projection_json FROM client_operations WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(sequence, json)| Ok((positive_u64(sequence)?, decode_operation(&json)?)))
        .transpose()
}

fn decode_operation(json: &str) -> Result<OperationEnvelope, ClientStoreError> {
    let operation: OperationEnvelope = serde_json::from_str(json)
        .map_err(|error| corrupt(format!("invalid stored operation JSON: {error}")))?;
    operation
        .verify()
        .map_err(|error| corrupt(format!("stored operation failed verification: {error}")))?;
    Ok(operation)
}

fn delivery_count(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<u64, ClientStoreError> {
    let value = connection.query_row(
        "SELECT count(*) FROM client_deliveries WHERE operation_id = ?1",
        params![operation_id.to_string()],
        |row| row.get::<_, i64>(0),
    )?;
    nonnegative_u64(value)
}

const fn is_client_schema(schema: EntitySchema) -> bool {
    matches!(
        schema,
        EntitySchema::Record | EntitySchema::Event | EntitySchema::Tag | EntitySchema::Profile
    )
}

const fn visibility_key(value: Visibility) -> &'static str {
    match value {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

fn parse_visibility(value: &str) -> Result<Visibility, ClientStoreError> {
    match value {
        "public" => Ok(Visibility::Public),
        "private" => Ok(Visibility::Private),
        _ => Err(corrupt("invalid stored visibility")),
    }
}

fn positive_u64(value: i64) -> Result<u64, ClientStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| corrupt("expected positive SQLite integer"))
}

fn nonnegative_u64(value: i64) -> Result<u64, ClientStoreError> {
    u64::try_from(value).map_err(|_| corrupt("expected nonnegative SQLite integer"))
}

fn limit_i64(value: usize) -> Result<i64, ClientStoreError> {
    i64::try_from(value).map_err(|_| corrupt("integer exceeds SQLite range"))
}

fn corrupt(detail: impl Into<String>) -> ClientStoreError {
    ClientStoreError::Corrupt(detail.into())
}

#[cfg(test)]
mod tests;
