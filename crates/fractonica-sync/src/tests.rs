use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderValue, StatusCode as AxumStatus},
    response::{IntoResponse, Response},
    routing::{get, head, post},
};
use fractonica_client_content::ClientContentStore;
use fractonica_client_sqlite::{PeerSpaceConfig, SyncTarget};
use fractonica_content::{ContentDescriptor, ResourceRef, hash_bytes};
use fractonica_data_model::{
    EntityId, EntitySchema, OperationBody, OperationId, OperationNonce, ProtectedDocument,
    RecordDocument, SigningKey, SpaceId,
};
use fractonica_peer::PeerSessionId;
use serde_json::Value;
use uuid::Uuid;

use super::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn space() -> SpaceId {
    SpaceId::from_bytes([1; 32])
}

fn entity(byte: u8) -> EntityId {
    EntityId::new(Uuid::from_bytes([byte; 16]))
}

fn genesis(signing_key: &SigningKey) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        entity(1),
        EntitySchema::SpaceGenesis,
        Vec::new(),
        Vec::new(),
        1,
        OperationNonce::from_bytes([1; 16]),
        OperationBody::SpaceGenesis {
            controller: signing_key.actor_id(),
        },
        signing_key,
    )
    .unwrap()
}

fn record(
    signing_key: &SigningKey,
    id: EntityId,
    authorization: OperationId,
    nonce: u8,
) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        id,
        EntitySchema::Record,
        Vec::new(),
        vec![authorization],
        10 + i64::from(nonce),
        OperationNonce::from_bytes([nonce; 16]),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public {
                document: RecordDocument {
                    start_at_unix_ms: 100,
                    end_at_unix_ms: None,
                    emoji: None,
                    text: Some("sync".into()),
                    metadata: BTreeMap::new(),
                    resources: Vec::new(),
                    references: Vec::new(),
                },
            },
        },
        signing_key,
    )
    .unwrap()
}

fn record_with_resource(
    signing_key: &SigningKey,
    id: EntityId,
    authorization: OperationId,
    nonce: u8,
    resource: ResourceRef,
) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        id,
        EntitySchema::Record,
        Vec::new(),
        vec![authorization],
        10 + i64::from(nonce),
        OperationNonce::from_bytes([nonce; 16]),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public {
                document: RecordDocument {
                    start_at_unix_ms: 100,
                    end_at_unix_ms: None,
                    emoji: Some("📎".into()),
                    text: Some("content sync".into()),
                    metadata: BTreeMap::new(),
                    resources: vec![resource],
                    references: Vec::new(),
                },
            },
        },
        signing_key,
    )
    .unwrap()
}

#[derive(Clone)]
struct FixedClock(Arc<AtomicI64>);

impl FixedClock {
    fn new(value: i64) -> Self {
        Self(Arc::new(AtomicI64::new(value)))
    }

    fn set(&self, value: i64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl SyncClock for FixedClock {
    fn now_unix_ms(&self) -> Result<i64, SyncError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
struct FakeTransport {
    pushes: Mutex<VecDeque<Result<(), TransportError>>>,
    pulls: Mutex<VecDeque<Result<PulledPage, TransportError>>>,
}

#[async_trait]
impl SyncTransport for FakeTransport {
    async fn push(
        &self,
        _peer: &PeerConfig,
        _operation: &OperationEnvelope,
    ) -> Result<(), TransportError> {
        self.pushes.lock().unwrap().pop_front().unwrap_or(Ok(()))
    }

    async fn pull(
        &self,
        target: &SyncTarget,
        _limit: u16,
        _now_unix_ms: i64,
        _request_lifetime: Duration,
    ) -> Result<PulledPage, TransportError> {
        self.pulls.lock().unwrap().pop_front().unwrap_or_else(|| {
            Ok(PulledPage {
                operations: Vec::new(),
                next_after: target.after,
                has_more: false,
            })
        })
    }
}

#[async_trait]
impl ContentSyncTransport for FakeTransport {
    async fn content_availability(
        &self,
        _peer: &PeerConfig,
        _content_ids: &[ContentId],
    ) -> Result<BlobAvailability, TransportError> {
        panic!("operation-only fixture unexpectedly received content work")
    }

    async fn create_content_upload(
        &self,
        _peer: &PeerConfig,
        _resource: &ResourceRef,
    ) -> Result<UploadChunkResult, TransportError> {
        panic!("operation-only fixture unexpectedly created an upload")
    }

    async fn content_upload_status(
        &self,
        _peer: &PeerConfig,
        _upload_url: Url,
    ) -> Result<UploadChunkResult, TransportError> {
        panic!("operation-only fixture unexpectedly resumed an upload")
    }

    async fn upload_content_chunk(
        &self,
        _peer: &PeerConfig,
        _content: &ClientContentStore,
        _descriptor: ContentDescriptor,
        _upload: RemoteUpload,
        _maximum_chunk_bytes: usize,
    ) -> Result<UploadChunkResult, TransportError> {
        panic!("operation-only fixture unexpectedly uploaded content")
    }

    async fn download_content_chunk(
        &self,
        _peer: &PeerConfig,
        _content: &ClientContentStore,
        _descriptor: ContentDescriptor,
        _maximum_chunk_bytes: usize,
    ) -> Result<fractonica_client_content::AppendResult, TransportError> {
        panic!("operation-only fixture unexpectedly downloaded content")
    }
}

fn config() -> SyncConfig {
    SyncConfig {
        push_batch_size: 10,
        pull_page_size: 10,
        max_peers_per_cycle: 10,
        idle_interval: Duration::from_millis(5),
        caught_up_poll_interval: Duration::from_secs(5),
        lease_duration: Duration::from_secs(5),
        request_lifetime: Duration::from_secs(1),
        initial_backoff: Duration::from_secs(1),
        maximum_backoff: Duration::from_secs(8),
        resource_scan_size: 10,
        resource_transfers_per_cycle: 10,
        content_chunk_bytes: 4,
    }
}

fn peer(endpoint: String, seed: u8) -> PeerConfig {
    PeerConfig {
        peer_id: key(seed).node_id(),
        endpoint,
        enabled: true,
        added_at_unix_ms: 1,
    }
}

#[tokio::test]
async fn worker_retries_then_acknowledges_without_blocking_the_async_executor() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(7);
    let genesis = genesis(&signing_key);
    store.commit_remote(&genesis, 1).unwrap();
    let peer = peer("https://peer.example".into(), 8);
    store.upsert_peer(&peer).unwrap();
    let operation = record(&signing_key, entity(2), genesis.operation_id, 2);
    store.commit_local(&operation, 2).unwrap();
    let transport = FakeTransport::default();
    transport
        .pushes
        .lock()
        .unwrap()
        .push_back(Err(TransportError::retryable("offline")));
    transport.pushes.lock().unwrap().push_back(Ok(()));
    let clock = FixedClock::new(10);
    let content_directory = tempfile::tempdir().unwrap();
    let content = ClientContentStore::open(content_directory.path()).unwrap();
    let (worker, _) =
        SyncWorker::with_clock(store.clone(), content, transport, clock.clone(), config()).unwrap();

    assert_eq!(worker.run_cycle().await.unwrap().retried, 1);
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().pending, 1);
    clock.set(1_010);
    assert_eq!(worker.run_cycle().await.unwrap().pushed, 1);
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().acknowledged, 1);
}

#[tokio::test]
async fn worker_commits_a_complete_pull_before_advancing_the_durable_cursor() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(7);
    let genesis = genesis(&signing_key);
    store.commit_remote(&genesis, 1).unwrap();
    let peer = peer("https://peer.example".into(), 9);
    store.upsert_peer(&peer).unwrap();
    store
        .configure_peer_space(&PeerSpaceConfig {
            peer_id: peer.peer_id,
            space_id: space(),
            read_mode: PeerReadMode::Paired {
                session_id: PeerSessionId::from_bytes([3; 16]),
                grant_operation_id: genesis.operation_id,
            },
            start_after: 0,
            next_pull_at_unix_ms: 10,
        })
        .unwrap();
    let remote = record(&signing_key, entity(3), genesis.operation_id, 3);
    let transport = FakeTransport::default();
    transport.pulls.lock().unwrap().push_back(Ok(PulledPage {
        operations: vec![remote.clone()],
        next_after: 7,
        has_more: false,
    }));
    let clock = FixedClock::new(10);
    let content_directory = tempfile::tempdir().unwrap();
    let content = ClientContentStore::open(content_directory.path()).unwrap();
    let (worker, _) =
        SyncWorker::with_clock(store.clone(), content, transport, clock, config()).unwrap();

    assert_eq!(worker.run_cycle().await.unwrap().pulled, 1);
    assert_eq!(
        store
            .entity(space(), remote.entity_id)
            .unwrap()
            .unwrap()
            .heads,
        vec![remote]
    );
    assert!(store.due_sync_targets(5_009, 10).unwrap().is_empty());
    assert_eq!(store.due_sync_targets(5_010, 10).unwrap()[0].after, 7);
}

#[derive(Clone)]
struct HttpState {
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    page: OperationChangePage,
}

async fn capture_push(
    State(state): State<HttpState>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> AxumStatus {
    state
        .requests
        .lock()
        .unwrap()
        .push((uri.path().to_owned(), body));
    AxumStatus::CREATED
}

async fn capture_pull(
    State(state): State<HttpState>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Json<OperationChangePage> {
    state
        .requests
        .lock()
        .unwrap()
        .push((uri.path().to_owned(), body));
    Json(state.page)
}

#[tokio::test]
async fn http_transport_uses_signed_admission_and_paired_read_contracts() {
    let signing_key = key(7);
    let genesis = genesis(&signing_key);
    let operation = record(&signing_key, entity(4), genesis.operation_id, 4);
    let page = OperationChangePage {
        space_id: space(),
        operations: vec![StoredOperation {
            local_sequence: 9,
            received_at_unix_ms: 10,
            operation: operation.clone(),
        }],
        next_after: 9,
        has_more: false,
    };
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = HttpState {
        requests: requests.clone(),
        page,
    };
    let app = Router::new()
        .route("/api/spaces/{space}/operations", post(capture_push))
        .route("/api/peer/spaces/{space}/changes", post(capture_pull))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let peer = peer(format!("http://{address}"), 10);
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(11), signing_key),
        BTreeMap::new(),
    )
    .unwrap();
    transport.push(&peer, &operation).await.unwrap();
    let pulled = transport
        .pull(
            &SyncTarget {
                peer_id: peer.peer_id,
                endpoint: peer.endpoint.clone(),
                space_id: space(),
                read_mode: PeerReadMode::Paired {
                    session_id: PeerSessionId::from_bytes([4; 16]),
                    grant_operation_id: genesis.operation_id,
                },
                after: 0,
                pull_failure_count: 0,
            },
            20,
            100,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_eq!(pulled.operations, vec![operation]);
    let captured = requests.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert!(captured[0].0.ends_with("/operations"));
    assert_eq!(captured[1].1["protocolVersion"], 1);
    assert_eq!(captured[1].1["after"], 0);
    assert_eq!(captured[1].1["limit"], 20);
    assert_eq!(
        captured[1].1["sessionId"],
        "04040404040404040404040404040404"
    );
    drop(captured);
    server.abort();
}

#[tokio::test]
async fn supervisor_publishes_stopped_status_when_cancelled() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    let content_directory = tempfile::tempdir().unwrap();
    let content = ClientContentStore::open(content_directory.path()).unwrap();
    let (worker, mut status) = SyncWorker::with_clock(
        store,
        content,
        FakeTransport::default(),
        FixedClock::new(1),
        config(),
    )
    .unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(worker.run(shutdown_rx));
    status.changed().await.unwrap();
    assert!(status.borrow().running);
    shutdown_tx.send(true).unwrap();
    task.await.unwrap();
    assert!(!status.borrow().running);
}

#[derive(Clone)]
struct ContentHttpState {
    uploaded: Arc<Mutex<Vec<u8>>>,
    source: Arc<Vec<u8>>,
    descriptor: ContentDescriptor,
}

async fn content_availability_handler(State(state): State<ContentHttpState>) -> Json<Value> {
    Json(serde_json::json!({
        "available": [state.descriptor],
        "missing": []
    }))
}

async fn upload_availability_handler(State(state): State<ContentHttpState>) -> Json<Value> {
    if state.uploaded.lock().unwrap().len() as u64 == state.descriptor.byte_length {
        Json(serde_json::json!({
            "available": [state.descriptor],
            "missing": []
        }))
    } else {
        Json(serde_json::json!({
            "available": [],
            "missing": [state.descriptor.content_id]
        }))
    }
}

async fn accept_operation() -> AxumStatus {
    AxumStatus::CREATED
}

async fn create_content_upload_handler() -> Response {
    let mut response = AxumStatus::CREATED.into_response();
    response.headers_mut().insert(
        "location",
        HeaderValue::from_static("/api/uploads/test-upload"),
    );
    response
        .headers_mut()
        .insert("upload-offset", HeaderValue::from_static("0"));
    response
}

async fn content_upload_status_handler(State(state): State<ContentHttpState>) -> Response {
    let uploaded = state.uploaded.lock().unwrap().len();
    let mut response = AxumStatus::OK.into_response();
    response.headers_mut().insert(
        "upload-offset",
        HeaderValue::from_str(&uploaded.to_string()).unwrap(),
    );
    response.headers_mut().insert(
        "upload-length",
        HeaderValue::from_str(&state.descriptor.byte_length.to_string()).unwrap(),
    );
    response
}

async fn append_content_handler(
    State(state): State<ContentHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let supplied: usize = headers["upload-offset"].to_str().unwrap().parse().unwrap();
    let mut uploaded = state.uploaded.lock().unwrap();
    assert_eq!(supplied, uploaded.len());
    uploaded.extend_from_slice(&body);
    let mut response = AxumStatus::NO_CONTENT.into_response();
    response.headers_mut().insert(
        "upload-offset",
        HeaderValue::from_str(&uploaded.len().to_string()).unwrap(),
    );
    response
}

async fn download_content_handler(
    State(state): State<ContentHttpState>,
    headers: HeaderMap,
) -> Response {
    let range = headers["range"].to_str().unwrap();
    let range = range.strip_prefix("bytes=").unwrap();
    let (start, end) = range.split_once('-').unwrap();
    let start: usize = start.parse().unwrap();
    let end: usize = end.parse().unwrap();
    (
        AxumStatus::PARTIAL_CONTENT,
        state.source[start..=end].to_vec(),
    )
        .into_response()
}

#[tokio::test]
async fn content_transport_checks_availability_and_moves_bounded_resumable_chunks() {
    let bytes = Arc::new(b"abcdefghij".to_vec());
    let descriptor = ContentDescriptor {
        content_id: hash_bytes(&bytes),
        byte_length: bytes.len() as u64,
    };
    let state = ContentHttpState {
        uploaded: Arc::new(Mutex::new(Vec::new())),
        source: bytes.clone(),
        descriptor,
    };
    let observed_upload = state.uploaded.clone();
    let app = Router::new()
        .route(
            "/api/blobs/availability",
            post(content_availability_handler),
        )
        .route("/api/uploads", post(create_content_upload_handler))
        .route(
            "/api/uploads/test-upload",
            head(content_upload_status_handler).patch(append_content_handler),
        )
        .route("/api/blobs/{content}", get(download_content_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let peer = peer(format!("http://{address}"), 20);
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(21), key(22)),
        BTreeMap::new(),
    )
    .unwrap();
    let availability = transport
        .content_availability(&peer, &[descriptor.content_id])
        .await
        .unwrap();
    assert_eq!(availability.available, vec![descriptor]);

    let upload_directory = tempfile::tempdir().unwrap();
    let upload_store = ClientContentStore::open(upload_directory.path()).unwrap();
    upload_store
        .import(descriptor, std::io::Cursor::new(bytes.as_slice()))
        .unwrap();
    let resource = ResourceRef {
        content_id: descriptor.content_id,
        byte_length: descriptor.byte_length,
        media_type: "application/octet-stream".into(),
        role: "attachment".into(),
        original_name: Some("fixture.bin".into()),
    };
    let created = transport
        .create_content_upload(&peer, &resource)
        .await
        .unwrap();
    let first = transport
        .upload_content_chunk(&peer, &upload_store, descriptor, created.upload, 4)
        .await
        .unwrap();
    assert_eq!(first.upload.offset, 4);
    let resumed = transport
        .content_upload_status(&peer, first.upload.url.clone())
        .await
        .unwrap();
    assert_eq!(resumed.upload.offset, 4);
    let second = transport
        .upload_content_chunk(&peer, &upload_store, descriptor, resumed.upload, 4)
        .await
        .unwrap();
    let complete = transport
        .upload_content_chunk(&peer, &upload_store, descriptor, second.upload, 4)
        .await
        .unwrap();
    assert!(complete.complete);
    assert_eq!(*observed_upload.lock().unwrap(), *bytes);

    let download_directory = tempfile::tempdir().unwrap();
    let download_store = ClientContentStore::open(download_directory.path()).unwrap();
    assert!(
        !transport
            .download_content_chunk(&peer, &download_store, descriptor, 4)
            .await
            .unwrap()
            .complete
    );
    assert_eq!(download_store.partial_offset(descriptor).unwrap(), 4);
    transport
        .download_content_chunk(&peer, &download_store, descriptor, 4)
        .await
        .unwrap();
    assert!(
        transport
            .download_content_chunk(&peer, &download_store, descriptor, 4)
            .await
            .unwrap()
            .complete
    );
    assert_eq!(
        download_store.read_range(descriptor, 0, 100).unwrap(),
        *bytes
    );
    server.abort();
}

#[tokio::test]
async fn supervisor_discovers_and_completes_a_bounded_resumable_upload() {
    let bytes = Arc::new(b"abcdefghij".to_vec());
    let descriptor = ContentDescriptor {
        content_id: hash_bytes(&bytes),
        byte_length: bytes.len() as u64,
    };
    let state = ContentHttpState {
        uploaded: Arc::new(Mutex::new(Vec::new())),
        source: bytes.clone(),
        descriptor,
    };
    let observed_upload = state.uploaded.clone();
    let app = Router::new()
        .route("/api/spaces/{space}/operations", post(accept_operation))
        .route("/api/blobs/availability", post(upload_availability_handler))
        .route("/api/uploads", post(create_content_upload_handler))
        .route(
            "/api/uploads/test-upload",
            head(content_upload_status_handler).patch(append_content_handler),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(40);
    let genesis = genesis(&signing_key);
    store.commit_remote(&genesis, 1).unwrap();
    let peer = peer(format!("http://{address}"), 41);
    store.upsert_peer(&peer).unwrap();
    let resource = ResourceRef {
        content_id: descriptor.content_id,
        byte_length: descriptor.byte_length,
        media_type: "application/octet-stream".into(),
        role: "attachment".into(),
        original_name: Some("fixture.bin".into()),
    };
    let operation =
        record_with_resource(&signing_key, entity(40), genesis.operation_id, 40, resource);
    store.commit_local(&operation, 2).unwrap();
    let content_directory = tempfile::tempdir().unwrap();
    let content = ClientContentStore::open(content_directory.path()).unwrap();
    content
        .import(descriptor, std::io::Cursor::new(bytes.as_slice()))
        .unwrap();
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(42), signing_key),
        BTreeMap::new(),
    )
    .unwrap();
    let (worker, _) = SyncWorker::with_clock(
        store.clone(),
        content,
        transport,
        FixedClock::new(10),
        config(),
    )
    .unwrap();

    let first = worker.run_cycle().await.unwrap();
    assert_eq!(first.resource_upload_bytes, 4);
    assert_eq!(first.resource_uploads_completed, 0);
    let second = worker.run_cycle().await.unwrap();
    assert_eq!(second.resource_upload_bytes, 4);
    let third = worker.run_cycle().await.unwrap();
    assert_eq!(third.resource_upload_bytes, 2);
    assert_eq!(third.resource_uploads_completed, 1);
    assert_eq!(*observed_upload.lock().unwrap(), *bytes);
    assert_eq!(
        store.sync_counts(10).unwrap().resources.completed_transfers,
        1
    );
    server.abort();
}

#[tokio::test]
async fn supervisor_resumes_a_peer_download_after_store_and_worker_reopen() {
    let bytes = Arc::new(b"abcdefghij".to_vec());
    let descriptor = ContentDescriptor {
        content_id: hash_bytes(&bytes),
        byte_length: bytes.len() as u64,
    };
    let state = ContentHttpState {
        uploaded: Arc::new(Mutex::new(Vec::new())),
        source: bytes.clone(),
        descriptor,
    };
    let app = Router::new()
        .route(
            "/api/blobs/availability",
            post(content_availability_handler),
        )
        .route("/api/blobs/{content}", get(download_content_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("client.sqlite3");
    let content_path = directory.path().join("content");
    let signing_key = key(50);
    let genesis = genesis(&signing_key);
    let source_peer = peer(format!("http://{address}"), 51);
    let resource = ResourceRef {
        content_id: descriptor.content_id,
        byte_length: descriptor.byte_length,
        media_type: "application/octet-stream".into(),
        role: "attachment".into(),
        original_name: Some("fixture.bin".into()),
    };
    let operation =
        record_with_resource(&signing_key, entity(50), genesis.operation_id, 50, resource);
    let store = ClientSqliteStore::open(&database_path).unwrap();
    store.commit_remote(&genesis, 1).unwrap();
    store.upsert_peer(&source_peer).unwrap();
    store
        .commit_from_peer(&operation, 2, source_peer.peer_id)
        .unwrap();
    let content = ClientContentStore::open(&content_path).unwrap();
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(52), key(50)),
        BTreeMap::new(),
    )
    .unwrap();
    let (worker, _) = SyncWorker::with_clock(
        store.clone(),
        content,
        transport,
        FixedClock::new(10),
        config(),
    )
    .unwrap();
    let first = worker.run_cycle().await.unwrap();
    assert_eq!(first.resource_download_bytes, 4);
    assert_eq!(first.resource_downloads_completed, 0);
    drop(worker);
    drop(store);

    let reopened = ClientSqliteStore::open(&database_path).unwrap();
    let reopened_content = ClientContentStore::open(&content_path).unwrap();
    assert_eq!(reopened_content.partial_offset(descriptor).unwrap(), 4);
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(52), signing_key),
        BTreeMap::new(),
    )
    .unwrap();
    let (worker, _) = SyncWorker::with_clock(
        reopened.clone(),
        reopened_content.clone(),
        transport,
        FixedClock::new(10),
        config(),
    )
    .unwrap();
    assert_eq!(worker.run_cycle().await.unwrap().resource_download_bytes, 4);
    let final_cycle = worker.run_cycle().await.unwrap();
    assert_eq!(final_cycle.resource_download_bytes, 2);
    assert_eq!(final_cycle.resource_downloads_completed, 1);
    assert_eq!(
        reopened_content.read_range(descriptor, 0, 100).unwrap(),
        *bytes
    );
    assert_eq!(
        reopened
            .sync_counts(10)
            .unwrap()
            .resources
            .completed_transfers,
        1
    );
    server.abort();
}

#[tokio::test]
async fn missing_peer_content_retries_without_blocking_operation_convergence() {
    let bytes = Arc::new(b"not available yet".to_vec());
    let descriptor = ContentDescriptor {
        content_id: hash_bytes(&bytes),
        byte_length: bytes.len() as u64,
    };
    let state = ContentHttpState {
        uploaded: Arc::new(Mutex::new(Vec::new())),
        source: bytes,
        descriptor,
    };
    let app = Router::new()
        .route("/api/blobs/availability", post(upload_availability_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(60);
    let genesis = genesis(&signing_key);
    store.commit_remote(&genesis, 1).unwrap();
    let source_peer = peer(format!("http://{address}"), 61);
    store.upsert_peer(&source_peer).unwrap();
    let operation = record_with_resource(
        &signing_key,
        entity(60),
        genesis.operation_id,
        60,
        ResourceRef {
            content_id: descriptor.content_id,
            byte_length: descriptor.byte_length,
            media_type: "application/octet-stream".into(),
            role: "attachment".into(),
            original_name: None,
        },
    );
    store
        .commit_from_peer(&operation, 2, source_peer.peer_id)
        .unwrap();
    assert_eq!(
        store
            .entity(space(), operation.entity_id)
            .unwrap()
            .unwrap()
            .heads,
        vec![operation]
    );
    let content_directory = tempfile::tempdir().unwrap();
    let content = ClientContentStore::open(content_directory.path()).unwrap();
    let transport = NodeHttpTransport::new(
        SoftwarePeerProofCustody::new(key(62), signing_key),
        BTreeMap::new(),
    )
    .unwrap();
    let (worker, _) = SyncWorker::with_clock(
        store.clone(),
        content.clone(),
        transport,
        FixedClock::new(10),
        config(),
    )
    .unwrap();

    let report = worker.run_cycle().await.unwrap();
    assert_eq!(report.resource_retried, 1);
    assert_eq!(
        store.sync_counts(10).unwrap().resources.pending_downloads,
        1
    );
    assert_eq!(content.partial_offset(descriptor).unwrap(), 0);
    server.abort();
}
