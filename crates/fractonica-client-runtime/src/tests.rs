use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use fractonica_application::OperationChangePage;
use fractonica_content::hash_bytes;
use fractonica_data_model::{
    CapabilityAction, CapabilityGrant, EntitySchema, OperationBody, OperationNonce, Visibility,
};
use fractonica_keystore::KeyStore;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct TestNodeState {
    node: Value,
    genesis: StoredOperation,
    grant: StoredOperation,
    pushed: Arc<Mutex<Vec<OperationEnvelope>>>,
}

fn require_token(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer 0123456789abcdef0123456789abcdef")
    );
}

async fn node_handler(State(state): State<TestNodeState>, headers: HeaderMap) -> Json<Value> {
    require_token(&headers);
    Json(state.node)
}

async fn operation_handler(
    State(state): State<TestNodeState>,
    AxumPath((_space, operation)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<StoredOperation>, StatusCode> {
    require_token(&headers);
    if operation == state.genesis.operation.operation_id.to_string() {
        Ok(Json(state.genesis))
    } else if operation == state.grant.operation.operation_id.to_string() {
        Ok(Json(state.grant))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn submit_handler(
    State(state): State<TestNodeState>,
    headers: HeaderMap,
    Json(operation): Json<OperationEnvelope>,
) -> StatusCode {
    require_token(&headers);
    state.pushed.lock().unwrap().push(operation);
    StatusCode::CREATED
}

#[derive(Deserialize)]
struct ChangesQuery {
    after: u64,
}

async fn changes_handler(
    State(state): State<TestNodeState>,
    AxumPath(space): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> Json<OperationChangePage> {
    require_token(&headers);
    let operations = if query.after == 0 {
        vec![state.genesis, state.grant]
    } else {
        Vec::new()
    };
    Json(OperationChangePage {
        space_id: space.parse().unwrap(),
        operations,
        next_after: 2,
        has_more: false,
    })
}

fn anchors(identity: &IdentityBundle) -> (SpaceDescriptor, StoredOperation, StoredOperation) {
    let genesis = OperationEnvelope::sign(
        identity.space_id(),
        EntityId::new(Uuid::from_bytes([1; 16])),
        EntitySchema::SpaceGenesis,
        Vec::new(),
        Vec::new(),
        1,
        OperationNonce::from_bytes([1; 16]),
        OperationBody::SpaceGenesis {
            controller: identity.space_controller_actor_id(),
        },
        identity.space_controller_key(),
    )
    .unwrap();
    let grant = OperationEnvelope::sign(
        identity.space_id(),
        EntityId::new(Uuid::from_bytes([2; 16])),
        EntitySchema::CapabilityGrant,
        Vec::new(),
        vec![genesis.operation_id],
        2,
        OperationNonce::from_bytes([2; 16]),
        OperationBody::CapabilityGrant {
            grant: CapabilityGrant {
                subject: identity.local_writer_actor_id(),
                actions: vec![
                    CapabilityAction::AppendOperation,
                    CapabilityAction::ReadSpace,
                ],
                schemas: vec![
                    EntitySchema::Event,
                    EntitySchema::Profile,
                    EntitySchema::Record,
                    EntitySchema::Tag,
                ],
                visibilities: vec![Visibility::Public, Visibility::Private],
                content_roles: Vec::new(),
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: "Local writer".into(),
            },
        },
        identity.space_controller_key(),
    )
    .unwrap();
    let descriptor = SpaceDescriptor {
        space_id: identity.space_id(),
        display_name: "Personal space".into(),
        genesis_operation_id: genesis.operation_id,
        initial_grant_operation_id: grant.operation_id,
        controller_actor_id: identity.space_controller_actor_id(),
        local_writer_actor_id: identity.local_writer_actor_id(),
        created_at_unix_ms: 1,
    };
    (
        descriptor,
        StoredOperation {
            local_sequence: 1,
            received_at_unix_ms: 1,
            operation: genesis,
        },
        StoredOperation {
            local_sequence: 2,
            received_at_unix_ms: 2,
            operation: grant,
        },
    )
}

#[tokio::test]
async fn adopts_exact_node_identity_commits_locally_and_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let node_data = directory.path().join("node");
    prepare_private_directory(&node_data).unwrap();
    let identity = FileKeyStore::new(node_data.join("identity"))
        .load_or_create()
        .unwrap();
    let (space, genesis, grant) = anchors(&identity);
    let pushed = Arc::new(Mutex::new(Vec::new()));
    let state = TestNodeState {
        node: json!({
            "nodeId": identity.node_id(),
            "spaces": [space],
            "profile": "node"
        }),
        genesis,
        grant,
        pushed: Arc::clone(&pushed),
    };
    let app = Router::new()
        .route("/api/node", get(node_handler))
        .route(
            "/api/spaces/{space}/operations/{operation}",
            get(operation_handler),
        )
        .route("/api/spaces/{space}/operations", post(submit_handler))
        .route("/api/spaces/{space}/changes", get(changes_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client_data = directory.path().join("client");
    let config = SupervisedNodeConfig {
        client_data_dir: client_data.clone(),
        node_data_dir: node_data.clone(),
        endpoint: format!("http://{address}"),
        bearer_token: TOKEN.into(),
        sync: SyncConfig {
            idle_interval: Duration::from_millis(5),
            caught_up_poll_interval: Duration::from_millis(10),
            ..SyncConfig::default()
        },
    };
    let runtime = ClientRuntime::bootstrap_supervised(config.clone())
        .await
        .unwrap();
    assert_eq!(runtime.status().node_id, identity.node_id());
    assert_eq!(runtime.status().actor_id, identity.local_writer_actor_id());
    assert_eq!(runtime.status().space_id, identity.space_id());

    let attachment_source = directory.path().join("eclipse.jpg");
    let attachment_bytes = b"native attachment";
    std::fs::write(&attachment_source, attachment_bytes).unwrap();
    assert!(matches!(
        runtime
            .import_attachment(
                attachment_source.clone(),
                "invalid media type".into(),
                Some("eclipse.jpg".into()),
            )
            .await,
        Err(ClientRuntimeError::ResourceValidation(_))
    ));
    let attachment = runtime
        .import_attachment(
            attachment_source.clone(),
            "image/jpeg".into(),
            Some("eclipse.jpg".into()),
        )
        .await
        .unwrap();
    assert_eq!(attachment.content_id, hash_bytes(attachment_bytes));
    assert_eq!(attachment.byte_length, attachment_bytes.len() as u64);
    assert_eq!(attachment.media_type, "image/jpeg");
    assert_eq!(attachment.role, RECORD_MEDIA_ROLE);
    assert_eq!(attachment.original_name.as_deref(), Some("eclipse.jpg"));
    assert_eq!(
        runtime
            .content_store()
            .read_range(attachment.descriptor(), 0, 100)
            .unwrap(),
        attachment_bytes
    );
    assert_eq!(
        runtime
            .import_attachment(
                attachment_source,
                "image/jpeg".into(),
                Some("eclipse.jpg".into()),
            )
            .await
            .unwrap(),
        attachment
    );

    let created = runtime
        .create_record(ProtectedDocument::Public {
            document: RecordDocument {
                start_at_unix_ms: 100,
                end_at_unix_ms: None,
                emoji: Some("🌀".into()),
                text: Some("local first".into()),
                metadata: BTreeMap::new(),
                resources: Vec::new(),
                references: Vec::new(),
            },
        })
        .await
        .unwrap();
    let records = runtime.list(EntitySchema::Record, 20).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation_id, created.operation_id);
    for _ in 0..100 {
        if !pushed.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(pushed.lock().unwrap()[0].operation_id, created.operation_id);
    runtime.shutdown().await.unwrap();
    drop(runtime);

    let restarted = ClientRuntime::bootstrap_supervised(config).await.unwrap();
    let records = restarted.list(EntitySchema::Record, 20).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation_id, created.operation_id);
    restarted.shutdown().await.unwrap();
    server.abort();
}

#[test]
fn rejects_non_loopback_supervisor_endpoints_before_touching_identity() {
    assert!(matches!(
        validate_supervised_endpoint("https://fractonica.com"),
        Err(ClientRuntimeError::NodeContract(_))
    ));
    assert!(matches!(
        validate_supervised_endpoint("http://192.168.0.24:8789"),
        Err(ClientRuntimeError::NodeContract(_))
    ));
}
