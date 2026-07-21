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
use fractonica_pairing::{CapabilityGrantTemplate, InvitationParameters};
use fractonica_trust::SigningKey;
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
    assert!(matches!(&runtime.sync, RuntimeSync::Worker { .. }));
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

#[test]
fn paired_transport_accepts_only_plain_http_local_network_origins() {
    assert!(validate_paired_endpoint("http://127.0.0.1:8787/path").is_ok());
    assert!(validate_paired_endpoint("http://localhost:8787").is_ok());
    assert!(validate_paired_endpoint("http://192.168.1.20:8787").is_ok());
    assert!(validate_paired_endpoint("https://127.0.0.1:8787").is_err());
    assert!(validate_paired_endpoint("http://8.8.8.8:8787").is_err());
    assert!(validate_paired_endpoint("http://user@127.0.0.1:8787").is_err());
    assert!(validate_paired_endpoint("http://127.0.0.1:8787?secret=x").is_err());
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingTestRequest {
    invitation_id: String,
    frame_base64url: String,
}

struct PairingTestResponder {
    issued: fractonica_pairing::IssuedInvitation,
    responder_key: SigningKey,
    grant_operation_id: OperationId,
}

async fn pairing_test_handler(
    State(state): State<Arc<Mutex<Option<PairingTestResponder>>>>,
    Json(request): Json<PairingTestRequest>,
) -> Json<Value> {
    let fixture = state.lock().unwrap().take().unwrap();
    let descriptor = fixture.issued.invitation.descriptor();
    assert_eq!(request.invitation_id, descriptor.invitation_id.to_string());
    let first = URL_SAFE_NO_PAD.decode(request.frame_base64url).unwrap();
    let mut responder = fixture.issued.secret.start_responder().unwrap();
    let claim =
        JoinerClaim::from_canonical_bytes(&responder.read_message(&first).unwrap()).unwrap();
    claim.verify_for(descriptor).unwrap();
    let response_frame = responder.write_message(&[]).unwrap();
    let mut transport = responder.finish().unwrap();
    let receipt = PairingReceipt::sign(
        descriptor,
        &claim,
        *transport.handshake_hash(),
        [21; 32],
        &fixture.responder_key,
    );
    let receipt_frame = transport
        .write_message(&receipt.canonical_bytes().unwrap())
        .unwrap();
    Json(json!({
        "responseFrameBase64url": URL_SAFE_NO_PAD.encode(response_frame),
        "receiptFrameBase64url": URL_SAFE_NO_PAD.encode(receipt_frame),
        "session": {
            "invitationId": descriptor.invitation_id.to_string(),
            "spaceId": descriptor.space_id.to_string(),
            "state": "claimed",
            "expiresAtUnixMs": descriptor.expires_at_unix_ms,
            "joinerNodeId": claim.joiner_node_id.to_string(),
            "subjectActorId": claim.subject_actor_id.to_string(),
            "confirmationOctal": transport.confirmation_octal(),
            "grantOperationId": fixture.grant_operation_id.to_string(),
        }
    }))
}

#[tokio::test]
async fn pairing_joiner_retries_a_lost_first_transport_and_verifies_the_noise_receipt() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let now = unix_time_millis().unwrap();
    let responder_key = SigningKey::from_seed([11; 32]);
    let issued = PairingInvitation::issue(
        &responder_key,
        InvitationParameters {
            space_id: SpaceId::from_bytes([12; 32]),
            genesis_operation_id: OperationId::from_bytes([13; 32]),
            now_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            endpoint_hints: vec![endpoint.clone()],
            capability: CapabilityGrantTemplate {
                actions: vec![CapabilityAction::ReadSpace],
                schemas: vec![],
                visibilities: vec![],
                content_roles: vec![],
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: "desktop test".into(),
            },
        },
    )
    .unwrap();
    let invitation =
        PairingInvitation::decode(&issued.invitation.to_qr_string().unwrap(), now).unwrap();
    let state = Arc::new(Mutex::new(Some(PairingTestResponder {
        issued,
        responder_key,
        grant_operation_id: OperationId::from_bytes([14; 32]),
    })));
    let server = tokio::spawn(async move {
        let (first_connection, _) = listener.accept().await.unwrap();
        drop(first_connection);
        axum::serve(
            listener,
            Router::new()
                .route("/api/pairing/handshake", post(pairing_test_handler))
                .with_state(state),
        )
        .await
        .unwrap();
    });
    let identity = Arc::new(
        IdentityBundle::from_keys(
            SigningKey::from_seed([21; 32]),
            SigningKey::from_seed([22; 32]),
            SigningKey::from_seed([23; 32]),
            SpaceId::from_bytes([24; 32]),
        )
        .unwrap(),
    );

    let result = claim_pairing(invitation, now, identity).await.unwrap();
    assert_eq!(result.claim.endpoint, endpoint);
    assert_eq!(result.claim.confirmation_octal.len(), 10);
    assert_eq!(result.grant_operation_id, OperationId::from_bytes([14; 32]));
    server.abort();
}

fn standalone_config(root: &std::path::Path) -> StandaloneClientConfig {
    StandaloneClientConfig {
        client_data_dir: root.join("client"),
        display_name: "Personal space".into(),
    }
}

fn standalone_record(text: &str) -> ProtectedDocument<RecordDocument> {
    ProtectedDocument::Public {
        document: RecordDocument {
            start_at_unix_ms: 1_800_000_000_000,
            end_at_unix_ms: None,
            emoji: Some("🌀".into()),
            text: Some(text.into()),
            metadata: BTreeMap::new(),
            resources: Vec::new(),
            references: Vec::new(),
        },
    }
}

#[tokio::test]
async fn standalone_client_creates_offline_and_survives_force_drop() {
    let directory = tempfile::tempdir().unwrap();
    let config = standalone_config(directory.path());
    assert_eq!(
        ClientRuntime::prepare_standalone(config.clone(), false)
            .await
            .unwrap(),
        StandaloneIdentityAction::CreateOrResume
    );
    let identities = Arc::new(FileKeyStore::new(directory.path().join("identity")));
    let runtime = ClientRuntime::bootstrap_standalone(config.clone(), Arc::clone(&identities))
        .await
        .unwrap();
    assert!(matches!(&runtime.sync, RuntimeSync::Worker { .. }));
    let initial = runtime.status();
    assert_eq!(initial.sync.counts.unwrap_or_default().enabled_peers, 0);

    let committed = runtime
        .create_record(standalone_record("offline and durable"))
        .await
        .unwrap();
    assert_eq!(committed.queued_peers, 0);
    let expected_node = runtime.status().node_id;
    let expected_actor = runtime.status().actor_id;
    let expected_space = runtime.status().space_id;
    // Deliberately omit graceful shutdown. A successful local commit is the
    // durability boundary even when the application is force-closed.
    drop(runtime);

    assert_eq!(
        ClientRuntime::prepare_standalone(config.clone(), true)
            .await
            .unwrap(),
        StandaloneIdentityAction::OpenExisting
    );
    let reopened = ClientRuntime::bootstrap_standalone(config, identities)
        .await
        .unwrap();
    assert_eq!(reopened.status().node_id, expected_node);
    assert_eq!(reopened.status().actor_id, expected_actor);
    assert_eq!(reopened.status().space_id, expected_space);
    let records = reopened.list_records(20).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].summary.operation_id, committed.operation_id);
    assert_eq!(
        records[0]
            .document
            .as_ref()
            .and_then(|document| document.text.as_deref()),
        Some("offline and durable")
    );
    let previews = reopened.list_record_previews(20).await.unwrap();
    assert_eq!(
        previews[0].text_preview.as_deref(),
        Some("offline and durable")
    );
    let detail = reopened
        .record(records[0].summary.entity_id, committed.operation_id)
        .await
        .unwrap()
        .expect("record detail");
    assert_eq!(
        detail
            .document
            .as_ref()
            .and_then(|document| document.text.as_deref()),
        Some("offline and durable")
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_rejects_a_non_directory_data_path() {
    let directory = tempfile::tempdir().unwrap();
    let data_path = directory.path().join("client");
    std::fs::write(&data_path, b"not a directory").unwrap();
    let config = StandaloneClientConfig {
        client_data_dir: data_path,
        display_name: "Personal space".into(),
    };

    assert!(matches!(
        ClientRuntime::prepare_standalone(config, false).await,
        Err(ClientRuntimeError::UnsafeClientDataDirectory(
            "path is not a directory"
        ))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn standalone_rejects_a_symbolic_link_data_directory() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let data_path = directory.path().join("client");
    symlink(&target, &data_path).unwrap();
    let config = StandaloneClientConfig {
        client_data_dir: data_path,
        display_name: "Personal space".into(),
    };

    assert!(matches!(
        ClientRuntime::prepare_standalone(config, false).await,
        Err(ClientRuntimeError::UnsafeClientDataDirectory(
            "path is a symbolic link"
        ))
    ));
    assert!(!target.join("client.sqlite3").exists());
}

#[tokio::test]
async fn standalone_preparation_resumes_both_sides_of_key_creation() {
    let directory = tempfile::tempdir().unwrap();
    let config = standalone_config(directory.path());
    assert_eq!(
        ClientRuntime::prepare_standalone(config.clone(), false)
            .await
            .unwrap(),
        StandaloneIdentityAction::CreateOrResume
    );
    assert_eq!(
        ClientRuntime::prepare_standalone(config.clone(), false)
            .await
            .unwrap(),
        StandaloneIdentityAction::CreateOrResume
    );

    let identities = Arc::new(FileKeyStore::new(directory.path().join("identity")));
    identities.load_or_create().unwrap();
    assert_eq!(
        ClientRuntime::prepare_standalone(config.clone(), true)
            .await
            .unwrap(),
        StandaloneIdentityAction::OpenExisting
    );
    let runtime = ClientRuntime::bootstrap_standalone(config, identities)
        .await
        .unwrap();
    assert_eq!(runtime.list_records(20).await.unwrap(), Vec::new());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_identity_database_mismatches_fail_closed() {
    let orphaned_identity_root = tempfile::tempdir().unwrap();
    let orphaned_config = standalone_config(orphaned_identity_root.path());
    let orphaned_identity = Arc::new(FileKeyStore::new(
        orphaned_identity_root.path().join("identity"),
    ));
    orphaned_identity.load_or_create().unwrap();
    assert!(matches!(
        ClientRuntime::bootstrap_standalone(orphaned_config, orphaned_identity).await,
        Err(ClientRuntimeError::StandaloneRecovery(
            "protected identity exists without its client database"
        ))
    ));

    let missing_identity_root = tempfile::tempdir().unwrap();
    let config = standalone_config(missing_identity_root.path());
    let identities = Arc::new(FileKeyStore::new(
        missing_identity_root.path().join("identity"),
    ));
    let runtime = ClientRuntime::bootstrap_standalone(config.clone(), Arc::clone(&identities))
        .await
        .unwrap();
    runtime.shutdown().await.unwrap();
    drop(runtime);
    std::fs::remove_dir_all(identities.identity_dir()).unwrap();
    assert!(matches!(
        ClientRuntime::bootstrap_standalone(config, identities).await,
        Err(ClientRuntimeError::StandaloneRecovery(
            "established client database has no established protected identity"
        ))
    ));
}

#[tokio::test]
async fn standalone_rejects_a_different_established_identity() {
    let directory = tempfile::tempdir().unwrap();
    let config = standalone_config(directory.path());
    let first = Arc::new(FileKeyStore::new(directory.path().join("identity-a")));
    let runtime = ClientRuntime::bootstrap_standalone(config.clone(), first)
        .await
        .unwrap();
    runtime.shutdown().await.unwrap();
    drop(runtime);

    let replacement = Arc::new(FileKeyStore::new(directory.path().join("identity-b")));
    replacement.load_or_create().unwrap();
    assert!(matches!(
        ClientRuntime::bootstrap_standalone(config, replacement).await,
        Err(ClientRuntimeError::StandaloneRecovery(
            "protected identity does not match the established client binding"
        ))
    ));
}
