#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use fractonica_client_runtime::{
    ClientRuntime, PairingClaim, PrePairRecordPolicy, SupervisedNodeConfig,
};
use fractonica_client_sqlite::{CommitResult, LocalEntitySummary, LocalRecordSummary};
use fractonica_content::ResourceRef;
use fractonica_data_model::{
    EntityId, EntitySchema, EventDocument, ProfileDocument, ProtectedDocument, RecordDocument,
    SpaceId, TagDocument,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, RunEvent, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::{ShellExt, process::CommandChild};
use uuid::Uuid;

const CONNECTION_WAIT_ATTEMPTS: usize = 100;
const CONNECTION_WAIT_INTERVAL: Duration = Duration::from_millis(50);
/// Paired devices persist the authenticated endpoint, so the desktop node must
/// not ask the OS for a different ephemeral port after every restart.
const DESKTOP_NODE_BIND: &str = "0.0.0.0:8789";
const RESET_MARKER_FILE: &str = ".reset-local-installation";
const RESET_MARKER_BYTES: &[u8] = b"fractonica-reset-local-installation-v1\n";
#[cfg(target_os = "windows")]
const WINDOWS_FIREWALL_SCRIPT: &[u8] = include_bytes!("../../scripts/allow-local-network.ps1");

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeConnection {
    base_url: String,
    bearer_token: String,
    pairing_endpoint_hints: Vec<String>,
}

#[derive(Default)]
struct NodeSidecar {
    child: Mutex<Option<CommandChild>>,
    connection: Mutex<Option<NodeConnection>>,
    ready_file: Mutex<Option<PathBuf>>,
    client: Mutex<Option<Arc<ClientRuntime>>>,
    client_error: Mutex<Option<String>>,
    stderr_tail: Mutex<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientStatusResponse {
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    space_id: Option<String>,
    sync_running: bool,
    cycle: u64,
    pending_operations: u64,
    rejected_operations: u64,
    waiting_uploads: u64,
    pending_uploads: u64,
    pending_downloads: u64,
    rejected_resources: u64,
    synchronized_bytes: u64,
    total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientWorkspaceResponse {
    space_id: String,
    display_name: String,
    genesis_operation_id: String,
    initial_grant_operation_id: String,
    controller_actor_id: String,
    local_writer_actor_id: String,
    created_at_unix_ms: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitResponse {
    local_sequence: u64,
    operation_id: String,
    replayed: bool,
    queued_peers: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingClaimResponse {
    invitation_id: String,
    responder_node_id: String,
    space_id: String,
    endpoint: String,
    confirmation_octal: String,
    grant_operation_id: String,
    local_record_count: u64,
}

impl From<PairingClaim> for PairingClaimResponse {
    fn from(value: PairingClaim) -> Self {
        Self {
            invitation_id: value.invitation_id,
            responder_node_id: value.responder_node_id,
            space_id: value.space_id,
            endpoint: value.endpoint,
            confirmation_octal: value.confirmation_octal,
            grant_operation_id: value.grant_operation_id,
            local_record_count: value.local_record_count,
        }
    }
}

impl From<CommitResult> for CommitResponse {
    fn from(value: CommitResult) -> Self {
        Self {
            local_sequence: value.local_sequence,
            operation_id: value.operation_id.to_string(),
            replayed: value.replayed,
            queued_peers: value.queued_peers,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntitySummaryResponse {
    operation_id: String,
    entity_id: String,
    schema: &'static str,
    visibility: &'static str,
    conflicted: bool,
    tombstone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort_text: Option<String>,
    resource_count: u64,
    media_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordSummaryResponse {
    #[serde(flatten)]
    summary: EntitySummaryResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    document: Option<RecordDocument>,
}

impl From<LocalRecordSummary> for RecordSummaryResponse {
    fn from(value: LocalRecordSummary) -> Self {
        Self {
            summary: value.summary.into(),
            document: value.document,
        }
    }
}

impl From<LocalEntitySummary> for EntitySummaryResponse {
    fn from(value: LocalEntitySummary) -> Self {
        Self {
            operation_id: value.operation_id.to_string(),
            entity_id: value.entity_id.to_string(),
            schema: value.schema.as_str(),
            visibility: match value.visibility {
                fractonica_data_model::Visibility::Public => "public",
                fractonica_data_model::Visibility::Private => "private",
            },
            conflicted: value.conflicted,
            tombstone: value.tombstone,
            start_at_unix_ms: value.start_at_unix_ms,
            end_at_unix_ms: value.end_at_unix_ms,
            sort_text: value.sort_text,
            resource_count: value.resource_count,
            media_bytes: value.media_bytes,
        }
    }
}

#[tauri::command]
async fn node_connection(sidecar: State<'_, NodeSidecar>) -> Result<NodeConnection, String> {
    for _ in 0..CONNECTION_WAIT_ATTEMPTS {
        if let Ok(connection) = sidecar.connection.lock()
            && let Some(connection) = connection.clone()
        {
            return Ok(connection);
        }
        if let Ok(error) = sidecar.client_error.lock()
            && let Some(error) = error.clone()
        {
            return Err(error);
        }
        tokio::time::sleep(CONNECTION_WAIT_INTERVAL).await;
    }

    Err("The supervised Fractonica node did not become ready.".into())
}

#[tauri::command]
fn client_status(sidecar: State<'_, NodeSidecar>) -> ClientStatusResponse {
    let runtime = sidecar.client.lock().ok().and_then(|value| value.clone());
    if let Some(runtime) = runtime {
        let status = runtime.status();
        let counts = status.sync.counts.unwrap_or_default();
        return ClientStatusResponse {
            phase: "ready",
            node_id: Some(status.node_id.to_string()),
            actor_id: Some(status.actor_id.to_string()),
            space_id: status.space_id.map(|space_id| space_id.to_string()),
            sync_running: status.sync.running,
            cycle: status.sync.cycle,
            pending_operations: counts.pending_deliveries + counts.leased_deliveries,
            rejected_operations: counts.rejected_deliveries,
            waiting_uploads: counts.resources.waiting_uploads,
            pending_uploads: counts.resources.pending_uploads,
            pending_downloads: counts.resources.pending_downloads,
            rejected_resources: counts.resources.rejected_transfers,
            synchronized_bytes: counts.resources.transferred_bytes,
            total_bytes: counts.resources.total_bytes,
            last_error: status.sync.last_error,
        };
    }
    let error = sidecar
        .client_error
        .lock()
        .ok()
        .and_then(|value| value.clone());
    ClientStatusResponse {
        phase: if error.is_some() {
            "failed"
        } else {
            "starting"
        },
        node_id: None,
        actor_id: None,
        space_id: None,
        sync_running: false,
        cycle: 0,
        pending_operations: 0,
        rejected_operations: 0,
        waiting_uploads: 0,
        pending_uploads: 0,
        pending_downloads: 0,
        rejected_resources: 0,
        synchronized_bytes: 0,
        total_bytes: 0,
        last_error: error,
    }
}

#[tauri::command]
async fn client_create_record(
    sidecar: State<'_, NodeSidecar>,
    payload: ProtectedDocument<RecordDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .create_record(payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_update_record(
    sidecar: State<'_, NodeSidecar>,
    entity_id: String,
    payload: ProtectedDocument<RecordDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .update_record(parse_entity(&entity_id)?, payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_create_event(
    sidecar: State<'_, NodeSidecar>,
    payload: ProtectedDocument<EventDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .create_event(payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_update_event(
    sidecar: State<'_, NodeSidecar>,
    entity_id: String,
    payload: ProtectedDocument<EventDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .update_event(parse_entity(&entity_id)?, payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_create_tag(
    sidecar: State<'_, NodeSidecar>,
    payload: ProtectedDocument<TagDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .create_tag(payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_update_tag(
    sidecar: State<'_, NodeSidecar>,
    entity_id: String,
    payload: ProtectedDocument<TagDocument>,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .update_tag(parse_entity(&entity_id)?, payload)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_put_profile(
    sidecar: State<'_, NodeSidecar>,
    document: ProfileDocument,
) -> Result<CommitResponse, String> {
    Ok(client(&sidecar)?
        .put_profile(document)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_delete(
    sidecar: State<'_, NodeSidecar>,
    entity_id: String,
    schema: String,
) -> Result<CommitResponse, String> {
    let schema = EntitySchema::parse(&schema).map_err(command_error)?;
    Ok(client(&sidecar)?
        .delete(parse_entity(&entity_id)?, schema)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_list(
    sidecar: State<'_, NodeSidecar>,
    schema: String,
    limit: usize,
) -> Result<Vec<EntitySummaryResponse>, String> {
    let schema = EntitySchema::parse(&schema).map_err(command_error)?;
    Ok(client(&sidecar)?
        .list(schema, limit)
        .await
        .map_err(command_error)?
        .into_iter()
        .map(EntitySummaryResponse::from)
        .collect())
}

#[tauri::command]
async fn client_list_records(
    sidecar: State<'_, NodeSidecar>,
    limit: usize,
) -> Result<Vec<RecordSummaryResponse>, String> {
    Ok(client(&sidecar)?
        .list_records(limit)
        .await
        .map_err(command_error)?
        .into_iter()
        .map(RecordSummaryResponse::from)
        .collect())
}

#[tauri::command]
async fn client_import_attachments(
    window: tauri::WebviewWindow,
    sidecar: State<'_, NodeSidecar>,
    limit: usize,
) -> Result<Vec<ResourceRef>, String> {
    if !(1..=fractonica_data_model::MAX_RECORD_RESOURCES).contains(&limit) {
        return Err("Attachment import limit must be between 1 and 64.".to_owned());
    }
    let runtime = client(&sidecar)?;
    let (selection_tx, selection_rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_title("Attach files to this record")
        .pick_files(move |selection| {
            let _ = selection_tx.send(selection.unwrap_or_default());
        });
    let selected = selection_rx
        .await
        .map_err(|_| "The attachment picker closed unexpectedly.".to_owned())?;
    if selected.len() > limit {
        return Err(format!(
            "Select at most {limit} more attachment{} for this record.",
            if limit == 1 { "" } else { "s" }
        ));
    }
    let mut resources = Vec::with_capacity(selected.len());
    for selected_file in selected {
        let path = selected_file
            .into_path()
            .map_err(|_| "Only local filesystem attachments are supported.".to_owned())?;
        let media_type = mime_guess::from_path(&path)
            .first_or_octet_stream()
            .essence_str()
            .to_owned();
        let original_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned);
        resources.push(
            runtime
                .import_attachment(path, media_type, original_name)
                .await
                .map_err(command_error)?,
        );
    }
    Ok(resources)
}

#[tauri::command]
async fn client_claim_pairing_invitation(
    sidecar: State<'_, NodeSidecar>,
    qr: String,
) -> Result<PairingClaimResponse, String> {
    Ok(client(&sidecar)?
        .claim_pairing_invitation(qr)
        .await
        .map_err(command_error)?
        .into())
}

#[tauri::command]
async fn client_accept_pairing_invitation(
    sidecar: State<'_, NodeSidecar>,
    invitation_id: String,
    record_policy: String,
) -> Result<PairingClaimResponse, String> {
    let record_policy = match record_policy.as_str() {
        "merge" => PrePairRecordPolicy::Merge,
        "discard" => PrePairRecordPolicy::Discard,
        _ => return Err("The pre-pair record policy is invalid.".to_owned()),
    };
    match client(&sidecar)?
        .accept_pairing_invitation(invitation_id.clone(), record_policy)
        .await
    {
        Ok(claim) => {
            eprintln!("Fractonica desktop pairing completed for invitation {invitation_id}");
            Ok(claim.into())
        }
        Err(error) => {
            eprintln!(
                "Fractonica desktop pairing failed after confirmation for invitation {invitation_id}: {error}"
            );
            Err(command_error(error))
        }
    }
}

#[tauri::command]
async fn client_reset_local_installation(
    app: AppHandle,
    confirmation: String,
) -> Result<(), String> {
    if confirmation != "RESET LOCAL INSTALLATION" {
        return Err("Resetting local storage requires explicit confirmation.".to_owned());
    }
    let application_data = app.path().app_data_dir().map_err(command_error)?;
    prepare_private_directory(&application_data).map_err(command_error)?;
    let marker = application_data.join(RESET_MARKER_FILE);
    publish_reset_marker(&marker)
        .map_err(|error| format!("Failed to persist the local storage reset request: {error}"))?;
    eprintln!("Fractonica local installation reset scheduled; restarting before deletion");
    app.request_restart();
    Ok(())
}

fn publish_reset_marker(path: &Path) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(RESET_MARKER_BYTES)?;
    file.sync_all()
}

fn apply_pending_local_reset(application_data: &Path) -> std::io::Result<bool> {
    let marker = application_data.join(RESET_MARKER_FILE);
    let contents = match fs::read(&marker) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if contents != RESET_MARKER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid local reset marker at {}", marker.display()),
        ));
    }
    for name in ["node", "client"] {
        let target = application_data.join(name);
        debug_assert_eq!(target.parent(), Some(application_data));
        match fs::remove_dir_all(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_file(&marker)?;
    eprintln!("Fractonica local installation reset applied before storage startup");
    Ok(true)
}

fn client(sidecar: &NodeSidecar) -> Result<Arc<ClientRuntime>, String> {
    sidecar
        .client
        .lock()
        .map_err(|_| "The native client lifecycle lock is unavailable.".to_owned())?
        .clone()
        .ok_or_else(|| {
            sidecar
                .client_error
                .lock()
                .ok()
                .and_then(|value| value.clone())
                .unwrap_or_else(|| "The native client is still starting.".to_owned())
        })
}

fn parse_entity(value: &str) -> Result<EntityId, String> {
    EntityId::parse(value).map_err(|_| "The entity ID is invalid.".to_owned())
}

fn command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn main() {
    let application = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(NodeSidecar::default())
        .invoke_handler(tauri::generate_handler![
            node_connection,
            client_status,
            client_list_workspaces,
            client_create_workspace,
            client_delete_workspace,
            client_activate_workspace,
            client_create_record,
            client_update_record,
            client_create_event,
            client_update_event,
            client_create_tag,
            client_update_tag,
            client_put_profile,
            client_delete,
            client_list,
            client_list_records,
            client_import_attachments,
            client_claim_pairing_invitation,
            client_accept_pairing_invitation,
            client_reset_local_installation,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            supervise_development_parent(&handle);
            let application_data = app.path().app_data_dir()?;
            prepare_private_directory(&application_data)?;
            apply_pending_local_reset(&application_data)?;
            let node_data = application_data.join("node");
            let client_data = application_data.join("client");
            prepare_private_directory(&node_data)?;
            prepare_private_directory(&client_data)?;
            let bootstrap_directory = app.path().app_cache_dir()?.join("bootstrap");
            prepare_private_directory(&bootstrap_directory)?;
            #[cfg(target_os = "windows")]
            request_windows_private_lan_access(&bootstrap_directory);
            let ready_file = bootstrap_directory.join("node.ready");
            let _ = fs::remove_file(&ready_file);
            let bearer_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());

            let arguments = vec![
                OsString::from("--bind"),
                OsString::from(DESKTOP_NODE_BIND),
                OsString::from("--allow-private-lan"),
                OsString::from("--data-dir"),
                node_data.as_os_str().to_owned(),
                OsString::from("--ready-file"),
                ready_file.as_os_str().to_owned(),
                OsString::from("--parent-pid"),
                OsString::from(std::process::id().to_string()),
            ];
            let command = handle
                .shell()
                .sidecar("fractonica-node")?
                .args(arguments)
                .env("FRACTONICA_BOOTSTRAP_TOKEN", &bearer_token);
            let (mut events, child) = command.spawn()?;

            if let Ok(mut current) = handle.state::<NodeSidecar>().child.lock() {
                *current = Some(child);
            }
            if let Ok(mut current) = handle.state::<NodeSidecar>().ready_file.lock() {
                *current = Some(ready_file.clone());
            }

            let readiness_handle = handle.clone();
            let runtime_node_data = node_data.clone();
            let runtime_client_data = client_data.clone();
            let runtime_bearer_token = bearer_token.clone();
            tauri::async_runtime::spawn(async move {
                for _ in 0..CONNECTION_WAIT_ATTEMPTS {
                    if let Some(base_url) = read_private_loopback_endpoint(&ready_file) {
                        let pairing_endpoint_hints = pairing_endpoint_hints(&base_url);
                        eprintln!(
                            "Fractonica node handoff ready at {base_url}; pairing endpoints: {}",
                            if pairing_endpoint_hints.is_empty() {
                                "none".to_owned()
                            } else {
                                pairing_endpoint_hints.join(", ")
                            }
                        );
                        if let Ok(mut connection) =
                            readiness_handle.state::<NodeSidecar>().connection.lock()
                        {
                            *connection = Some(NodeConnection {
                                base_url: base_url.clone(),
                                bearer_token: bearer_token.clone(),
                                pairing_endpoint_hints,
                            });
                        }
                        match ClientRuntime::bootstrap_supervised(SupervisedNodeConfig {
                            client_data_dir: runtime_client_data,
                            node_data_dir: runtime_node_data,
                            endpoint: base_url,
                            bearer_token: runtime_bearer_token,
                            sync: fractonica_sync::SyncConfig::default(),
                        })
                        .await
                        {
                            Ok(runtime) => {
                                let state = readiness_handle.state::<NodeSidecar>();
                                if let Ok(mut client) = state.client.lock() {
                                    let sidecar_is_running =
                                        state.child.lock().is_ok_and(|child| child.is_some());
                                    if sidecar_is_running {
                                        *client = Some(Arc::new(runtime));
                                        if let Ok(mut client_error) = state.client_error.lock() {
                                            *client_error = None;
                                        }
                                    } else {
                                        runtime.request_shutdown();
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("Fractonica client runtime failed to start: {error}");
                                if let Ok(mut client_error) =
                                    readiness_handle.state::<NodeSidecar>().client_error.lock()
                                {
                                    *client_error = Some(error.to_string());
                                }
                            }
                        }
                        return;
                    }
                    tokio::time::sleep(CONNECTION_WAIT_INTERVAL).await;
                }
                if let Ok(mut client_error) =
                    readiness_handle.state::<NodeSidecar>().client_error.lock()
                {
                    *client_error = Some(
                        "The supervised Fractonica node did not publish its readiness endpoint."
                            .to_owned(),
                    );
                }
                eprintln!("Fractonica node did not publish its readiness endpoint");
            });

            let events_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = events.recv().await {
                    match event {
                        tauri_plugin_shell::process::CommandEvent::Stdout(bytes) => {
                            eprint!("{}", String::from_utf8_lossy(&bytes));
                        }
                        tauri_plugin_shell::process::CommandEvent::Stderr(bytes) => {
                            let text = String::from_utf8_lossy(&bytes);
                            eprint!("{text}");
                            if let Ok(mut tail) =
                                events_handle.state::<NodeSidecar>().stderr_tail.lock()
                            {
                                tail.push_str(&text);
                                if tail.len() > 4_096 {
                                    let mut boundary = tail.len() - 4_096;
                                    while !tail.is_char_boundary(boundary) {
                                        boundary += 1;
                                    }
                                    tail.drain(..boundary);
                                }
                            }
                        }
                        tauri_plugin_shell::process::CommandEvent::Terminated(status) => {
                            if let Ok(mut client) =
                                events_handle.state::<NodeSidecar>().client.lock()
                                && let Some(runtime) = client.take()
                            {
                                runtime.request_shutdown();
                            }
                            if let Ok(mut connection) =
                                events_handle.state::<NodeSidecar>().connection.lock()
                            {
                                *connection = None;
                            }
                            if let Ok(mut client_error) =
                                events_handle.state::<NodeSidecar>().client_error.lock()
                            {
                                let detail = events_handle
                                    .state::<NodeSidecar>()
                                    .stderr_tail
                                    .lock()
                                    .ok()
                                    .map(|tail| tail.trim().to_owned())
                                    .filter(|tail| !tail.is_empty());
                                *client_error = Some(match detail {
                                    Some(detail) => {
                                        format!("The supervised Fractonica node exited: {detail}")
                                    }
                                    None => "The supervised Fractonica node exited.".to_owned(),
                                });
                            }
                            if let Ok(mut child) = events_handle.state::<NodeSidecar>().child.lock()
                            {
                                *child = None;
                            }
                            eprintln!("Fractonica node sidecar exited: {status:?}");
                            break;
                        }
                        _ => {}
                    }
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build Fractonica desktop application");

    application.run(|handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            stop_sidecar(handle);
        }
    });
}

#[cfg(all(debug_assertions, unix))]
fn supervise_development_parent(handle: &tauri::AppHandle) {
    // `tauri dev` owns this process. If its CLI is interrupted or crashes,
    // terminate the development app as well so it cannot keep the node lock
    // while a later `pnpm desktop:dev` launch starts a replacement.
    // SAFETY: getppid only reads process metadata.
    let parent_pid = unsafe { libc::getppid() };
    let handle = handle.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(500));
            // SAFETY: signal 0 performs an existence check without delivering
            // a signal to the captured parent process.
            if unsafe { libc::kill(parent_pid, 0) } != 0 {
                handle.exit(0);
                break;
            }
        }
    });
}

#[cfg(not(all(debug_assertions, unix)))]
fn supervise_development_parent(_handle: &tauri::AppHandle) {}

fn read_private_loopback_endpoint(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let base_url = contents.trim();
    let authority = base_url.strip_prefix("http://")?;
    let address = SocketAddr::from_str(authority).ok()?;
    address.ip().is_loopback().then(|| base_url.to_owned())
}

fn pairing_endpoint_hints(control_base_url: &str) -> Vec<String> {
    let Some(port) = control_base_url
        .strip_prefix("http://")
        .and_then(|authority| SocketAddr::from_str(authority).ok())
        .map(|address| address.port())
    else {
        return Vec::new();
    };
    let mut candidates = Vec::new();

    // UDP connect performs route selection without sending traffic. Keep this
    // fast cross-platform path, then augment it with direct interface
    // enumeration on Unix because sandboxed app processes can lack a usable
    // route even while Wi-Fi is connected.
    for destination in ["192.0.2.1:9", "1.1.1.1:53", "8.8.8.8:53"] {
        let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        if socket.connect(destination).is_err() {
            continue;
        }
        let Ok(address) = socket.local_addr() else {
            continue;
        };
        let std::net::IpAddr::V4(ip) = address.ip() else {
            continue;
        };
        if ip.is_private() || ip.is_link_local() {
            candidates.push((interface_preference("route", ip), ip));
        }
    }
    candidates.extend(private_interface_ipv4s());
    candidates.sort_by_key(|(preference, ip)| (*preference, ip.octets()));

    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter_map(|(_, ip)| seen.insert(ip).then_some(format!("http://{ip}:{port}")))
        .take(3)
        .collect()
}

fn interface_preference(name: &str, ip: Ipv4Addr) -> u8 {
    let name = name.to_ascii_lowercase();
    let virtual_interface = [
        "awdl",
        "bridge",
        "docker",
        "llw",
        "tap",
        "tailscale",
        "tun",
        "utun",
        "veth",
        "virtualbox",
        "vmnet",
        "vmware",
        "zerotier",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix));
    let physical_interface = name == "en0"
        || name == "wi-fi"
        || name == "wifi"
        || name.starts_with("eth")
        || name.starts_with("wlan")
        || name.starts_with("wl");
    let address_preference = match ip.octets() {
        [192, 168, _, _] => 0,
        [172, second, _, _] if (16..=31).contains(&second) => 1,
        [10, _, _, _] => 2,
        _ if ip.is_link_local() => 4,
        _ => 3,
    };
    address_preference
        + if physical_interface { 0 } else { 10 }
        + if virtual_interface { 50 } else { 0 }
}

#[cfg(unix)]
fn private_interface_ipv4s() -> Vec<(u8, Ipv4Addr)> {
    use std::{ffi::CStr, ptr};

    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs initializes `head` on success. Every pointer is read
    // only until the matching freeifaddrs call below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Vec::new();
    }

    let mut addresses = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: `current` belongs to the live getifaddrs list.
        let interface = unsafe { &*current };
        let is_up = interface.ifa_flags & libc::IFF_UP as u32 != 0;
        let is_loopback = interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        if is_up && !is_loopback && !interface.ifa_addr.is_null() {
            // SAFETY: the family check precedes the sockaddr_in cast.
            let family = unsafe { (*interface.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                // SAFETY: AF_INET entries use sockaddr_in and ifa_name is a
                // NUL-terminated interface name owned by the list.
                let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
                if ip.is_private() || ip.is_link_local() {
                    let name = if interface.ifa_name.is_null() {
                        ""
                    } else {
                        // SAFETY: ifa_name is valid for the list lifetime.
                        unsafe { CStr::from_ptr(interface.ifa_name) }
                            .to_str()
                            .unwrap_or("")
                    };
                    addresses.push((interface_preference(name, ip), ip));
                }
            }
        }
        current = interface.ifa_next;
    }
    // SAFETY: `head` was returned by a successful getifaddrs call.
    unsafe { libc::freeifaddrs(head) };
    addresses
}

#[cfg(not(unix))]
fn private_interface_ipv4s() -> Vec<(u8, Ipv4Addr)> {
    local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, address)| {
            let std::net::IpAddr::V4(ip) = address else {
                return None;
            };
            (!ip.is_loopback() && (ip.is_private() || ip.is_link_local()))
                .then_some((interface_preference(&name, ip), ip))
        })
        .collect()
}

fn prepare_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn stop_sidecar(handle: &tauri::AppHandle) {
    let state = handle.state::<NodeSidecar>();
    if let Ok(mut client) = state.client.lock()
        && let Some(runtime) = client.take()
    {
        runtime.request_shutdown();
    }
    if let Ok(mut connection) = state.connection.lock() {
        *connection = None;
    }
    if let Ok(mut ready_file) = state.ready_file.lock()
        && let Some(path) = ready_file.take()
    {
        let _ = fs::remove_file(path);
    }
    if let Ok(mut child) = state.child.lock()
        && let Some(child) = child.take()
    {
        terminate_child(child);
    }
}

#[cfg(unix)]
fn terminate_child(child: CommandChild) {
    let process_id = child.pid() as libc::pid_t;
    // SAFETY: `process_id` came from the live child process spawned above and
    // SIGTERM does not access memory in this process.
    let term_result = unsafe { libc::kill(process_id, libc::SIGTERM) };
    if term_result == 0 {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(25));
            // SAFETY: signal 0 only checks whether this process ID still exists.
            let running = unsafe { libc::kill(process_id, 0) } == 0;
            if !running {
                return;
            }
        }
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_child(child: CommandChild) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_reset_removes_only_node_and_client_storage() {
        let root = tempfile::tempdir().expect("temporary app data");
        let node = root.path().join("node");
        let client = root.path().join("client");
        let preserved = root.path().join("preserved.txt");
        fs::create_dir(&node).expect("node directory");
        fs::create_dir(&client).expect("client directory");
        fs::write(node.join("identity"), b"node").expect("node fixture");
        fs::write(client.join("database"), b"client").expect("client fixture");
        fs::write(&preserved, b"keep").expect("preserved fixture");
        publish_reset_marker(&root.path().join(RESET_MARKER_FILE)).expect("reset marker");

        assert!(apply_pending_local_reset(root.path()).expect("apply reset"));
        assert!(!node.exists());
        assert!(!client.exists());
        assert!(preserved.exists());
        assert!(!root.path().join(RESET_MARKER_FILE).exists());
        assert!(!apply_pending_local_reset(root.path()).expect("reset is one-shot"));
    }

    #[test]
    fn local_summary_wire_shape_omits_absent_optional_values() {
        let serialized = serde_json::to_value(EntitySummaryResponse {
            operation_id: format!("sha-256:{}", "a".repeat(64)),
            entity_id: "019f6576-f20d-7ba0-a718-e1db44d6c9b2".to_owned(),
            schema: "record",
            visibility: "public",
            conflicted: false,
            tombstone: false,
            start_at_unix_ms: Some(1_784_265_600_000),
            end_at_unix_ms: None,
            sort_text: None,
            resource_count: 0,
            media_bytes: 0,
        })
        .expect("summary serializes");

        assert_eq!(serialized["startAtUnixMs"], 1_784_265_600_000_i64);
        assert!(serialized.get("endAtUnixMs").is_none());
        assert!(serialized.get("sortText").is_none());
    }

    #[test]
    fn node_connection_wire_shape_is_camel_case() {
        let serialized = serde_json::to_value(NodeConnection {
            base_url: "http://127.0.0.1:49152".to_owned(),
            bearer_token: "a".repeat(64),
            pairing_endpoint_hints: vec!["http://192.168.1.12:49152".to_owned()],
        })
        .expect("connection serializes");

        assert_eq!(serialized["baseUrl"], "http://127.0.0.1:49152");
        assert_eq!(serialized["bearerToken"], "a".repeat(64));
        assert_eq!(
            serialized["pairingEndpointHints"],
            serde_json::json!(["http://192.168.1.12:49152"])
        );
        assert!(serialized.get("base_url").is_none());
    }

    #[test]
    fn physical_private_interfaces_are_preferred_for_pairing() {
        assert!(
            interface_preference("en0", Ipv4Addr::new(192, 168, 1, 20))
                < interface_preference("utun3", Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(
            interface_preference("wlan0", Ipv4Addr::new(10, 0, 0, 20))
                < interface_preference("docker0", Ipv4Addr::new(192, 168, 65, 1))
        );
        assert!(
            interface_preference("Wi-Fi", Ipv4Addr::new(10, 0, 0, 20))
                < interface_preference("Tailscale", Ipv4Addr::new(192, 168, 65, 1))
        );
    }
}

#[tauri::command]
async fn client_create_workspace(
    sidecar: State<'_, NodeSidecar>,
    display_name: String,
) -> Result<(), String> {
    client(&sidecar)?
        .create_workspace(display_name)
        .await
        .map_err(command_error)?;
    Ok(())
}

#[tauri::command]
async fn client_list_workspaces(
    sidecar: State<'_, NodeSidecar>,
) -> Result<Vec<ClientWorkspaceResponse>, String> {
    for _ in 0..CONNECTION_WAIT_ATTEMPTS {
        if let Some(runtime) = sidecar.client.lock().ok().and_then(|value| value.clone()) {
            return runtime.workspaces().map_err(command_error).map(|spaces| {
                spaces
                    .into_iter()
                    .map(|space| ClientWorkspaceResponse {
                        space_id: space.space_id.to_string(),
                        display_name: space.display_name,
                        genesis_operation_id: space.genesis_operation_id.to_string(),
                        initial_grant_operation_id: space.initial_grant_operation_id.to_string(),
                        controller_actor_id: space.controller_actor_id.to_string(),
                        local_writer_actor_id: space.local_writer_actor_id.to_string(),
                        created_at_unix_ms: space.created_at_unix_ms,
                    })
                    .collect()
            });
        }
        if let Some(error) = sidecar
            .client_error
            .lock()
            .ok()
            .and_then(|value| value.clone())
        {
            return Err(error);
        }
        tokio::time::sleep(CONNECTION_WAIT_INTERVAL).await;
    }
    Err("The local client runtime did not become ready.".into())
}

#[tauri::command]
async fn client_delete_workspace(
    sidecar: State<'_, NodeSidecar>,
    space_id: String,
) -> Result<(), String> {
    let space_id = SpaceId::parse(&space_id).map_err(command_error)?;
    client(&sidecar)?
        .delete_workspace(space_id)
        .await
        .map_err(command_error)
}

#[tauri::command]
async fn client_activate_workspace(
    sidecar: State<'_, NodeSidecar>,
    space_id: String,
) -> Result<(), String> {
    let space_id = SpaceId::parse(&space_id).map_err(command_error)?;
    client(&sidecar)?
        .activate_workspace(space_id)
        .await
        .map_err(command_error)
}

#[cfg(target_os = "windows")]
fn request_windows_private_lan_access(bootstrap_directory: &Path) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Some(node_path) = std::env::current_exe()
        .ok()
        .and_then(|executable| {
            executable
                .parent()
                .map(|parent| parent.join("fractonica-node.exe"))
        })
        .filter(|path| path.is_file())
    else {
        eprintln!("Fractonica could not locate its node sidecar for Windows Firewall setup");
        return;
    };
    let script_path = bootstrap_directory.join("allow-local-network.ps1");
    if fs::read(&script_path).ok().as_deref() != Some(WINDOWS_FIREWALL_SCRIPT)
        && let Err(error) = fs::write(&script_path, WINDOWS_FIREWALL_SCRIPT)
    {
        eprintln!("Fractonica could not prepare Windows Firewall setup: {error}");
        return;
    }
    std::thread::spawn(move || {
        let result = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script_path)
            .arg("-NodePath")
            .arg(&node_path)
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        match result {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("Fractonica Windows Firewall setup exited with status {status}")
            }
            Err(error) => eprintln!("Fractonica could not start Windows Firewall setup: {error}"),
        }
    });
}
