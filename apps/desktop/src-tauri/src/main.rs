#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use fractonica_client_runtime::{ClientRuntime, SupervisedNodeConfig};
use fractonica_client_sqlite::{CommitResult, LocalEntitySummary};
use fractonica_data_model::{
    EntityId, EntitySchema, EventDocument, ProfileDocument, ProtectedDocument, RecordDocument,
    TagDocument,
};
use serde::Serialize;
use tauri::{Manager, RunEvent, State};
use tauri_plugin_shell::{ShellExt, process::CommandChild};
use uuid::Uuid;

const CONNECTION_WAIT_ATTEMPTS: usize = 100;
const CONNECTION_WAIT_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeConnection {
    base_url: String,
    bearer_token: String,
}

#[derive(Default)]
struct NodeSidecar {
    child: Mutex<Option<CommandChild>>,
    connection: Mutex<Option<NodeConnection>>,
    ready_file: Mutex<Option<PathBuf>>,
    client: Mutex<Option<Arc<ClientRuntime>>>,
    client_error: Mutex<Option<String>>,
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
struct CommitResponse {
    local_sequence: u64,
    operation_id: String,
    replayed: bool,
    queued_peers: u64,
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
    start_at_unix_ms: Option<i64>,
    end_at_unix_ms: Option<i64>,
    sort_text: Option<String>,
    resource_count: u64,
    media_bytes: u64,
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
            space_id: Some(status.space_id.to_string()),
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
        .plugin(tauri_plugin_shell::init())
        .manage(NodeSidecar::default())
        .invoke_handler(tauri::generate_handler![
            node_connection,
            client_status,
            client_create_record,
            client_update_record,
            client_create_event,
            client_update_event,
            client_create_tag,
            client_update_tag,
            client_put_profile,
            client_delete,
            client_list,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let application_data = app.path().app_data_dir()?;
            prepare_private_directory(&application_data)?;
            let node_data = application_data.join("node");
            let client_data = application_data.join("client");
            prepare_private_directory(&node_data)?;
            prepare_private_directory(&client_data)?;
            let bootstrap_directory = app.path().app_cache_dir()?.join("bootstrap");
            prepare_private_directory(&bootstrap_directory)?;
            let ready_file = bootstrap_directory.join("node.ready");
            let _ = fs::remove_file(&ready_file);
            let bearer_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());

            let arguments = vec![
                OsString::from("--bind"),
                OsString::from("127.0.0.1:0"),
                OsString::from("--data-dir"),
                node_data.as_os_str().to_owned(),
                OsString::from("--ready-file"),
                ready_file.as_os_str().to_owned(),
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
                        if let Ok(mut connection) =
                            readiness_handle.state::<NodeSidecar>().connection.lock()
                        {
                            *connection = Some(NodeConnection {
                                base_url: base_url.clone(),
                                bearer_token: bearer_token.clone(),
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
                            eprint!("{}", String::from_utf8_lossy(&bytes));
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
                                *client_error =
                                    Some("The supervised Fractonica node exited.".to_owned());
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

fn read_private_loopback_endpoint(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let base_url = contents.trim();
    let authority = base_url.strip_prefix("http://")?;
    let address = SocketAddr::from_str(authority).ok()?;
    address.ip().is_loopback().then(|| base_url.to_owned())
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
