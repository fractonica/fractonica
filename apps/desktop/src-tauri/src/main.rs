#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Mutex,
    time::Duration,
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

fn main() {
    let application = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(NodeSidecar::default())
        .invoke_handler(tauri::generate_handler![node_connection])
        .setup(|app| {
            let handle = app.handle().clone();
            let bootstrap_directory = app.path().app_cache_dir()?.join("bootstrap");
            prepare_private_directory(&bootstrap_directory)?;
            let ready_file = bootstrap_directory.join("node.ready");
            let _ = fs::remove_file(&ready_file);
            let bearer_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());

            let arguments = vec![
                OsString::from("--bind"),
                OsString::from("127.0.0.1:0"),
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
            tauri::async_runtime::spawn(async move {
                for _ in 0..CONNECTION_WAIT_ATTEMPTS {
                    if let Some(base_url) = read_private_loopback_endpoint(&ready_file) {
                        if let Ok(mut connection) =
                            readiness_handle.state::<NodeSidecar>().connection.lock()
                        {
                            *connection = Some(NodeConnection {
                                base_url,
                                bearer_token,
                            });
                        }
                        return;
                    }
                    tokio::time::sleep(CONNECTION_WAIT_INTERVAL).await;
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
                            if let Ok(mut connection) =
                                events_handle.state::<NodeSidecar>().connection.lock()
                            {
                                *connection = None;
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
