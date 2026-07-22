use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use fractonica_api::ApiState;
use fractonica_application::ApplicationService;
use fractonica_blob_store::BlobStore;
use fractonica_keystore::{FileKeyStore, FilePairingSecretVault, IdentityBundle, KeyStore};
use fractonica_node::{
    NodeProcessLock, NodeReadyFile, default_data_dir,
    durable_pairing::{DurablePairingStore, NodePairingControl},
    installation::{InstallationPhase, NodeInstallation},
    validate_bind_policy,
};
use fractonica_store_sqlite::SqliteStore;
use tokio::{net::TcpListener, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "fractonica-node",
    version,
    about = "Run a local Fractonica node"
)]
struct Arguments {
    /// Loopback address used by the node API.
    #[arg(long, env = "FRACTONICA_BIND", default_value = "127.0.0.1:8789")]
    bind: SocketAddr,

    /// Explicitly expose the authenticated node transport on private LAN
    /// interfaces. This requires a supervisor-provided bootstrap bearer.
    #[arg(long, default_value_t = false)]
    allow_private_lan: bool,

    /// Runtime profile. `full` owns local storage; `saros` is a stateless,
    /// read-only Saros engine.
    #[arg(
        long,
        env = "FRACTONICA_PROFILE",
        value_enum,
        default_value_t = NodeProfile::Full
    )]
    profile: NodeProfile,

    /// Directory containing the full-profile node database and process lock.
    #[arg(long, env = "FRACTONICA_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Human-readable name returned by the local node API.
    #[arg(
        long,
        env = "FRACTONICA_DISPLAY_NAME",
        default_value = "Fractonica Node"
    )]
    display_name: String,

    /// Internal readiness handoff used by a local process supervisor.
    #[arg(long, env = "FRACTONICA_READY_FILE", hide = true)]
    ready_file: Option<PathBuf>,

    /// Optional per-launch bearer token supplied by a local process supervisor.
    #[arg(
        long,
        env = "FRACTONICA_BOOTSTRAP_TOKEN",
        hide = true,
        hide_env_values = true
    )]
    bootstrap_token: Option<String>,

    /// Optional supervisor process. A supervised node exits when this process
    /// disappears, preventing an orphan from retaining the installation lock.
    #[arg(long, hide = true)]
    parent_pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum NodeProfile {
    /// The default local-storage node profile.
    Full,
    /// A stateless, read-only Saros calculation and geometry profile.
    Saros,
}

impl NodeProfile {
    const fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Saros => "saros",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let arguments = Arguments::parse();
    let bind = validate_bind_policy(
        arguments.bind,
        arguments.allow_private_lan,
        arguments.bootstrap_token.is_some(),
    )?;
    validate_profile_arguments(&arguments)?;

    // The guard remains in scope for the duration of the HTTP server. The
    // Saros profile deliberately creates neither a directory nor a lock.
    let (mut state, runtime_storage) = match arguments.profile {
        NodeProfile::Full => {
            let data_dir = arguments.data_dir.map_or_else(default_data_dir, Ok)?;
            let process_lock = NodeProcessLock::acquire(&data_dir)?;
            let database_path = data_dir.join("fractonica.db");
            let identity_path = data_dir.join("identity");
            let mut installation =
                NodeInstallation::begin(&data_dir, &database_path, &identity_path)
                    .context("failed to validate the node installation lifecycle")?;
            let keystore = FileKeyStore::new(identity_path);
            let identity = Arc::new(prepare_installation_identity(&keystore, &mut installation)?);
            let store = Arc::new(
                SqliteStore::open(&database_path)
                    .with_context(|| format!("failed to open {}", database_path.display()))?,
            );
            let application = Arc::new(ApplicationService::new(Arc::clone(&store)));
            let node_id = identity.node_id();
            let pairing = DurablePairingStore::new(
                store.as_ref().clone(),
                FilePairingSecretVault::new(data_dir.join("pairing-secrets")),
            );
            let pairing_recovery = pairing
                .reconcile(unix_time_millis()?)
                .context("failed to reconcile durable pairing state")?;
            tracing::debug!(
                active = pairing_recovery.active_sessions,
                expired = pairing_recovery.expired_sessions,
                removed_secrets = pairing_recovery.removed_secrets,
                "pairing state reconciled"
            );
            let pairing = Arc::new(NodePairingControl::new(pairing, Arc::clone(&identity)));
            let blob_store = Arc::new(
                BlobStore::open(data_dir.join("content"), Arc::clone(&store))
                    .context("failed to open the local content store")?,
            );
            (
                ApiState::new(
                    application,
                    node_id,
                    arguments.display_name,
                    env!("CARGO_PKG_VERSION"),
                )?
                .with_pairing(pairing)
                .with_blob_store(blob_store),
                RuntimeStorage::Full {
                    data_dir,
                    process_lock,
                    node_id,
                },
            )
        }
        NodeProfile::Saros => (
            ApiState::new_saros_only(arguments.display_name, env!("CARGO_PKG_VERSION"))?,
            RuntimeStorage::Saros,
        ),
    };
    if let Some(token) = arguments.bootstrap_token {
        state = state.with_bearer_token(token)?;
    }

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;
    let local_address = listener.local_addr()?;
    let _ready_file = arguments
        .ready_file
        .as_deref()
        .map(|path| NodeReadyFile::publish(path, local_address))
        .transpose()?;

    match &runtime_storage {
        RuntimeStorage::Full {
            data_dir,
            process_lock,
            node_id,
        } => info!(
            profile = arguments.profile.name(),
            address = %local_address,
            data_dir = %data_dir.display(),
            lock = %process_lock.path().display(),
            node_id = %node_id,
            "Fractonica node is ready"
        ),
        RuntimeStorage::Saros => info!(
            profile = arguments.profile.name(),
            address = %local_address,
            "Fractonica Saros engine is ready"
        ),
    }

    axum::serve(listener, fractonica_api::router(state))
        .with_graceful_shutdown(shutdown_signal(arguments.parent_pid))
        .await
        .context("node HTTP server failed")?;

    info!("Fractonica node stopped");
    Ok(())
}

enum RuntimeStorage {
    Full {
        data_dir: PathBuf,
        process_lock: NodeProcessLock,
        node_id: fractonica_data_model::NodeId,
    },
    Saros,
}

fn validate_profile_arguments(arguments: &Arguments) -> Result<()> {
    if arguments.profile == NodeProfile::Saros && arguments.data_dir.is_some() {
        bail!(
            "--data-dir is incompatible with --profile saros because the Saros profile is stateless"
        );
    }
    Ok(())
}

fn prepare_installation_identity(
    keystore: &FileKeyStore,
    installation: &mut NodeInstallation,
) -> Result<IdentityBundle> {
    match installation.phase().clone() {
        InstallationPhase::Fresh => {
            installation
                .start_identity()
                .context("failed to persist the identity-bootstrap marker")?;
            let identity = keystore
                .load_or_create()
                .context("failed to create the local node identities")?;
            installation
                .complete_identity(&identity)
                .context("failed to persist the node installation identity")?;
            Ok(identity)
        }
        InstallationPhase::IdentityInitializing => {
            let identity = keystore
                .load_or_create()
                .context("failed to resume the local node identity bootstrap")?;
            installation
                .complete_identity(&identity)
                .context("failed to persist the node installation identity")?;
            Ok(identity)
        }
        InstallationPhase::Established(manifest) => {
            let identity = keystore
                .load_existing()
                .context("failed to load the established local node identities")?;
            manifest
                .validate_identity(&identity)
                .context("the installation manifest does not match the protected identity")?;
            Ok(identity)
        }
    }
}

fn unix_time_millis() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is earlier than the Unix epoch")?
        .as_millis()
        .try_into()
        .context("system clock is outside the supported Unix-millisecond range")
}

async fn shutdown_signal(parent_pid: Option<u32>) {
    let parent_shutdown = async move {
        let Some(parent_pid) = parent_pid else {
            std::future::pending::<()>().await;
            return;
        };
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if !process_is_alive(parent_pid) {
                tracing::warn!(parent_pid, "node supervisor disappeared");
                return;
            }
        }
    };

    #[cfg(unix)]
    {
        let mut terminate = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                if let Err(error) = signal::ctrl_c().await {
                    tracing::error!(%error, "failed to install shutdown handler");
                }
                return;
            }
        };

        tokio::select! {
            result = signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(%error, "failed to install Ctrl-C handler");
                }
            }
            _ = terminate.recv() => {}
            _ = parent_shutdown => {}
        }
    }

    #[cfg(not(unix))]
    tokio::select! {
        result = signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to install shutdown handler");
            }
        }
        _ = parent_shutdown => {}
    }
}

#[cfg(unix)]
fn process_is_alive(process_id: u32) -> bool {
    let Ok(process_id) = libc::pid_t::try_from(process_id) else {
        return false;
    };
    // SAFETY: signal 0 performs no mutation; it only asks the kernel whether
    // the process exists and is visible to this user.
    let result = unsafe { libc::kill(process_id, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_is_alive(_process_id: u32) -> bool {
    // Tauri's child handle remains the Windows lifecycle boundary until an
    // equivalent process-handle watcher is added there.
    true
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn defaults_to_the_full_profile() {
        let arguments = Arguments::try_parse_from(["fractonica-node"]).expect("arguments");

        assert_eq!(arguments.profile, NodeProfile::Full);
        assert!(arguments.data_dir.is_none());
        assert!(validate_profile_arguments(&arguments).is_ok());
    }

    #[test]
    fn parses_a_stateless_saros_profile() {
        let arguments = Arguments::try_parse_from([
            "fractonica-node",
            "--profile",
            "saros",
            "--bind",
            "127.0.0.1:0",
        ])
        .expect("arguments");

        assert_eq!(arguments.profile, NodeProfile::Saros);
        assert!(arguments.data_dir.is_none());
        assert!(validate_profile_arguments(&arguments).is_ok());
    }

    #[test]
    fn rejects_a_data_directory_for_the_stateless_saros_profile() {
        let arguments = Arguments::try_parse_from([
            "fractonica-node",
            "--profile",
            "saros",
            "--data-dir",
            "ignored",
        ])
        .expect("arguments");

        let error = validate_profile_arguments(&arguments).expect_err("must reject data directory");
        assert!(error.to_string().contains("--data-dir is incompatible"));
    }

    #[test]
    fn a_fresh_installation_starts_without_a_workspace_and_reopens() {
        let root = tempdir().expect("temporary directory");
        make_private(root.path());
        let database_path = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        let keystore = FileKeyStore::new(&identity_path);
        let first_identity = prepare_installation_identity(&keystore, &mut installation).unwrap();
        let store = Arc::new(SqliteStore::open(&database_path).unwrap());
        let application = ApplicationService::new(Arc::clone(&store));
        let expected_node = first_identity.node_id();
        assert!(application.spaces().unwrap().is_empty());
        drop(first_identity);

        let mut restarted =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        assert!(matches!(
            restarted.phase(),
            InstallationPhase::Established(_)
        ));
        let reloaded_identity = prepare_installation_identity(&keystore, &mut restarted).unwrap();
        assert_eq!(reloaded_identity.node_id(), expected_node);
        assert!(application.spaces().unwrap().is_empty());
    }

    fn make_private(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }
}
