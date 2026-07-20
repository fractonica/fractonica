use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use fractonica_api::ApiState;
use fractonica_application::{ApplicationService, SpaceDescriptor};
use fractonica_blob_store::BlobStore;
use fractonica_keystore::{FileKeyStore, FilePairingSecretVault, IdentityBundle, KeyStore};
use fractonica_node::{
    NodeProcessLock, NodeReadyFile,
    bootstrap::build_trusted_space_bootstrap,
    default_data_dir,
    durable_pairing::{DurablePairingStore, NodePairingControl},
    installation::{InstallationManifest, InstallationPhase, NodeInstallation},
    validate_bind,
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
    let bind = validate_bind(arguments.bind)?;
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
            let space = finish_installation(&application, &identity, &mut installation)?;
            let node_id = identity.node_id();
            let space_id = identity.space_id();
            debug_assert_eq!(space.space_id, space_id);
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
            let pairing = Arc::new(NodePairingControl::new(
                pairing,
                Arc::clone(&identity),
                space.genesis_operation_id,
            ));
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
                    space_id,
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
            space_id,
        } => info!(
            profile = arguments.profile.name(),
            address = %local_address,
            data_dir = %data_dir.display(),
            lock = %process_lock.path().display(),
            node_id = %node_id,
            space_id = %space_id,
            "Fractonica node is ready"
        ),
        RuntimeStorage::Saros => info!(
            profile = arguments.profile.name(),
            address = %local_address,
            "Fractonica Saros engine is ready"
        ),
    }

    axum::serve(listener, fractonica_api::router(state))
        .with_graceful_shutdown(shutdown_signal())
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
        space_id: fractonica_data_model::SpaceId,
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
            let bootstrap =
                build_trusted_space_bootstrap(&identity, "Personal space", unix_time_millis()?)
                    .context("failed to construct the initial signed authorization space")?;
            installation
                .prepare(&identity, bootstrap)
                .context("failed to persist the pending signed trust anchor")?;
            Ok(identity)
        }
        InstallationPhase::IdentityInitializing => {
            let identity = keystore
                .load_or_create()
                .context("failed to resume the local node identity bootstrap")?;
            let bootstrap =
                build_trusted_space_bootstrap(&identity, "Personal space", unix_time_millis()?)
                    .context("failed to construct the initial signed authorization space")?;
            installation
                .prepare(&identity, bootstrap)
                .context("failed to persist the pending signed trust anchor")?;
            Ok(identity)
        }
        InstallationPhase::Initializing(plan) => {
            let identity = keystore
                .load_existing()
                .context("failed to load identities for the pending signed trust anchor")?;
            plan.validate_identity(&identity)
                .context("the pending signed trust anchor does not match the protected identity")?;
            Ok(identity)
        }
        InstallationPhase::Established(manifest) => {
            let identity = keystore
                .load_existing()
                .context("failed to load the established local node identities")?;
            manifest
                .plan()
                .validate_identity(&identity)
                .context("the installation manifest does not match the protected identity")?;
            Ok(identity)
        }
    }
}

fn finish_installation(
    application: &ApplicationService,
    identity: &IdentityBundle,
    installation: &mut NodeInstallation,
) -> Result<SpaceDescriptor> {
    match installation.phase().clone() {
        InstallationPhase::Fresh | InstallationPhase::IdentityInitializing => {
            bail!("the installation trust anchor was not prepared before opening storage")
        }
        InstallationPhase::Established(manifest) => {
            let space = application
                .space(manifest.default_space_id())
                .context("failed to inspect the established authorization space")?
                .context(
                    "the database is missing the default trust anchor recorded by the installation manifest",
                )?;
            validate_space_identity(&space, identity)?;
            manifest
                .validate(identity, &space)
                .context("the node installation binding is inconsistent")?;
            let replay = application
                .bootstrap_trusted_space(manifest.plan().bootstrap().clone())
                .context("failed to cryptographically verify the stored bootstrap anchors")?;
            if !replay.replayed || replay.space != space {
                bail!("established bootstrap anchor did not replay exactly");
            }
            // Cleans a matching pending file if the previous process crashed
            // after manifest publication but before its removal.
            installation.complete(manifest)?;
            Ok(space)
        }
        InstallationPhase::Initializing(plan) => {
            plan.validate_identity(identity)
                .context("pending bootstrap does not match the protected identity")?;
            let spaces = application
                .spaces()
                .context("failed to inspect authorization spaces during first-run recovery")?;
            if spaces.len() > 1
                || spaces
                    .first()
                    .is_some_and(|space| space.space_id != plan.default_space_id())
            {
                bail!(
                    "the incomplete installation database contains an unrelated authorization space"
                );
            }
            let result = application
                .bootstrap_trusted_space(plan.bootstrap().clone())
                .context("failed to commit or replay the pending signed trust anchor")?;
            let space = result.space;
            validate_space_identity(&space, identity)?;
            plan.validate_space(&space)
                .context("the database did not preserve the pending signed trust anchor")?;
            let manifest =
                InstallationManifest::from_plan_and_space(plan, identity, space.clone())?;
            installation
                .complete(manifest)
                .context("failed to finalize the node installation binding")?;
            Ok(space)
        }
    }
}

fn validate_space_identity(space: &SpaceDescriptor, identity: &IdentityBundle) -> Result<()> {
    if space.space_id != identity.space_id()
        || space.controller_actor_id != identity.space_controller_actor_id()
        || space.local_writer_actor_id != identity.local_writer_actor_id()
    {
        bail!(
            "the database trust anchor for space {} does not match the protected local identity",
            identity.space_id()
        );
    }
    Ok(())
}

fn unix_time_millis() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is earlier than the Unix epoch")?
        .as_millis()
        .try_into()
        .context("system clock is outside the supported Unix-millisecond range")
}

async fn shutdown_signal() {
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
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown handler");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

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
    fn first_run_bootstrap_is_bound_and_exactly_replayable() {
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
        let first_space =
            finish_installation(&application, &first_identity, &mut installation).unwrap();
        let expected_node = first_identity.node_id();
        let expected_space = first_space.clone();
        let changes = application
            .changes_after(first_space.space_id, 0, 10)
            .unwrap();
        assert_eq!(changes.operations.len(), 2);
        assert!(!changes.has_more);
        drop(first_identity);

        let mut restarted =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        assert!(matches!(
            restarted.phase(),
            InstallationPhase::Established(_)
        ));
        let reloaded_identity = prepare_installation_identity(&keystore, &mut restarted).unwrap();
        let reloaded_space =
            finish_installation(&application, &reloaded_identity, &mut restarted).unwrap();
        assert_eq!(reloaded_identity.node_id(), expected_node);
        assert_eq!(reloaded_space, expected_space);
        assert_eq!(application.spaces().unwrap().len(), 1);
        assert_eq!(
            application
                .changes_after(reloaded_space.space_id, 0, 10)
                .unwrap()
                .operations
                .len(),
            2
        );
    }

    #[test]
    fn incomplete_bootstrap_never_replaces_missing_identity_after_db_commit() {
        let root = tempdir().expect("temporary directory");
        make_private(root.path());
        let database_path = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        let keystore = FileKeyStore::new(&identity_path);
        let identity = prepare_installation_identity(&keystore, &mut installation).unwrap();
        let InstallationPhase::Initializing(plan) = installation.phase().clone() else {
            panic!("expected pending installation");
        };
        let store = Arc::new(SqliteStore::open(&database_path).unwrap());
        let application = ApplicationService::new(store);
        application
            .bootstrap_trusted_space(plan.bootstrap().clone())
            .unwrap();
        drop(identity);
        fs::remove_dir_all(&identity_path).unwrap();

        let error =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap_err();
        assert!(error.to_string().contains("protected identity is missing"));
        assert!(!identity_path.exists());
    }

    #[test]
    fn incomplete_bootstrap_replays_identical_anchor_after_database_loss() {
        let root = tempdir().expect("temporary directory");
        make_private(root.path());
        let database_path = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        let keystore = FileKeyStore::new(&identity_path);
        let identity = prepare_installation_identity(&keystore, &mut installation).unwrap();
        let InstallationPhase::Initializing(plan) = installation.phase().clone() else {
            panic!("expected pending installation");
        };
        let expected_genesis = plan.bootstrap().genesis.operation_id;
        {
            let store = Arc::new(SqliteStore::open(&database_path).unwrap());
            let application = ApplicationService::new(store);
            application
                .bootstrap_trusted_space(plan.bootstrap().clone())
                .unwrap();
        }
        fs::remove_file(&database_path).unwrap();
        drop(identity);

        let mut recovered =
            NodeInstallation::begin(root.path(), &database_path, &identity_path).unwrap();
        let recovered_identity = prepare_installation_identity(&keystore, &mut recovered).unwrap();
        let store = Arc::new(SqliteStore::open(&database_path).unwrap());
        let application = ApplicationService::new(store);
        let space = finish_installation(&application, &recovered_identity, &mut recovered).unwrap();

        assert_eq!(space.genesis_operation_id, expected_genesis);
        assert_eq!(
            application
                .changes_after(space.space_id, 0, 10)
                .unwrap()
                .operations
                .len(),
            2
        );
    }

    fn make_private(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
