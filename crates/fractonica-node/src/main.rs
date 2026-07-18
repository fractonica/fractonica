use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use fractonica_api::ApiState;
use fractonica_application::ApplicationService;
use fractonica_blob_store::BlobStore;
use fractonica_data_model::ActorId;
use fractonica_node::{NodeProcessLock, NodeReadyFile, default_data_dir, validate_bind};
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
            let store = Arc::new(
                SqliteStore::open(&database_path)
                    .with_context(|| format!("failed to open {}", database_path.display()))?,
            );
            let installation = store
                .installation()
                .context("failed to read the local installation identity")?;
            let actor_id = ActorId::new(installation.installation_id.as_uuid());
            let blob_store = Arc::new(
                BlobStore::open(data_dir.join("content"), Arc::clone(&store))
                    .context("failed to open the local content store")?,
            );
            let application = Arc::new(ApplicationService::new(store, actor_id));
            (
                ApiState::new(
                    application,
                    arguments.display_name,
                    env!("CARGO_PKG_VERSION"),
                )?
                .with_blob_store(blob_store),
                RuntimeStorage::Full {
                    data_dir,
                    process_lock,
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
        } => info!(
            profile = arguments.profile.name(),
            address = %local_address,
            data_dir = %data_dir.display(),
            lock = %process_lock.path().display(),
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
}
