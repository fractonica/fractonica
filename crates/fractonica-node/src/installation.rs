//! Crash-safe binding between a full node's protected identity and database.
//!
//! A database and a keystore are one installation unit. Silently recreating
//! either half would fork a `SpaceId` trust anchor or replace the node with a
//! fresh empty identity. Before SQLite receives its first operation, this
//! module durably records the exact signed genesis and writer grant. Recovery
//! can therefore replay the same anchor, never generate a lookalike.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use fractonica_application::{SpaceDescriptor, TrustedSpaceBootstrapRequest};
use fractonica_data_model::{EntitySchema, NodeId, OperationBody, SpaceId};
use fractonica_keystore::IdentityBundle;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const INSTALLATION_FORMAT_VERSION: u32 = 1;
const IDENTITY_PENDING_FILE: &str = "installation.identity.pending.json";
const IDENTITY_PENDING_TEMP_FILE: &str = ".installation.identity.pending.json.tmp";
const PENDING_FILE: &str = "installation.pending.json";
const PENDING_TEMP_FILE: &str = ".installation.pending.json.tmp";
const MANIFEST_FILE: &str = "installation.json";
const MANIFEST_TEMP_FILE: &str = ".installation.json.tmp";
const MAX_STATE_BYTES: usize = 64 * 1_024;

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IdentityBootstrapMarker {
    format_version: u32,
}

impl IdentityBootstrapMarker {
    const fn current() -> Self {
        Self {
            format_version: INSTALLATION_FORMAT_VERSION,
        }
    }

    fn validate(&self) -> Result<(), InstallationError> {
        if self.format_version != INSTALLATION_FORMAT_VERSION {
            return Err(InstallationError::UnsupportedManifestVersion(
                self.format_version,
            ));
        }
        Ok(())
    }
}

/// Exact first-run material written before the database trust anchor.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallationPlan {
    format_version: u32,
    node_id: NodeId,
    bootstrap: TrustedSpaceBootstrapRequest,
}

impl InstallationPlan {
    pub fn new(
        identity: &IdentityBundle,
        bootstrap: TrustedSpaceBootstrapRequest,
    ) -> Result<Self, InstallationError> {
        let plan = Self {
            format_version: INSTALLATION_FORMAT_VERSION,
            node_id: identity.node_id(),
            bootstrap,
        };
        plan.validate_identity(identity)?;
        Ok(plan)
    }

    /// Verifies the signed pending material against protected local keys.
    pub fn validate_identity(&self, identity: &IdentityBundle) -> Result<(), InstallationError> {
        if self.format_version != INSTALLATION_FORMAT_VERSION {
            return Err(InstallationError::UnsupportedManifestVersion(
                self.format_version,
            ));
        }
        self.bootstrap
            .genesis
            .verify()
            .map_err(|error| InstallationError::InvalidBootstrap(error.to_string()))?;
        self.bootstrap
            .initial_grant
            .verify()
            .map_err(|error| InstallationError::InvalidBootstrap(error.to_string()))?;

        let controller = identity.space_controller_actor_id();
        let writer = identity.local_writer_actor_id();
        let genesis_controller = match &self.bootstrap.genesis.body {
            OperationBody::SpaceGenesis { controller } => *controller,
            _ => return Err(InstallationError::BindingMismatch),
        };
        let grant_subject = match &self.bootstrap.initial_grant.body {
            OperationBody::CapabilityGrant { grant } => grant.subject,
            _ => return Err(InstallationError::BindingMismatch),
        };
        if self.node_id != identity.node_id()
            || self.bootstrap.genesis.space_id != identity.space_id()
            || self.bootstrap.genesis.schema != EntitySchema::SpaceGenesisV1
            || self.bootstrap.genesis.actor_id != controller
            || genesis_controller != controller
            || self.bootstrap.initial_grant.space_id != identity.space_id()
            || self.bootstrap.initial_grant.schema != EntitySchema::CapabilityGrantV1
            || self.bootstrap.initial_grant.actor_id != controller
            || grant_subject != writer
            || !self.bootstrap.genesis.causal_parents.is_empty()
            || !self.bootstrap.genesis.authorization.is_empty()
            || !self.bootstrap.initial_grant.causal_parents.is_empty()
            || self.bootstrap.initial_grant.authorization != [self.bootstrap.genesis.operation_id]
        {
            return Err(InstallationError::BindingMismatch);
        }
        Ok(())
    }

    pub fn validate_space(&self, space: &SpaceDescriptor) -> Result<(), InstallationError> {
        if space.space_id != self.bootstrap.genesis.space_id
            || space.display_name != self.bootstrap.display_name
            || space.genesis_operation_id != self.bootstrap.genesis.operation_id
            || space.initial_grant_operation_id != self.bootstrap.initial_grant.operation_id
            || space.controller_actor_id != self.bootstrap.genesis.actor_id
            || space.local_writer_actor_id
                != match &self.bootstrap.initial_grant.body {
                    OperationBody::CapabilityGrant { grant } => grant.subject,
                    _ => return Err(InstallationError::BindingMismatch),
                }
        {
            return Err(InstallationError::BindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn default_space_id(&self) -> SpaceId {
        self.bootstrap.genesis.space_id
    }

    #[must_use]
    pub const fn bootstrap(&self) -> &TrustedSpaceBootstrapRequest {
        &self.bootstrap
    }
}

/// Exact public binding for one completed node installation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallationManifest {
    plan: InstallationPlan,
    default_space: SpaceDescriptor,
}

impl InstallationManifest {
    pub fn from_plan_and_space(
        plan: InstallationPlan,
        identity: &IdentityBundle,
        space: SpaceDescriptor,
    ) -> Result<Self, InstallationError> {
        plan.validate_identity(identity)?;
        plan.validate_space(&space)?;
        Ok(Self {
            plan,
            default_space: space,
        })
    }

    pub fn validate(
        &self,
        identity: &IdentityBundle,
        space: &SpaceDescriptor,
    ) -> Result<(), InstallationError> {
        self.plan.validate_identity(identity)?;
        self.plan.validate_space(space)?;
        if &self.default_space != space {
            return Err(InstallationError::BindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn plan(&self) -> &InstallationPlan {
        &self.plan
    }

    #[must_use]
    pub const fn default_space_id(&self) -> SpaceId {
        self.plan.default_space_id()
    }
}

/// State discovered before SQLite or the keystore is allowed to create data.
#[derive(Clone, Debug, PartialEq)]
pub enum InstallationPhase {
    /// No persistent identity, database, or installation state exists.
    Fresh,
    /// Identity bootstrap was durably announced and may be resumed in place.
    IdentityInitializing,
    /// Exact identity and signed bootstrap are durable; SQLite may be resumed.
    Initializing(InstallationPlan),
    /// Both persistent halves must already exist and match this binding.
    Established(InstallationManifest),
}

/// Exclusive first-run lifecycle guard held under [`crate::NodeProcessLock`].
#[derive(Debug)]
pub struct NodeInstallation {
    data_dir: PathBuf,
    phase: InstallationPhase,
}

impl NodeInstallation {
    /// Inspects the installation lifecycle without creating identity or SQLite.
    /// Existing artifacts without an exact state file fail closed.
    pub fn begin(
        data_dir: &Path,
        database_path: &Path,
        identity_path: &Path,
    ) -> Result<Self, InstallationError> {
        recover_json_publication::<IdentityBootstrapMarker>(
            data_dir,
            IDENTITY_PENDING_FILE,
            IDENTITY_PENDING_TEMP_FILE,
        )?;
        recover_json_publication::<InstallationPlan>(data_dir, PENDING_FILE, PENDING_TEMP_FILE)?;
        recover_json_publication::<InstallationManifest>(
            data_dir,
            MANIFEST_FILE,
            MANIFEST_TEMP_FILE,
        )?;
        let identity_marker_path = data_dir.join(IDENTITY_PENDING_FILE);
        let pending_path = data_dir.join(PENDING_FILE);
        let manifest_path = data_dir.join(MANIFEST_FILE);
        let database_preexisting = inspect_optional_regular(database_path)?;
        let identity_preexisting = inspect_optional_directory(identity_path)?;
        let identity_marker: Option<IdentityBootstrapMarker> =
            read_optional_json(&identity_marker_path)?;
        if let Some(marker) = &identity_marker {
            marker.validate()?;
        }
        let pending: Option<InstallationPlan> = read_optional_json(&pending_path)?;
        let manifest: Option<InstallationManifest> = read_optional_json(&manifest_path)?;

        let phase = if let Some(manifest) = manifest {
            if !database_preexisting || !identity_preexisting {
                return Err(InstallationError::EstablishedStateIncomplete {
                    database_present: database_preexisting,
                    identity_present: identity_preexisting,
                });
            }
            if pending.as_ref().is_some_and(|plan| plan != manifest.plan()) {
                return Err(InstallationError::BindingMismatch);
            }
            InstallationPhase::Established(manifest)
        } else if let Some(plan) = pending {
            if !identity_preexisting {
                return Err(InstallationError::PendingIdentityMissing);
            }
            InstallationPhase::Initializing(plan)
        } else if identity_marker.is_some() {
            if database_preexisting {
                return Err(InstallationError::UntrackedPersistentState {
                    database_present: true,
                    identity_present: identity_preexisting,
                });
            }
            InstallationPhase::IdentityInitializing
        } else {
            if database_preexisting || identity_preexisting {
                return Err(InstallationError::UntrackedPersistentState {
                    database_present: database_preexisting,
                    identity_present: identity_preexisting,
                });
            }
            InstallationPhase::Fresh
        };

        Ok(Self {
            data_dir: data_dir.to_owned(),
            phase,
        })
    }

    #[must_use]
    pub const fn phase(&self) -> &InstallationPhase {
        &self.phase
    }

    /// Announces identity creation before the keystore can write any key.
    pub fn start_identity(&mut self) -> Result<(), InstallationError> {
        if !matches!(self.phase, InstallationPhase::Fresh) {
            return Err(InstallationError::InvalidLifecycleTransition);
        }
        publish_json_atomically(
            &self.data_dir,
            IDENTITY_PENDING_FILE,
            IDENTITY_PENDING_TEMP_FILE,
            &IdentityBootstrapMarker::current(),
        )?;
        self.phase = InstallationPhase::IdentityInitializing;
        Ok(())
    }

    /// Publishes exact signed bootstrap material before SQLite is created.
    pub fn prepare(
        &mut self,
        identity: &IdentityBundle,
        bootstrap: TrustedSpaceBootstrapRequest,
    ) -> Result<InstallationPlan, InstallationError> {
        if !matches!(self.phase, InstallationPhase::IdentityInitializing) {
            return Err(InstallationError::InvalidLifecycleTransition);
        }
        let plan = InstallationPlan::new(identity, bootstrap)?;
        publish_json_atomically(&self.data_dir, PENDING_FILE, PENDING_TEMP_FILE, &plan)?;
        remove_identity_marker(&self.data_dir)?;
        self.phase = InstallationPhase::Initializing(plan.clone());
        Ok(plan)
    }

    /// Durably publishes or revalidates the completed installation binding.
    pub fn complete(&mut self, expected: InstallationManifest) -> Result<(), InstallationError> {
        match &self.phase {
            InstallationPhase::Fresh | InstallationPhase::IdentityInitializing => {
                return Err(InstallationError::InvalidLifecycleTransition);
            }
            InstallationPhase::Initializing(plan) if plan != expected.plan() => {
                return Err(InstallationError::BindingMismatch);
            }
            InstallationPhase::Initializing(_) => publish_json_atomically(
                &self.data_dir,
                MANIFEST_FILE,
                MANIFEST_TEMP_FILE,
                &expected,
            )?,
            InstallationPhase::Established(existing) if existing != &expected => {
                return Err(InstallationError::BindingMismatch);
            }
            InstallationPhase::Established(_) => {}
        }

        let pending_path = self.data_dir.join(PENDING_FILE);
        if let Some(pending) = read_optional_json::<InstallationPlan>(&pending_path)? {
            if &pending != expected.plan() {
                return Err(InstallationError::BindingMismatch);
            }
            fs::remove_file(&pending_path).map_err(|source| InstallationError::Io {
                action: "remove completed installation plan",
                path: pending_path,
                source,
            })?;
            sync_directory(&self.data_dir)?;
        }
        remove_identity_marker(&self.data_dir)?;
        self.phase = InstallationPhase::Established(expected);
        Ok(())
    }
}

fn remove_identity_marker(data_dir: &Path) -> Result<(), InstallationError> {
    let path = data_dir.join(IDENTITY_PENDING_FILE);
    let Some(marker) = read_optional_json::<IdentityBootstrapMarker>(&path)? else {
        return Ok(());
    };
    marker.validate()?;
    fs::remove_file(&path).map_err(|source| InstallationError::Io {
        action: "remove completed identity-bootstrap marker",
        path,
        source,
    })?;
    sync_directory(data_dir)
}

/// Completes either crash window of the hard-link no-replace publication.
///
/// A temporary file without a destination was never authoritative. A valid,
/// fully persisted JSON value can be promoted; a truncated staging value is
/// discarded so its enclosing lifecycle can deterministically rebuild it. If
/// both names exist they must be the two links to the exact same inode.
fn recover_json_publication<T: DeserializeOwned>(
    data_dir: &Path,
    file_name: &str,
    temporary_name: &str,
) -> Result<(), InstallationError> {
    let temporary = data_dir.join(temporary_name);
    let temporary_metadata = match fs::symlink_metadata(&temporary) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(InstallationError::Io {
                action: "inspect staged installation state",
                path: temporary,
                source,
            });
        }
    };
    let destination = data_dir.join(file_name);
    let destination_metadata = match fs::symlink_metadata(&destination) {
        Ok(metadata) => Some(metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(InstallationError::Io {
                action: "inspect published installation state",
                path: destination,
                source,
            });
        }
    };

    if let Some(destination_metadata) = destination_metadata {
        validate_private_regular_with_links(&temporary, &temporary_metadata, &[2])?;
        validate_private_regular_with_links(&destination, &destination_metadata, &[2])?;
        if !same_file(&temporary_metadata, &destination_metadata) {
            return Err(InstallationError::ConflictingPublication {
                destination,
                temporary,
            });
        }
        let bytes = read_bounded_existing(&temporary, MAX_STATE_BYTES, &[2])?;
        serde_json::from_slice::<T>(&bytes).map_err(|source| {
            InstallationError::InvalidManifest {
                path: temporary.clone(),
                source,
            }
        })?;
        sync_private_existing(&temporary, &[2])?;
        fs::remove_file(&temporary).map_err(|source| InstallationError::Io {
            action: "finish installation-state publication",
            path: temporary,
            source,
        })?;
        return sync_directory(data_dir);
    }

    validate_private_regular_with_links(&temporary, &temporary_metadata, &[1])?;
    let bytes = read_bounded_existing(&temporary, MAX_STATE_BYTES, &[1])?;
    if serde_json::from_slice::<T>(&bytes).is_err() {
        fs::remove_file(&temporary).map_err(|source| InstallationError::Io {
            action: "discard incomplete staged installation state",
            path: temporary,
            source,
        })?;
        return sync_directory(data_dir);
    }
    sync_private_existing(&temporary, &[1])?;
    fs::hard_link(&temporary, &destination).map_err(|source| InstallationError::Io {
        action: "recover installation-state publication",
        path: destination,
        source,
    })?;
    sync_directory(data_dir)?;
    fs::remove_file(&temporary).map_err(|source| InstallationError::Io {
        action: "remove recovered installation-state staging file",
        path: temporary,
        source,
    })?;
    sync_directory(data_dir)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn read_optional_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, InstallationError> {
    let Some(bytes) = read_optional_bounded(path, MAX_STATE_BYTES)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| InstallationError::InvalidManifest {
            path: path.to_owned(),
            source,
        })
}

fn read_optional_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, InstallationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(InstallationError::Io {
                action: "inspect installation state",
                path: path.to_owned(),
                source,
            });
        }
    }
    Ok(Some(read_bounded_existing(path, maximum, &[1])?))
}

fn read_bounded_existing(
    path: &Path,
    maximum: usize,
    allowed_link_counts: &[u64],
) -> Result<Vec<u8>, InstallationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| InstallationError::Io {
        action: "inspect installation state",
        path: path.to_owned(),
        source,
    })?;
    validate_private_regular_with_links(path, &metadata, allowed_link_counts)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|source| InstallationError::Io {
        action: "open installation state",
        path: path.to_owned(),
        source,
    })?;
    validate_private_regular_with_links(
        path,
        &file.metadata().map_err(|source| InstallationError::Io {
            action: "inspect opened installation state",
            path: path.to_owned(),
            source,
        })?,
        allowed_link_counts,
    )?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| InstallationError::Io {
            action: "read installation state",
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(InstallationError::ManifestTooLarge(bytes.len()));
    }
    Ok(bytes)
}

fn sync_private_existing(
    path: &Path,
    allowed_link_counts: &[u64],
) -> Result<(), InstallationError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| InstallationError::Io {
        action: "open staged installation state for durability recovery",
        path: path.to_owned(),
        source,
    })?;
    validate_private_regular_with_links(
        path,
        &file.metadata().map_err(|source| InstallationError::Io {
            action: "inspect staged installation state for durability recovery",
            path: path.to_owned(),
            source,
        })?,
        allowed_link_counts,
    )?;
    file.sync_all().map_err(|source| InstallationError::Io {
        action: "synchronize staged installation state during recovery",
        path: path.to_owned(),
        source,
    })
}

fn publish_json_atomically<T: Serialize>(
    data_dir: &Path,
    file_name: &str,
    temporary_name: &str,
    value: &T,
) -> Result<(), InstallationError> {
    let bytes = serde_json::to_vec(value).map_err(InstallationError::SerializeManifest)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(InstallationError::ManifestTooLarge(bytes.len()));
    }
    let destination = data_dir.join(file_name);
    if path_entry_exists(&destination)? {
        return Err(InstallationError::RefuseManifestReplacement(destination));
    }
    let temporary = data_dir.join(temporary_name);
    if path_entry_exists(&temporary)? {
        return Err(InstallationError::StaleTemporaryState(temporary));
    }
    publish_exact(&temporary, &bytes)?;
    // A hard-link publication is an atomic no-replace operation. Removing the
    // temporary name leaves the destination with exactly one link.
    fs::hard_link(&temporary, &destination).map_err(|source| InstallationError::Io {
        action: "publish installation state",
        path: destination.clone(),
        source,
    })?;
    sync_directory(data_dir)?;
    fs::remove_file(&temporary).map_err(|source| InstallationError::Io {
        action: "remove published installation temporary file",
        path: temporary,
        source,
    })?;
    sync_directory(data_dir)
}

fn publish_exact(path: &Path, bytes: &[u8]) -> Result<(), InstallationError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    let mut file = options.open(path).map_err(|source| InstallationError::Io {
        action: "create installation state",
        path: path.to_owned(),
        source,
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| InstallationError::Io {
            action: "persist installation state",
            path: path.to_owned(),
            source,
        })
}

fn inspect_optional_regular(path: &Path) -> Result<bool, InstallationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            validate_private_regular(path, &metadata)?;
            Ok(true)
        }
        Ok(_) => Err(InstallationError::UnsafePersistentObject {
            path: path.to_owned(),
            expected: "a regular database file",
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallationError::Io {
            action: "inspect database path",
            path: path.to_owned(),
            source,
        }),
    }
}

fn inspect_optional_directory(path: &Path) -> Result<bool, InstallationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(InstallationError::UnsafePersistentObject {
            path: path.to_owned(),
            expected: "a private identity directory",
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallationError::Io {
            action: "inspect identity path",
            path: path.to_owned(),
            source,
        }),
    }
}

fn path_entry_exists(path: &Path) -> Result<bool, InstallationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallationError::Io {
            action: "inspect installation path",
            path: path.to_owned(),
            source,
        }),
    }
}

fn validate_private_regular(path: &Path, metadata: &fs::Metadata) -> Result<(), InstallationError> {
    validate_private_regular_with_links(path, metadata, &[1])
}

fn validate_private_regular_with_links(
    path: &Path,
    metadata: &fs::Metadata,
    allowed_link_counts: &[u64],
) -> Result<(), InstallationError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(InstallationError::UnsafePersistentObject {
            path: path.to_owned(),
            expected: "a private regular file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let expected_owner = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_owner {
            return Err(InstallationError::WrongOwner {
                path: path.to_owned(),
                expected: expected_owner,
                found: metadata.uid(),
            });
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != PRIVATE_FILE_MODE {
            return Err(InstallationError::UnsafeFileMode {
                path: path.to_owned(),
                found: mode,
            });
        }
        if !allowed_link_counts.contains(&metadata.nlink()) {
            return Err(InstallationError::UnsafeLinkCount {
                path: path.to_owned(),
                found: metadata.nlink(),
            });
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), InstallationError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| InstallationError::Io {
            action: "synchronize installation directory",
            path: path.to_owned(),
            source,
        })?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum InstallationError {
    #[error("failed to {action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe persistent object at {path}; expected {expected}")]
    UnsafePersistentObject {
        path: PathBuf,
        expected: &'static str,
    },
    #[error("unsafe installation-state permissions at {path}: found {found:#o}, expected 0o600")]
    UnsafeFileMode { path: PathBuf, found: u32 },
    #[error("persistent file {path} has an unsafe hard-link count of {found}")]
    UnsafeLinkCount { path: PathBuf, found: u64 },
    #[error("persistent file {path} is owned by uid {found}; expected uid {expected}")]
    WrongOwner {
        path: PathBuf,
        expected: u32,
        found: u32,
    },
    #[error("invalid installation state at {path}: {source}")]
    InvalidManifest {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported installation state version {0}")]
    UnsupportedManifestVersion(u32),
    #[error("installation state is unexpectedly large ({0} bytes)")]
    ManifestTooLarge(usize),
    #[error("signed installation bootstrap is invalid: {0}")]
    InvalidBootstrap(String),
    #[error(
        "persistent node state exists without an installation binding (database={database_present}, identity={identity_present}); explicit recovery or migration is required"
    )]
    UntrackedPersistentState {
        database_present: bool,
        identity_present: bool,
    },
    #[error(
        "established node installation is incomplete (database={database_present}, identity={identity_present}); refusing automatic identity or trust-anchor replacement"
    )]
    EstablishedStateIncomplete {
        database_present: bool,
        identity_present: bool,
    },
    #[error("the pending signed bootstrap exists but its protected identity is missing")]
    PendingIdentityMissing,
    #[error("the protected identity, signed bootstrap, database, and installation state disagree")]
    BindingMismatch,
    #[error("invalid installation lifecycle transition")]
    InvalidLifecycleTransition,
    #[error("refusing to replace existing installation state at {0}")]
    RefuseManifestReplacement(PathBuf),
    #[error(
        "published installation state at {destination} and staging file at {temporary} are not the same inode"
    )]
    ConflictingPublication {
        destination: PathBuf,
        temporary: PathBuf,
    },
    #[error("stale temporary installation state requires explicit inspection at {0}")]
    StaleTemporaryState(PathBuf),
    #[error("failed to serialize installation state: {0}")]
    SerializeManifest(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fractonica_application::ApplicationService;
    use fractonica_keystore::{FileKeyStore, KeyStore};
    use fractonica_store_sqlite::SqliteStore;
    use tempfile::tempdir;

    use crate::bootstrap::build_trusted_space_bootstrap;

    use super::*;

    const NOW: i64 = 1_720_000_000_123;

    #[test]
    fn fresh_start_writes_nothing_until_exact_bootstrap_is_ready() {
        let root = tempdir().unwrap();
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let installation = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        assert!(matches!(installation.phase(), InstallationPhase::Fresh));
        assert!(!root.path().join(PENDING_FILE).exists());
        assert!(!database.exists());
        assert!(!identity_path.exists());
    }

    #[test]
    fn identity_bootstrap_resumes_before_a_signed_plan_exists() {
        let root = tempdir().unwrap();
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        installation.start_identity().unwrap();

        let keystore = FileKeyStore::new(&identity_path);
        let identity = keystore.load_or_create().unwrap();
        let expected_node = identity.node_id();
        let expected_space = identity.space_id();
        drop(identity);
        drop(installation);

        let mut resumed = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        assert!(matches!(
            resumed.phase(),
            InstallationPhase::IdentityInitializing
        ));
        let identity = keystore.load_or_create().unwrap();
        assert_eq!(identity.node_id(), expected_node);
        assert_eq!(identity.space_id(), expected_space);
        resumed
            .prepare(
                &identity,
                build_trusted_space_bootstrap(&identity, "Personal space", NOW).unwrap(),
            )
            .unwrap();
        assert!(!root.path().join(IDENTITY_PENDING_FILE).exists());
        assert!(root.path().join(PENDING_FILE).exists());
    }

    #[test]
    fn identity_marker_recovers_a_crash_before_the_keystore_directory_exists() {
        let root = tempdir().unwrap();
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        installation.start_identity().unwrap();
        assert!(!identity_path.exists());

        let resumed = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        assert!(matches!(
            resumed.phase(),
            InstallationPhase::IdentityInitializing
        ));
        FileKeyStore::new(identity_path).load_or_create().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pending_publication_recovers_before_and_after_the_no_replace_link() {
        use std::os::unix::fs::MetadataExt;

        for destination_was_linked in [false, true] {
            let root = tempdir().unwrap();
            let database = root.path().join("fractonica.db");
            let identity_path = root.path().join("identity");
            let mut installation =
                NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
            installation.start_identity().unwrap();
            let keystore = FileKeyStore::new(&identity_path);
            let identity = keystore.load_or_create().unwrap();
            let plan = InstallationPlan::new(
                &identity,
                build_trusted_space_bootstrap(&identity, "Personal space", NOW).unwrap(),
            )
            .unwrap();
            let temporary = root.path().join(PENDING_TEMP_FILE);
            let destination = root.path().join(PENDING_FILE);
            publish_exact(&temporary, &serde_json::to_vec(&plan).unwrap()).unwrap();
            if destination_was_linked {
                fs::hard_link(&temporary, &destination).unwrap();
                assert_eq!(fs::metadata(&destination).unwrap().nlink(), 2);
            }
            drop(installation);

            let resumed = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
            let InstallationPhase::Initializing(recovered) = resumed.phase() else {
                panic!("expected recovered signed installation plan");
            };
            assert_eq!(recovered, &plan);
            assert!(!temporary.exists());
            assert_eq!(fs::metadata(destination).unwrap().nlink(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn installation_state_rejects_special_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        installation.start_identity().unwrap();
        let marker = root.path().join(IDENTITY_PENDING_FILE);
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o4600)).unwrap();
        assert!(matches!(
            NodeInstallation::begin(root.path(), &database, &identity_path),
            Err(InstallationError::UnsafeFileMode { found: 0o4600, .. })
        ));
    }

    #[test]
    fn pending_plan_replays_the_exact_anchor_after_database_loss() {
        let root = tempdir().unwrap();
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        installation.start_identity().unwrap();
        let keystore = FileKeyStore::new(&identity_path);
        let identity = keystore.load_or_create().unwrap();
        let bootstrap = build_trusted_space_bootstrap(&identity, "Personal space", NOW).unwrap();
        let expected_genesis = bootstrap.genesis.operation_id;
        installation.prepare(&identity, bootstrap).unwrap();

        let resumed = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        let InstallationPhase::Initializing(plan) = resumed.phase() else {
            panic!("expected pending plan");
        };
        assert_eq!(plan.bootstrap().genesis.operation_id, expected_genesis);
        plan.validate_identity(&keystore.load_existing().unwrap())
            .unwrap();
    }

    #[test]
    fn pending_plan_never_recreates_a_missing_or_empty_identity() {
        for leave_empty_directory in [false, true] {
            let root = tempdir().unwrap();
            let database = root.path().join("fractonica.db");
            let identity_path = root.path().join("identity");
            let mut installation =
                NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
            installation.start_identity().unwrap();
            let keystore = FileKeyStore::new(&identity_path);
            let identity = keystore.load_or_create().unwrap();
            let bootstrap =
                build_trusted_space_bootstrap(&identity, "Personal space", NOW).unwrap();
            installation.prepare(&identity, bootstrap).unwrap();
            let expected_space = identity.space_id();
            drop(identity);
            fs::remove_dir_all(&identity_path).unwrap();
            if leave_empty_directory {
                fs::create_dir(&identity_path).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }

            if leave_empty_directory {
                let recovered =
                    NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
                let InstallationPhase::Initializing(plan) = recovered.phase() else {
                    panic!("expected pending plan");
                };
                assert_eq!(plan.default_space_id(), expected_space);
                assert!(FileKeyStore::new(&identity_path).load_existing().is_err());
                assert!(!identity_path.join("space-controller.ed25519").exists());
            } else {
                assert!(matches!(
                    NodeInstallation::begin(root.path(), &database, &identity_path),
                    Err(InstallationError::PendingIdentityMissing)
                ));
            }
        }
    }

    #[test]
    fn completed_manifest_refuses_partial_state_loss_and_hardlinked_database() {
        let root = tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let database = root.path().join("fractonica.db");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        installation.start_identity().unwrap();
        let keystore = FileKeyStore::new(&identity_path);
        let identity = keystore.load_or_create().unwrap();
        let plan = installation
            .prepare(
                &identity,
                build_trusted_space_bootstrap(&identity, "Personal space", NOW).unwrap(),
            )
            .unwrap();
        let store = Arc::new(SqliteStore::open(&database).unwrap());
        let application = ApplicationService::new(store);
        let result = application
            .bootstrap_trusted_space(plan.bootstrap().clone())
            .unwrap();
        let manifest =
            InstallationManifest::from_plan_and_space(plan, &identity, result.space).unwrap();
        installation.complete(manifest).unwrap();

        let linked_database = root.path().join("database-copy");
        fs::hard_link(&database, &linked_database).unwrap();
        assert!(matches!(
            NodeInstallation::begin(root.path(), &database, &identity_path),
            Err(InstallationError::UnsafeLinkCount { .. })
        ));
        fs::remove_file(linked_database).unwrap();
        drop(identity);

        fs::remove_dir_all(&identity_path).unwrap();
        assert!(matches!(
            NodeInstallation::begin(root.path(), &database, &identity_path),
            Err(InstallationError::EstablishedStateIncomplete {
                database_present: true,
                identity_present: false
            })
        ));
    }
}
