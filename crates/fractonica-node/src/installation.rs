//! Minimal binding between one node installation and its protected keys.
//!
//! Workspaces are independent vault roots stored in SQLite. They are not part
//! of installation identity and an installation may host zero or many of them.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use fractonica_data_model::{ActorId, NodeId};
use fractonica_keystore::IdentityBundle;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const IDENTITY_PENDING_FILE: &str = "installation.identity.pending";
const MANIFEST_FILE: &str = "installation.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstallationManifest {
    node_id: NodeId,
    controller_actor_id: ActorId,
    local_writer_actor_id: ActorId,
}

impl InstallationManifest {
    #[must_use]
    pub fn from_identity(identity: &IdentityBundle) -> Self {
        Self {
            node_id: identity.node_id(),
            controller_actor_id: identity.space_controller_actor_id(),
            local_writer_actor_id: identity.local_writer_actor_id(),
        }
    }

    pub fn validate_identity(&self, identity: &IdentityBundle) -> Result<(), InstallationError> {
        if self != &Self::from_identity(identity) {
            return Err(InstallationError::IdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallationPhase {
    Fresh,
    IdentityInitializing,
    Established(InstallationManifest),
}

#[derive(Debug)]
pub struct NodeInstallation {
    data_dir: PathBuf,
    phase: InstallationPhase,
}

impl NodeInstallation {
    pub fn begin(
        data_dir: &Path,
        _database_path: &Path,
        _identity_path: &Path,
    ) -> Result<Self, InstallationError> {
        let manifest_path = data_dir.join(MANIFEST_FILE);
        let marker_path = data_dir.join(IDENTITY_PENDING_FILE);
        let phase = match fs::read(&manifest_path) {
            Ok(bytes) => InstallationPhase::Established(serde_json::from_slice(&bytes).map_err(
                |source| InstallationError::Json {
                    path: manifest_path,
                    source,
                },
            )?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if marker_path.exists() {
                    InstallationPhase::IdentityInitializing
                } else {
                    InstallationPhase::Fresh
                }
            }
            Err(source) => {
                return Err(InstallationError::Io {
                    action: "read installation manifest",
                    path: manifest_path,
                    source,
                });
            }
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

    pub fn start_identity(&mut self) -> Result<(), InstallationError> {
        if !matches!(self.phase, InstallationPhase::Fresh) {
            return Err(InstallationError::InvalidLifecycleTransition);
        }
        let path = self.data_dir.join(IDENTITY_PENDING_FILE);
        fs::write(&path, b"fractonica-identity-pending\n").map_err(|source| {
            InstallationError::Io {
                action: "write identity marker",
                path,
                source,
            }
        })?;
        self.phase = InstallationPhase::IdentityInitializing;
        Ok(())
    }

    pub fn complete_identity(
        &mut self,
        identity: &IdentityBundle,
    ) -> Result<InstallationManifest, InstallationError> {
        match &self.phase {
            InstallationPhase::Fresh => return Err(InstallationError::InvalidLifecycleTransition),
            InstallationPhase::Established(manifest) => {
                manifest.validate_identity(identity)?;
                return Ok(manifest.clone());
            }
            InstallationPhase::IdentityInitializing => {}
        }
        let manifest = InstallationManifest::from_identity(identity);
        let path = self.data_dir.join(MANIFEST_FILE);
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(InstallationError::Serialize)?;
        fs::write(&path, bytes).map_err(|source| InstallationError::Io {
            action: "write installation manifest",
            path,
            source,
        })?;
        let marker = self.data_dir.join(IDENTITY_PENDING_FILE);
        match fs::remove_file(&marker) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(InstallationError::Io {
                    action: "remove identity marker",
                    path: marker,
                    source,
                });
            }
        }
        self.phase = InstallationPhase::Established(manifest.clone());
        Ok(manifest)
    }
}

#[derive(Debug, Error)]
pub enum InstallationError {
    #[error("installation identity does not match the protected keys")]
    IdentityMismatch,
    #[error("invalid installation lifecycle transition")]
    InvalidLifecycleTransition,
    #[error("failed to decode installation manifest at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to encode installation manifest: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to {action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use fractonica_data_model::{SigningKey, SpaceId};

    fn identity(seed: u8) -> IdentityBundle {
        IdentityBundle::from_keys(
            SigningKey::from_seed([seed; 32]),
            SigningKey::from_seed([seed + 1; 32]),
            SigningKey::from_seed([seed + 2; 32]),
            SpaceId::from_bytes([seed + 3; 32]),
        )
        .unwrap()
    }

    #[test]
    fn installation_manifest_contains_identity_but_no_workspace() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("node.sqlite3");
        let identity_path = root.path().join("identity");
        let mut installation =
            NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        assert_eq!(installation.phase(), &InstallationPhase::Fresh);
        installation.start_identity().unwrap();
        installation.complete_identity(&identity(1)).unwrap();

        let reopened = NodeInstallation::begin(root.path(), &database, &identity_path).unwrap();
        let InstallationPhase::Established(manifest) = reopened.phase() else {
            panic!("expected established installation");
        };
        manifest.validate_identity(&identity(1)).unwrap();
        let json = fs::read_to_string(root.path().join(MANIFEST_FILE)).unwrap();
        assert!(!json.contains("space"));
        assert!(!json.contains("workspace"));
    }
}
