use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use fractonica_pairing::{InvitationId, ResponderInvitationSecret};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const LOCK_NAME: &str = ".pairing-secrets.lock";
const SECRET_SUFFIX: &str = ".secret-v1";
const SECRET_BYTES: usize = 113;

/// Hardened filesystem adapter for short-lived pairing invitation secrets.
#[derive(Clone)]
pub struct FilePairingSecretVault {
    directory: PathBuf,
}

impl FilePairingSecretVault {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Stores one secret without replacing a different existing value.
    /// Returns `true` only for an exact idempotent replay.
    pub fn store(
        &self,
        secret: &ResponderInvitationSecret,
    ) -> Result<bool, PairingSecretVaultError> {
        self.with_lock(|| {
            let path = self.secret_path(secret.invitation_id());
            if path_exists(&path)? {
                let existing = read_secret_file(&path)?;
                let expected = secret.protected_store_bytes();
                if existing == *expected {
                    return Ok(true);
                }
                return Err(PairingSecretVaultError::Conflict(secret.invitation_id()));
            }

            let mut bytes = secret.protected_store_bytes();
            let stored_bytes = protect_secret_bytes(&bytes)?;
            let temporary = self.temporary_path()?;
            let result = (|| {
                let mut file = private_create_new(&temporary)?;
                file.write_all(&stored_bytes)
                    .map_err(|source| io_error(&temporary, source))?;
                file.sync_all()
                    .map_err(|source| io_error(&temporary, source))?;
                fs::hard_link(&temporary, &path).map_err(|source| io_error(&path, source))?;
                sync_directory(&self.directory)?;
                fs::remove_file(&temporary).map_err(|source| io_error(&temporary, source))?;
                sync_directory(&self.directory)?;
                Ok(false)
            })();
            bytes.zeroize();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
    }

    pub fn load(
        &self,
        invitation_id: InvitationId,
    ) -> Result<Option<ResponderInvitationSecret>, PairingSecretVaultError> {
        self.with_lock(|| {
            let path = self.secret_path(invitation_id);
            if !path_exists(&path)? {
                return Ok(None);
            }
            let bytes = read_secret_file(&path)?;
            let secret = ResponderInvitationSecret::from_protected_store_bytes(bytes)
                .map_err(|_| PairingSecretVaultError::Corrupt(path.clone()))?;
            if secret.invitation_id() != invitation_id {
                return Err(PairingSecretVaultError::Corrupt(path));
            }
            Ok(Some(secret))
        })
    }

    /// Removes a secret idempotently after terminal lifecycle persistence.
    pub fn remove(&self, invitation_id: InvitationId) -> Result<bool, PairingSecretVaultError> {
        self.with_lock(|| {
            let path = self.secret_path(invitation_id);
            match fs::remove_file(&path) {
                Ok(()) => {
                    sync_directory(&self.directory)?;
                    Ok(true)
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(source) => Err(io_error(&path, source)),
            }
        })
    }

    pub fn invitation_ids(&self) -> Result<Vec<InvitationId>, PairingSecretVaultError> {
        self.with_lock(|| {
            let mut ids = Vec::new();
            for entry in
                fs::read_dir(&self.directory).map_err(|source| io_error(&self.directory, source))?
            {
                let entry = entry.map_err(|source| io_error(&self.directory, source))?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| PairingSecretVaultError::UnsafeObject(entry.path()))?;
                if name == LOCK_NAME {
                    continue;
                }
                let Some(hex) = name.strip_suffix(SECRET_SUFFIX) else {
                    return Err(PairingSecretVaultError::UnsafeObject(entry.path()));
                };
                let id = InvitationId::parse_hex(hex)
                    .map_err(|_| PairingSecretVaultError::UnsafeObject(entry.path()))?;
                read_secret_file(&entry.path())?;
                ids.push(id);
            }
            ids.sort_unstable();
            Ok(ids)
        })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, PairingSecretVaultError>,
    ) -> Result<T, PairingSecretVaultError> {
        prepare_private_directory(&self.directory)?;
        let lock_path = self.directory.join(LOCK_NAME);
        let lock = private_open_or_create(&lock_path)?;
        fs4::FileExt::lock(&lock).map_err(|source| io_error(&lock_path, source))?;
        cleanup_temporary_files(&self.directory)?;
        operation()
    }

    fn secret_path(&self, invitation_id: InvitationId) -> PathBuf {
        self.directory
            .join(format!("{invitation_id}{SECRET_SUFFIX}"))
    }

    fn temporary_path(&self) -> Result<PathBuf, PairingSecretVaultError> {
        for _ in 0..32 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(PairingSecretVaultError::Random)?;
            let name = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = self.directory.join(format!(".pairing.tmp.{name}"));
            if !path_exists(&path)? {
                return Ok(path);
            }
        }
        Err(PairingSecretVaultError::TemporaryNameExhausted)
    }
}

fn cleanup_temporary_files(directory: &Path) -> Result<(), PairingSecretVaultError> {
    for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
        let entry = entry.map_err(|source| io_error(directory, source))?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".pairing.tmp.")
        {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error(&entry.path(), source))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(PairingSecretVaultError::UnsafeObject(entry.path()));
            }
            fs::remove_file(entry.path()).map_err(|source| io_error(&entry.path(), source))?;
        }
    }
    Ok(())
}

impl std::fmt::Debug for FilePairingSecretVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FilePairingSecretVault")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

fn prepare_private_directory(path: &Path) -> Result<(), PairingSecretVaultError> {
    #[cfg(not(any(unix, windows)))]
    return Err(PairingSecretVaultError::UnsupportedPlatform);

    #[cfg(windows)]
    {
        if !path_exists(path)? {
            fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
        }
        let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(PairingSecretVaultError::UnsafeObject(path.to_owned()));
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        if !path_exists(path)? {
            fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|source| io_error(path, source))?;
        }
        let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != unsafe_uid()
        {
            return Err(PairingSecretVaultError::UnsafeObject(path.to_owned()));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn unsafe_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn private_open_or_create(path: &Path) -> Result<File, PairingSecretVaultError> {
    #[cfg(not(any(unix, windows)))]
    return Err(PairingSecretVaultError::UnsupportedPlatform);

    #[cfg(windows)]
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        validate_private_file(path, &file, None)?;
        Ok(file)
    }

    #[cfg(unix)]
    {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        validate_private_file(path, &file, None)?;
        Ok(file)
    }
}

fn private_create_new(path: &Path) -> Result<File, PairingSecretVaultError> {
    #[cfg(not(any(unix, windows)))]
    return Err(PairingSecretVaultError::UnsupportedPlatform);

    #[cfg(windows)]
    return OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error(path, source));

    #[cfg(unix)]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| io_error(path, source))
    }
}

fn read_secret_file(path: &Path) -> Result<Vec<u8>, PairingSecretVaultError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    validate_private_file(path, &file, platform_secret_length())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    unprotect_secret_bytes(&bytes, path)
}

fn validate_private_file(
    path: &Path,
    file: &File,
    expected_length: Option<usize>,
) -> Result<(), PairingSecretVaultError> {
    #[cfg(not(any(unix, windows)))]
    return Err(PairingSecretVaultError::UnsupportedPlatform);

    #[cfg(windows)]
    {
        let link = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(path, source))?;
        if !link.file_type().is_file()
            || link.file_type().is_symlink()
            || expected_length.is_some_and(|length| metadata.len() != length as u64)
        {
            return Err(PairingSecretVaultError::UnsafeObject(path.to_owned()));
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        let link = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(path, source))?;
        if !link.file_type().is_file()
            || link.file_type().is_symlink()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != unsafe_uid()
            || metadata.nlink() != 1
            || expected_length.is_some_and(|length| metadata.len() != length as u64)
        {
            return Err(PairingSecretVaultError::UnsafeObject(path.to_owned()));
        }
        Ok(())
    }
}

fn path_exists(path: &Path) -> Result<bool, PairingSecretVaultError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), PairingSecretVaultError> {
    #[cfg(windows)]
    {
        let _ = path;
        return Ok(());
    }
    #[cfg(not(windows))]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(unix)]
fn platform_secret_length() -> Option<usize> {
    Some(SECRET_BYTES)
}

#[cfg(windows)]
fn platform_secret_length() -> Option<usize> {
    None
}

#[cfg(not(any(unix, windows)))]
fn platform_secret_length() -> Option<usize> {
    Some(SECRET_BYTES)
}

#[cfg(unix)]
fn protect_secret_bytes(bytes: &[u8]) -> Result<Vec<u8>, PairingSecretVaultError> {
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn protect_secret_bytes(bytes: &[u8]) -> Result<Vec<u8>, PairingSecretVaultError> {
    fractonica_windows_protection::protect(bytes, b"fractonica/pairing-secret/v1")
        .map_err(PairingSecretVaultError::Protection)
}

#[cfg(unix)]
fn unprotect_secret_bytes(bytes: &[u8], _path: &Path) -> Result<Vec<u8>, PairingSecretVaultError> {
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn unprotect_secret_bytes(bytes: &[u8], path: &Path) -> Result<Vec<u8>, PairingSecretVaultError> {
    let value = fractonica_windows_protection::unprotect(bytes, b"fractonica/pairing-secret/v1")
        .map_err(|source| PairingSecretVaultError::ProtectedSecret {
            path: path.to_owned(),
            source,
        })?;
    if value.len() != SECRET_BYTES {
        return Err(PairingSecretVaultError::Corrupt(path.to_owned()));
    }
    Ok(value)
}

#[cfg(not(any(unix, windows)))]
fn protect_secret_bytes(_bytes: &[u8]) -> Result<Vec<u8>, PairingSecretVaultError> {
    Err(PairingSecretVaultError::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
fn unprotect_secret_bytes(_bytes: &[u8], _path: &Path) -> Result<Vec<u8>, PairingSecretVaultError> {
    Err(PairingSecretVaultError::UnsupportedPlatform)
}

fn io_error(path: &Path, source: io::Error) -> PairingSecretVaultError {
    PairingSecretVaultError::Io {
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum PairingSecretVaultError {
    #[error("pairing secret files are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("Windows DPAPI failed to protect a pairing secret: {0}")]
    Protection(#[source] io::Error),
    #[error("Windows DPAPI failed to decrypt pairing secret at {path}: {source}")]
    ProtectedSecret {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("pairing secret path is not a private regular object: {0}")]
    UnsafeObject(PathBuf),
    #[error("pairing secret is corrupt: {0}")]
    Corrupt(PathBuf),
    #[error("pairing secret already exists with different material: {0}")]
    Conflict(InvitationId),
    #[error("failed to allocate a temporary pairing secret name")]
    TemporaryNameExhausted,
    #[error("cryptographic random source failed: {0}")]
    Random(#[source] getrandom::Error),
    #[error("pairing secret filesystem operation failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use fractonica_data_model::CapabilityAction;
    use fractonica_pairing::{
        CapabilityGrantTemplate, InvitationMaterial, InvitationParameters, PairingInvitation,
    };
    use fractonica_trust::{OperationId, SigningKey, SpaceId};
    use tempfile::tempdir;

    fn secret() -> ResponderInvitationSecret {
        PairingInvitation::issue_with_material(
            &SigningKey::from_seed([1; 32]),
            InvitationParameters {
                space_id: SpaceId::from_bytes([2; 32]),
                genesis_operation_id: OperationId::from_bytes([3; 32]),
                now_unix_ms: 10,
                expires_at_unix_ms: 2_010,
                endpoint_hints: vec![],
                capability: CapabilityGrantTemplate {
                    actions: vec![CapabilityAction::ReadSpace],
                    schemas: vec![],
                    visibilities: vec![],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 0,
                    label: "test peer".to_owned(),
                },
            },
            InvitationMaterial {
                invitation_id: [4; 16],
                one_time_secret: [5; 32],
                noise_private: [6; 32],
            },
        )
        .unwrap()
        .secret
    }

    #[test]
    fn stores_loads_replays_and_removes_without_replacement() {
        let root = tempdir().unwrap();
        let vault = FilePairingSecretVault::new(root.path().join("pairing"));
        let secret = secret();
        assert!(!vault.store(&secret).unwrap());
        assert!(vault.store(&secret).unwrap());
        assert_eq!(
            vault.invitation_ids().unwrap(),
            vec![secret.invitation_id()]
        );
        let loaded = vault.load(secret.invitation_id()).unwrap().unwrap();
        assert_eq!(loaded.descriptor_digest(), secret.descriptor_digest());
        assert!(vault.remove(secret.invitation_id()).unwrap());
        assert!(!vault.remove(secret.invitation_id()).unwrap());
        assert!(vault.load(secret.invitation_id()).unwrap().is_none());
    }

    #[test]
    fn rejects_permissive_and_symlinked_secret_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempdir().unwrap();
        let directory = root.path().join("pairing");
        let vault = FilePairingSecretVault::new(&directory);
        let secret = secret();
        vault.store(&secret).unwrap();
        let path = vault.secret_path(secret.invitation_id());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            vault.load(secret.invitation_id()),
            Err(PairingSecretVaultError::UnsafeObject(_))
        ));

        fs::remove_file(&path).unwrap();
        let target = root.path().join("target");
        fs::write(&target, vec![0_u8; SECRET_BYTES]).unwrap();
        symlink(&target, &path).unwrap();
        assert!(matches!(
            vault.load(secret.invitation_id()),
            Err(PairingSecretVaultError::UnsafeObject(_))
        ));
    }
}
