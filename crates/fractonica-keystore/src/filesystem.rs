use std::{
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use fractonica_trust::{SigningKey, SpaceId};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{IdentityBundle, IdentityError, KeyRole, KeyStore};

pub const NODE_TRANSPORT_FILE: &str = "node-transport.ed25519";
pub const SPACE_CONTROLLER_FILE: &str = "space-controller.ed25519";
pub const LOCAL_WRITER_FILE: &str = "local-writer.ed25519";
pub const SPACE_ID_FILE: &str = "space.id";

const LOCK_FILE: &str = ".bootstrap.lock";
const STARTED_FILE: &str = ".bootstrap-started";
const MANIFEST_FILE: &str = "identity.manifest";
const TEMP_PREFIX: &str = ".fractonica-keystore.tmp.";
const STARTED_BYTES: &[u8] = b"fractonica-keystore-bootstrap-v1\n";
const MANIFEST_BYTES: &[u8] = b"fractonica-keystore-complete-v1\n";
const MATERIAL_BYTES: usize = 32;
#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Hardened raw-file key store for desktop and headless node bootstrap.
pub struct FileKeyStore {
    identity_dir: PathBuf,
}

impl FileKeyStore {
    #[must_use]
    pub fn new(identity_dir: impl Into<PathBuf>) -> Self {
        Self {
            identity_dir: identity_dir.into(),
        }
    }

    #[must_use]
    pub fn identity_dir(&self) -> &Path {
        &self.identity_dir
    }

    /// Loads an identity only when its internal completion manifest exists.
    ///
    /// Established node startup uses this instead of [`KeyStore::load_or_create`]
    /// so deleting the identity directory can never silently mint replacement
    /// controller keys.
    pub fn load_existing(&self) -> Result<IdentityBundle, FileKeyStoreError> {
        {
            let metadata = fs::symlink_metadata(&self.identity_dir).map_err(|source| {
                FileKeyStoreError::Io {
                    action: "inspect established identity directory",
                    path: self.identity_dir.clone(),
                    source,
                }
            })?;
            validate_private_directory(&self.identity_dir, &metadata)?;
            let lock = open_bootstrap_lock(&self.identity_dir)?;
            fs4::FileExt::lock(&lock).map_err(|source| FileKeyStoreError::Io {
                action: "lock established identity",
                path: self.identity_dir.join(LOCK_FILE),
                source,
            })?;
            cleanup_temporary_files(&self.identity_dir)?;
            let manifest_path = self.identity_dir.join(MANIFEST_FILE);
            if !validate_marker_if_present(&manifest_path, MANIFEST_BYTES)? {
                return Err(FileKeyStoreError::IdentityNotEstablished(
                    self.identity_dir.clone(),
                ));
            }
            self.load_established()
        }
    }

    fn bootstrap(&self) -> Result<IdentityBundle, FileKeyStoreError> {
        {
            prepare_identity_directory(&self.identity_dir)?;
            let lock = open_bootstrap_lock(&self.identity_dir)?;
            fs4::FileExt::lock(&lock).map_err(|source| FileKeyStoreError::Io {
                action: "lock identity bootstrap",
                path: self.identity_dir.join(LOCK_FILE),
                source,
            })?;

            cleanup_temporary_files(&self.identity_dir)?;

            let manifest_path = self.identity_dir.join(MANIFEST_FILE);
            let started_path = self.identity_dir.join(STARTED_FILE);
            let manifest_exists = validate_marker_if_present(&manifest_path, MANIFEST_BYTES)?;
            let started_exists = validate_marker_if_present(&started_path, STARTED_BYTES)?;

            let bundle = if manifest_exists {
                self.load_established()?
            } else {
                if !started_exists {
                    refuse_untracked_identity_files(&self.identity_dir)?;
                    publish_or_validate_marker(&self.identity_dir, &started_path, STARTED_BYTES)?;
                }
                self.recover_or_create()?
            };

            if !manifest_exists {
                publish_or_validate_marker(&self.identity_dir, &manifest_path, MANIFEST_BYTES)?;
            }
            if started_path.exists() {
                remove_private_regular_file(&started_path)?;
                sync_directory(&self.identity_dir)?;
            }
            Ok(bundle)
        }
    }

    fn load_established(&self) -> Result<IdentityBundle, FileKeyStoreError> {
        let node = read_required_material(
            &self.identity_dir.join(NODE_TRANSPORT_FILE),
            KeyRole::NodeTransport,
        )?;
        let controller = read_required_material(
            &self.identity_dir.join(SPACE_CONTROLLER_FILE),
            KeyRole::SpaceController,
        )?;
        let writer = read_required_material(
            &self.identity_dir.join(LOCAL_WRITER_FILE),
            KeyRole::LocalWriter,
        )?;
        let space = read_required_space_id(&self.identity_dir.join(SPACE_ID_FILE))?;
        assemble(node, controller, writer, space)
    }

    fn recover_or_create(&self) -> Result<IdentityBundle, FileKeyStoreError> {
        let node = load_or_create_material(
            &self.identity_dir,
            NODE_TRANSPORT_FILE,
            KeyRole::NodeTransport,
        )?;
        let controller = load_or_create_material(
            &self.identity_dir,
            SPACE_CONTROLLER_FILE,
            KeyRole::SpaceController,
        )?;
        let writer =
            load_or_create_material(&self.identity_dir, LOCAL_WRITER_FILE, KeyRole::LocalWriter)?;
        let space = load_or_create_space_id(&self.identity_dir)?;
        assemble(node, controller, writer, space)
    }
}

impl KeyStore for FileKeyStore {
    type Error = FileKeyStoreError;

    fn load_or_create(&self) -> Result<IdentityBundle, Self::Error> {
        self.bootstrap()
    }
}

impl fmt::Debug for FileKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileKeyStore")
            .field("identity_dir", &self.identity_dir)
            .finish_non_exhaustive()
    }
}

fn assemble(
    node: Zeroizing<[u8; 32]>,
    controller: Zeroizing<[u8; 32]>,
    writer: Zeroizing<[u8; 32]>,
    space: [u8; 32],
) -> Result<IdentityBundle, FileKeyStoreError> {
    let node_key = SigningKey::from_seed(*node);
    let controller_key = SigningKey::from_seed(*controller);
    let writer_key = SigningKey::from_seed(*writer);
    IdentityBundle::from_keys(
        node_key,
        controller_key,
        writer_key,
        SpaceId::from_bytes(space),
    )
    .map_err(FileKeyStoreError::Identity)
}

fn prepare_identity_directory(path: &Path) -> Result<(), FileKeyStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = usable_parent(path);
            let parent_metadata = fs::metadata(parent).map_err(|source| FileKeyStoreError::Io {
                action: "inspect identity parent directory",
                path: parent.to_owned(),
                source,
            })?;
            if !parent_metadata.is_dir() {
                return Err(FileKeyStoreError::UnsafeObject {
                    path: parent.to_owned(),
                    expected: "an existing directory",
                });
            }
            match private_directory_builder().create(path) {
                Ok(()) => {
                    sync_directory(parent)?;
                    let metadata =
                        fs::symlink_metadata(path).map_err(|source| FileKeyStoreError::Io {
                            action: "inspect created identity directory",
                            path: path.to_owned(),
                            source,
                        })?;
                    validate_private_directory(path, &metadata)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata =
                        fs::symlink_metadata(path).map_err(|source| FileKeyStoreError::Io {
                            action: "inspect concurrently created identity directory",
                            path: path.to_owned(),
                            source,
                        })?;
                    validate_private_directory(path, &metadata)
                }
                Err(source) => Err(FileKeyStoreError::Io {
                    action: "create identity directory",
                    path: path.to_owned(),
                    source,
                }),
            }
        }
        Err(source) => Err(FileKeyStoreError::Io {
            action: "inspect identity directory",
            path: path.to_owned(),
            source,
        }),
    }
}

fn validate_private_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FileKeyStoreError::UnsafeObject {
            path: path.to_owned(),
            expected: "a non-symlink directory",
        });
    }
    validate_unix_directory_security(path, metadata)
}

fn open_bootstrap_lock(identity_dir: &Path) -> Result<File, FileKeyStoreError> {
    let path = identity_dir.join(LOCK_FILE);
    let mut create = private_open_options();
    create.read(true).write(true).create_new(true);
    let file = match create.open(&path) {
        Ok(file) => {
            file.sync_all().map_err(|source| FileKeyStoreError::Io {
                action: "sync bootstrap lock",
                path: path.clone(),
                source,
            })?;
            sync_directory(identity_dir)?;
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = private_open_options();
            existing.read(true).write(true);
            existing
                .open(&path)
                .map_err(|source| FileKeyStoreError::Io {
                    action: "open bootstrap lock",
                    path: path.clone(),
                    source,
                })?
        }
        Err(source) => {
            return Err(FileKeyStoreError::Io {
                action: "create bootstrap lock",
                path,
                source,
            });
        }
    };
    validate_open_private_file(&path, &file, Some(0))?;
    Ok(file)
}

fn load_or_create_material(
    identity_dir: &Path,
    file_name: &str,
    role: KeyRole,
) -> Result<Zeroizing<[u8; 32]>, FileKeyStoreError> {
    let path = identity_dir.join(file_name);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_required_material(&path, role),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let candidate = random_material()?;
            let protected = protect_key_material(&candidate, role)?;
            match publish_new_file(identity_dir, &path, &protected)? {
                PublishOutcome::Created => {
                    read_required_material(&path, role)?;
                    Ok(candidate)
                }
                PublishOutcome::Existing => read_required_material(&path, role),
            }
        }
        Err(source) => Err(FileKeyStoreError::Io {
            action: "inspect key material",
            path,
            source,
        }),
    }
}

fn load_or_create_space_id(identity_dir: &Path) -> Result<[u8; 32], FileKeyStoreError> {
    let path = identity_dir.join(SPACE_ID_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => read_required_space_id(&path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let candidate = random_nonzero_space_id()?;
            match publish_new_file(identity_dir, &path, &candidate)? {
                PublishOutcome::Created => {
                    let file = open_validated_private_file(&path, Some(MATERIAL_BYTES))?;
                    drop(file);
                    Ok(candidate)
                }
                PublishOutcome::Existing => read_required_space_id(&path),
            }
        }
        Err(source) => Err(FileKeyStoreError::Io {
            action: "inspect space identity",
            path,
            source,
        }),
    }
}

fn read_required_material(
    path: &Path,
    role: KeyRole,
) -> Result<Zeroizing<[u8; 32]>, FileKeyStoreError> {
    if !path_exists(path)? {
        return Err(FileKeyStoreError::MissingEstablishedIdentity {
            path: path.to_owned(),
            role: Some(role),
        });
    }
    let bytes = read_key_material_file(path)?;
    unprotect_key_material(&bytes, role, path)
}

fn read_required_space_id(path: &Path) -> Result<[u8; 32], FileKeyStoreError> {
    if !path_exists(path)? {
        return Err(FileKeyStoreError::MissingEstablishedIdentity {
            path: path.to_owned(),
            role: None,
        });
    }
    let bytes = read_private_exact(path, MATERIAL_BYTES)?;
    let value: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("exact-length reader returned 32 bytes");
    if value == [0; 32] {
        return Err(FileKeyStoreError::ZeroSpaceId(path.to_owned()));
    }
    Ok(value)
}

fn read_private_exact(path: &Path, expected: usize) -> Result<Vec<u8>, FileKeyStoreError> {
    let mut file = open_validated_private_file(path, Some(expected))?;
    let mut bytes = vec![0_u8; expected];
    file.read_exact(&mut bytes)
        .map_err(|source| FileKeyStoreError::Io {
            action: "read private file",
            path: path.to_owned(),
            source,
        })?;
    verify_end_of_file(path, &mut file, expected)?;
    Ok(bytes)
}

fn open_validated_private_file(
    path: &Path,
    expected: Option<usize>,
) -> Result<File, FileKeyStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| FileKeyStoreError::Io {
        action: "inspect private file",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FileKeyStoreError::UnsafeObject {
            path: path.to_owned(),
            expected: "a non-symlink regular file",
        });
    }
    let mut options = private_open_options();
    options.read(true);
    let file = options.open(path).map_err(|source| FileKeyStoreError::Io {
        action: "open private file",
        path: path.to_owned(),
        source,
    })?;
    validate_open_private_file(path, &file, expected.map(|value| value as u64))?;
    Ok(file)
}

fn verify_end_of_file(
    path: &Path,
    file: &mut File,
    expected: usize,
) -> Result<(), FileKeyStoreError> {
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|source| FileKeyStoreError::Io {
            action: "verify private file length",
            path: path.to_owned(),
            source,
        })?
        != 0
    {
        return Err(FileKeyStoreError::InvalidLength {
            path: path.to_owned(),
            expected,
            found: expected + 1,
        });
    }
    Ok(())
}

fn validate_marker_if_present(path: &Path, expected: &[u8]) -> Result<bool, FileKeyStoreError> {
    if !path_exists(path)? {
        return Ok(false);
    }
    let found = read_private_exact(path, expected.len())?;
    if found != expected {
        return Err(FileKeyStoreError::InvalidMarker(path.to_owned()));
    }
    Ok(true)
}

fn publish_or_validate_marker(
    identity_dir: &Path,
    path: &Path,
    expected: &[u8],
) -> Result<(), FileKeyStoreError> {
    match publish_new_file(identity_dir, path, expected)? {
        PublishOutcome::Created => {
            validate_marker_if_present(path, expected)?;
            Ok(())
        }
        PublishOutcome::Existing => {
            validate_marker_if_present(path, expected)?;
            Ok(())
        }
    }
}

enum PublishOutcome {
    Created,
    Existing,
}

fn publish_new_file(
    identity_dir: &Path,
    target: &Path,
    bytes: &[u8],
) -> Result<PublishOutcome, FileKeyStoreError> {
    let (temporary_path, mut temporary_file) = create_private_temporary_file(identity_dir)?;
    temporary_file
        .write_all(bytes)
        .map_err(|source| FileKeyStoreError::Io {
            action: "write private temporary file",
            path: temporary_path.clone(),
            source,
        })?;
    temporary_file
        .sync_all()
        .map_err(|source| FileKeyStoreError::Io {
            action: "sync private temporary file",
            path: temporary_path.clone(),
            source,
        })?;
    drop(temporary_file);

    let outcome = match fs::hard_link(&temporary_path, target) {
        Ok(()) => {
            sync_directory(identity_dir)?;
            PublishOutcome::Created
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => PublishOutcome::Existing,
        Err(source) => {
            let _ = fs::remove_file(&temporary_path);
            return Err(FileKeyStoreError::Io {
                action: "atomically publish private file",
                path: target.to_owned(),
                source,
            });
        }
    };
    fs::remove_file(&temporary_path).map_err(|source| FileKeyStoreError::Io {
        action: "remove private temporary file",
        path: temporary_path,
        source,
    })?;
    sync_directory(identity_dir)?;
    Ok(outcome)
}

fn create_private_temporary_file(
    identity_dir: &Path,
) -> Result<(PathBuf, File), FileKeyStoreError> {
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(FileKeyStoreError::Random)?;
        let name = format!("{TEMP_PREFIX}{}", lower_hex(&random));
        let path = identity_dir.join(name);
        let mut options = private_open_options();
        options.read(true).write(true).create_new(true);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(FileKeyStoreError::Io {
                    action: "create private temporary file",
                    path,
                    source,
                });
            }
        }
    }
    Err(FileKeyStoreError::TemporaryNameExhausted)
}

fn random_material() -> Result<Zeroizing<[u8; 32]>, FileKeyStoreError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut bytes[..]).map_err(FileKeyStoreError::Random)?;
    Ok(bytes)
}

#[cfg(unix)]
fn protect_key_material(
    material: &[u8; MATERIAL_BYTES],
    _role: KeyRole,
) -> Result<Vec<u8>, FileKeyStoreError> {
    Ok(material.to_vec())
}

#[cfg(unix)]
fn read_key_material_file(path: &Path) -> Result<Vec<u8>, FileKeyStoreError> {
    read_private_exact(path, MATERIAL_BYTES)
}

#[cfg(unix)]
fn unprotect_key_material(
    bytes: &[u8],
    _role: KeyRole,
    path: &Path,
) -> Result<Zeroizing<[u8; MATERIAL_BYTES]>, FileKeyStoreError> {
    bytes
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| FileKeyStoreError::InvalidLength {
            path: path.to_owned(),
            expected: MATERIAL_BYTES,
            found: bytes.len(),
        })
}

#[cfg(windows)]
fn key_entropy(role: KeyRole) -> &'static [u8] {
    match role {
        KeyRole::NodeTransport => b"fractonica/identity/node-transport/v1",
        KeyRole::SpaceController => b"fractonica/identity/space-controller/v1",
        KeyRole::LocalWriter => b"fractonica/identity/local-writer/v1",
    }
}

#[cfg(windows)]
fn protect_key_material(
    material: &[u8; MATERIAL_BYTES],
    role: KeyRole,
) -> Result<Vec<u8>, FileKeyStoreError> {
    fractonica_windows_protection::protect(material, key_entropy(role))
        .map_err(FileKeyStoreError::PlatformProtection)
}

#[cfg(windows)]
fn read_key_material_file(path: &Path) -> Result<Vec<u8>, FileKeyStoreError> {
    const MAX_DPAPI_BLOB_BYTES: u64 = 16 * 1024;
    let mut file = open_validated_private_file(path, None)?;
    let length = file
        .metadata()
        .map_err(|source| FileKeyStoreError::Io {
            action: "inspect protected key material",
            path: path.to_owned(),
            source,
        })?
        .len();
    if length == 0 || length > MAX_DPAPI_BLOB_BYTES {
        return Err(FileKeyStoreError::InvalidProtectedLength {
            path: path.to_owned(),
            found: length,
        });
    }
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes)
        .map_err(|source| FileKeyStoreError::Io {
            action: "read protected key material",
            path: path.to_owned(),
            source,
        })?;
    Ok(bytes)
}

#[cfg(windows)]
fn unprotect_key_material(
    bytes: &[u8],
    role: KeyRole,
    path: &Path,
) -> Result<Zeroizing<[u8; MATERIAL_BYTES]>, FileKeyStoreError> {
    let output = Zeroizing::new(
        fractonica_windows_protection::unprotect(bytes, key_entropy(role)).map_err(|source| {
            FileKeyStoreError::ProtectedMaterial {
                path: path.to_owned(),
                source,
            }
        })?,
    );
    if output.len() == MATERIAL_BYTES {
        let mut material = Zeroizing::new([0; MATERIAL_BYTES]);
        material.copy_from_slice(&output);
        Ok(material)
    } else {
        Err(FileKeyStoreError::InvalidProtectedLength {
            path: path.to_owned(),
            found: output.len() as u64,
        })
    }
}

#[cfg(not(any(unix, windows)))]
fn protect_key_material(
    _material: &[u8; MATERIAL_BYTES],
    _role: KeyRole,
) -> Result<Vec<u8>, FileKeyStoreError> {
    Err(FileKeyStoreError::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
fn read_key_material_file(_path: &Path) -> Result<Vec<u8>, FileKeyStoreError> {
    Err(FileKeyStoreError::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
fn unprotect_key_material(
    _bytes: &[u8],
    _role: KeyRole,
    _path: &Path,
) -> Result<Zeroizing<[u8; MATERIAL_BYTES]>, FileKeyStoreError> {
    Err(FileKeyStoreError::UnsupportedPlatform)
}

fn random_nonzero_space_id() -> Result<[u8; 32], FileKeyStoreError> {
    for _ in 0..16 {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(FileKeyStoreError::Random)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(FileKeyStoreError::RandomSpaceIdExhausted)
}

fn cleanup_temporary_files(identity_dir: &Path) -> Result<(), FileKeyStoreError> {
    let entries = fs::read_dir(identity_dir).map_err(|source| FileKeyStoreError::Io {
        action: "scan identity directory",
        path: identity_dir.to_owned(),
        source,
    })?;
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|source| FileKeyStoreError::Io {
            action: "read identity directory entry",
            path: identity_dir.to_owned(),
            source,
        })?;
        if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| FileKeyStoreError::Io {
            action: "inspect private temporary file",
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(FileKeyStoreError::UnsafeObject {
                path,
                expected: "a non-symlink regular temporary file",
            });
        }
        validate_unix_file_owner_and_mode(&path, &metadata)?;
        fs::remove_file(&path).map_err(|source| FileKeyStoreError::Io {
            action: "remove stale private temporary file",
            path,
            source,
        })?;
        removed = true;
    }
    if removed {
        sync_directory(identity_dir)?;
    }
    Ok(())
}

fn refuse_untracked_identity_files(identity_dir: &Path) -> Result<(), FileKeyStoreError> {
    for name in [
        NODE_TRANSPORT_FILE,
        SPACE_CONTROLLER_FILE,
        LOCAL_WRITER_FILE,
        SPACE_ID_FILE,
    ] {
        if path_exists(&identity_dir.join(name))? {
            return Err(FileKeyStoreError::UntrackedIdentityFiles(
                identity_dir.to_owned(),
            ));
        }
    }
    Ok(())
}

fn remove_private_regular_file(path: &Path) -> Result<(), FileKeyStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| FileKeyStoreError::Io {
        action: "inspect private marker before removal",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FileKeyStoreError::UnsafeObject {
            path: path.to_owned(),
            expected: "a non-symlink regular marker file",
        });
    }
    validate_unix_file_security(path, &metadata)?;
    fs::remove_file(path).map_err(|source| FileKeyStoreError::Io {
        action: "remove private marker",
        path: path.to_owned(),
        source,
    })
}

fn path_exists(path: &Path) -> Result<bool, FileKeyStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FileKeyStoreError::Io {
            action: "inspect identity path",
            path: path.to_owned(),
            source,
        }),
    }
}

fn private_open_options() -> OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
    }
}

#[cfg(unix)]
fn private_directory_builder() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    builder
}

#[cfg(not(unix))]
fn private_directory_builder() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

fn validate_open_private_file(
    path: &Path,
    file: &File,
    expected_length: Option<u64>,
) -> Result<(), FileKeyStoreError> {
    let metadata = file.metadata().map_err(|source| FileKeyStoreError::Io {
        action: "inspect opened private file",
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(FileKeyStoreError::UnsafeObject {
            path: path.to_owned(),
            expected: "a regular file",
        });
    }
    validate_unix_file_security(path, &metadata)?;
    if let Some(expected) = expected_length
        && metadata.len() != expected
    {
        return Err(FileKeyStoreError::InvalidLength {
            path: path.to_owned(),
            expected: expected as usize,
            found: metadata.len() as usize,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_directory_security(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    use std::os::unix::fs::MetadataExt;

    validate_unix_owner(path, metadata)?;
    let actual = metadata.mode() & 0o7777;
    if actual != PRIVATE_DIRECTORY_MODE {
        return Err(FileKeyStoreError::InvalidMode {
            path: path.to_owned(),
            expected: PRIVATE_DIRECTORY_MODE,
            found: actual,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_directory_security(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    Ok(())
}

#[cfg(unix)]
fn validate_unix_file_security(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    use std::os::unix::fs::MetadataExt;

    validate_unix_file_owner_and_mode(path, metadata)?;
    if metadata.nlink() != 1 {
        return Err(FileKeyStoreError::MultipleHardLinks {
            path: path.to_owned(),
            links: metadata.nlink(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_file_owner_and_mode(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    use std::os::unix::fs::MetadataExt;

    validate_unix_owner(path, metadata)?;
    let actual = metadata.mode() & 0o7777;
    if actual != PRIVATE_FILE_MODE {
        return Err(FileKeyStoreError::InvalidMode {
            path: path.to_owned(),
            expected: PRIVATE_FILE_MODE,
            found: actual,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_file_security(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_unix_file_owner_and_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), FileKeyStoreError> {
    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner(path: &Path, metadata: &fs::Metadata) -> Result<(), FileKeyStoreError> {
    use std::os::unix::fs::MetadataExt;

    let expected = effective_user_id();
    if metadata.uid() != expected {
        return Err(FileKeyStoreError::WrongOwner {
            path: path.to_owned(),
            expected,
            found: metadata.uid(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn sync_directory(path: &Path) -> Result<(), FileKeyStoreError> {
    #[cfg(unix)]
    {
        let directory = File::open(path).map_err(|source| FileKeyStoreError::Io {
            action: "open directory for durability sync",
            path: path.to_owned(),
            source,
        })?;
        directory
            .sync_all()
            .map_err(|source| FileKeyStoreError::Io {
                action: "sync directory",
                path: path.to_owned(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[derive(Debug, Error)]
pub enum FileKeyStoreError {
    #[error(
        "the raw-file keystore is disabled on this platform because private ACL guarantees are not implemented"
    )]
    UnsupportedPlatform,
    #[error("Windows DPAPI failed to protect key material: {0}")]
    PlatformProtection(io::Error),
    #[error("Windows DPAPI failed to decrypt protected key material at {path}: {source}")]
    ProtectedMaterial {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid protected key-material length at {path}: found {found} bytes")]
    InvalidProtectedLength { path: PathBuf, found: u64 },
    #[error("failed to {action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("OS cryptographic random source failed: {0}")]
    Random(getrandom::Error),
    #[error("unsafe object at {path}; expected {expected}")]
    UnsafeObject {
        path: PathBuf,
        expected: &'static str,
    },
    #[error("unsafe permissions on {path}: found {found:#o}, expected {expected:#o}")]
    InvalidMode {
        path: PathBuf,
        expected: u32,
        found: u32,
    },
    #[error("wrong owner on {path}: uid {found}, expected uid {expected}")]
    WrongOwner {
        path: PathBuf,
        expected: u32,
        found: u32,
    },
    #[error("private file {path} has {links} hard links; expected exactly one")]
    MultipleHardLinks { path: PathBuf, links: u64 },
    #[error("invalid private-file length at {path}: found {found}, expected {expected}")]
    InvalidLength {
        path: PathBuf,
        expected: usize,
        found: usize,
    },
    #[error("established identity file is missing at {path} (role {role:?})")]
    MissingEstablishedIdentity {
        path: PathBuf,
        role: Option<KeyRole>,
    },
    #[error("space identity at {0} is all zeroes")]
    ZeroSpaceId(PathBuf),
    #[error("invalid bootstrap marker at {0}")]
    InvalidMarker(PathBuf),
    #[error("identity files exist without a bootstrap state marker in {0}")]
    UntrackedIdentityFiles(PathBuf),
    #[error("protected identity at {0} has no valid completion manifest")]
    IdentityNotEstablished(PathBuf),
    #[error("could not allocate a unique private temporary file name")]
    TemporaryNameExhausted,
    #[error("OS random source repeatedly returned an invalid zero space identity")]
    RandomSpaceIdExhausted,
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        sync::{Arc, Barrier},
        thread,
    };

    use fractonica_trust::SigningKey;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn fresh_bootstrap_is_distinct_private_and_stable() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        let store = FileKeyStore::new(&identity_dir);
        let first = store.load_or_create().unwrap();
        let expected = public_tuple(&first);

        assert_ne!(
            first.node_transport_key().public_key(),
            first.space_controller_key().public_key()
        );
        assert_ne!(
            first.node_transport_key().public_key(),
            first.local_writer_key().public_key()
        );
        assert_ne!(
            first.space_controller_key().public_key(),
            first.local_writer_key().public_key()
        );
        assert_ne!(first.space_id().as_bytes(), &[0; 32]);
        assert!(format!("{first:?}").contains("[REDACTED]"));

        for name in [
            NODE_TRANSPORT_FILE,
            SPACE_CONTROLLER_FILE,
            LOCAL_WRITER_FILE,
        ] {
            let length = fs::metadata(identity_dir.join(name)).unwrap().len();
            #[cfg(unix)]
            assert_eq!(length, 32);
            #[cfg(windows)]
            assert!(length > 32);
        }
        assert_eq!(
            fs::metadata(identity_dir.join(SPACE_ID_FILE))
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            fs::read(identity_dir.join(MANIFEST_FILE)).unwrap(),
            MANIFEST_BYTES
        );
        assert!(!identity_dir.join(STARTED_FILE).exists());

        #[cfg(unix)]
        assert_private_modes(&identity_dir);

        let reopened = store.load_or_create().unwrap();
        assert_eq!(public_tuple(&reopened), expected);
        let existing = store.load_existing().unwrap();
        assert_eq!(public_tuple(&existing), expected);
    }

    #[test]
    fn established_load_never_bootstraps_an_empty_directory() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        fs::create_dir(&identity_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&identity_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_existing(),
            Err(FileKeyStoreError::IdentityNotEstablished(_))
        ));
        assert!(!identity_dir.join(NODE_TRANSPORT_FILE).exists());
    }

    #[test]
    fn concurrent_bootstrap_has_one_winner_and_one_identity() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        let barrier = Arc::new(Barrier::new(12));
        let mut workers = Vec::new();
        for _ in 0..12 {
            let identity_dir = identity_dir.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                public_tuple(&FileKeyStore::new(identity_dir).load_or_create().unwrap())
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn completed_manifest_prevents_silent_key_replacement() {
        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        fs::remove_file(identity_dir.join(LOCAL_WRITER_FILE)).unwrap();
        let error = FileKeyStore::new(&identity_dir)
            .load_or_create()
            .unwrap_err();
        assert!(matches!(
            error,
            FileKeyStoreError::MissingEstablishedIdentity {
                role: Some(KeyRole::LocalWriter),
                ..
            }
        ));
        assert!(!identity_dir.join(LOCAL_WRITER_FILE).exists());
    }

    #[test]
    fn partial_bootstrap_recovers_without_replacing_valid_material() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(STARTED_FILE), STARTED_BYTES);
        let seed = [7_u8; 32];
        write_key(
            &identity_dir.join(NODE_TRANSPORT_FILE),
            &seed,
            KeyRole::NodeTransport,
        );
        let expected = SigningKey::from_seed(seed).node_id();

        let loaded = FileKeyStore::new(&identity_dir).load_or_create().unwrap();
        assert_eq!(loaded.node_id(), expected);
        assert!(identity_dir.join(MANIFEST_FILE).exists());
        assert!(!identity_dir.join(STARTED_FILE).exists());
    }

    #[test]
    fn corrupt_length_fails_closed_and_is_not_rewritten() {
        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        write_private(&identity_dir.join(LOCAL_WRITER_FILE), &[3_u8; 31]);
        let error = FileKeyStore::new(&identity_dir)
            .load_or_create()
            .unwrap_err();
        #[cfg(unix)]
        assert!(matches!(
            error,
            FileKeyStoreError::InvalidLength {
                expected: 32,
                found: 31,
                ..
            }
        ));
        #[cfg(windows)]
        assert!(matches!(error, FileKeyStoreError::ProtectedMaterial { .. }));
        assert_eq!(
            fs::metadata(identity_dir.join(LOCAL_WRITER_FILE))
                .unwrap()
                .len(),
            31
        );
    }

    #[test]
    fn colliding_roles_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(MANIFEST_FILE), MANIFEST_BYTES);
        write_key(
            &identity_dir.join(NODE_TRANSPORT_FILE),
            &[1_u8; 32],
            KeyRole::NodeTransport,
        );
        write_key(
            &identity_dir.join(SPACE_CONTROLLER_FILE),
            &[2_u8; 32],
            KeyRole::SpaceController,
        );
        write_key(
            &identity_dir.join(LOCAL_WRITER_FILE),
            &[2_u8; 32],
            KeyRole::LocalWriter,
        );
        write_private(&identity_dir.join(SPACE_ID_FILE), &[3_u8; 32]);
        let error = FileKeyStore::new(&identity_dir)
            .load_or_create()
            .unwrap_err();
        assert!(matches!(
            error,
            FileKeyStoreError::Identity(IdentityError::KeyCollision { .. })
        ));
    }

    #[test]
    fn zero_space_id_fails_closed() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(MANIFEST_FILE), MANIFEST_BYTES);
        write_key(
            &identity_dir.join(NODE_TRANSPORT_FILE),
            &[1_u8; 32],
            KeyRole::NodeTransport,
        );
        write_key(
            &identity_dir.join(SPACE_CONTROLLER_FILE),
            &[2_u8; 32],
            KeyRole::SpaceController,
        );
        write_key(
            &identity_dir.join(LOCAL_WRITER_FILE),
            &[3_u8; 32],
            KeyRole::LocalWriter,
        );
        write_private(&identity_dir.join(SPACE_ID_FILE), &[0_u8; 32]);
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::ZeroSpaceId(_))
        ));
    }

    #[test]
    fn non_regular_secret_file_is_refused() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(STARTED_FILE), STARTED_BYTES);
        create_private_dir(&identity_dir.join(NODE_TRANSPORT_FILE));
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::UnsafeObject { .. })
        ));
    }

    #[test]
    fn identities_without_bootstrap_state_are_not_adopted() {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(NODE_TRANSPORT_FILE), &[7_u8; 32]);
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::UntrackedIdentityFiles(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_secret_and_identity_directory_are_refused() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        create_private_dir(&identity_dir);
        write_private(&identity_dir.join(STARTED_FILE), STARTED_BYTES);
        let target = temporary.path().join("target");
        write_private(&target, &[4_u8; 32]);
        symlink(&target, identity_dir.join(NODE_TRANSPORT_FILE)).unwrap();
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::UnsafeObject { .. }) | Err(FileKeyStoreError::Io { .. })
        ));

        let linked_dir = temporary.path().join("linked-identity");
        symlink(&identity_dir, &linked_dir).unwrap();
        assert!(matches!(
            FileKeyStore::new(linked_dir).load_or_create(),
            Err(FileKeyStoreError::UnsafeObject { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn permissive_file_or_directory_modes_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        let writer = identity_dir.join(LOCAL_WRITER_FILE);
        fs::set_permissions(&writer, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::InvalidMode { .. })
        ));

        fs::set_permissions(&writer, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&identity_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::InvalidMode { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_secret_is_refused() {
        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        fs::hard_link(
            identity_dir.join(NODE_TRANSPORT_FILE),
            identity_dir.join("unexpected-link"),
        )
        .unwrap();
        assert!(matches!(
            FileKeyStore::new(&identity_dir).load_or_create(),
            Err(FileKeyStoreError::MultipleHardLinks { .. })
        ));
    }

    #[test]
    fn stale_private_temporary_files_are_removed_during_recovery() {
        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        let stale = identity_dir.join(format!("{TEMP_PREFIX}stale"));
        write_private(&stale, b"sensitive partial material");
        FileKeyStore::new(&identity_dir).load_or_create().unwrap();
        assert!(!stale.exists());
    }

    #[cfg(unix)]
    #[test]
    fn crash_after_atomic_link_publication_is_recoverable() {
        use std::os::unix::fs::MetadataExt;

        let (temporary, identity_dir) = bootstrapped();
        let _keep_alive = temporary;
        let node = identity_dir.join(NODE_TRANSPORT_FILE);
        let orphaned_temporary = identity_dir.join(format!("{TEMP_PREFIX}linked"));
        fs::hard_link(&node, &orphaned_temporary).unwrap();
        assert_eq!(fs::metadata(&node).unwrap().nlink(), 2);

        FileKeyStore::new(&identity_dir).load_or_create().unwrap();

        assert!(!orphaned_temporary.exists());
        assert_eq!(fs::metadata(node).unwrap().nlink(), 1);
    }

    fn public_tuple(bundle: &IdentityBundle) -> (String, String, String, String) {
        (
            bundle.node_id().to_string(),
            bundle.space_controller_actor_id().to_string(),
            bundle.local_writer_actor_id().to_string(),
            bundle.space_id().to_string(),
        )
    }

    fn bootstrapped() -> (TempDir, PathBuf) {
        let temporary = TempDir::new().unwrap();
        let identity_dir = temporary.path().join("identity");
        FileKeyStore::new(&identity_dir).load_or_create().unwrap();
        (temporary, identity_dir)
    }

    fn create_private_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn write_key(path: &Path, seed: &[u8; MATERIAL_BYTES], role: KeyRole) {
        write_private(path, &protect_key_material(seed, role).unwrap());
    }

    #[cfg(unix)]
    fn assert_private_modes(identity_dir: &Path) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        assert_eq!(
            fs::metadata(identity_dir).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        for entry in fs::read_dir(identity_dir).unwrap() {
            let metadata = entry.unwrap().metadata().unwrap();
            if metadata.is_file() {
                assert_eq!(metadata.mode() & 0o7777, 0o600);
            }
        }
    }
}
