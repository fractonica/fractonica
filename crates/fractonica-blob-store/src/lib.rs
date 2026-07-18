#![forbid(unsafe_code)]
//! Atomic filesystem storage for immutable content-addressed bytes.
//!
//! SQLite stores only short metadata transactions. Upload bytes are written,
//! hashed, and synchronized outside those transactions, then atomically moved
//! into their digest-derived path.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use fractonica_application::{
    ContentRepository, ContentRepositoryError, NewUpload, UploadId, UploadSession, UploadState,
};
use fractonica_content::{ContentDescriptor, ContentId};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_UPLOAD_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const MAINTENANCE_BATCH: usize = 1_024;
const UPLOAD_LOCK_STRIPES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUpload {
    pub upload_length: u64,
    pub expected_content_id: Option<ContentId>,
    pub upload_metadata: Option<String>,
    pub media_type: Option<String>,
    pub original_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendOutcome {
    pub session: UploadSession,
    pub content: Option<ContentDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobObject {
    pub descriptor: ContentDescriptor,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Availability {
    pub available: Vec<ContentDescriptor>,
    pub missing: Vec<ContentId>,
}

#[derive(Debug, Error)]
pub enum BlobStoreError {
    #[error("failed to access content storage: {0}")]
    Io(#[from] io::Error),

    #[error(transparent)]
    Repository(#[from] ContentRepositoryError),

    #[error("content storage lock was poisoned")]
    LockPoisoned,

    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,

    #[error("upload length {found} exceeds the configured maximum {maximum}")]
    UploadTooLarge { found: u64, maximum: u64 },

    #[error("PATCH body contains {found} bytes; maximum is {maximum}")]
    PatchTooLarge { found: usize, maximum: usize },

    #[error("upload {0} does not exist")]
    UploadNotFound(UploadId),

    #[error("upload {0} expired before it was completed")]
    UploadExpired(UploadId),

    #[error("upload {0} is not active")]
    UploadNotActive(UploadId),

    #[error("upload offset mismatch: node expects {expected}, request supplied {supplied}")]
    OffsetMismatch { expected: u64, supplied: u64 },

    #[error("chunk would end at {attempted}, beyond upload length {upload_length}")]
    UploadOverflow { attempted: u64, upload_length: u64 },

    #[error("chunk SHA-256 checksum does not match Upload-Checksum")]
    ChunkChecksumMismatch,

    #[error("completed bytes hash to {actual}, but the upload declared {expected}")]
    ContentIdMismatch {
        expected: ContentId,
        actual: ContentId,
    },

    #[error("content storage is inconsistent: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
pub struct BlobStore {
    root: Arc<PathBuf>,
    repository: Arc<dyn ContentRepository>,
    upload_locks: Arc<[Mutex<()>; UPLOAD_LOCK_STRIPES]>,
    publication_lock: Arc<Mutex<()>>,
    verified_files: Arc<Mutex<HashMap<ContentId, FileFingerprint>>>,
    max_blob_bytes: u64,
    upload_ttl_ms: i64,
}

impl BlobStore {
    pub fn open<R>(root: impl AsRef<Path>, repository: Arc<R>) -> Result<Self, BlobStoreError>
    where
        R: ContentRepository + 'static,
    {
        Self::open_with_limits(
            root,
            repository,
            DEFAULT_MAX_BLOB_BYTES,
            DEFAULT_UPLOAD_TTL_MS,
        )
    }

    pub fn open_with_limits<R>(
        root: impl AsRef<Path>,
        repository: Arc<R>,
        max_blob_bytes: u64,
        upload_ttl_ms: i64,
    ) -> Result<Self, BlobStoreError>
    where
        R: ContentRepository + 'static,
    {
        let root = root.as_ref().to_path_buf();
        prepare_private_directory(&root)?;
        prepare_private_subdirectory(&root, &root.join("staging"))?;
        prepare_private_subdirectory(&root, &root.join("blobs"))?;
        prepare_private_subdirectory(&root, &root.join("blobs/sha-256"))?;
        let store = Self {
            root: Arc::new(root),
            repository,
            upload_locks: Arc::new(std::array::from_fn(|_| Mutex::new(()))),
            publication_lock: Arc::new(Mutex::new(())),
            verified_files: Arc::new(Mutex::new(HashMap::new())),
            max_blob_bytes,
            upload_ttl_ms,
        };
        store.recover()?;
        Ok(store)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.as_path()
    }

    #[must_use]
    pub const fn max_blob_bytes(&self) -> u64 {
        self.max_blob_bytes
    }

    pub fn create_upload(&self, request: CreateUpload) -> Result<UploadSession, BlobStoreError> {
        if request.upload_length > self.max_blob_bytes {
            return Err(BlobStoreError::UploadTooLarge {
                found: request.upload_length,
                maximum: self.max_blob_bytes,
            });
        }
        if request.upload_length == 0
            && let Some(expected) = request.expected_content_id
        {
            let actual = ContentId::new(Sha256::digest([]).into());
            if expected != actual {
                return Err(BlobStoreError::ContentIdMismatch { expected, actual });
            }
        }
        let now = unix_time_millis()?;
        let upload_id = UploadId::new(Uuid::now_v7());
        let expires_at_unix_ms = now
            .checked_add(self.upload_ttl_ms)
            .ok_or(BlobStoreError::ClockBeforeUnixEpoch)?;
        validate_private_subdirectory(&self.root, &self.root.join("staging"))?;
        let staging_path = self.staging_path(upload_id);
        prepare_private_file(&staging_path)?;
        sync_directory(&self.root.join("staging"))?;
        let session = match self.repository.create_upload(&NewUpload {
            upload_id,
            upload_length: request.upload_length,
            expected_content_id: request.expected_content_id,
            upload_metadata: request.upload_metadata,
            media_type: request.media_type,
            original_name: request.original_name,
            created_at_unix_ms: now,
            expires_at_unix_ms,
        }) {
            Ok(session) => session,
            Err(error) => {
                if fs::remove_file(&staging_path).is_ok() {
                    let _ = sync_directory(&self.root.join("staging"));
                }
                return Err(error.into());
            }
        };
        if session.upload_length == 0 {
            return self.finalize_locked(session).map(|outcome| outcome.session);
        }
        Ok(session)
    }

    pub fn upload(&self, upload_id: UploadId) -> Result<Option<UploadSession>, BlobStoreError> {
        self.repository.upload(upload_id).map_err(Into::into)
    }

    pub fn append_chunk(
        &self,
        upload_id: UploadId,
        supplied_offset: u64,
        bytes: &[u8],
        checksum: Option<[u8; 32]>,
    ) -> Result<AppendOutcome, BlobStoreError> {
        if bytes.len() > MAX_PATCH_BYTES {
            return Err(BlobStoreError::PatchTooLarge {
                found: bytes.len(),
                maximum: MAX_PATCH_BYTES,
            });
        }
        if let Some(expected) = checksum {
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            if actual != expected {
                return Err(BlobStoreError::ChunkChecksumMismatch);
            }
        }

        let _guard = self
            .upload_lock(upload_id)
            .lock()
            .map_err(|_| BlobStoreError::LockPoisoned)?;
        let session = self
            .repository
            .upload(upload_id)?
            .ok_or(BlobStoreError::UploadNotFound(upload_id))?;
        let now = unix_time_millis()?;
        if session.state != UploadState::Active {
            return Err(BlobStoreError::UploadNotActive(upload_id));
        }
        if now >= session.expires_at_unix_ms {
            return Err(BlobStoreError::UploadExpired(upload_id));
        }
        if supplied_offset != session.upload_offset {
            return Err(BlobStoreError::OffsetMismatch {
                expected: session.upload_offset,
                supplied: supplied_offset,
            });
        }
        let byte_count = u64::try_from(bytes.len()).map_err(|_| BlobStoreError::PatchTooLarge {
            found: bytes.len(),
            maximum: MAX_PATCH_BYTES,
        })?;
        let new_offset =
            supplied_offset
                .checked_add(byte_count)
                .ok_or(BlobStoreError::UploadOverflow {
                    attempted: u64::MAX,
                    upload_length: session.upload_length,
                })?;
        if new_offset > session.upload_length {
            return Err(BlobStoreError::UploadOverflow {
                attempted: new_offset,
                upload_length: session.upload_length,
            });
        }

        validate_private_subdirectory(&self.root, &self.root.join("staging"))?;
        let staging_path = self.staging_path(upload_id);
        let mut file = open_regular_file(&staging_path, true)?;
        let stored_length = file.metadata()?.len();
        if stored_length < session.upload_offset {
            return Err(BlobStoreError::Corrupt(format!(
                "staging file for {upload_id} has {stored_length} bytes, below committed offset {}",
                session.upload_offset
            )));
        }
        if stored_length > session.upload_offset {
            file.set_len(session.upload_offset)?;
        }
        file.seek(SeekFrom::Start(session.upload_offset))?;
        file.write_all(bytes)?;
        file.sync_all()?;

        let expires = now
            .checked_add(self.upload_ttl_ms)
            .ok_or(BlobStoreError::ClockBeforeUnixEpoch)?;
        if new_offset == session.upload_length {
            let actual = hash_file(&mut file)?;
            if let Some(expected) = session.expected_content_id
                && actual != expected
            {
                file.set_len(session.upload_offset)?;
                file.sync_all()?;
                return Err(BlobStoreError::ContentIdMismatch { expected, actual });
            }
            drop(file);
            let advanced =
                self.repository
                    .advance_upload(upload_id, supplied_offset, new_offset, expires)?;
            return self.finalize_locked_with_id(advanced, actual);
        }

        let session =
            self.repository
                .advance_upload(upload_id, supplied_offset, new_offset, expires)?;
        Ok(AppendOutcome {
            session,
            content: None,
        })
    }

    pub fn blob(&self, content_id: ContentId) -> Result<Option<BlobObject>, BlobStoreError> {
        let Some(descriptor) = self.repository.content(content_id)? else {
            return Ok(None);
        };
        let path = self.blob_path(content_id);
        let parent = path
            .parent()
            .ok_or_else(|| BlobStoreError::Corrupt("blob path has no parent".into()))?;
        validate_private_subdirectory(&self.root, parent)?;
        let mut file = match open_regular_file(&path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(BlobStoreError::Corrupt(format!(
                    "metadata declares {content_id}, but its file is missing"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != descriptor.byte_length {
            return Err(BlobStoreError::Corrupt(format!(
                "file for {content_id} does not match its immutable descriptor"
            )));
        }
        let fingerprint = file_fingerprint(&metadata);
        if let Some(fingerprint) = &fingerprint {
            let verified = self
                .verified_files
                .lock()
                .map_err(|_| BlobStoreError::LockPoisoned)?;
            if verified.get(&content_id) == Some(fingerprint) {
                return Ok(Some(BlobObject { descriptor, path }));
            }
        }
        let actual = hash_file(&mut file)?;
        if actual != content_id {
            self.verified_files
                .lock()
                .map_err(|_| BlobStoreError::LockPoisoned)?
                .remove(&content_id);
            return Err(BlobStoreError::Corrupt(format!(
                "file for {content_id} hashes to {actual}"
            )));
        }
        if let Some(fingerprint) = fingerprint {
            let after = file_fingerprint(&file.metadata()?);
            if after.as_ref() != Some(&fingerprint) {
                return Err(BlobStoreError::Corrupt(format!(
                    "file for {content_id} changed while its integrity was being verified"
                )));
            }
            self.verified_files
                .lock()
                .map_err(|_| BlobStoreError::LockPoisoned)?
                .insert(content_id, fingerprint);
        }
        Ok(Some(BlobObject { descriptor, path }))
    }

    pub fn availability(&self, content_ids: &[ContentId]) -> Result<Availability, BlobStoreError> {
        let declared = self.repository.available_content(content_ids)?;
        let mut verified = std::collections::BTreeMap::new();
        for descriptor in declared {
            if self.blob(descriptor.content_id)?.is_some() {
                verified.insert(descriptor.content_id, descriptor);
            }
        }
        let mut available = Vec::with_capacity(verified.len());
        let mut missing = Vec::with_capacity(content_ids.len().saturating_sub(verified.len()));
        for content_id in content_ids {
            if let Some(descriptor) = verified.get(content_id) {
                available.push(*descriptor);
            } else {
                missing.push(*content_id);
            }
        }
        Ok(Availability { available, missing })
    }

    fn finalize_locked(&self, session: UploadSession) -> Result<AppendOutcome, BlobStoreError> {
        validate_private_subdirectory(&self.root, &self.root.join("staging"))?;
        let mut file = open_regular_file(&self.staging_path(session.upload_id), false)?;
        let content_id = hash_file(&mut file)?;
        if let Some(expected) = session.expected_content_id
            && expected != content_id
        {
            return Err(BlobStoreError::ContentIdMismatch {
                expected,
                actual: content_id,
            });
        }
        drop(file);
        self.finalize_locked_with_id(session, content_id)
    }

    fn finalize_locked_with_id(
        &self,
        session: UploadSession,
        content_id: ContentId,
    ) -> Result<AppendOutcome, BlobStoreError> {
        let session = self
            .repository
            .begin_upload_finalize(session.upload_id, content_id)?;
        self.publish_final_file(&session)?;
        let descriptor = self
            .repository
            .complete_upload(session.upload_id, unix_time_millis()?)?;
        let session = self
            .repository
            .upload(session.upload_id)?
            .ok_or(BlobStoreError::UploadNotFound(session.upload_id))?;
        Ok(AppendOutcome {
            session,
            content: Some(descriptor),
        })
    }

    fn install_final_file(&self, session: &UploadSession) -> Result<(), BlobStoreError> {
        let content_id = session.final_content_id.ok_or_else(|| {
            BlobStoreError::Corrupt(format!(
                "finalizing upload {} has no content ID",
                session.upload_id
            ))
        })?;
        let staging_path = self.staging_path(session.upload_id);
        let final_path = self.blob_path(content_id);
        let parent = final_path
            .parent()
            .ok_or_else(|| BlobStoreError::Corrupt("blob path has no parent".into()))?;
        prepare_private_subdirectory(&self.root, parent)?;

        match fs::symlink_metadata(&final_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() != session.upload_length
                {
                    return Err(BlobStoreError::Corrupt(format!(
                        "existing file for {content_id} has conflicting metadata"
                    )));
                }
                let mut existing = open_regular_file(&final_path, false)?;
                let existing_content_id = hash_file(&mut existing)?;
                if existing_content_id != content_id {
                    return Err(BlobStoreError::Corrupt(format!(
                        "existing file at the path for {content_id} hashes to {existing_content_id}"
                    )));
                }
                self.remove_staging_file(session.upload_id)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let staging_metadata = fs::symlink_metadata(&staging_path)?;
                if staging_metadata.file_type().is_symlink() || !staging_metadata.is_file() {
                    return Err(BlobStoreError::Corrupt(format!(
                        "staging path for {} is not a regular file",
                        session.upload_id
                    )));
                }
                fs::rename(&staging_path, &final_path)?;
                set_private_file_permissions(&final_path)?;
                sync_directory(parent)?;
                sync_directory(&self.root.join("staging"))?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn recover(&self) -> Result<(), BlobStoreError> {
        self.remove_orphan_staging_files()?;
        loop {
            let sessions = self
                .repository
                .uploads_requiring_finalization(MAINTENANCE_BATCH)?;
            let fetched = sessions.len();
            for session in sessions {
                match session.state {
                    UploadState::Active => {
                        match self.finalize_locked(session.clone()) {
                            Ok(_) => {}
                            Err(BlobStoreError::ContentIdMismatch { .. }) => {
                                // A pre-fix zero-length upload could reach durable metadata
                                // before its declared digest was checked. It is not resumable
                                // and must not prevent every subsequent node startup.
                                self.discard_upload(session.upload_id)?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    UploadState::Finalizing => {
                        self.publish_final_file(&session)?;
                        self.repository
                            .complete_upload(session.upload_id, unix_time_millis()?)?;
                    }
                    UploadState::Complete => {
                        return Err(BlobStoreError::Corrupt(format!(
                            "complete upload {} was returned for finalization",
                            session.upload_id
                        )));
                    }
                }
            }
            if fetched < MAINTENANCE_BATCH {
                break;
            }
        }
        let now = unix_time_millis()?;
        loop {
            let sessions = self.repository.expired_uploads(now, MAINTENANCE_BATCH)?;
            let fetched = sessions.len();
            for session in sessions {
                self.discard_upload(session.upload_id)?;
            }
            if fetched < MAINTENANCE_BATCH {
                break;
            }
        }
        Ok(())
    }

    fn remove_orphan_staging_files(&self) -> Result<(), BlobStoreError> {
        let staging = self.root.join("staging");
        validate_private_subdirectory(&self.root, &staging)?;
        let mut removed = false;
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BlobStoreError::Corrupt(format!(
                    "staging entry {} is not a regular file",
                    path.display()
                )));
            }
            let name = entry.file_name().into_string().map_err(|_| {
                BlobStoreError::Corrupt(format!(
                    "staging entry {} is not valid UTF-8",
                    path.display()
                ))
            })?;
            let encoded = name.strip_suffix(".part").ok_or_else(|| {
                BlobStoreError::Corrupt(format!(
                    "staging entry {name} does not use the canonical UUID.part form"
                ))
            })?;
            let upload_id = UploadId::parse(encoded).map_err(|_| {
                BlobStoreError::Corrupt(format!(
                    "staging entry {name} does not contain a valid upload UUID"
                ))
            })?;
            if name != format!("{upload_id}.part") {
                return Err(BlobStoreError::Corrupt(format!(
                    "staging entry {name} does not use the canonical UUID.part form"
                )));
            }
            if self.repository.upload(upload_id)?.is_none() {
                fs::remove_file(path)?;
                removed = true;
            }
        }
        if removed {
            sync_directory(&staging)?;
        }
        Ok(())
    }

    fn publish_final_file(&self, session: &UploadSession) -> Result<(), BlobStoreError> {
        let _guard = self
            .publication_lock
            .lock()
            .map_err(|_| BlobStoreError::LockPoisoned)?;
        self.install_final_file(session)
    }

    fn discard_upload(&self, upload_id: UploadId) -> Result<(), BlobStoreError> {
        self.remove_staging_file(upload_id)?;
        self.repository.delete_upload(upload_id)?;
        Ok(())
    }

    fn remove_staging_file(&self, upload_id: UploadId) -> Result<(), BlobStoreError> {
        validate_private_subdirectory(&self.root, &self.root.join("staging"))?;
        match fs::remove_file(self.staging_path(upload_id)) {
            Ok(()) => sync_directory(&self.root.join("staging"))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn upload_lock(&self, upload_id: UploadId) -> &Mutex<()> {
        &self.upload_locks[self.upload_lock_index(upload_id)]
    }

    fn upload_lock_index(&self, upload_id: UploadId) -> usize {
        let uuid = upload_id.as_uuid();
        uuid.as_bytes().iter().fold(0_usize, |hash, byte| {
            hash.wrapping_mul(31) ^ usize::from(*byte)
        }) % UPLOAD_LOCK_STRIPES
    }

    fn staging_path(&self, upload_id: UploadId) -> PathBuf {
        self.root.join("staging").join(format!("{upload_id}.part"))
    }

    fn blob_path(&self, content_id: ContentId) -> PathBuf {
        let wire = content_id.to_string();
        let digest = wire
            .strip_prefix("sha-256:")
            .expect("ContentId v1 always emits sha-256");
        self.root
            .join("blobs/sha-256")
            .join(&digest[..2])
            .join(&digest[2..4])
            .join(digest)
    }
}

fn hash_file(file: &mut File) -> Result<ContentId, BlobStoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(ContentId::new(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    byte_length: u64,
    modified: SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

fn file_fingerprint(metadata: &fs::Metadata) -> Option<FileFingerprint> {
    let modified = metadata.modified().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileFingerprint {
            byte_length: metadata.len(),
            modified,
            device: metadata.dev(),
            inode: metadata.ino(),
            change_seconds: metadata.ctime(),
            change_nanoseconds: metadata.ctime_nsec(),
        })
    }
    #[cfg(not(unix))]
    {
        Some(FileFingerprint {
            byte_length: metadata.len(),
            modified,
        })
    }
}

fn unix_time_millis() -> Result<i64, BlobStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BlobStoreError::ClockBeforeUnixEpoch)?
        .as_millis()
        .try_into()
        .map_err(|_| BlobStoreError::ClockBeforeUnixEpoch)
}

fn prepare_private_directory(path: &Path) -> io::Result<()> {
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a private content directory", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            created = true;
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    if created
        && let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
    {
        sync_directory(parent)?;
    }
    Ok(())
}

fn prepare_private_subdirectory(root: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is outside content root {}",
                path.display(),
                root.display()
            ),
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        use std::path::Component;
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a normalized content path", path.display()),
            ));
        };
        let parent = current.clone();
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a private content directory", current.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
                }
                sync_directory(&parent)?;
            }
            Err(error) => return Err(error),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn validate_private_subdirectory(root: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is outside content root {}",
                path.display(),
                root.display()
            ),
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        use std::path::Component;
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a normalized content path", path.display()),
            ));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a private content directory", current.display()),
            ));
        }
    }
    Ok(())
}

fn open_regular_file(path: &Path, writable: bool) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular content file", path.display()),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular content file", path.display()),
        ));
    }
    Ok(file)
}

fn prepare_private_file(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?;
    set_private_file_permissions(path)
}

fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Duration};

    use fractonica_application::ContentRepository;
    use fractonica_content::hash_bytes;
    use fractonica_store_sqlite::SqliteStore;
    use sha2::{Digest, Sha256};

    use super::*;

    fn upload_request(bytes: &[u8]) -> CreateUpload {
        CreateUpload {
            upload_length: u64::try_from(bytes.len()).expect("test length"),
            expected_content_id: Some(hash_bytes(bytes)),
            upload_metadata: None,
            media_type: Some("application/octet-stream".to_owned()),
            original_name: Some("fixture.bin".to_owned()),
        }
    }

    #[test]
    fn resumes_chunks_and_atomically_exposes_completed_content() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let bytes = b"resumable bytes";
        let session = store
            .create_upload(upload_request(bytes))
            .expect("create upload");

        let first = store
            .append_chunk(session.upload_id, 0, &bytes[..5], None)
            .expect("first chunk");
        assert_eq!(first.session.upload_offset, 5);
        assert_eq!(first.content, None);
        assert!(matches!(
            store.append_chunk(session.upload_id, 0, &bytes[5..], None),
            Err(BlobStoreError::OffsetMismatch {
                expected: 5,
                supplied: 0
            })
        ));

        let checksum: [u8; 32] = Sha256::digest(&bytes[5..]).into();
        let completed = store
            .append_chunk(session.upload_id, 5, &bytes[5..], Some(checksum))
            .expect("final chunk");
        assert_eq!(completed.session.state, UploadState::Complete);
        assert_eq!(
            completed.content.map(|item| item.content_id),
            Some(hash_bytes(bytes))
        );

        let blob = store
            .blob(hash_bytes(bytes))
            .expect("lookup")
            .expect("available");
        assert_eq!(fs::read(blob.path).expect("read blob"), bytes);
        assert_eq!(
            store
                .availability(&[hash_bytes(b"missing"), hash_bytes(bytes)])
                .expect("availability"),
            Availability {
                available: vec![ContentDescriptor {
                    content_id: hash_bytes(bytes),
                    byte_length: u64::try_from(bytes.len()).expect("length"),
                }],
                missing: vec![hash_bytes(b"missing")],
            }
        );
    }

    #[test]
    fn checksum_and_declared_content_mismatches_do_not_advance_the_upload() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let session = store
            .create_upload(upload_request(b"expected"))
            .expect("create upload");

        assert!(matches!(
            store.append_chunk(session.upload_id, 0, b"differen", Some([0; 32])),
            Err(BlobStoreError::ChunkChecksumMismatch)
        ));
        assert_eq!(
            store
                .upload(session.upload_id)
                .expect("upload")
                .expect("present")
                .upload_offset,
            0
        );
        assert_eq!(
            fs::metadata(store.staging_path(session.upload_id))
                .expect("staging metadata")
                .len(),
            0
        );

        assert!(matches!(
            store.append_chunk(session.upload_id, 0, b"differen", None),
            Err(BlobStoreError::ContentIdMismatch { .. })
        ));
        assert_eq!(
            store
                .upload(session.upload_id)
                .expect("upload")
                .expect("present")
                .upload_offset,
            0
        );
        assert_eq!(
            fs::metadata(store.staging_path(session.upload_id))
                .expect("staging metadata")
                .len(),
            0
        );
    }

    #[test]
    fn rejected_zero_length_digest_leaves_no_recovery_poison() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let request = CreateUpload {
            upload_length: 0,
            expected_content_id: Some(hash_bytes(b"not empty")),
            upload_metadata: Some("agent ZmFrZQ==".to_owned()),
            media_type: None,
            original_name: None,
        };

        assert!(matches!(
            store.create_upload(request),
            Err(BlobStoreError::ContentIdMismatch { .. })
        ));
        assert_eq!(
            fs::read_dir(directory.path().join("staging"))
                .expect("staging directory")
                .count(),
            0
        );
        drop(store);
        BlobStore::open(directory.path(), repository).expect("clean restart");
    }

    #[test]
    fn startup_drains_more_than_one_full_recovery_batch() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let now = unix_time_millis().expect("now");
        let empty = hash_bytes(b"");
        let mut upload_ids = Vec::with_capacity(MAINTENANCE_BATCH + 1);

        for _ in 0..=MAINTENANCE_BATCH {
            let upload_id = UploadId::new(Uuid::now_v7());
            prepare_private_file(&store.staging_path(upload_id)).expect("staging file");
            repository
                .create_upload(&NewUpload {
                    upload_id,
                    upload_length: 0,
                    expected_content_id: Some(empty),
                    upload_metadata: None,
                    media_type: None,
                    original_name: None,
                    created_at_unix_ms: now,
                    expires_at_unix_ms: now + 60_000,
                })
                .expect("upload metadata");
            upload_ids.push(upload_id);
        }
        drop(store);

        let recovered =
            BlobStore::open(directory.path(), Arc::clone(&repository)).expect("recover");
        for upload_id in upload_ids {
            assert_eq!(
                recovered
                    .upload(upload_id)
                    .expect("lookup")
                    .expect("session")
                    .state,
                UploadState::Complete
            );
        }
    }

    #[test]
    fn startup_drains_more_than_one_full_expiration_batch() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let mut upload_ids = Vec::with_capacity(MAINTENANCE_BATCH + 1);
        for _ in 0..=MAINTENANCE_BATCH {
            let upload_id = UploadId::new(Uuid::now_v7());
            repository
                .create_upload(&NewUpload {
                    upload_id,
                    upload_length: 1,
                    expected_content_id: None,
                    upload_metadata: None,
                    media_type: None,
                    original_name: None,
                    created_at_unix_ms: 0,
                    expires_at_unix_ms: 0,
                })
                .expect("expired upload metadata");
            upload_ids.push(upload_id);
        }

        let recovered =
            BlobStore::open(directory.path(), Arc::clone(&repository)).expect("recover");
        for upload_id in upload_ids {
            assert_eq!(recovered.upload(upload_id).expect("lookup"), None);
        }
    }

    #[test]
    fn startup_removes_canonical_orphan_staging_files() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let orphan_id = UploadId::new(Uuid::now_v7());
        let orphan = store.staging_path(orphan_id);
        prepare_private_file(&orphan).expect("orphan staging file");
        sync_directory(&directory.path().join("staging")).expect("durable orphan");
        drop(store);

        BlobStore::open(directory.path(), repository).expect("recover");
        assert!(!orphan.exists());
    }

    #[test]
    fn startup_rejects_malformed_staging_entries() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        fs::write(directory.path().join("staging/not-an-upload.part"), b"")
            .expect("malformed entry");
        drop(store);

        assert!(matches!(
            BlobStore::open(directory.path(), repository),
            Err(BlobStoreError::Corrupt(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn startup_rejects_symlinked_staging_entries() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let external = directory.path().join("external.part");
        fs::write(&external, b"").expect("external file");
        let upload_id = UploadId::new(Uuid::now_v7());
        symlink(&external, store.staging_path(upload_id)).expect("staging symlink");
        drop(store);

        assert!(matches!(
            BlobStore::open(directory.path(), repository),
            Err(BlobStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn same_length_corruption_is_neither_served_nor_available() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let bytes = b"good";
        let content_id = hash_bytes(bytes);
        let upload = store
            .create_upload(upload_request(bytes))
            .expect("create upload");
        store
            .append_chunk(upload.upload_id, 0, bytes, None)
            .expect("complete upload");
        let path = store.blob_path(content_id);
        store
            .blob(content_id)
            .expect("initial verification")
            .expect("available blob");
        let previous_modified = fs::metadata(&path)
            .expect("blob metadata")
            .modified()
            .expect("modified time");
        fs::write(&path, b"evil").expect("corrupt blob without changing its length");
        let corrupted = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("corrupted blob");
        corrupted
            .set_times(
                fs::FileTimes::new().set_modified(
                    previous_modified
                        .checked_add(Duration::from_secs(2))
                        .expect("later modified time"),
                ),
            )
            .expect("change fingerprint");

        assert!(matches!(
            store.blob(content_id),
            Err(BlobStoreError::Corrupt(_))
        ));
        assert!(matches!(
            store.availability(&[content_id]),
            Err(BlobStoreError::Corrupt(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_blob_files_and_digest_directories() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let bytes = b"safe";
        let content_id = hash_bytes(bytes);
        let upload = store
            .create_upload(upload_request(bytes))
            .expect("create upload");
        store
            .append_chunk(upload.upload_id, 0, bytes, None)
            .expect("complete upload");
        let blob_path = store.blob_path(content_id);
        fs::remove_file(&blob_path).expect("remove blob");
        let external = directory.path().join("external.bin");
        fs::write(&external, bytes).expect("external bytes");
        symlink(&external, &blob_path).expect("blob symlink");
        assert!(store.blob(content_id).is_err());

        let (other, prefix) = (0_u64..)
            .map(|counter| format!("other bytes {counter}"))
            .find_map(|bytes| {
                let wire = hash_bytes(bytes.as_bytes()).to_string();
                let digest = wire.strip_prefix("sha-256:").expect("digest");
                let prefix = directory.path().join("blobs/sha-256").join(&digest[..2]);
                (!prefix.exists()).then_some((bytes, prefix))
            })
            .expect("unused digest prefix");
        let redirected = directory.path().join("redirected");
        fs::create_dir(&redirected).expect("redirect target");
        symlink(&redirected, &prefix).expect("prefix symlink");
        let other_upload = store
            .create_upload(upload_request(other.as_bytes()))
            .expect("create second upload");
        assert!(
            store
                .append_chunk(other_upload.upload_id, 0, other.as_bytes(), None)
                .is_err()
        );
        assert_eq!(
            fs::read_dir(redirected).expect("redirect target").count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_digest_directories_during_lookup() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let bytes = b"safe lookup";
        let content_id = hash_bytes(bytes);
        let upload = store
            .create_upload(upload_request(bytes))
            .expect("create upload");
        store
            .append_chunk(upload.upload_id, 0, bytes, None)
            .expect("complete upload");
        let blob_path = store.blob_path(content_id);
        let first_prefix = blob_path
            .parent()
            .and_then(Path::parent)
            .expect("first digest prefix");
        let relocated = directory.path().join("relocated-prefix");
        fs::rename(first_prefix, &relocated).expect("relocate digest prefix");
        symlink(&relocated, first_prefix).expect("prefix symlink");

        assert!(store.blob(content_id).is_err());
    }

    #[test]
    fn an_unrelated_upload_progresses_while_another_upload_stripe_is_busy() {
        use std::sync::mpsc;

        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = Arc::new(
            BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store"),
        );
        let blocked = store
            .create_upload(upload_request(b"blocked"))
            .expect("blocked upload");
        let independent = loop {
            let candidate = store
                .create_upload(upload_request(b"independent"))
                .expect("independent upload");
            if store.upload_lock_index(candidate.upload_id)
                != store.upload_lock_index(blocked.upload_id)
            {
                break candidate;
            }
        };
        let worker_store = Arc::clone(&store);
        let (sent, received) = mpsc::channel();
        let busy = store
            .upload_lock(blocked.upload_id)
            .lock()
            .expect("busy upload stripe");
        let worker = thread::spawn(move || {
            let result = worker_store.append_chunk(independent.upload_id, 0, b"independent", None);
            sent.send(result).expect("send result");
        });

        let result = received
            .recv_timeout(Duration::from_secs(2))
            .expect("unrelated upload must not wait for the busy stripe");
        result.expect("independent upload");
        drop(busy);
        worker.join().expect("worker");
    }

    #[test]
    fn identical_uploads_deduplicate_to_one_verified_file() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let store = BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
        let bytes = b"same bytes";

        for _ in 0..2 {
            let session = store
                .create_upload(upload_request(bytes))
                .expect("create upload");
            store
                .append_chunk(session.upload_id, 0, bytes, None)
                .expect("complete upload");
        }

        let blob = store
            .blob(hash_bytes(bytes))
            .expect("lookup")
            .expect("available");
        assert_eq!(fs::read(blob.path).expect("read blob"), bytes);
        assert_eq!(
            repository
                .available_content(&[hash_bytes(bytes)])
                .expect("metadata")
                .len(),
            1
        );
    }

    #[test]
    fn startup_recovers_both_crash_windows_around_finalization() {
        for begin_finalization in [false, true] {
            let directory = tempfile::tempdir().expect("directory");
            let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
            let bytes = b"recover me";
            let upload_id = {
                let store =
                    BlobStore::open(directory.path(), Arc::clone(&repository)).expect("blob store");
                let session = store
                    .create_upload(upload_request(bytes))
                    .expect("create upload");
                fs::write(store.staging_path(session.upload_id), bytes).expect("stage bytes");
                repository
                    .advance_upload(
                        session.upload_id,
                        0,
                        u64::try_from(bytes.len()).expect("length"),
                        unix_time_millis().expect("now") + 60_000,
                    )
                    .expect("commit final offset");
                if begin_finalization {
                    repository
                        .begin_upload_finalize(session.upload_id, hash_bytes(bytes))
                        .expect("begin finalization");
                }
                session.upload_id
            };

            let recovered =
                BlobStore::open(directory.path(), Arc::clone(&repository)).expect("recover");
            assert_eq!(
                recovered
                    .upload(upload_id)
                    .expect("upload")
                    .expect("present")
                    .state,
                UploadState::Complete
            );
            assert_eq!(
                fs::read(
                    recovered
                        .blob(hash_bytes(bytes))
                        .expect("lookup")
                        .expect("blob")
                        .path
                )
                .expect("read"),
                bytes
            );
        }
    }

    #[test]
    fn startup_expires_abandoned_uploads_and_zero_length_uploads_complete_immediately() {
        let directory = tempfile::tempdir().expect("directory");
        let repository = Arc::new(SqliteStore::open_in_memory().expect("repository"));
        let abandoned = {
            let store = BlobStore::open_with_limits(
                directory.path(),
                Arc::clone(&repository),
                DEFAULT_MAX_BLOB_BYTES,
                1,
            )
            .expect("blob store");
            store
                .create_upload(upload_request(b"abandoned"))
                .expect("create")
                .upload_id
        };
        thread::sleep(Duration::from_millis(5));
        let store = BlobStore::open_with_limits(
            directory.path(),
            Arc::clone(&repository),
            DEFAULT_MAX_BLOB_BYTES,
            1,
        )
        .expect("recover");
        assert_eq!(store.upload(abandoned).expect("lookup"), None);

        let empty = store
            .create_upload(upload_request(b""))
            .expect("zero-length upload");
        assert_eq!(empty.state, UploadState::Complete);
        assert_eq!(
            store
                .blob(hash_bytes(b""))
                .expect("lookup")
                .expect("empty blob")
                .descriptor
                .byte_length,
            0
        );
    }
}
