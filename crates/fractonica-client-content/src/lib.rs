#![forbid(unsafe_code)]
//! Crash-safe local storage for immutable client media.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use fractonica_content::{ContentDescriptor, ContentId, MAX_CONTENT_BYTE_LENGTH};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;
pub const MAX_DOWNLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct ClientContentStore {
    root: Arc<PathBuf>,
    verified: Arc<Mutex<HashMap<ContentId, FileFingerprint>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBlob {
    pub descriptor: ContentDescriptor,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendResult {
    pub offset: u64,
    pub complete: bool,
}

#[derive(Debug, Error)]
pub enum ClientContentError {
    #[error("content filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("content bytes exceed declared length {expected}")]
    LengthOverflow { expected: u64 },
    #[error("content length {actual} exceeds protocol maximum {maximum}")]
    ContentTooLarge { actual: u64, maximum: u64 },
    #[error("content length is {actual}, expected {expected}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("content digest is {actual}, expected {expected}")]
    DigestMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    #[error("download offset is {supplied}, but the durable partial file is at {expected}")]
    OffsetMismatch { expected: u64, supplied: u64 },
    #[error("download chunk has {found} bytes; maximum is {maximum}")]
    ChunkTooLarge { found: usize, maximum: usize },
    #[error("content path is not a private regular file: {0}")]
    UnsafePath(PathBuf),
    #[error("content verification cache lock was poisoned")]
    LockPoisoned,
}

impl ClientContentStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ClientContentError> {
        let root = root.as_ref().to_path_buf();
        prepare_private_directory(&root)?;
        prepare_private_directory(&root.join("blobs"))?;
        prepare_private_directory(&root.join("blobs/sha-256"))?;
        prepare_private_directory(&root.join("partial"))?;
        Ok(Self {
            root: Arc::new(root),
            verified: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.as_path()
    }

    pub fn import(
        &self,
        descriptor: ContentDescriptor,
        mut source: impl Read,
    ) -> Result<LocalBlob, ClientContentError> {
        descriptor
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if let Some(existing) = self.blob(descriptor)? {
            return Ok(existing);
        }
        let temporary = self.import_path(descriptor.content_id, Uuid::now_v7());
        let mut output = create_private_truncated(&temporary)?;
        let mut hasher = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            length = length
                .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                .ok_or(ClientContentError::LengthOverflow {
                    expected: descriptor.byte_length,
                })?;
            if length > descriptor.byte_length {
                drop(output);
                remove_if_exists(&temporary)?;
                return Err(ClientContentError::LengthOverflow {
                    expected: descriptor.byte_length,
                });
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        output.sync_all()?;
        drop(output);
        verify_expected(descriptor, length, hasher.finalize().into()).inspect_err(|_| {
            let _ = remove_if_exists(&temporary);
        })?;
        self.publish(descriptor, &temporary)
    }

    /// Imports a native file without trusting caller-supplied content metadata.
    ///
    /// The source must be a regular, non-symlink file. Its SHA-256 identity and
    /// byte length are derived while copying it into a private temporary file,
    /// and publication into the immutable store is atomic and deduplicating.
    pub fn import_file(
        &self,
        source_path: impl AsRef<Path>,
    ) -> Result<LocalBlob, ClientContentError> {
        let source_path = source_path.as_ref();
        let mut source = open_regular_file(source_path)?;
        let initial_length = source.metadata()?.len();
        ensure_protocol_length(initial_length)?;

        let temporary = self.unidentified_import_path(Uuid::now_v7());
        let result = (|| {
            let mut output = create_private_truncated(&temporary)?;
            let mut hasher = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
            loop {
                let read = source.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                length = length
                    .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                    .ok_or(ClientContentError::ContentTooLarge {
                        actual: u64::MAX,
                        maximum: MAX_CONTENT_BYTE_LENGTH,
                    })?;
                ensure_protocol_length(length)?;
                hasher.update(&buffer[..read]);
                output.write_all(&buffer[..read])?;
            }
            output.sync_all()?;
            drop(output);

            let descriptor = ContentDescriptor {
                content_id: ContentId::new(hasher.finalize().into()),
                byte_length: length,
            };
            self.publish(descriptor, &temporary)
        })();

        if result.is_err() {
            let _ = remove_if_exists(&temporary);
        }
        result
    }

    pub fn partial_offset(&self, descriptor: ContentDescriptor) -> Result<u64, ClientContentError> {
        if self.blob(descriptor)?.is_some() {
            return Ok(descriptor.byte_length);
        }
        let path = self.partial_path(descriptor.content_id);
        let Some(metadata) = regular_metadata_if_exists(&path)? else {
            return Ok(0);
        };
        if metadata.len() > descriptor.byte_length {
            return Err(ClientContentError::LengthOverflow {
                expected: descriptor.byte_length,
            });
        }
        Ok(metadata.len())
    }

    pub fn append_download_chunk(
        &self,
        descriptor: ContentDescriptor,
        supplied_offset: u64,
        bytes: &[u8],
    ) -> Result<AppendResult, ClientContentError> {
        if bytes.len() > MAX_DOWNLOAD_CHUNK_BYTES {
            return Err(ClientContentError::ChunkTooLarge {
                found: bytes.len(),
                maximum: MAX_DOWNLOAD_CHUNK_BYTES,
            });
        }
        if self.blob(descriptor)?.is_some() {
            return Ok(AppendResult {
                offset: descriptor.byte_length,
                complete: true,
            });
        }
        let current = self.partial_offset(descriptor)?;
        if current != supplied_offset {
            return Err(ClientContentError::OffsetMismatch {
                expected: current,
                supplied: supplied_offset,
            });
        }
        let added = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next = current
            .checked_add(added)
            .filter(|value| *value <= descriptor.byte_length)
            .ok_or(ClientContentError::LengthOverflow {
                expected: descriptor.byte_length,
            })?;
        let path = self.partial_path(descriptor.content_id);
        let mut file = open_private_append(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if next != descriptor.byte_length {
            return Ok(AppendResult {
                offset: next,
                complete: false,
            });
        }
        verify_file(&path, descriptor).inspect_err(|_| {
            let _ = remove_if_exists(&path);
        })?;
        self.publish(descriptor, &path)?;
        Ok(AppendResult {
            offset: next,
            complete: true,
        })
    }

    pub fn blob(
        &self,
        descriptor: ContentDescriptor,
    ) -> Result<Option<LocalBlob>, ClientContentError> {
        let path = self.blob_path(descriptor.content_id);
        let Some(metadata) = regular_metadata_if_exists(&path)? else {
            return Ok(None);
        };
        if metadata.len() != descriptor.byte_length {
            return Err(ClientContentError::LengthMismatch {
                expected: descriptor.byte_length,
                actual: metadata.len(),
            });
        }
        let fingerprint = FileFingerprint::from_metadata(&metadata);
        let cached = self
            .verified
            .lock()
            .map_err(|_| ClientContentError::LockPoisoned)?
            .get(&descriptor.content_id)
            .is_some_and(|value| value == &fingerprint);
        if !cached {
            verify_file(&path, descriptor)?;
            let verified_metadata = regular_metadata(&path)?;
            let verified_fingerprint = FileFingerprint::from_metadata(&verified_metadata);
            self.verified
                .lock()
                .map_err(|_| ClientContentError::LockPoisoned)?
                .insert(descriptor.content_id, verified_fingerprint);
        }
        Ok(Some(LocalBlob { descriptor, path }))
    }

    pub fn read_range(
        &self,
        descriptor: ContentDescriptor,
        offset: u64,
        maximum: usize,
    ) -> Result<Vec<u8>, ClientContentError> {
        let blob = self.blob(descriptor)?.ok_or_else(|| {
            ClientContentError::Io(io::Error::new(io::ErrorKind::NotFound, "blob is absent"))
        })?;
        if offset > descriptor.byte_length {
            return Err(ClientContentError::OffsetMismatch {
                expected: descriptor.byte_length,
                supplied: offset,
            });
        }
        let remaining = descriptor.byte_length - offset;
        let length = usize::try_from(remaining.min(maximum as u64)).unwrap_or(maximum);
        let mut file = open_regular_file(&blob.path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn publish(
        &self,
        descriptor: ContentDescriptor,
        temporary: &Path,
    ) -> Result<LocalBlob, ClientContentError> {
        let directory = self.blob_directory(descriptor.content_id);
        prepare_private_directory(&directory)?;
        let destination = self.blob_path(descriptor.content_id);
        match fs::hard_link(temporary, &destination) {
            Ok(()) => {
                remove_if_exists(temporary)?;
                sync_directory(&directory)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_file(&destination, descriptor)?;
                remove_if_exists(temporary)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(LocalBlob {
            descriptor,
            path: destination,
        })
    }

    fn blob_directory(&self, content_id: ContentId) -> PathBuf {
        let hex = content_id.to_string();
        self.root.join("blobs/sha-256").join(&hex[8..10])
    }

    fn blob_path(&self, content_id: ContentId) -> PathBuf {
        let wire = content_id.to_string();
        self.blob_directory(content_id)
            .join(format!("{}.blob", &wire[8..]))
    }

    fn partial_path(&self, content_id: ContentId) -> PathBuf {
        let wire = content_id.to_string();
        self.root
            .join("partial")
            .join(format!("{}.part", &wire[8..]))
    }

    fn import_path(&self, content_id: ContentId, nonce: Uuid) -> PathBuf {
        let wire = content_id.to_string();
        self.root
            .join("partial")
            .join(format!("{}.{}.import", &wire[8..], nonce.simple()))
    }

    fn unidentified_import_path(&self, nonce: Uuid) -> PathBuf {
        self.root
            .join("partial")
            .join(format!("pending.{}.import", nonce.simple()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            change_seconds: metadata.ctime(),
            #[cfg(unix)]
            change_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn verify_file(path: &Path, expected: ContentDescriptor) -> Result<(), ClientContentError> {
    let metadata = regular_metadata(path)?;
    if metadata.len() != expected.byte_length {
        return Err(ClientContentError::LengthMismatch {
            expected: expected.byte_length,
            actual: metadata.len(),
        });
    }
    let mut file = open_regular_file(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    verify_expected(expected, metadata.len(), hasher.finalize().into())
}

fn verify_expected(
    expected: ContentDescriptor,
    length: u64,
    digest: [u8; 32],
) -> Result<(), ClientContentError> {
    if length != expected.byte_length {
        return Err(ClientContentError::LengthMismatch {
            expected: expected.byte_length,
            actual: length,
        });
    }
    let actual = ContentId::new(digest);
    if actual != expected.content_id {
        return Err(ClientContentError::DigestMismatch {
            expected: expected.content_id,
            actual,
        });
    }
    Ok(())
}

fn ensure_protocol_length(actual: u64) -> Result<(), ClientContentError> {
    if actual > MAX_CONTENT_BYTE_LENGTH {
        Err(ClientContentError::ContentTooLarge {
            actual,
            maximum: MAX_CONTENT_BYTE_LENGTH,
        })
    } else {
        Ok(())
    }
}

fn prepare_private_directory(path: &Path) -> Result<(), ClientContentError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_truncated(path: &Path) -> Result<File, ClientContentError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    make_private_file(path)?;
    Ok(file)
}

fn open_private_append(path: &Path) -> Result<File, ClientContentError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    make_private_file(path)?;
    Ok(file)
}

fn make_private_file(path: &Path) -> Result<(), ClientContentError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn regular_metadata(path: &Path) -> Result<fs::Metadata, ClientContentError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    Ok(metadata)
}

fn open_regular_file(path: &Path) -> Result<File, ClientContentError> {
    regular_metadata(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(ClientContentError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn regular_metadata_if_exists(path: &Path) -> Result<Option<fs::Metadata>, ClientContentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(Some(metadata))
        }
        Ok(_) => Err(ClientContentError::UnsafePath(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn remove_if_exists(path: &Path) -> Result<(), ClientContentError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> Result<(), ClientContentError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
