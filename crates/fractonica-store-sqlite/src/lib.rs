#![forbid(unsafe_code)]
//! SQLite persistence for embedded and headless Fractonica nodes.

mod pairing_repository;
mod signed_repository;

pub use pairing_repository::{PairingLifecycle, PairingSession, PairingStoreError};

use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fractonica_application::{
    ContentRepository, ContentRepositoryError, MAX_AVAILABILITY_CONTENT_IDS, NewUpload,
    RepositoryError, UploadId, UploadSession, UploadState,
};
use fractonica_content::{ContentDescriptor, ContentId};
use fractonica_core::{InstallationId, InstallationMetadata};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 8;

struct Migration {
    version: u32,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../migrations/0001_node_installation.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../migrations/0002_operation_log.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../migrations/0003_content_store.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../migrations/0004_signed_spaces.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../migrations/0005_pairing_lifecycle.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("../migrations/0006_peer_request_replay.sql"),
    },
    Migration {
        version: 7,
        sql: include_str!("../migrations/0007_client_contract.sql"),
    },
    Migration {
        version: 8,
        sql: include_str!("../migrations/0008_peer_transport_credentials.sql"),
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreReadiness {
    pub schema_version: u32,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to prepare the node data directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("node database uses schema {found}, but this binary supports up to {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("SQLite migration history has a gap after schema {current}; next migration is {next}")]
    MigrationGap { current: u32, next: u32 },

    #[error("SQLite migration declared schema {expected}, but database reports {found}")]
    MigrationVersionMismatch { expected: u32, found: u32 },

    #[error("stored installation ID is invalid: {0}")]
    InvalidInstallationId(#[from] uuid::Error),

    #[error("node database lock was poisoned")]
    LockPoisoned,

    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,
}

#[derive(Clone)]
pub struct SqliteStore {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            prepare_private_directory(parent)?;
        }
        prepare_private_file(&path)?;

        let mut connection = Connection::open(&path)?;
        configure_connection(&connection, true)?;
        migrate(&mut connection)?;
        ensure_installation(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(path),
        })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&connection, false)?;
        migrate(&mut connection)?;
        ensure_installation(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(PathBuf::from(":memory:")),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn readiness(&self) -> Result<StoreReadiness, StoreError> {
        self.with_connection(|connection| {
            connection.query_row("SELECT 1", [], |_| Ok(()))?;
            let schema_version = schema_version(connection)?;
            Ok(StoreReadiness { schema_version })
        })
    }

    pub fn installation(&self) -> Result<InstallationMetadata, StoreError> {
        self.with_connection(|connection| {
            let (installation_id, created_at_unix_ms): (String, i64) = connection.query_row(
                "SELECT installation_id, created_at_unix_ms
                 FROM node_installation
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;

            Ok(InstallationMetadata {
                installation_id: InstallationId::parse(&installation_id)?,
                created_at_unix_ms,
            })
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        operation(&connection)
    }
}

impl ContentRepository for SqliteStore {
    fn create_upload(&self, upload: &NewUpload) -> Result<UploadSession, ContentRepositoryError> {
        if upload.created_at_unix_ms < 0 || upload.expires_at_unix_ms < upload.created_at_unix_ms {
            return Err(ContentRepositoryError::Corrupt(
                "new upload contains an invalid lifetime".into(),
            ));
        }
        let upload_length = content_i64(upload.upload_length)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        connection
            .execute(
                "INSERT INTO upload_sessions (
                    upload_id, upload_length, upload_offset, state,
                    expected_content_id, final_content_id, media_type,
                    original_name, upload_metadata, created_at_unix_ms, expires_at_unix_ms
                 ) VALUES (?1, ?2, 0, 'active', ?3, NULL, ?4, ?5, ?6, ?7, ?8)",
                params![
                    upload.upload_id.to_string(),
                    upload_length,
                    upload.expected_content_id.map(|value| value.to_string()),
                    upload.media_type,
                    upload.original_name,
                    upload.upload_metadata,
                    upload.created_at_unix_ms,
                    upload.expires_at_unix_ms,
                ],
            )
            .map_err(content_sqlite)?;
        load_upload(&connection, upload.upload_id)?.ok_or_else(|| {
            ContentRepositoryError::Corrupt(format!(
                "new upload {} disappeared after insertion",
                upload.upload_id
            ))
        })
    }

    fn upload(&self, upload_id: UploadId) -> Result<Option<UploadSession>, ContentRepositoryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        load_upload(&connection, upload_id)
    }

    fn advance_upload(
        &self,
        upload_id: UploadId,
        expected_offset: u64,
        new_offset: u64,
        expires_at_unix_ms: i64,
    ) -> Result<UploadSession, ContentRepositoryError> {
        let expected_offset_sql = content_i64(expected_offset)?;
        let new_offset_sql = content_i64(new_offset)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(content_sqlite)?;
        let current = load_upload(&transaction, upload_id)?
            .ok_or(ContentRepositoryError::UploadNotFound(upload_id))?;
        if current.state != UploadState::Active {
            return Err(ContentRepositoryError::UploadNotActive(upload_id));
        }
        if current.upload_offset != expected_offset {
            return Err(ContentRepositoryError::OffsetMismatch {
                expected: current.upload_offset,
                supplied: expected_offset,
            });
        }
        if new_offset < expected_offset || new_offset > current.upload_length {
            return Err(ContentRepositoryError::Corrupt(format!(
                "invalid offset transition {expected_offset} -> {new_offset} for {upload_id}"
            )));
        }
        transaction
            .execute(
                "UPDATE upload_sessions
                 SET upload_offset = ?2, expires_at_unix_ms = ?3
                 WHERE upload_id = ?1 AND state = 'active' AND upload_offset = ?4",
                params![
                    upload_id.to_string(),
                    new_offset_sql,
                    expires_at_unix_ms,
                    expected_offset_sql,
                ],
            )
            .map_err(content_sqlite)?;
        let updated = load_upload(&transaction, upload_id)?.ok_or_else(|| {
            ContentRepositoryError::Corrupt(format!(
                "upload {upload_id} disappeared during offset update"
            ))
        })?;
        transaction.commit().map_err(content_sqlite)?;
        Ok(updated)
    }

    fn begin_upload_finalize(
        &self,
        upload_id: UploadId,
        content_id: ContentId,
    ) -> Result<UploadSession, ContentRepositoryError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(content_sqlite)?;
        let current = load_upload(&transaction, upload_id)?
            .ok_or(ContentRepositoryError::UploadNotFound(upload_id))?;
        if matches!(
            current.state,
            UploadState::Finalizing | UploadState::Complete
        ) {
            if current.final_content_id == Some(content_id) {
                transaction.commit().map_err(content_sqlite)?;
                return Ok(current);
            }
            return Err(ContentRepositoryError::ContentConflict(content_id));
        }
        if current.upload_offset != current.upload_length {
            return Err(ContentRepositoryError::Corrupt(format!(
                "upload {upload_id} cannot finalize at offset {} of {}",
                current.upload_offset, current.upload_length
            )));
        }
        if current
            .expected_content_id
            .is_some_and(|expected| expected != content_id)
        {
            return Err(ContentRepositoryError::ContentConflict(content_id));
        }
        transaction
            .execute(
                "UPDATE upload_sessions
                 SET state = 'finalizing', final_content_id = ?2
                 WHERE upload_id = ?1 AND state = 'active'",
                params![upload_id.to_string(), content_id.to_string()],
            )
            .map_err(content_sqlite)?;
        let updated = load_upload(&transaction, upload_id)?.ok_or_else(|| {
            ContentRepositoryError::Corrupt(format!(
                "upload {upload_id} disappeared while beginning finalization"
            ))
        })?;
        transaction.commit().map_err(content_sqlite)?;
        Ok(updated)
    }

    fn complete_upload(
        &self,
        upload_id: UploadId,
        stored_at_unix_ms: i64,
    ) -> Result<ContentDescriptor, ContentRepositoryError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(content_sqlite)?;
        let current = load_upload(&transaction, upload_id)?
            .ok_or(ContentRepositoryError::UploadNotFound(upload_id))?;
        if !matches!(
            current.state,
            UploadState::Finalizing | UploadState::Complete
        ) {
            return Err(ContentRepositoryError::UploadNotActive(upload_id));
        }
        let content_id = current.final_content_id.ok_or_else(|| {
            ContentRepositoryError::Corrupt(format!(
                "upload {upload_id} reached finalization without a content ID"
            ))
        })?;
        let descriptor = ContentDescriptor {
            content_id,
            byte_length: current.upload_length,
        };
        descriptor
            .validate()
            .map_err(|error| ContentRepositoryError::Corrupt(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO blobs (content_id, byte_length, stored_at_unix_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(content_id) DO NOTHING",
                params![
                    content_id.to_string(),
                    content_i64(descriptor.byte_length)?,
                    stored_at_unix_ms,
                ],
            )
            .map_err(content_sqlite)?;
        let stored_length: i64 = transaction
            .query_row(
                "SELECT byte_length FROM blobs WHERE content_id = ?1",
                params![content_id.to_string()],
                |row| row.get(0),
            )
            .map_err(content_sqlite)?;
        if content_u64(stored_length)? != descriptor.byte_length {
            return Err(ContentRepositoryError::ContentConflict(content_id));
        }
        transaction
            .execute(
                "UPDATE upload_sessions SET state = 'complete' WHERE upload_id = ?1",
                params![upload_id.to_string()],
            )
            .map_err(content_sqlite)?;
        transaction.commit().map_err(content_sqlite)?;
        Ok(descriptor)
    }

    fn content(
        &self,
        content_id: ContentId,
    ) -> Result<Option<ContentDescriptor>, ContentRepositoryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        load_content(&connection, content_id)
    }

    fn available_content(
        &self,
        content_ids: &[ContentId],
    ) -> Result<Vec<ContentDescriptor>, ContentRepositoryError> {
        if content_ids.len() > MAX_AVAILABILITY_CONTENT_IDS {
            return Err(ContentRepositoryError::Corrupt(format!(
                "availability query contains {} IDs; maximum is {MAX_AVAILABILITY_CONTENT_IDS}",
                content_ids.len()
            )));
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        let mut available = Vec::new();
        for content_id in content_ids {
            if let Some(descriptor) = load_content(&connection, *content_id)? {
                available.push(descriptor);
            }
        }
        available.sort_unstable_by_key(|descriptor| descriptor.content_id);
        available.dedup_by_key(|descriptor| descriptor.content_id);
        Ok(available)
    }

    fn uploads_requiring_finalization(
        &self,
        limit: usize,
    ) -> Result<Vec<UploadSession>, ContentRepositoryError> {
        load_uploads_by_query(
            self,
            "SELECT upload_id, upload_length, upload_offset, state,
                    expected_content_id, final_content_id, upload_metadata, media_type,
                    original_name, created_at_unix_ms, expires_at_unix_ms
             FROM upload_sessions
             WHERE state = 'finalizing'
                OR (state = 'active' AND upload_offset = upload_length)
             ORDER BY created_at_unix_ms, upload_id
             LIMIT ?1",
            params![content_i64(limit as u64)?],
        )
    }

    fn expired_uploads(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<UploadSession>, ContentRepositoryError> {
        load_uploads_by_query(
            self,
            "SELECT upload_id, upload_length, upload_offset, state,
                    expected_content_id, final_content_id, upload_metadata, media_type,
                    original_name, created_at_unix_ms, expires_at_unix_ms
             FROM upload_sessions
             WHERE state <> 'finalizing' AND expires_at_unix_ms <= ?1
             ORDER BY expires_at_unix_ms, upload_id
             LIMIT ?2",
            params![now_unix_ms, content_i64(limit as u64)?],
        )
    }

    fn delete_upload(&self, upload_id: UploadId) -> Result<(), ContentRepositoryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| content_unavailable("node database lock was poisoned"))?;
        connection
            .execute(
                "DELETE FROM upload_sessions WHERE upload_id = ?1",
                params![upload_id.to_string()],
            )
            .map_err(content_sqlite)?;
        Ok(())
    }
}

const UPLOAD_COLUMNS: &str = "upload_id, upload_length, upload_offset, state, \
    expected_content_id, final_content_id, upload_metadata, media_type, original_name, \
    created_at_unix_ms, expires_at_unix_ms";

fn load_upload(
    connection: &Connection,
    upload_id: UploadId,
) -> Result<Option<UploadSession>, ContentRepositoryError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {UPLOAD_COLUMNS} FROM upload_sessions WHERE upload_id = ?1"
        ))
        .map_err(content_sqlite)?;
    let mut rows = statement
        .query(params![upload_id.to_string()])
        .map_err(content_sqlite)?;
    let result = rows
        .next()
        .map_err(content_sqlite)?
        .map(decode_upload_row)
        .transpose()?;
    if rows.next().map_err(content_sqlite)?.is_some() {
        return Err(ContentRepositoryError::Corrupt(format!(
            "upload ID {upload_id} is not unique"
        )));
    }
    Ok(result)
}

fn load_uploads_by_query<P: rusqlite::Params>(
    store: &SqliteStore,
    sql: &str,
    query_params: P,
) -> Result<Vec<UploadSession>, ContentRepositoryError> {
    let connection = store
        .connection
        .lock()
        .map_err(|_| content_unavailable("node database lock was poisoned"))?;
    let mut statement = connection.prepare(sql).map_err(content_sqlite)?;
    let mut rows = statement.query(query_params).map_err(content_sqlite)?;
    let mut uploads = Vec::new();
    while let Some(row) = rows.next().map_err(content_sqlite)? {
        uploads.push(decode_upload_row(row)?);
    }
    Ok(uploads)
}

fn decode_upload_row(row: &Row<'_>) -> Result<UploadSession, ContentRepositoryError> {
    let upload_id_text: String = row.get(0).map_err(content_sqlite)?;
    let expected_content_id: Option<String> = row.get(4).map_err(content_sqlite)?;
    let final_content_id: Option<String> = row.get(5).map_err(content_sqlite)?;
    Ok(UploadSession {
        upload_id: UploadId::parse(&upload_id_text).map_err(|error| {
            ContentRepositoryError::Corrupt(format!(
                "invalid stored upload ID {upload_id_text}: {error}"
            ))
        })?,
        upload_length: content_u64(row.get(1).map_err(content_sqlite)?)?,
        upload_offset: content_u64(row.get(2).map_err(content_sqlite)?)?,
        state: parse_upload_state(&row.get::<_, String>(3).map_err(content_sqlite)?)?,
        expected_content_id: expected_content_id
            .map(|value| parse_content_id(&value))
            .transpose()?,
        final_content_id: final_content_id
            .map(|value| parse_content_id(&value))
            .transpose()?,
        upload_metadata: row.get(6).map_err(content_sqlite)?,
        media_type: row.get(7).map_err(content_sqlite)?,
        original_name: row.get(8).map_err(content_sqlite)?,
        created_at_unix_ms: row.get(9).map_err(content_sqlite)?,
        expires_at_unix_ms: row.get(10).map_err(content_sqlite)?,
    })
}

fn parse_upload_state(value: &str) -> Result<UploadState, ContentRepositoryError> {
    match value {
        "active" => Ok(UploadState::Active),
        "finalizing" => Ok(UploadState::Finalizing),
        "complete" => Ok(UploadState::Complete),
        _ => Err(ContentRepositoryError::Corrupt(format!(
            "unknown stored upload state {value}"
        ))),
    }
}

fn load_content(
    connection: &Connection,
    content_id: ContentId,
) -> Result<Option<ContentDescriptor>, ContentRepositoryError> {
    connection
        .query_row(
            "SELECT byte_length FROM blobs WHERE content_id = ?1",
            params![content_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(content_sqlite)?
        .map(|byte_length| {
            Ok(ContentDescriptor {
                content_id,
                byte_length: content_u64(byte_length)?,
            })
        })
        .transpose()
}

fn parse_content_id(value: &str) -> Result<ContentId, ContentRepositoryError> {
    ContentId::parse(value).map_err(|error| {
        ContentRepositoryError::Corrupt(format!("invalid stored content ID {value}: {error}"))
    })
}

fn content_i64(value: u64) -> Result<i64, ContentRepositoryError> {
    i64::try_from(value).map_err(|_| {
        ContentRepositoryError::Corrupt(format!(
            "unsigned content value {value} exceeds SQLite integer range"
        ))
    })
}

fn content_u64(value: i64) -> Result<u64, ContentRepositoryError> {
    u64::try_from(value).map_err(|_| {
        ContentRepositoryError::Corrupt(format!("negative SQLite content value {value}"))
    })
}

fn content_unavailable(detail: impl Into<String>) -> ContentRepositoryError {
    ContentRepositoryError::Unavailable(detail.into())
}

fn content_sqlite(error: rusqlite::Error) -> ContentRepositoryError {
    content_unavailable(error.to_string())
}

fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| RepositoryError::Corrupt(format!("invalid local sequence {value}")))
}

fn nonnegative_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .map_err(|_| RepositoryError::Corrupt(format!("invalid nonnegative count {value}")))
}

fn repository_unavailable(error: StoreError) -> RepositoryError {
    RepositoryError::Unavailable(error.to_string())
}

fn repository_sqlite(error: rusqlite::Error) -> RepositoryError {
    RepositoryError::Unavailable(error.to_string())
}

fn configure_connection(connection: &Connection, persistent: bool) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(Duration::from_secs(5))?;
    if persistent {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn prepare_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a private data directory", path.display()),
            ));
        }
        Ok(metadata) => validate_private_directory(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            validate_private_directory(path, &fs::symlink_metadata(path)?)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn prepare_private_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular database file", path.display()),
            ));
        }
        Ok(metadata) => validate_private_file(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?.sync_all()?;
            validate_private_file(path, &fs::symlink_metadata(path)?)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        validate_owner(path, metadata)?;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o700 {
            return Err(private_state_error(
                path,
                format!("mode is {mode:#o}, expected 0o700"),
            ));
        }
    }
    Ok(())
}

fn validate_private_file(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        validate_owner(path, metadata)?;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o600 {
            return Err(private_state_error(
                path,
                format!("mode is {mode:#o}, expected 0o600"),
            ));
        }
        if metadata.nlink() != 1 {
            return Err(private_state_error(
                path,
                format!("has {} hard links, expected exactly one", metadata.nlink()),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let expected = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected {
        return Err(private_state_error(
            path,
            format!("owner is uid {}, expected uid {expected}", metadata.uid()),
        ));
    }
    Ok(())
}

fn private_state_error(path: &Path, detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} is not private node state: {detail}", path.display()),
    )
}

fn schema_version(connection: &Connection) -> Result<u32, StoreError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StoreError::from)
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let mut current = schema_version(connection)?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }
        if migration.version != current + 1 {
            return Err(StoreError::MigrationGap {
                current,
                next: migration.version,
            });
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.sql)?;
        transaction.commit()?;
        current = schema_version(connection)?;
        if current != migration.version {
            return Err(StoreError::MigrationVersionMismatch {
                expected: migration.version,
                found: current,
            });
        }
    }

    Ok(())
}

fn ensure_installation(connection: &Connection) -> Result<(), StoreError> {
    let existing: Option<i64> = connection
        .query_row(
            "SELECT singleton FROM node_installation WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    if existing.is_none() {
        let created_at_unix_ms: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::ClockBeforeUnixEpoch)?
            .as_millis()
            .try_into()
            .map_err(|_| StoreError::ClockBeforeUnixEpoch)?;

        connection.execute(
            "INSERT INTO node_installation
                (singleton, installation_id, created_at_unix_ms)
             VALUES (1, ?1, ?2)",
            params![Uuid::now_v7().to_string(), created_at_unix_ms],
        )?;
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod private_state_tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn existing_database_permissions_are_rejected_not_repaired() {
        let root = tempdir().unwrap();
        let data = root.path().join("node");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let database = data.join("fractonica.db");
        drop(SqliteStore::open(&database).unwrap());

        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SqliteStore::open(&database),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(
            fs::metadata(&database).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn hardlinked_database_is_refused() {
        let root = tempdir().unwrap();
        let data = root.path().join("node");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let database = data.join("fractonica.db");
        drop(SqliteStore::open(&database).unwrap());
        fs::hard_link(&database, root.path().join("database-copy")).unwrap();

        assert!(matches!(
            SqliteStore::open(&database),
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}
