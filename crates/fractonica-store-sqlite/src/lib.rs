#![forbid(unsafe_code)]
//! SQLite persistence for embedded and headless Fractonica nodes.

use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fractonica_application::{
    ContentRepository, ContentRepositoryError, EntityState, MAX_AVAILABILITY_CONTENT_IDS,
    MAX_CHANGE_LIMIT, MAX_ENTITY_HEADS, MAX_IDEMPOTENCY_KEY_LENGTH, MIN_IDEMPOTENCY_KEY_LENGTH,
    NewUpload, OperationChangePage, OperationRepository, RepositoryError, RepositoryReadiness,
    StoredOperation, SubmitOperationRequest, SubmitOperationResult, UploadId, UploadSession,
    UploadState,
};
use fractonica_content::{ContentDescriptor, ContentId};
use fractonica_core::{InstallationId, InstallationMetadata};
use fractonica_data_model::{EntityId, EntitySchema, OperationBody, OperationEnvelope};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 3;

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

impl OperationRepository for SqliteStore {
    fn readiness(&self) -> Result<RepositoryReadiness, RepositoryError> {
        SqliteStore::readiness(self)
            .map(|ready| RepositoryReadiness {
                schema_version: ready.schema_version,
            })
            .map_err(repository_unavailable)
    }

    fn installation(&self) -> Result<InstallationMetadata, RepositoryError> {
        SqliteStore::installation(self).map_err(repository_unavailable)
    }

    fn submit_operation(
        &self,
        request: &SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, RepositoryError> {
        request
            .operation
            .validate()
            .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
        validate_idempotency_key(&request.idempotency.key)?;

        let encoded = serde_json::to_vec(&request.operation)
            .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
        let actor_id = request.operation.actor_id.to_string();
        let operation_id = request.operation.operation_id.to_string();
        let entity_id = request.operation.entity_id.to_string();
        let schema_id = schema_key(request.operation.schema);
        let now = unix_time_millis().map_err(repository_unavailable)?;

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RepositoryError::Unavailable("node database lock was poisoned".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(repository_sqlite)?;

        if let Some((stored_hash, stored_operation_id)) = transaction
            .query_row(
                "SELECT semantic_request_hash, operation_id
                 FROM idempotency_receipts
                 WHERE actor_id = ?1 AND idempotency_key = ?2",
                params![actor_id, request.idempotency.key],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(repository_sqlite)?
        {
            if stored_hash.as_slice() != request.idempotency.semantic_request_hash {
                return Err(RepositoryError::IdempotencyConflict);
            }
            let stored = load_operation(&transaction, &stored_operation_id)?.ok_or_else(|| {
                RepositoryError::Corrupt(format!(
                    "idempotency receipt references missing operation {stored_operation_id}"
                ))
            })?;
            transaction.commit().map_err(repository_sqlite)?;
            return Ok(SubmitOperationResult {
                operation: stored,
                replayed: true,
            });
        }

        if let Some((stored, stored_payload)) =
            load_operation_and_payload(&transaction, &operation_id)?
        {
            if stored_payload != encoded {
                return Err(RepositoryError::OperationConflict(
                    request.operation.operation_id,
                ));
            }
            insert_idempotency_receipt(&transaction, request, now)?;
            transaction.commit().map_err(repository_sqlite)?;
            return Ok(SubmitOperationResult {
                operation: stored,
                replayed: true,
            });
        }

        validate_topology(&transaction, &request.operation, &entity_id, schema_id)?;
        validate_resulting_head_count(&transaction, &request.operation, &entity_id)?;

        transaction
            .execute(
                "INSERT INTO operations (
                    operation_id, protocol_version, entity_id, schema_id, actor_id,
                    kind, occurred_at_unix_ms, received_at_unix_ms, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    operation_id,
                    request.operation.protocol_version,
                    entity_id,
                    schema_id,
                    actor_id,
                    operation_kind(&request.operation.body),
                    request.operation.occurred_at_unix_ms,
                    now,
                    encoded,
                ],
            )
            .map_err(repository_sqlite)?;
        let local_sequence = u64::try_from(transaction.last_insert_rowid()).map_err(|_| {
            RepositoryError::Corrupt("SQLite allocated a negative operation sequence".into())
        })?;

        if let OperationBody::Put { document } = &request.operation.body {
            for (position, resource) in document.resources.iter().enumerate() {
                transaction
                    .execute(
                        "INSERT INTO operation_resources (
                            operation_id, position, content_id, byte_length,
                            media_type, role, original_name
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            operation_id,
                            i64::try_from(position).map_err(|_| {
                                RepositoryError::InvalidTopology(
                                    "resource position exceeds SQLite integer range".into(),
                                )
                            })?,
                            resource.content_id.to_string(),
                            i64::try_from(resource.byte_length).map_err(|_| {
                                RepositoryError::InvalidTopology(
                                    "resource length exceeds SQLite integer range".into(),
                                )
                            })?,
                            resource.media_type,
                            resource.role,
                            resource.original_name,
                        ],
                    )
                    .map_err(repository_sqlite)?;
            }
        }

        for (position, parent) in request.operation.causal_parents.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO operation_parents (
                        entity_id, schema_id, operation_id,
                        parent_operation_id, position
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        entity_id,
                        schema_id,
                        operation_id,
                        parent.to_string(),
                        i64::try_from(position).map_err(|_| {
                            RepositoryError::InvalidTopology(
                                "causal parent position exceeds SQLite integer range".into(),
                            )
                        })?,
                    ],
                )
                .map_err(repository_sqlite)?;
            transaction
                .execute(
                    "DELETE FROM entity_heads
                     WHERE entity_id = ?1 AND operation_id = ?2",
                    params![entity_id, parent.to_string()],
                )
                .map_err(repository_sqlite)?;
        }
        transaction
            .execute(
                "INSERT INTO entity_heads (entity_id, operation_id) VALUES (?1, ?2)",
                params![entity_id, operation_id],
            )
            .map_err(repository_sqlite)?;
        insert_idempotency_receipt(&transaction, request, now)?;
        transaction.commit().map_err(repository_sqlite)?;

        Ok(SubmitOperationResult {
            operation: StoredOperation {
                local_sequence,
                operation: request.operation.clone(),
            },
            replayed: false,
        })
    }

    fn entity_state(&self, entity_id: EntityId) -> Result<Option<EntityState>, RepositoryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| RepositoryError::Unavailable("node database lock was poisoned".into()))?;
        let entity_id_text = entity_id.to_string();
        let mut summary = connection
            .prepare(
                "SELECT schema_id, count(*)
                 FROM operations
                 WHERE entity_id = ?1
                 GROUP BY schema_id
                 ORDER BY schema_id",
            )
            .map_err(repository_sqlite)?;
        let mut summaries = summary
            .query(params![entity_id_text])
            .map_err(repository_sqlite)?;
        let Some(first) = summaries.next().map_err(repository_sqlite)? else {
            return Ok(None);
        };
        let schema_id: String = first.get(0).map_err(repository_sqlite)?;
        let operation_count = positive_u64(first.get::<_, i64>(1).map_err(repository_sqlite)?)?;
        if summaries.next().map_err(repository_sqlite)?.is_some() {
            return Err(RepositoryError::Corrupt(format!(
                "entity {entity_id} has operations from more than one schema"
            )));
        }
        drop(summaries);
        drop(summary);

        let schema = parse_schema_key(&schema_id)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {OPERATION_COLUMNS}
                 FROM operations
                 JOIN entity_heads USING (operation_id)
                 WHERE entity_heads.entity_id = ?1
                 ORDER BY operations.operation_id"
            ))
            .map_err(repository_sqlite)?;
        let mut rows = statement
            .query(params![entity_id_text])
            .map_err(repository_sqlite)?;
        let mut heads = Vec::new();
        while let Some(row) = rows.next().map_err(repository_sqlite)? {
            let stored = decode_operation_row(row)?;
            if stored.operation.entity_id != entity_id || stored.operation.schema != schema {
                return Err(RepositoryError::Corrupt(format!(
                    "entity head {} does not match its projection",
                    stored.operation.operation_id
                )));
            }
            heads.push(stored);
        }
        if heads.is_empty() {
            return Err(RepositoryError::Corrupt(format!(
                "entity {entity_id} has history but no current head"
            )));
        }

        Ok(Some(EntityState {
            entity_id,
            schema,
            operation_count,
            heads,
        }))
    }

    fn changes_after(
        &self,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, RepositoryError> {
        if !(1..=MAX_CHANGE_LIMIT).contains(&limit) {
            return Err(RepositoryError::InvalidTopology(format!(
                "change limit must be between 1 and {MAX_CHANGE_LIMIT}"
            )));
        }
        let Ok(after) = i64::try_from(after_local_sequence) else {
            return Ok(OperationChangePage {
                operations: Vec::new(),
                next_after: after_local_sequence,
                has_more: false,
            });
        };
        let fetch_limit = i64::try_from(limit + 1)
            .map_err(|_| RepositoryError::InvalidTopology("change limit overflow".into()))?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| RepositoryError::Unavailable("node database lock was poisoned".into()))?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {OPERATION_COLUMNS}
                 FROM operations
                 WHERE local_sequence > ?1
                 ORDER BY local_sequence
                 LIMIT ?2"
            ))
            .map_err(repository_sqlite)?;
        let mut rows = statement
            .query(params![after, fetch_limit])
            .map_err(repository_sqlite)?;
        let mut operations = Vec::with_capacity(limit + 1);
        while let Some(row) = rows.next().map_err(repository_sqlite)? {
            operations.push(decode_operation_row(row)?);
        }
        let has_more = operations.len() > limit;
        if has_more {
            operations.pop();
        }
        let next_after = operations
            .last()
            .map_or(after_local_sequence, |stored| stored.local_sequence);

        Ok(OperationChangePage {
            operations,
            next_after,
            has_more,
        })
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

const OPERATION_COLUMNS: &str = "operations.local_sequence, operations.operation_id, \
    operations.protocol_version, operations.entity_id, operations.schema_id, \
    operations.actor_id, operations.kind, operations.occurred_at_unix_ms, \
    operations.received_at_unix_ms, operations.payload";

fn validate_topology(
    connection: &Connection,
    operation: &OperationEnvelope,
    entity_id: &str,
    schema_id: &str,
) -> Result<(), RepositoryError> {
    let existing_schema = connection
        .query_row(
            "SELECT schema_id FROM operations WHERE entity_id = ?1 LIMIT 1",
            params![entity_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(repository_sqlite)?;

    if operation.causal_parents.is_empty() {
        if existing_schema.is_some() {
            return Err(RepositoryError::EntityAlreadyExists(operation.entity_id));
        }
        if matches!(operation.body, OperationBody::Tombstone) {
            return Err(RepositoryError::InvalidTopology(
                "an entity cannot begin with a tombstone".into(),
            ));
        }
        return Ok(());
    }
    for parent in &operation.causal_parents {
        let parent_state = connection
            .query_row(
                "SELECT entity_id, schema_id
                 FROM operations
                 WHERE operation_id = ?1",
                params![parent.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(repository_sqlite)?;
        let Some((parent_entity, parent_schema)) = parent_state else {
            return Err(RepositoryError::MissingParent(*parent));
        };
        if parent_entity != entity_id || parent_schema != schema_id {
            return Err(RepositoryError::ParentMismatch { parent: *parent });
        }
    }
    if existing_schema.as_deref() != Some(schema_id) {
        return Err(RepositoryError::Corrupt(format!(
            "validated parents exist for entity {}, but its schema projection is missing",
            operation.entity_id
        )));
    }
    Ok(())
}

fn validate_resulting_head_count(
    connection: &Connection,
    operation: &OperationEnvelope,
    entity_id: &str,
) -> Result<(), RepositoryError> {
    let stored_head_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM entity_heads WHERE entity_id = ?1",
            params![entity_id],
            |row| row.get(0),
        )
        .map_err(repository_sqlite)?;
    let mut surviving_heads = usize::try_from(stored_head_count).map_err(|_| {
        RepositoryError::Corrupt(format!("invalid entity head count {stored_head_count}"))
    })?;
    for parent in &operation.causal_parents {
        let is_current: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM entity_heads
                    WHERE entity_id = ?1 AND operation_id = ?2
                 )",
                params![entity_id, parent.to_string()],
                |row| row.get(0),
            )
            .map_err(repository_sqlite)?;
        if is_current {
            surviving_heads = surviving_heads
                .checked_sub(1)
                .ok_or_else(|| RepositoryError::Corrupt("entity head count underflow".into()))?;
        }
    }
    let resulting_heads = surviving_heads
        .checked_add(1)
        .ok_or_else(|| RepositoryError::InvalidTopology("entity head count overflow".into()))?;
    if resulting_heads > MAX_ENTITY_HEADS {
        return Err(RepositoryError::InvalidTopology(format!(
            "operation would create {resulting_heads} concurrent entity heads; maximum is {MAX_ENTITY_HEADS}"
        )));
    }
    Ok(())
}

fn insert_idempotency_receipt(
    connection: &Connection,
    request: &SubmitOperationRequest,
    created_at_unix_ms: i64,
) -> Result<(), RepositoryError> {
    connection
        .execute(
            "INSERT INTO idempotency_receipts (
                actor_id, idempotency_key, semantic_request_hash,
                operation_id, created_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.operation.actor_id.to_string(),
                request.idempotency.key,
                request.idempotency.semantic_request_hash.as_slice(),
                request.operation.operation_id.to_string(),
                created_at_unix_ms,
            ],
        )
        .map_err(repository_sqlite)?;
    Ok(())
}

fn load_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<StoredOperation>, RepositoryError> {
    connection
        .query_row(
            &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE operation_id = ?1"),
            params![operation_id],
            decode_operation_row_sqlite,
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(decode_checked_row)
        .transpose()
}

fn load_operation_and_payload(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<(StoredOperation, Vec<u8>)>, RepositoryError> {
    connection
        .query_row(
            &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE operation_id = ?1"),
            params![operation_id],
            decode_operation_row_sqlite,
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(|row| {
            let payload = row.payload.clone();
            decode_checked_row(row).map(|stored| (stored, payload))
        })
        .transpose()
}

#[derive(Debug)]
struct StoredOperationRow {
    local_sequence: i64,
    operation_id: String,
    protocol_version: i64,
    entity_id: String,
    schema_id: String,
    actor_id: String,
    kind: String,
    occurred_at_unix_ms: i64,
    received_at_unix_ms: i64,
    payload: Vec<u8>,
}

fn decode_operation_row_sqlite(row: &Row<'_>) -> rusqlite::Result<StoredOperationRow> {
    Ok(StoredOperationRow {
        local_sequence: row.get(0)?,
        operation_id: row.get(1)?,
        protocol_version: row.get(2)?,
        entity_id: row.get(3)?,
        schema_id: row.get(4)?,
        actor_id: row.get(5)?,
        kind: row.get(6)?,
        occurred_at_unix_ms: row.get(7)?,
        received_at_unix_ms: row.get(8)?,
        payload: row.get(9)?,
    })
}

fn decode_operation_row(row: &Row<'_>) -> Result<StoredOperation, RepositoryError> {
    decode_operation_row_sqlite(row)
        .map_err(repository_sqlite)
        .and_then(decode_checked_row)
}

fn decode_checked_row(row: StoredOperationRow) -> Result<StoredOperation, RepositoryError> {
    let operation: OperationEnvelope = serde_json::from_slice(&row.payload)
        .map_err(|error| RepositoryError::Corrupt(error.to_string()))?;
    operation
        .validate()
        .map_err(|error| RepositoryError::Corrupt(error.to_string()))?;
    if row.received_at_unix_ms < 0
        || i64::from(operation.protocol_version) != row.protocol_version
        || operation.operation_id.to_string() != row.operation_id
        || operation.entity_id.to_string() != row.entity_id
        || schema_key(operation.schema) != row.schema_id
        || operation.actor_id.to_string() != row.actor_id
        || operation_kind(&operation.body) != row.kind
        || operation.occurred_at_unix_ms != row.occurred_at_unix_ms
    {
        return Err(RepositoryError::Corrupt(format!(
            "operation {} columns do not match its canonical payload",
            row.operation_id
        )));
    }
    Ok(StoredOperation {
        local_sequence: positive_u64(row.local_sequence)?,
        operation,
    })
}

fn schema_key(schema: EntitySchema) -> &'static str {
    match schema {
        EntitySchema::RecordV1 => "record.v1",
    }
}

fn parse_schema_key(value: &str) -> Result<EntitySchema, RepositoryError> {
    match value {
        "record.v1" => Ok(EntitySchema::RecordV1),
        _ => Err(RepositoryError::Corrupt(format!(
            "unsupported stored entity schema {value}"
        ))),
    }
}

fn operation_kind(body: &OperationBody) -> &'static str {
    match body {
        OperationBody::Put { .. } => "put",
        OperationBody::Tombstone => "tombstone",
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), RepositoryError> {
    if !(MIN_IDEMPOTENCY_KEY_LENGTH..=MAX_IDEMPOTENCY_KEY_LENGTH).contains(&value.len())
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RepositoryError::InvalidTopology(format!(
            "idempotency key must be {MIN_IDEMPOTENCY_KEY_LENGTH}-{MAX_IDEMPOTENCY_KEY_LENGTH} visible non-whitespace ASCII characters"
        )));
    }
    Ok(())
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

fn unix_time_millis() -> Result<i64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::ClockBeforeUnixEpoch)?
        .as_millis()
        .try_into()
        .map_err(|_| StoreError::ClockBeforeUnixEpoch)
}

fn repository_unavailable(error: impl std::fmt::Display) -> RepositoryError {
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
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
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
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?;
        }
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fractonica_application::{IdempotencyContext, SubmitOperationRequest};
    use fractonica_content::{ResourceRef, hash_bytes};
    use fractonica_data_model::{
        ActorId, EntityId, EntitySchema, OperationBody, OperationEnvelope, OperationId,
        PROTOCOL_VERSION, RecordDocument, RecordVisibility,
    };

    use super::*;

    #[test]
    fn creates_a_ready_database() {
        let store = SqliteStore::open_in_memory().expect("open database");

        assert_eq!(
            store.readiness().expect("database ready"),
            StoreReadiness {
                schema_version: SCHEMA_VERSION,
            }
        );
        assert!(store.installation().is_ok());
    }

    #[test]
    fn installation_identity_survives_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fractonica.db");

        let first_id = {
            let store = SqliteStore::open(&path).expect("first open");
            store.installation().expect("installation").installation_id
        };

        let reopened = SqliteStore::open(&path).expect("second open");
        let second_id = reopened
            .installation()
            .expect("installation")
            .installation_id;

        assert_eq!(first_id, second_id);
    }

    #[test]
    fn migrates_a_v1_database_without_replacing_its_installation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fractonica.db");
        let installation_id = Uuid::now_v7();
        {
            let connection = Connection::open(&path).expect("legacy database");
            connection
                .execute_batch(MIGRATIONS[0].sql)
                .expect("schema v1");
            connection
                .execute(
                    "INSERT INTO node_installation (
                        singleton, installation_id, created_at_unix_ms
                     ) VALUES (1, ?1, 1234)",
                    params![installation_id.to_string()],
                )
                .expect("legacy installation");
        }

        let store = SqliteStore::open(&path).expect("migrated store");
        assert_eq!(
            store
                .installation()
                .expect("installation after migration")
                .installation_id
                .as_uuid(),
            installation_id
        );
        assert_eq!(
            store.readiness().expect("ready").schema_version,
            SCHEMA_VERSION
        );
        store
            .with_connection(|connection| {
                let strict: i64 = connection.query_row(
                    "SELECT strict FROM pragma_table_list WHERE name = 'operations'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(strict, 1);
                Ok(())
            })
            .expect("operation table metadata");
    }

    #[test]
    fn migrates_a_v2_database_to_the_content_schema() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fractonica.db");
        {
            let connection = Connection::open(&path).expect("legacy database");
            connection
                .execute_batch(MIGRATIONS[0].sql)
                .expect("schema v1");
            connection
                .execute_batch(MIGRATIONS[1].sql)
                .expect("schema v2");
            assert_eq!(schema_version(&connection).expect("version"), 2);
        }

        let store = SqliteStore::open(&path).expect("migrated store");
        assert_eq!(store.readiness().expect("ready").schema_version, 3);
        store
            .with_connection(|connection| {
                for table in ["blobs", "upload_sessions", "operation_resources"] {
                    let strict: i64 = connection.query_row(
                        "SELECT strict FROM pragma_table_list WHERE name = ?1",
                        params![table],
                        |row| row.get(0),
                    )?;
                    assert_eq!(strict, 1, "{table} must remain a STRICT table");
                }
                Ok(())
            })
            .expect("content table metadata");
    }

    #[test]
    fn accepts_resource_references_before_the_bytes_are_available() {
        let store = SqliteStore::open_in_memory().expect("store");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let content_id = hash_bytes(b"bytes may arrive later");
        let resource = ResourceRef {
            content_id,
            byte_length: 21,
            media_type: "text/plain".to_owned(),
            role: "attachment".to_owned(),
            original_name: Some("note.txt".to_owned()),
        };
        let mut operation = put(entity, actor, Vec::new(), "record", 10);
        let OperationBody::Put { document } = &mut operation.body else {
            panic!("put helper must create a put operation");
        };
        document.resources.push(resource.clone());

        submit(&store, operation.clone(), "missing-content1", 1);
        assert_eq!(store.content(content_id).expect("lookup"), None);
        store
            .with_connection(|connection| {
                let stored: (String, i64, String, String, Option<String>) = connection.query_row(
                    "SELECT content_id, byte_length, media_type, role, original_name
                     FROM operation_resources
                     WHERE operation_id = ?1 AND position = 0",
                    params![operation.operation_id.to_string()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )?;
                assert_eq!(stored.0, resource.content_id.to_string());
                assert_eq!(stored.1, 21);
                assert_eq!(stored.2, resource.media_type);
                assert_eq!(stored.3, resource.role);
                assert_eq!(stored.4, resource.original_name);
                Ok(())
            })
            .expect("resource projection");
    }

    #[test]
    fn persists_the_resumable_upload_lifecycle_and_content_availability() {
        let store = SqliteStore::open_in_memory().expect("store");
        let upload_id = UploadId::new(Uuid::now_v7());
        let content_id = hash_bytes(b"hello");
        let created = store
            .create_upload(&NewUpload {
                upload_id,
                upload_length: 5,
                expected_content_id: Some(content_id),
                upload_metadata: Some("filename aGVsbG8udHh0".to_owned()),
                media_type: Some("text/plain".to_owned()),
                original_name: Some("hello.txt".to_owned()),
                created_at_unix_ms: 100,
                expires_at_unix_ms: 1_000,
            })
            .expect("create upload");
        assert_eq!(created.upload_offset, 0);
        assert_eq!(created.state, UploadState::Active);
        assert_eq!(
            created.upload_metadata.as_deref(),
            Some("filename aGVsbG8udHh0")
        );

        let advanced = store
            .advance_upload(upload_id, 0, 5, 2_000)
            .expect("advance upload");
        assert_eq!(advanced.upload_offset, 5);
        assert_eq!(advanced.expires_at_unix_ms, 2_000);
        let finalizing = store
            .begin_upload_finalize(upload_id, content_id)
            .expect("begin finalization");
        assert_eq!(finalizing.state, UploadState::Finalizing);
        assert_eq!(finalizing.final_content_id, Some(content_id));

        let descriptor = store.complete_upload(upload_id, 300).expect("complete");
        assert_eq!(descriptor.content_id, content_id);
        assert_eq!(descriptor.byte_length, 5);
        assert_eq!(
            store.content(content_id).expect("content"),
            Some(descriptor)
        );
        assert_eq!(
            store
                .available_content(&[hash_bytes(b"missing"), content_id, content_id])
                .expect("availability"),
            vec![descriptor]
        );
        assert_eq!(
            store
                .upload(upload_id)
                .expect("session")
                .expect("present")
                .state,
            UploadState::Complete
        );
    }

    #[test]
    fn upload_expiration_includes_the_exact_deadline() {
        let store = SqliteStore::open_in_memory().expect("store");
        let upload_id = UploadId::new(Uuid::now_v7());
        store
            .create_upload(&NewUpload {
                upload_id,
                upload_length: 1,
                expected_content_id: None,
                upload_metadata: Some("agent ZmFrZQ==".to_owned()),
                media_type: None,
                original_name: None,
                created_at_unix_ms: 100,
                expires_at_unix_ms: 1_000,
            })
            .expect("create upload");

        assert_eq!(
            store.expired_uploads(1_000, 10).expect("expired"),
            vec![store.upload(upload_id).expect("lookup").expect("session")]
        );
    }

    #[test]
    fn submits_replays_and_linearly_edits_an_entity() {
        let store = SqliteStore::open_in_memory().expect("store");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let root = put(entity, actor, Vec::new(), "root", 10);
        let root_request = request(root.clone(), "create-record-001", 1);

        let created = store.submit_operation(&root_request).expect("create");
        assert!(!created.replayed);
        assert_eq!(created.operation.local_sequence, 1);
        let replayed = store.submit_operation(&root_request).expect("replay");
        assert!(replayed.replayed);
        assert_eq!(replayed.operation, created.operation);

        let hash_conflict = SubmitOperationRequest {
            operation: root.clone(),
            idempotency: IdempotencyContext {
                key: root_request.idempotency.key.clone(),
                semantic_request_hash: [2; 32],
            },
        };
        assert!(matches!(
            store.submit_operation(&hash_conflict),
            Err(RepositoryError::IdempotencyConflict)
        ));

        let edit = put(entity, actor, vec![root.operation_id], "edited", 20);
        let edited = store
            .submit_operation(&request(edit.clone(), "edit-record-0001", 3))
            .expect("edit");
        assert_eq!(edited.operation.local_sequence, 2);

        let duplicate = store
            .submit_operation(&request(edit.clone(), "edit-record-retry", 3))
            .expect("operation replay under a new receipt");
        assert!(duplicate.replayed);
        assert_eq!(duplicate.operation, edited.operation);

        let mut conflicting_edit = edit.clone();
        conflicting_edit.occurred_at_unix_ms += 1;
        assert!(matches!(
            store.submit_operation(&request(
                conflicting_edit,
                "edit-record-conflict",
                4,
            )),
            Err(RepositoryError::OperationConflict(id)) if id == edit.operation_id
        ));

        let state = store
            .entity_state(entity)
            .expect("state")
            .expect("existing entity");
        assert_eq!(state.operation_count, 2);
        assert_eq!(state.heads, vec![edited.operation]);
        assert!(!state.is_conflicted());
    }

    #[test]
    fn stale_parents_branch_all_heads_merge_and_tombstones_retire_only_named_heads() {
        let store = SqliteStore::open_in_memory().expect("store");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let root = put(entity, actor, Vec::new(), "root", 10);
        submit(&store, root.clone(), "branch-root-001", 1);

        let mut left = put(entity, actor, vec![root.operation_id], "left", 20);
        left.operation_id =
            OperationId::parse("00000000-0000-7000-8000-000000000002").expect("fixed operation ID");
        submit(&store, left.clone(), "branch-left-001", 2);
        let mut right = put(entity, actor, vec![root.operation_id], "right", 21);
        right.operation_id =
            OperationId::parse("00000000-0000-7000-8000-000000000001").expect("fixed operation ID");
        submit(&store, right.clone(), "branch-right-001", 3);

        let branched = store.entity_state(entity).expect("state").expect("entity");
        assert!(branched.is_conflicted());
        assert_eq!(
            head_ids(&branched),
            vec![right.operation_id, left.operation_id]
        );
        assert_eq!(
            branched
                .heads
                .iter()
                .map(|stored| stored.local_sequence)
                .collect::<Vec<_>>(),
            vec![3, 2],
            "head order is canonical operation ID order, not acceptance order"
        );

        let merge = put(
            entity,
            actor,
            vec![left.operation_id, right.operation_id],
            "merged",
            30,
        );
        submit(&store, merge.clone(), "branch-merge-001", 4);
        let merged = store.entity_state(entity).expect("state").expect("entity");
        assert_eq!(head_ids(&merged), vec![merge.operation_id]);

        let live = put(entity, actor, vec![merge.operation_id], "live", 40);
        submit(&store, live.clone(), "branch-live-0001", 5);
        let alternate = put(entity, actor, vec![merge.operation_id], "alternate", 41);
        submit(&store, alternate.clone(), "branch-alternate", 6);
        let tombstone = tombstone(entity, actor, vec![live.operation_id], 50);
        submit(&store, tombstone.clone(), "branch-delete-01", 7);

        let deleted_branch = store.entity_state(entity).expect("state").expect("entity");
        let mut expected_heads = vec![alternate.operation_id, tombstone.operation_id];
        expected_heads.sort_unstable();
        assert_eq!(head_ids(&deleted_branch), expected_heads);
        assert!(
            deleted_branch
                .heads
                .iter()
                .any(|head| matches!(head.operation.body, OperationBody::Tombstone))
        );
    }

    #[test]
    fn rejects_missing_foreign_and_parentless_existing_operations() {
        let store = SqliteStore::open_in_memory().expect("store");
        let actor = ActorId::new(Uuid::now_v7());
        let first_entity = EntityId::new(Uuid::now_v7());
        let second_entity = EntityId::new(Uuid::now_v7());
        let absent_entity = EntityId::new(Uuid::now_v7());
        let first = put(first_entity, actor, Vec::new(), "first", 10);
        let second = put(second_entity, actor, Vec::new(), "second", 11);
        submit(&store, first.clone(), "parents-first-01", 1);
        submit(&store, second.clone(), "parents-second-1", 2);

        let missing = put(
            absent_entity,
            actor,
            vec![OperationId::new(Uuid::now_v7())],
            "missing",
            20,
        );
        assert!(matches!(
            store.submit_operation(&request(missing, "parents-missing1", 3)),
            Err(RepositoryError::MissingParent(_))
        ));

        let foreign = put(
            first_entity,
            actor,
            vec![second.operation_id],
            "foreign",
            21,
        );
        assert!(matches!(
            store.submit_operation(&request(foreign, "parents-foreign1", 4)),
            Err(RepositoryError::ParentMismatch { parent }) if parent == second.operation_id
        ));

        let parentless = put(first_entity, actor, Vec::new(), "again", 22);
        assert!(matches!(
            store.submit_operation(&request(parentless, "parents-empty-001", 5)),
            Err(RepositoryError::EntityAlreadyExists(entity)) if entity == first_entity
        ));
    }

    #[test]
    fn paginates_the_monotonic_operation_feed_without_skips() {
        let store = SqliteStore::open_in_memory().expect("store");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let mut parent = None;
        let mut expected = Vec::new();
        for index in 0_u8..5 {
            let operation = put(
                entity,
                actor,
                parent.into_iter().collect(),
                &format!("operation-{index}"),
                i64::from(index) + 1,
            );
            parent = Some(operation.operation_id);
            expected.push(operation.operation_id);
            submit(
                &store,
                operation,
                &format!("pagination-{index:03}"),
                index + 1,
            );
        }

        let first = store.changes_after(0, 2).expect("first page");
        assert!(first.has_more);
        assert_eq!(first.next_after, 2);
        let second = store
            .changes_after(first.next_after, 2)
            .expect("second page");
        assert!(second.has_more);
        assert_eq!(second.next_after, 4);
        let third = store
            .changes_after(second.next_after, 2)
            .expect("third page");
        assert!(!third.has_more);
        assert_eq!(third.next_after, 5);

        let actual: Vec<_> = first
            .operations
            .into_iter()
            .chain(second.operations)
            .chain(third.operations)
            .map(|stored| stored.operation.operation_id)
            .collect();
        assert_eq!(actual, expected);
        assert!(matches!(
            store.changes_after(0, MAX_CHANGE_LIMIT + 1),
            Err(RepositoryError::InvalidTopology(_))
        ));
    }

    #[test]
    fn operation_history_and_heads_survive_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fractonica.db");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let root = put(entity, actor, Vec::new(), "persistent", 10);
        {
            let store = SqliteStore::open(&path).expect("first open");
            submit(&store, root.clone(), "persistent-root", 1);
        }

        let reopened = SqliteStore::open(&path).expect("reopen");
        let state = reopened
            .entity_state(entity)
            .expect("state")
            .expect("entity");
        assert_eq!(state.operation_count, 1);
        assert_eq!(head_ids(&state), vec![root.operation_id]);
        let changes = reopened.changes_after(0, 10).expect("changes");
        assert_eq!(changes.operations, state.heads);
    }

    #[test]
    fn rejects_a_branch_that_would_exceed_the_head_bound() {
        let store = SqliteStore::open_in_memory().expect("store");
        let entity = EntityId::new(Uuid::now_v7());
        let actor = ActorId::new(Uuid::now_v7());
        let root = put(entity, actor, Vec::new(), "root", 1);
        submit(&store, root.clone(), "head-bound-root", 1);

        for index in 0..MAX_ENTITY_HEADS {
            let branch = put(
                entity,
                actor,
                vec![root.operation_id],
                &format!("branch-{index}"),
                i64::try_from(index + 2).expect("test timestamp"),
            );
            let result = store.submit_operation(&request(
                branch,
                &format!("head-bound-{index:03}"),
                u8::try_from(index % 255).expect("hash byte"),
            ));
            if index < MAX_ENTITY_HEADS {
                result.expect("branch inside bound");
            }
        }

        let overflow = put(entity, actor, vec![root.operation_id], "overflow", 1_000);
        assert!(matches!(
            store.submit_operation(&request(overflow, "head-bound-over", 250)),
            Err(RepositoryError::InvalidTopology(_))
        ));
    }

    #[test]
    fn refuses_a_database_from_a_newer_binary() {
        let mut connection = Connection::open_in_memory().expect("database");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("set schema");

        assert!(matches!(
            migrate(&mut connection),
            Err(StoreError::UnsupportedSchema { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persistent_state_is_private_and_fully_synchronous() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let data_directory = directory.path().join("node");
        let path = data_directory.join("fractonica.db");
        let store = SqliteStore::open(&path).expect("open database");

        assert_eq!(
            fs::metadata(&data_directory)
                .expect("data directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).expect("database").permissions().mode() & 0o777,
            0o600
        );
        store
            .with_connection(|connection| {
                let synchronous: u8 =
                    connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
                assert_eq!(synchronous, 2);
                Ok(())
            })
            .expect("synchronous mode");
    }

    fn put(
        entity_id: EntityId,
        actor_id: ActorId,
        causal_parents: Vec<OperationId>,
        text: &str,
        occurred_at_unix_ms: i64,
    ) -> OperationEnvelope {
        OperationEnvelope {
            protocol_version: PROTOCOL_VERSION,
            operation_id: OperationId::new(Uuid::now_v7()),
            entity_id,
            schema: EntitySchema::RecordV1,
            actor_id,
            causal_parents,
            occurred_at_unix_ms,
            body: OperationBody::Put {
                document: RecordDocument {
                    start_at_unix_ms: occurred_at_unix_ms,
                    end_at_unix_ms: None,
                    visibility: RecordVisibility::Public,
                    emoji: None,
                    text: Some(text.to_owned()),
                    metadata: BTreeMap::new(),
                    resources: Vec::new(),
                },
            },
        }
    }

    fn tombstone(
        entity_id: EntityId,
        actor_id: ActorId,
        causal_parents: Vec<OperationId>,
        occurred_at_unix_ms: i64,
    ) -> OperationEnvelope {
        OperationEnvelope {
            protocol_version: PROTOCOL_VERSION,
            operation_id: OperationId::new(Uuid::now_v7()),
            entity_id,
            schema: EntitySchema::RecordV1,
            actor_id,
            causal_parents,
            occurred_at_unix_ms,
            body: OperationBody::Tombstone,
        }
    }

    fn request(operation: OperationEnvelope, key: &str, hash_byte: u8) -> SubmitOperationRequest {
        SubmitOperationRequest {
            operation,
            idempotency: IdempotencyContext {
                key: key.to_owned(),
                semantic_request_hash: [hash_byte; 32],
            },
        }
    }

    fn submit(
        store: &SqliteStore,
        operation: OperationEnvelope,
        key: &str,
        hash_byte: u8,
    ) -> StoredOperation {
        store
            .submit_operation(&request(operation, key, hash_byte))
            .expect("submit operation")
            .operation
    }

    fn head_ids(state: &EntityState) -> Vec<OperationId> {
        state
            .heads
            .iter()
            .map(|stored| stored.operation.operation_id)
            .collect()
    }
}
