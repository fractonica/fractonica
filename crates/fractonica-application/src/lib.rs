//! Fractonica application use cases and persistence ports.
//!
//! HTTP, SQLite, clocks, and replication transports are adapters around this
//! boundary. The application service validates canonical operations before a
//! repository is allowed to make them durable.

use std::{fmt, sync::Arc};

use fractonica_content::{ContentDescriptor, ContentId};
use fractonica_core::InstallationMetadata;
use fractonica_data_model::{
    ActorId, DataModelError, EntityId, EntitySchema, OperationBody, OperationEnvelope, OperationId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const MIN_IDEMPOTENCY_KEY_LENGTH: usize = 8;
pub const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 200;
pub const DEFAULT_CHANGE_LIMIT: usize = 100;
pub const MAX_CHANGE_LIMIT: usize = 200;
/// Hard bound that keeps entity materialization and all-head merges finite.
pub const MAX_ENTITY_HEADS: usize = 64;
pub const MAX_AVAILABILITY_CONTENT_IDS: usize = 256;

/// Identifies one node-local resumable upload session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UploadId(Uuid);

impl UploadId {
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UploadState {
    Active,
    Finalizing,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewUpload {
    pub upload_id: UploadId,
    pub upload_length: u64,
    pub expected_content_id: Option<ContentId>,
    /// Exact validated tus `Upload-Metadata` value for protocol round trips.
    pub upload_metadata: Option<String>,
    pub media_type: Option<String>,
    pub original_name: Option<String>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadSession {
    pub upload_id: UploadId,
    pub upload_length: u64,
    pub upload_offset: u64,
    pub state: UploadState,
    pub expected_content_id: Option<ContentId>,
    pub final_content_id: Option<ContentId>,
    pub upload_metadata: Option<String>,
    pub media_type: Option<String>,
    pub original_name: Option<String>,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Error)]
pub enum ContentRepositoryError {
    #[error("upload {0} does not exist")]
    UploadNotFound(UploadId),

    #[error("upload {0} is no longer active")]
    UploadNotActive(UploadId),

    #[error("upload offset mismatch: node expects {expected}, request supplied {supplied}")]
    OffsetMismatch { expected: u64, supplied: u64 },

    #[error("content metadata conflicts with existing immutable content {0}")]
    ContentConflict(ContentId),

    #[error("content repository state is corrupt: {0}")]
    Corrupt(String),

    #[error("content repository is unavailable: {0}")]
    Unavailable(String),
}

/// Metadata port used by the filesystem blob adapter. Implementations keep
/// every call transactional and short; byte streaming never occurs here.
pub trait ContentRepository: Send + Sync {
    fn create_upload(&self, upload: &NewUpload) -> Result<UploadSession, ContentRepositoryError>;

    fn upload(&self, upload_id: UploadId) -> Result<Option<UploadSession>, ContentRepositoryError>;

    fn advance_upload(
        &self,
        upload_id: UploadId,
        expected_offset: u64,
        new_offset: u64,
        expires_at_unix_ms: i64,
    ) -> Result<UploadSession, ContentRepositoryError>;

    fn begin_upload_finalize(
        &self,
        upload_id: UploadId,
        content_id: ContentId,
    ) -> Result<UploadSession, ContentRepositoryError>;

    fn complete_upload(
        &self,
        upload_id: UploadId,
        stored_at_unix_ms: i64,
    ) -> Result<ContentDescriptor, ContentRepositoryError>;

    fn content(
        &self,
        content_id: ContentId,
    ) -> Result<Option<ContentDescriptor>, ContentRepositoryError>;

    fn available_content(
        &self,
        content_ids: &[ContentId],
    ) -> Result<Vec<ContentDescriptor>, ContentRepositoryError>;

    /// Returns uploads which have either entered finalization or reached their
    /// declared length but crashed before that transition became durable.
    fn uploads_requiring_finalization(
        &self,
        limit: usize,
    ) -> Result<Vec<UploadSession>, ContentRepositoryError>;

    fn expired_uploads(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<UploadSession>, ContentRepositoryError>;

    fn delete_upload(&self, upload_id: UploadId) -> Result<(), ContentRepositoryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryReadiness {
    pub schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredOperation {
    pub local_sequence: u64,
    pub operation: OperationEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyContext {
    pub key: String,
    /// Hash of the validated semantic request used only for retry equality.
    /// It is not a content ID and is not a cryptographic signing format.
    pub semantic_request_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubmitOperationRequest {
    pub operation: OperationEnvelope,
    pub idempotency: IdempotencyContext,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitOperationResult {
    pub operation: StoredOperation,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationChangePage {
    pub operations: Vec<StoredOperation>,
    pub next_after: u64,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityState {
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: u64,
    pub heads: Vec<StoredOperation>,
}

impl EntityState {
    #[must_use]
    pub fn is_conflicted(&self) -> bool {
        self.heads.len() > 1
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitOperationCommand {
    pub protocol_version: u16,
    pub operation_id: OperationId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub causal_parents: Vec<OperationId>,
    pub occurred_at_unix_ms: i64,
    pub body: OperationBody,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("causal parent {0} does not exist on this node")]
    MissingParent(OperationId),

    #[error("causal parent {parent} belongs to another entity or schema")]
    ParentMismatch { parent: OperationId },

    #[error("entity {0} already exists; a new operation must name a causal parent")]
    EntityAlreadyExists(EntityId),

    #[error("operation topology is invalid for the entity's current history: {0}")]
    InvalidTopology(String),

    #[error("operation ID {0} is already bound to different canonical content")]
    OperationConflict(OperationId),

    #[error("the idempotency key is already bound to another semantic request")]
    IdempotencyConflict,

    #[error("stored operation data is corrupt: {0}")]
    Corrupt(String),

    #[error("operation repository is unavailable: {0}")]
    Unavailable(String),
}

/// Persistence port implemented by the node's sole-writer storage adapter.
pub trait OperationRepository: Send + Sync {
    fn readiness(&self) -> Result<RepositoryReadiness, RepositoryError>;

    fn installation(&self) -> Result<InstallationMetadata, RepositoryError>;

    fn submit_operation(
        &self,
        request: &SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, RepositoryError>;

    fn entity_state(&self, entity_id: EntityId) -> Result<Option<EntityState>, RepositoryError>;

    fn changes_after(
        &self,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, RepositoryError>;
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error(transparent)]
    InvalidOperation(#[from] DataModelError),

    #[error(
        "idempotency key must be {MIN_IDEMPOTENCY_KEY_LENGTH}-{MAX_IDEMPOTENCY_KEY_LENGTH} visible ASCII characters"
    )]
    InvalidIdempotencyKey,

    #[error("change limit must be between 1 and {MAX_CHANGE_LIMIT}")]
    InvalidChangeLimit,

    #[error("failed to encode the semantic operation: {0}")]
    SemanticEncoding(#[from] serde_json::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Clone)]
pub struct ApplicationService {
    repository: Arc<dyn OperationRepository>,
    local_actor_id: ActorId,
}

impl ApplicationService {
    #[must_use]
    pub fn new<R>(repository: Arc<R>, local_actor_id: ActorId) -> Self
    where
        R: OperationRepository + 'static,
    {
        Self {
            repository,
            local_actor_id,
        }
    }

    #[must_use]
    pub const fn local_actor_id(&self) -> ActorId {
        self.local_actor_id
    }

    pub fn readiness(&self) -> Result<RepositoryReadiness, ApplicationError> {
        self.repository.readiness().map_err(Into::into)
    }

    pub fn installation(&self) -> Result<InstallationMetadata, ApplicationError> {
        self.repository.installation().map_err(Into::into)
    }

    pub fn submit_operation(
        &self,
        command: SubmitOperationCommand,
        idempotency_key: &str,
    ) -> Result<SubmitOperationResult, ApplicationError> {
        validate_idempotency_key(idempotency_key)?;
        let operation = OperationEnvelope {
            protocol_version: command.protocol_version,
            operation_id: command.operation_id,
            entity_id: command.entity_id,
            schema: command.schema,
            actor_id: self.local_actor_id,
            causal_parents: command.causal_parents,
            occurred_at_unix_ms: command.occurred_at_unix_ms,
            body: command.body,
        };
        operation.validate()?;

        let encoded = serde_json::to_vec(&operation)?;
        let semantic_request_hash: [u8; 32] = Sha256::digest(encoded).into();
        self.repository
            .submit_operation(&SubmitOperationRequest {
                operation,
                idempotency: IdempotencyContext {
                    key: idempotency_key.to_owned(),
                    semantic_request_hash,
                },
            })
            .map_err(Into::into)
    }

    pub fn entity_state(
        &self,
        entity_id: EntityId,
    ) -> Result<Option<EntityState>, ApplicationError> {
        self.repository.entity_state(entity_id).map_err(Into::into)
    }

    pub fn changes_after(
        &self,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, ApplicationError> {
        if !(1..=MAX_CHANGE_LIMIT).contains(&limit) {
            return Err(ApplicationError::InvalidChangeLimit);
        }
        self.repository
            .changes_after(after_local_sequence, limit)
            .map_err(Into::into)
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    let length = value.len();
    if !(MIN_IDEMPOTENCY_KEY_LENGTH..=MAX_IDEMPOTENCY_KEY_LENGTH).contains(&length)
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ApplicationError::InvalidIdempotencyKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_idempotency_keys_and_change_limits_before_storage() {
        assert!(matches!(
            validate_idempotency_key("short"),
            Err(ApplicationError::InvalidIdempotencyKey)
        ));
        assert!(matches!(
            validate_idempotency_key("contains space"),
            Err(ApplicationError::InvalidIdempotencyKey)
        ));
        assert!(validate_idempotency_key("record-create-001").is_ok());
    }
}
