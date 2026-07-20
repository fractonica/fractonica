//! Fractonica application use cases and persistence ports.
//!
//! HTTP, SQLite, clocks, key custody, and replication are adapters around this
//! boundary. The application accepts already signed operations;
//! it never injects a local actor or signs on a remote caller's behalf.

pub mod authorization;

use std::{fmt, sync::Arc};

use authorization::AuthorizationError;
use fractonica_content::{ContentDescriptor, ContentId};
use fractonica_core::InstallationMetadata;
use fractonica_data_model::{
    ActorId, CapabilityAction, DataModelError, EntityId, EntitySchema, OperationBody,
    OperationEnvelope, OperationId, SpaceId, Visibility,
};
use fractonica_peer::{PeerProofError, PeerReadChangesProof};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_CHANGE_LIMIT: usize = 100;
pub const MAX_CHANGE_LIMIT: usize = 200;
pub const MAX_SPACE_DISPLAY_NAME_CHARS: usize = 128;
/// Hard bound that keeps entity materialization and all-head merges finite.
pub const MAX_ENTITY_HEADS: usize = 64;
pub const MAX_AVAILABILITY_CONTENT_IDS: usize = 256;
pub const DEFAULT_CLIENT_QUERY_LIMIT: usize = 50;
pub const MAX_CLIENT_QUERY_LIMIT: usize = 200;

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

/// One admitted operation plus node-local receipt metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredOperation {
    pub local_sequence: u64,
    pub received_at_unix_ms: i64,
    pub operation: OperationEnvelope,
}

/// Request to admit an already signed operation.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitOperationRequest {
    pub operation: OperationEnvelope,
    /// Trusted receiving-node clock sampled before entering the repository.
    pub received_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitOperationResult {
    pub operation: StoredOperation,
    /// True when this exact operation digest was already admitted.
    pub replayed: bool,
}

/// Node-local information about one explicitly trusted space.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceDescriptor {
    pub space_id: SpaceId,
    pub display_name: String,
    pub genesis_operation_id: OperationId,
    pub initial_grant_operation_id: OperationId,
    pub controller_actor_id: ActorId,
    pub local_writer_actor_id: ActorId,
    pub created_at_unix_ms: i64,
}

/// Explicit in-process request for the only trusted genesis admission path.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustedSpaceBootstrapRequest {
    pub display_name: String,
    pub genesis: OperationEnvelope,
    pub initial_grant: OperationEnvelope,
    pub received_at_unix_ms: i64,
}

/// Atomic bootstrap result. An exact retry may be reported as replayed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedSpaceBootstrapResult {
    pub space: SpaceDescriptor,
    pub genesis: StoredOperation,
    pub initial_grant: StoredOperation,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationChangePage {
    pub space_id: SpaceId,
    pub operations: Vec<StoredOperation>,
    pub next_after: u64,
    pub has_more: bool,
}

#[derive(Clone, Debug)]
pub struct PeerReadChangesRequest {
    pub proof: PeerReadChangesProof,
    pub received_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityState {
    pub space_id: SpaceId,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientProjectionCursor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_number: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_text: Option<String>,
    pub entity_id: EntityId,
    pub operation_id: OperationId,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientEntitySummary {
    pub operation: StoredOperation,
    pub visibility: Visibility,
    pub conflicted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_text: Option<String>,
    pub resource_count: u64,
    pub media_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientEntityPage {
    pub space_id: SpaceId,
    pub schema: EntitySchema,
    pub items: Vec<ClientEntitySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<ClientProjectionCursor>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientStats {
    pub records: u64,
    pub events: u64,
    pub tags: u64,
    pub profiles: u64,
    pub media_files: u64,
    pub media_bytes: u64,
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("space {0} is not trusted on this node")]
    SpaceNotFound(SpaceId),

    #[error("causal parent {0} does not exist on this node")]
    MissingParent(OperationId),

    #[error("causal parent {0} belongs to another space")]
    CrossSpaceParent(OperationId),

    #[error("causal parent {parent} belongs to another entity or schema")]
    ParentMismatch { parent: OperationId },

    #[error("authorization operation {0} does not exist on this node")]
    MissingAuthorization(OperationId),

    #[error("authorization operation {0} belongs to another space")]
    CrossSpaceAuthorization(OperationId),

    #[error(transparent)]
    Authorization(#[from] AuthorizationError),

    #[error("entity {0} already exists; a new operation must name a causal parent")]
    EntityAlreadyExists(EntityId),

    #[error("operation topology is invalid for the entity's current history: {0}")]
    InvalidTopology(String),

    #[error("operation ID {0} is already bound to different canonical content")]
    OperationConflict(OperationId),

    #[error("space {0} already has a different trusted genesis or initial grant")]
    GenesisConflict(SpaceId),

    #[error("stored operation data is corrupt: {0}")]
    Corrupt(String),

    #[error("operation repository is unavailable: {0}")]
    Unavailable(String),

    #[error("peer request is not authorized")]
    PeerUnauthorized,

    #[error("peer request nonce was already consumed")]
    PeerReplay,
}

/// Persistence port implemented by the node's sole-writer storage adapter.
///
/// `bootstrap_trusted_space` and `submit_operation` are transaction boundaries.
/// A submit implementation validates topology, resolves all parent and
/// authorization references in the selected space, invokes
/// [`authorization::authorize_operation`] against that same transaction view.
/// For record revisions or tombstones it uses
/// [`authorization::authorize_operation_for_visibility`] with the
/// immutable visibility derived from admitted entity state. It then updates
/// heads and inserts atomically. The operation digest is the only protocol
/// idempotency identity.
pub trait OperationRepository: Send + Sync {
    fn readiness(&self) -> Result<RepositoryReadiness, RepositoryError>;

    fn installation(&self) -> Result<InstallationMetadata, RepositoryError>;

    fn space(&self, space_id: SpaceId) -> Result<Option<SpaceDescriptor>, RepositoryError>;

    fn spaces(&self) -> Result<Vec<SpaceDescriptor>, RepositoryError>;

    fn bootstrap_trusted_space(
        &self,
        request: &TrustedSpaceBootstrapRequest,
    ) -> Result<TrustedSpaceBootstrapResult, RepositoryError>;

    fn submit_operation(
        &self,
        space_id: SpaceId,
        request: &SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, RepositoryError>;

    fn operation(
        &self,
        space_id: SpaceId,
        operation_id: OperationId,
    ) -> Result<Option<StoredOperation>, RepositoryError>;

    fn entity_state(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
    ) -> Result<Option<EntityState>, RepositoryError>;

    fn changes_after(
        &self,
        space_id: SpaceId,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, RepositoryError>;

    fn peer_changes(
        &self,
        _request: &PeerReadChangesRequest,
    ) -> Result<OperationChangePage, RepositoryError> {
        Err(RepositoryError::Unavailable(
            "peer reads are not implemented by this repository".into(),
        ))
    }

    fn client_entities(
        &self,
        _space_id: SpaceId,
        _schema: EntitySchema,
        _cursor: Option<&ClientProjectionCursor>,
        _limit: usize,
    ) -> Result<ClientEntityPage, RepositoryError> {
        Err(RepositoryError::Unavailable(
            "client projections are not implemented by this repository".into(),
        ))
    }

    fn client_stats(&self, _space_id: SpaceId) -> Result<ClientStats, RepositoryError> {
        Err(RepositoryError::Unavailable(
            "client projections are not implemented by this repository".into(),
        ))
    }
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error(transparent)]
    InvalidOperation(#[from] DataModelError),

    #[error("operation belongs to space {operation}, but request path selected {path}")]
    SpacePathMismatch { path: SpaceId, operation: SpaceId },

    #[error("space genesis is admitted only through explicit trusted bootstrap")]
    GenericGenesisForbidden,

    #[error("trusted bootstrap is invalid: {0}")]
    InvalidTrustedBootstrap(&'static str),

    #[error("node receipt time must be nonnegative, got {0}")]
    InvalidReceivedAt(i64),

    #[error("change limit must be between 1 and {MAX_CHANGE_LIMIT}")]
    InvalidChangeLimit,

    #[error("client query limit must be between 1 and {MAX_CLIENT_QUERY_LIMIT}")]
    InvalidClientQueryLimit,

    #[error("schema {0} is not a client entity schema")]
    InvalidClientSchema(EntitySchema),

    #[error("peer proof is invalid: {0}")]
    InvalidPeerProof(#[from] PeerProofError),

    #[error("peer proof belongs to space {proof}, but request path selected {path}")]
    PeerSpacePathMismatch { path: SpaceId, proof: SpaceId },

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Clone)]
pub struct ApplicationService {
    repository: Arc<dyn OperationRepository>,
}

impl ApplicationService {
    #[must_use]
    pub fn new<R>(repository: Arc<R>) -> Self
    where
        R: OperationRepository + 'static,
    {
        Self { repository }
    }

    pub fn readiness(&self) -> Result<RepositoryReadiness, ApplicationError> {
        self.repository.readiness().map_err(Into::into)
    }

    pub fn installation(&self) -> Result<InstallationMetadata, ApplicationError> {
        self.repository.installation().map_err(Into::into)
    }

    pub fn space(&self, space_id: SpaceId) -> Result<Option<SpaceDescriptor>, ApplicationError> {
        self.repository.space(space_id).map_err(Into::into)
    }

    pub fn spaces(&self) -> Result<Vec<SpaceDescriptor>, ApplicationError> {
        self.repository.spaces().map_err(Into::into)
    }

    /// Explicit local trust-anchor creation. This must not be exposed as a
    /// generic remote operation-ingestion route.
    pub fn bootstrap_trusted_space(
        &self,
        request: TrustedSpaceBootstrapRequest,
    ) -> Result<TrustedSpaceBootstrapResult, ApplicationError> {
        validate_trusted_space_bootstrap(&request)?;
        self.repository
            .bootstrap_trusted_space(&request)
            .map_err(Into::into)
    }

    /// Admits an externally signed operation. The service never signs it.
    pub fn submit_operation(
        &self,
        path_space_id: SpaceId,
        request: SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, ApplicationError> {
        validate_received_at(request.received_at_unix_ms)?;
        request.operation.verify()?;
        if request.operation.space_id != path_space_id {
            return Err(ApplicationError::SpacePathMismatch {
                path: path_space_id,
                operation: request.operation.space_id,
            });
        }
        if request.operation.schema == EntitySchema::SpaceGenesis {
            return Err(ApplicationError::GenericGenesisForbidden);
        }
        self.repository
            .submit_operation(path_space_id, &request)
            .map_err(Into::into)
    }

    pub fn operation(
        &self,
        space_id: SpaceId,
        operation_id: OperationId,
    ) -> Result<Option<StoredOperation>, ApplicationError> {
        self.repository
            .operation(space_id, operation_id)
            .map_err(Into::into)
    }

    pub fn entity_state(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
    ) -> Result<Option<EntityState>, ApplicationError> {
        self.repository
            .entity_state(space_id, entity_id)
            .map_err(Into::into)
    }

    pub fn changes_after(
        &self,
        space_id: SpaceId,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, ApplicationError> {
        if !(1..=MAX_CHANGE_LIMIT).contains(&limit) {
            return Err(ApplicationError::InvalidChangeLimit);
        }
        self.repository
            .changes_after(space_id, after_local_sequence, limit)
            .map_err(Into::into)
    }

    pub fn peer_changes(
        &self,
        path_space_id: SpaceId,
        request: PeerReadChangesRequest,
    ) -> Result<OperationChangePage, ApplicationError> {
        validate_received_at(request.received_at_unix_ms)?;
        request.proof.verify(request.received_at_unix_ms)?;
        if request.proof.space_id != path_space_id {
            return Err(ApplicationError::PeerSpacePathMismatch {
                path: path_space_id,
                proof: request.proof.space_id,
            });
        }
        self.repository.peer_changes(&request).map_err(Into::into)
    }

    pub fn client_entities(
        &self,
        space_id: SpaceId,
        schema: EntitySchema,
        cursor: Option<&ClientProjectionCursor>,
        limit: usize,
    ) -> Result<ClientEntityPage, ApplicationError> {
        if !(1..=MAX_CLIENT_QUERY_LIMIT).contains(&limit) {
            return Err(ApplicationError::InvalidClientQueryLimit);
        }
        if !matches!(
            schema,
            EntitySchema::Record | EntitySchema::Event | EntitySchema::Tag | EntitySchema::Profile
        ) {
            return Err(ApplicationError::InvalidClientSchema(schema));
        }
        self.repository
            .client_entities(space_id, schema, cursor, limit)
            .map_err(Into::into)
    }

    pub fn client_stats(&self, space_id: SpaceId) -> Result<ClientStats, ApplicationError> {
        self.repository.client_stats(space_id).map_err(Into::into)
    }
}

fn validate_received_at(received_at_unix_ms: i64) -> Result<(), ApplicationError> {
    if received_at_unix_ms < 0 {
        Err(ApplicationError::InvalidReceivedAt(received_at_unix_ms))
    } else {
        Ok(())
    }
}

/// Validates the complete trusted personal-space bootstrap contract without
/// admitting it to a repository.
///
/// Local clients use the same pure boundary before atomically establishing
/// their offline store. Keeping this validation here prevents node and client
/// bootstrap rules from drifting apart.
pub fn validate_trusted_space_bootstrap(
    request: &TrustedSpaceBootstrapRequest,
) -> Result<(), ApplicationError> {
    validate_received_at(request.received_at_unix_ms)?;
    request.genesis.verify()?;
    request.initial_grant.verify()?;
    let display_name_length = request.display_name.chars().count();
    if display_name_length == 0
        || display_name_length > MAX_SPACE_DISPLAY_NAME_CHARS
        || request.display_name.chars().any(char::is_control)
    {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "display name must be a bounded non-control label",
        ));
    }
    if request.genesis.schema != EntitySchema::SpaceGenesis {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis operation has the wrong schema",
        ));
    }
    if request.initial_grant.schema != EntitySchema::CapabilityGrant {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant operation has the wrong schema",
        ));
    }
    if request.genesis.space_id != request.initial_grant.space_id {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis and initial grant belong to different spaces",
        ));
    }
    let OperationBody::SpaceGenesis { controller } = &request.genesis.body else {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis body has the wrong kind",
        ));
    };
    let OperationBody::CapabilityGrant { grant } = &request.initial_grant.body else {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant body has the wrong kind",
        ));
    };
    if request.genesis.actor_id != *controller {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis must be signed by the controller named in its body",
        ));
    }
    if !request.genesis.causal_parents.is_empty() || !request.genesis.authorization.is_empty() {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis cannot have causal parents or authorization references",
        ));
    }
    if request.initial_grant.actor_id != *controller {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant must be signed by the genesis controller",
        ));
    }
    if grant.subject == *controller {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant must target a distinct local writer actor",
        ));
    }
    if grant.actions.as_slice()
        != [
            CapabilityAction::AppendOperation,
            CapabilityAction::ReadSpace,
        ]
        || grant.schemas.as_slice()
            != [
                EntitySchema::Event,
                EntitySchema::Profile,
                EntitySchema::Record,
                EntitySchema::Tag,
            ]
        || grant.visibilities.as_slice() != [Visibility::Public, Visibility::Private]
        || !grant.content_roles.is_empty()
        || grant.max_resource_byte_length.is_some()
        || grant.not_before_unix_ms.is_some()
        || grant.expires_at_unix_ms.is_some()
        || grant.delegation_depth != 0
    {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial writer grant must have the exact bounded local-writer scope",
        ));
    }
    if request.initial_grant.authorization.as_slice() != [request.genesis.operation_id] {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant must rely only on the genesis operation",
        ));
    }
    if !request.initial_grant.causal_parents.is_empty() {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "initial grant must start its entity history",
        ));
    }
    if request.genesis.entity_id == request.initial_grant.entity_id {
        return Err(ApplicationError::InvalidTrustedBootstrap(
            "genesis and initial grant must use distinct entity IDs",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
