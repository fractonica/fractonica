#![forbid(unsafe_code)]
//! Offline operation authoring shared by native clients and import agents.
//!
//! This crate does not perform HTTP, own a database, or decide when to sync.
//! A client first commits the returned signed operation to its local store and
//! may then enqueue the exact same operation for any number of nodes.

use std::time::{SystemTime, UNIX_EPOCH};

use fractonica_data_model::{
    ActorId, DataModelError, EntityId, EntitySchema, EventDocument, MAX_AUTHORIZATION_REFERENCES,
    MAX_CAUSAL_PARENTS, OperationBody, OperationEnvelope, OperationId, OperationNonce,
    ProfileDocument, ProtectedDocument, RecordDocument, SigningKey, SpaceId, TagDocument,
    profile_entity_id,
};
use thiserror::Error;
use uuid::Uuid;

/// Immutable namespace and capability references used by one local author.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoringContext {
    pub space_id: SpaceId,
    pub authorization: Vec<OperationId>,
}

impl AuthoringContext {
    pub fn new(
        space_id: SpaceId,
        mut authorization: Vec<OperationId>,
    ) -> Result<Self, ClientError> {
        if space_id.as_bytes() == &[0; 32] {
            return Err(ClientError::InvalidSpaceId);
        }
        authorization.sort_unstable();
        authorization.dedup();
        if authorization.is_empty() {
            return Err(ClientError::MissingAuthorization);
        }
        if authorization.len() > MAX_AUTHORIZATION_REFERENCES {
            return Err(ClientError::TooManyAuthorizationReferences {
                count: authorization.len(),
                maximum: MAX_AUTHORIZATION_REFERENCES,
            });
        }
        Ok(Self {
            space_id,
            authorization,
        })
    }
}

/// The exact current heads observed locally before authoring an edit or delete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEntity {
    pub space_id: SpaceId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub heads: Vec<OperationId>,
}

impl ObservedEntity {
    pub fn new(
        space_id: SpaceId,
        entity_id: EntityId,
        schema: EntitySchema,
        mut heads: Vec<OperationId>,
    ) -> Result<Self, ClientError> {
        if space_id.as_bytes() == &[0; 32] {
            return Err(ClientError::InvalidSpaceId);
        }
        if entity_id.as_uuid().is_nil() {
            return Err(ClientError::InvalidObservedEntity("entity ID is nil"));
        }
        if !is_client_schema(schema) {
            return Err(ClientError::InvalidObservedEntity(
                "schema is not authorable client data",
            ));
        }
        heads.sort_unstable();
        heads.dedup();
        if heads.is_empty() {
            return Err(ClientError::InvalidObservedEntity(
                "an existing entity must have at least one head",
            ));
        }
        if heads.len() > MAX_CAUSAL_PARENTS {
            return Err(ClientError::TooManyCausalHeads {
                count: heads.len(),
                maximum: MAX_CAUSAL_PARENTS,
            });
        }
        Ok(Self {
            space_id,
            entity_id,
            schema,
            heads,
        })
    }
}

/// Fully explicit unsigned input handed to platform key custody.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationDraft {
    pub space_id: SpaceId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub causal_parents: Vec<OperationId>,
    pub authorization: Vec<OperationId>,
    pub occurred_at_unix_ms: i64,
    pub nonce: OperationNonce,
    pub body: OperationBody,
}

/// Key custody signs a draft without exposing private key bytes to callers.
pub trait ActorKeyCustody: Send + Sync {
    fn actor_id(&self) -> ActorId;

    fn sign_operation(&self, draft: &OperationDraft) -> Result<OperationEnvelope, KeyCustodyError>;
}

/// In-process key adapter for tests, headless agents, and reviewed native stores.
pub struct SoftwareActorKey {
    key: SigningKey,
}

impl SoftwareActorKey {
    #[must_use]
    pub const fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

impl ActorKeyCustody for SoftwareActorKey {
    fn actor_id(&self) -> ActorId {
        self.key.actor_id()
    }

    fn sign_operation(&self, draft: &OperationDraft) -> Result<OperationEnvelope, KeyCustodyError> {
        OperationEnvelope::sign(
            draft.space_id,
            draft.entity_id,
            draft.schema,
            draft.causal_parents.clone(),
            draft.authorization.clone(),
            draft.occurred_at_unix_ms,
            draft.nonce,
            draft.body.clone(),
            &self.key,
        )
        .map_err(KeyCustodyError::from)
    }
}

/// Injected time and entropy make operation creation deterministic in tests.
pub trait AuthoringRuntime: Send + Sync {
    fn now_unix_ms(&self) -> Result<i64, RuntimeError>;
    fn new_entity_id(&self) -> Result<EntityId, RuntimeError>;
    fn new_nonce(&self) -> Result<OperationNonce, RuntimeError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAuthoringRuntime;

impl AuthoringRuntime for SystemAuthoringRuntime {
    fn now_unix_ms(&self) -> Result<i64, RuntimeError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeError::ClockBeforeUnixEpoch)?
            .as_millis();
        i64::try_from(millis).map_err(|_| RuntimeError::ClockOverflow)
    }

    fn new_entity_id(&self) -> Result<EntityId, RuntimeError> {
        Ok(EntityId::new(Uuid::now_v7()))
    }

    fn new_nonce(&self) -> Result<OperationNonce, RuntimeError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|error| RuntimeError::Entropy(error.to_string()))?;
        Ok(OperationNonce::from_bytes(bytes))
    }
}

/// Stateless authoring facade. Persistence and network delivery stay outside.
pub struct OperationAuthor<K, R> {
    context: AuthoringContext,
    keys: K,
    runtime: R,
}

impl<K, R> OperationAuthor<K, R>
where
    K: ActorKeyCustody,
    R: AuthoringRuntime,
{
    #[must_use]
    pub const fn new(context: AuthoringContext, keys: K, runtime: R) -> Self {
        Self {
            context,
            keys,
            runtime,
        }
    }

    #[must_use]
    pub const fn context(&self) -> &AuthoringContext {
        &self.context
    }

    pub fn create_record(
        &self,
        payload: ProtectedDocument<RecordDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.create(EntitySchema::Record, OperationBody::PutRecord { payload })
    }

    /// Authors an imported record under its existing stable entity id.
    ///
    /// This is intentionally narrower than the normal create API. It lets a
    /// local-first client move an unpaired record into a newly paired space
    /// without breaking references to that entity. The destination must not
    /// already contain the entity; callers establish that invariant while
    /// importing.
    pub fn import_record(
        &self,
        entity_id: EntityId,
        payload: ProtectedDocument<RecordDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        if entity_id.as_uuid().is_nil() {
            return Err(ClientError::Runtime(RuntimeError::NilEntityId));
        }
        self.author(
            entity_id,
            EntitySchema::Record,
            Vec::new(),
            OperationBody::PutRecord { payload },
        )
    }

    pub fn update_record(
        &self,
        entity: &ObservedEntity,
        payload: ProtectedDocument<RecordDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.update(
            entity,
            EntitySchema::Record,
            OperationBody::PutRecord { payload },
        )
    }

    pub fn create_event(
        &self,
        payload: ProtectedDocument<EventDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.create(EntitySchema::Event, OperationBody::PutEvent { payload })
    }

    pub fn update_event(
        &self,
        entity: &ObservedEntity,
        payload: ProtectedDocument<EventDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.update(
            entity,
            EntitySchema::Event,
            OperationBody::PutEvent { payload },
        )
    }

    pub fn create_tag(
        &self,
        payload: ProtectedDocument<TagDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.create(EntitySchema::Tag, OperationBody::PutTag { payload })
    }

    pub fn update_tag(
        &self,
        entity: &ObservedEntity,
        payload: ProtectedDocument<TagDocument>,
    ) -> Result<OperationEnvelope, ClientError> {
        self.update(entity, EntitySchema::Tag, OperationBody::PutTag { payload })
    }

    pub fn put_profile(
        &self,
        observed: Option<&ObservedEntity>,
        document: ProfileDocument,
    ) -> Result<OperationEnvelope, ClientError> {
        let entity_id = profile_entity_id(self.keys.actor_id());
        let parents = match observed {
            None => Vec::new(),
            Some(entity) => {
                self.require_entity(entity, EntitySchema::Profile)?;
                if entity.entity_id != entity_id {
                    return Err(ClientError::InvalidObservedEntity(
                        "profile entity does not belong to this actor",
                    ));
                }
                entity.heads.clone()
            }
        };
        self.author(
            entity_id,
            EntitySchema::Profile,
            parents,
            OperationBody::PutProfile { document },
        )
    }

    pub fn delete(&self, entity: &ObservedEntity) -> Result<OperationEnvelope, ClientError> {
        self.require_entity(entity, entity.schema)?;
        if entity.schema == EntitySchema::Profile
            && entity.entity_id != profile_entity_id(self.keys.actor_id())
        {
            return Err(ClientError::InvalidObservedEntity(
                "profile entity does not belong to this actor",
            ));
        }
        self.author(
            entity.entity_id,
            entity.schema,
            entity.heads.clone(),
            OperationBody::Tombstone,
        )
    }

    fn create(
        &self,
        schema: EntitySchema,
        body: OperationBody,
    ) -> Result<OperationEnvelope, ClientError> {
        let entity_id = self.runtime.new_entity_id()?;
        if entity_id.as_uuid().is_nil() {
            return Err(ClientError::Runtime(RuntimeError::NilEntityId));
        }
        self.author(entity_id, schema, Vec::new(), body)
    }

    fn update(
        &self,
        entity: &ObservedEntity,
        schema: EntitySchema,
        body: OperationBody,
    ) -> Result<OperationEnvelope, ClientError> {
        self.require_entity(entity, schema)?;
        self.author(entity.entity_id, schema, entity.heads.clone(), body)
    }

    fn require_entity(
        &self,
        entity: &ObservedEntity,
        schema: EntitySchema,
    ) -> Result<(), ClientError> {
        if entity.space_id != self.context.space_id {
            return Err(ClientError::ObservedSpaceMismatch);
        }
        if entity.schema != schema {
            return Err(ClientError::ObservedSchemaMismatch {
                expected: schema,
                found: entity.schema,
            });
        }
        Ok(())
    }

    fn author(
        &self,
        entity_id: EntityId,
        schema: EntitySchema,
        causal_parents: Vec<OperationId>,
        body: OperationBody,
    ) -> Result<OperationEnvelope, ClientError> {
        let draft = OperationDraft {
            space_id: self.context.space_id,
            entity_id,
            schema,
            causal_parents,
            authorization: self.context.authorization.clone(),
            occurred_at_unix_ms: self.runtime.now_unix_ms()?,
            nonce: self.runtime.new_nonce()?,
            body,
        };
        if draft.occurred_at_unix_ms < 0 {
            return Err(ClientError::Runtime(RuntimeError::ClockBeforeUnixEpoch));
        }
        let operation = self.keys.sign_operation(&draft)?;
        operation.verify()?;
        verify_signer_projection(&operation, &draft, self.keys.actor_id())?;
        Ok(operation)
    }
}

fn verify_signer_projection(
    operation: &OperationEnvelope,
    draft: &OperationDraft,
    actor_id: ActorId,
) -> Result<(), ClientError> {
    let matches = operation.space_id == draft.space_id
        && operation.entity_id == draft.entity_id
        && operation.schema == draft.schema
        && operation.actor_id == actor_id
        && operation.causal_parents == draft.causal_parents
        && operation.authorization == draft.authorization
        && operation.occurred_at_unix_ms == draft.occurred_at_unix_ms
        && operation.nonce == draft.nonce
        && operation.body == draft.body;
    if matches {
        Ok(())
    } else {
        Err(ClientError::SignerProjectionMismatch)
    }
}

const fn is_client_schema(schema: EntitySchema) -> bool {
    matches!(
        schema,
        EntitySchema::Record | EntitySchema::Event | EntitySchema::Tag | EntitySchema::Profile
    )
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("key custody failed: {detail}")]
pub struct KeyCustodyError {
    detail: String,
}

impl KeyCustodyError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl From<DataModelError> for KeyCustodyError {
    fn from(error: DataModelError) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("system clock does not fit signed Unix milliseconds")]
    ClockOverflow,
    #[error("runtime generated a nil entity ID")]
    NilEntityId,
    #[error("operating-system entropy is unavailable: {0}")]
    Entropy(String),
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    DataModel(#[from] DataModelError),
    #[error(transparent)]
    KeyCustody(#[from] KeyCustodyError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("authoring requires at least one capability reference")]
    MissingAuthorization,
    #[error("space ID must not be all-zero")]
    InvalidSpaceId,
    #[error("authorization contains {count} references; maximum is {maximum}")]
    TooManyAuthorizationReferences { count: usize, maximum: usize },
    #[error("observed entity has {count} heads; maximum is {maximum}")]
    TooManyCausalHeads { count: usize, maximum: usize },
    #[error("invalid observed entity: {0}")]
    InvalidObservedEntity(&'static str),
    #[error("observed entity belongs to another space")]
    ObservedSpaceMismatch,
    #[error("observed entity schema is {found}, expected {expected}")]
    ObservedSchemaMismatch {
        expected: EntitySchema,
        found: EntitySchema,
    },
    #[error("key custody returned a valid operation that differs from the requested draft")]
    SignerProjectionMismatch,
}

#[cfg(test)]
mod tests;
