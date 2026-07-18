#![forbid(unsafe_code)]
//! Canonical, storage-independent operations for Fractonica entities.
//!
//! An entity is represented by an ordered causal DAG of immutable operations.
//! The reducer in this crate is deterministic: it does not read a clock, use
//! random values, access storage, or depend on iteration order from hash maps.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fractonica_content::{ContentId, ContentValidationError, ResourceRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

/// Version of the canonical operation envelope implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum number of direct causal parents carried by one operation.
pub const MAX_CAUSAL_PARENTS: usize = 64;
/// Maximum number of Unicode scalar values in the optional emoji label.
pub const MAX_EMOJI_CHARS: usize = 32;
/// Maximum number of Unicode scalar values in record text.
pub const MAX_TEXT_CHARS: usize = 262_144;
/// Maximum number of top-level metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 128;
/// Maximum number of Unicode scalar values in a metadata key.
pub const MAX_METADATA_KEY_CHARS: usize = 128;
/// Maximum encoded JSON size of a record's metadata object.
pub const MAX_METADATA_JSON_BYTES: usize = 65_536;
/// Maximum nested JSON container depth below the metadata object.
pub const MAX_METADATA_DEPTH: usize = 16;
/// Maximum number of entries in any nested JSON object or array.
pub const MAX_METADATA_CONTAINER_ITEMS: usize = 256;
/// Maximum number of Unicode scalar values in a metadata string value.
pub const MAX_METADATA_STRING_CHARS: usize = 16_384;
/// Maximum number of immutable content resources referenced by one record.
pub const MAX_RECORD_RESOURCES: usize = 64;

macro_rules! uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(OperationId, "Identifies one immutable operation.");
uuid_id!(
    EntityId,
    "Identifies one logical entity across its operation history."
);
uuid_id!(ActorId, "Identifies the actor that authored an operation.");

/// Versioned schema interpreted by an operation body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EntitySchema {
    #[serde(rename = "record.v1")]
    RecordV1,
}

/// Visibility policy requested by a record document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordVisibility {
    Public,
    Private,
}

/// Materialized contents written by a `put` operation for `record.v1`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordDocument {
    pub start_at_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at_unix_ms: Option<i64>,
    pub visibility: RecordVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceRef>,
}

impl RecordDocument {
    /// Validates all record and metadata resource bounds without external I/O.
    pub fn validate(&self) -> Result<(), DataModelError> {
        if self.start_at_unix_ms < 0 {
            return Err(DataModelError::NegativeRecordStart(self.start_at_unix_ms));
        }
        if let Some(end) = self.end_at_unix_ms
            && end < self.start_at_unix_ms
        {
            return Err(DataModelError::RecordEndBeforeStart {
                start: self.start_at_unix_ms,
                end,
            });
        }

        if let Some(emoji) = &self.emoji {
            let length = emoji.chars().count();
            if length == 0 || length > MAX_EMOJI_CHARS || emoji.chars().any(char::is_control) {
                return Err(DataModelError::InvalidEmoji {
                    length,
                    maximum: MAX_EMOJI_CHARS,
                });
            }
        }

        if let Some(text) = &self.text {
            let length = text.chars().count();
            if length > MAX_TEXT_CHARS {
                return Err(DataModelError::TextTooLong {
                    length,
                    maximum: MAX_TEXT_CHARS,
                });
            }
        }

        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(DataModelError::TooManyMetadataEntries {
                count: self.metadata.len(),
                maximum: MAX_METADATA_ENTRIES,
            });
        }
        for (key, value) in &self.metadata {
            let length = key.chars().count();
            if length == 0 || length > MAX_METADATA_KEY_CHARS || key.chars().any(char::is_control) {
                return Err(DataModelError::InvalidMetadataKey {
                    key: key.clone(),
                    maximum: MAX_METADATA_KEY_CHARS,
                });
            }
            validate_metadata_value(value, 1)?;
        }

        let encoded_size = serde_json::to_vec(&self.metadata)
            .map_err(|error| DataModelError::MetadataSerialization(error.to_string()))?
            .len();
        if encoded_size > MAX_METADATA_JSON_BYTES {
            return Err(DataModelError::MetadataTooLarge {
                bytes: encoded_size,
                maximum: MAX_METADATA_JSON_BYTES,
            });
        }

        if self.resources.len() > MAX_RECORD_RESOURCES {
            return Err(DataModelError::TooManyResources {
                count: self.resources.len(),
                maximum: MAX_RECORD_RESOURCES,
            });
        }
        let mut content_ids = BTreeSet::new();
        for (index, resource) in self.resources.iter().enumerate() {
            resource
                .validate()
                .map_err(|source| DataModelError::InvalidResource { index, source })?;
            if !content_ids.insert(resource.content_id) {
                return Err(DataModelError::DuplicateResourceContentId(
                    resource.content_id,
                ));
            }
        }

        Ok(())
    }
}

fn validate_metadata_value(value: &Value, depth: usize) -> Result<(), DataModelError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) => {
            let length = value.chars().count();
            if length > MAX_METADATA_STRING_CHARS {
                Err(DataModelError::MetadataStringTooLong {
                    length,
                    maximum: MAX_METADATA_STRING_CHARS,
                })
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            validate_metadata_container(depth, values.len())?;
            for value in values {
                validate_metadata_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            validate_metadata_container(depth, values.len())?;
            for (key, value) in values {
                let length = key.chars().count();
                if length == 0
                    || length > MAX_METADATA_KEY_CHARS
                    || key.chars().any(char::is_control)
                {
                    return Err(DataModelError::InvalidMetadataKey {
                        key: key.clone(),
                        maximum: MAX_METADATA_KEY_CHARS,
                    });
                }
                validate_metadata_value(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn validate_metadata_container(depth: usize, count: usize) -> Result<(), DataModelError> {
    if depth > MAX_METADATA_DEPTH {
        return Err(DataModelError::MetadataTooDeep {
            depth,
            maximum: MAX_METADATA_DEPTH,
        });
    }
    if count > MAX_METADATA_CONTAINER_ITEMS {
        return Err(DataModelError::MetadataContainerTooLarge {
            count,
            maximum: MAX_METADATA_CONTAINER_ITEMS,
        });
    }
    Ok(())
}

/// Mutation carried by an operation for the selected entity schema.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationBody {
    Put { document: RecordDocument },
    Tombstone,
}

impl OperationBody {
    fn validate(&self) -> Result<(), DataModelError> {
        match self {
            Self::Put { document } => document.validate(),
            Self::Tombstone => Ok(()),
        }
    }
}

/// Canonical immutable operation exchanged between Fractonica nodes.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationEnvelope {
    pub protocol_version: u16,
    pub operation_id: OperationId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub actor_id: ActorId,
    pub causal_parents: Vec<OperationId>,
    pub occurred_at_unix_ms: i64,
    pub body: OperationBody,
}

impl OperationEnvelope {
    /// Validates the operation's intrinsic fields and payload bounds.
    ///
    /// Causal parent existence is validated by [`EntityReducer::apply`],
    /// because it depends on the already accepted history.
    pub fn validate(&self) -> Result<(), DataModelError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(DataModelError::UnsupportedProtocolVersion {
                found: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        if self.operation_id.as_uuid().is_nil() {
            return Err(DataModelError::NilOperationId);
        }
        if self.entity_id.as_uuid().is_nil() {
            return Err(DataModelError::NilEntityId);
        }
        if self.actor_id.as_uuid().is_nil() {
            return Err(DataModelError::NilActorId);
        }
        if self.occurred_at_unix_ms < 0 {
            return Err(DataModelError::NegativeOccurredAt(self.occurred_at_unix_ms));
        }
        if self.causal_parents.len() > MAX_CAUSAL_PARENTS {
            return Err(DataModelError::TooManyCausalParents {
                count: self.causal_parents.len(),
                maximum: MAX_CAUSAL_PARENTS,
            });
        }

        let mut unique = BTreeSet::new();
        for parent in &self.causal_parents {
            if *parent == self.operation_id {
                return Err(DataModelError::SelfCausalParent(self.operation_id));
            }
            if !unique.insert(*parent) {
                return Err(DataModelError::DuplicateCausalParent(*parent));
            }
        }

        self.body.validate()
    }
}

/// One surviving causal head after reduction.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntityHead {
    pub operation_id: OperationId,
    pub actor_id: ActorId,
    pub occurred_at_unix_ms: i64,
    pub body: OperationBody,
}

impl EntityHead {
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self.body, OperationBody::Tombstone)
    }
}

/// Deterministic materialized view of one entity's current causal heads.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReducedEntity {
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: usize,
    pub heads: Vec<EntityHead>,
}

/// Incremental deterministic reducer for one entity and schema.
#[derive(Clone, Debug)]
pub struct EntityReducer {
    entity_id: EntityId,
    schema: EntitySchema,
    operations: BTreeMap<OperationId, OperationEnvelope>,
    heads: BTreeSet<OperationId>,
}

impl EntityReducer {
    #[must_use]
    pub const fn new(entity_id: EntityId, schema: EntitySchema) -> Self {
        Self {
            entity_id,
            schema,
            operations: BTreeMap::new(),
            heads: BTreeSet::new(),
        }
    }

    /// Applies one operation after all of its causal parents have been applied.
    pub fn apply(&mut self, operation: OperationEnvelope) -> Result<(), DataModelError> {
        operation.validate()?;
        if operation.entity_id != self.entity_id {
            return Err(DataModelError::ForeignEntity {
                expected: self.entity_id,
                found: operation.entity_id,
            });
        }
        if operation.schema != self.schema {
            return Err(DataModelError::ForeignSchema {
                expected: self.schema,
                found: operation.schema,
            });
        }
        if self.operations.contains_key(&operation.operation_id) {
            return Err(DataModelError::DuplicateOperationId(operation.operation_id));
        }

        for parent_id in &operation.causal_parents {
            let Some(parent) = self.operations.get(parent_id) else {
                return Err(DataModelError::CausalParentNotPreexisting {
                    operation_id: operation.operation_id,
                    parent_id: *parent_id,
                });
            };
            if parent.entity_id != operation.entity_id {
                return Err(DataModelError::ForeignCausalParent {
                    parent_id: *parent_id,
                    expected: operation.entity_id,
                    found: parent.entity_id,
                });
            }
        }

        for parent_id in &operation.causal_parents {
            self.heads.remove(parent_id);
        }
        self.heads.insert(operation.operation_id);
        self.operations.insert(operation.operation_id, operation);
        Ok(())
    }

    #[must_use]
    pub fn finish(self) -> ReducedEntity {
        let heads = self
            .heads
            .iter()
            .map(|operation_id| {
                let operation = self
                    .operations
                    .get(operation_id)
                    .expect("head IDs are inserted with their operations");
                EntityHead {
                    operation_id: operation.operation_id,
                    actor_id: operation.actor_id,
                    occurred_at_unix_ms: operation.occurred_at_unix_ms,
                    body: operation.body.clone(),
                }
            })
            .collect();

        ReducedEntity {
            entity_id: self.entity_id,
            schema: self.schema,
            operation_count: self.operations.len(),
            heads,
        }
    }
}

/// Reduces an ordered stream whose parents always precede their children.
pub fn reduce_entity(
    entity_id: EntityId,
    schema: EntitySchema,
    operations: impl IntoIterator<Item = OperationEnvelope>,
) -> Result<ReducedEntity, DataModelError> {
    let mut reducer = EntityReducer::new(entity_id, schema);
    for operation in operations {
        reducer.apply(operation)?;
    }
    Ok(reducer.finish())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DataModelError {
    #[error("unsupported operation protocol version {found}; this build supports {supported}")]
    UnsupportedProtocolVersion { found: u16, supported: u16 },
    #[error("operation ID must not be the nil UUID")]
    NilOperationId,
    #[error("entity ID must not be the nil UUID")]
    NilEntityId,
    #[error("actor ID must not be the nil UUID")]
    NilActorId,
    #[error("operation occurrence time must be nonnegative, got {0}")]
    NegativeOccurredAt(i64),
    #[error("record start time must be nonnegative, got {0}")]
    NegativeRecordStart(i64),
    #[error("record end time {end} precedes start time {start}")]
    RecordEndBeforeStart { start: i64, end: i64 },
    #[error("emoji must contain 1..={maximum} non-control characters, got {length}")]
    InvalidEmoji { length: usize, maximum: usize },
    #[error("record text contains {length} characters; maximum is {maximum}")]
    TextTooLong { length: usize, maximum: usize },
    #[error("operation has {count} causal parents; maximum is {maximum}")]
    TooManyCausalParents { count: usize, maximum: usize },
    #[error("operation cannot name itself as causal parent: {0}")]
    SelfCausalParent(OperationId),
    #[error("causal parent appears more than once: {0}")]
    DuplicateCausalParent(OperationId),
    #[error("metadata has {count} top-level entries; maximum is {maximum}")]
    TooManyMetadataEntries { count: usize, maximum: usize },
    #[error("metadata key {key:?} must contain 1..={maximum} non-control characters")]
    InvalidMetadataKey { key: String, maximum: usize },
    #[error("metadata string contains {length} characters; maximum is {maximum}")]
    MetadataStringTooLong { length: usize, maximum: usize },
    #[error("metadata nesting depth {depth} exceeds maximum {maximum}")]
    MetadataTooDeep { depth: usize, maximum: usize },
    #[error("metadata container has {count} entries; maximum is {maximum}")]
    MetadataContainerTooLarge { count: usize, maximum: usize },
    #[error("metadata encodes to {bytes} bytes; maximum is {maximum}")]
    MetadataTooLarge { bytes: usize, maximum: usize },
    #[error("metadata could not be serialized: {0}")]
    MetadataSerialization(String),
    #[error("record has {count} resources; maximum is {maximum}")]
    TooManyResources { count: usize, maximum: usize },
    #[error("record resource at index {index} is invalid: {source}")]
    InvalidResource {
        index: usize,
        source: ContentValidationError,
    },
    #[error("record references content ID more than once: {0}")]
    DuplicateResourceContentId(ContentId),
    #[error("operation ID was already applied: {0}")]
    DuplicateOperationId(OperationId),
    #[error("operation belongs to entity {found}, expected {expected}")]
    ForeignEntity { expected: EntityId, found: EntityId },
    #[error("operation uses schema {found:?}, expected {expected:?}")]
    ForeignSchema {
        expected: EntitySchema,
        found: EntitySchema,
    },
    #[error(
        "operation {operation_id} references parent {parent_id}, which is missing, foreign, or not yet applied"
    )]
    CausalParentNotPreexisting {
        operation_id: OperationId,
        parent_id: OperationId,
    },
    #[error("causal parent {parent_id} belongs to entity {found}, expected {expected}")]
    ForeignCausalParent {
        parent_id: OperationId,
        expected: EntityId,
        found: EntityId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn operation_id(value: u128) -> OperationId {
        OperationId::new(uuid(value))
    }

    fn entity_id(value: u128) -> EntityId {
        EntityId::new(uuid(value))
    }

    fn actor_id(value: u128) -> ActorId {
        ActorId::new(uuid(value))
    }

    fn document(text: &str) -> RecordDocument {
        RecordDocument {
            start_at_unix_ms: 1_000,
            end_at_unix_ms: None,
            visibility: RecordVisibility::Public,
            emoji: Some("🌒".into()),
            text: Some(text.into()),
            metadata: BTreeMap::from([("source".into(), json!("test"))]),
            resources: Vec::new(),
        }
    }

    fn put(id: u128, entity: EntityId, parents: &[u128], text: &str) -> OperationEnvelope {
        OperationEnvelope {
            protocol_version: PROTOCOL_VERSION,
            operation_id: operation_id(id),
            entity_id: entity,
            schema: EntitySchema::RecordV1,
            actor_id: actor_id(100),
            causal_parents: parents.iter().copied().map(operation_id).collect(),
            occurred_at_unix_ms: 2_000 + i64::try_from(id).expect("test ID fits"),
            body: OperationBody::Put {
                document: document(text),
            },
        }
    }

    fn tombstone(id: u128, entity: EntityId, parents: &[u128]) -> OperationEnvelope {
        OperationEnvelope {
            body: OperationBody::Tombstone,
            ..put(id, entity, parents, "ignored")
        }
    }

    #[test]
    fn serde_uses_camel_case_and_tagged_record_body() {
        let entity = entity_id(1);
        let operation = put(2, entity, &[], "created");
        let value = serde_json::to_value(&operation).expect("serialize operation");

        assert_eq!(value["protocolVersion"], 1);
        assert_eq!(value["schema"], "record.v1");
        assert_eq!(value["body"]["kind"], "put");
        assert_eq!(value["body"]["document"]["visibility"], "public");
        assert!(value["body"]["document"].get("resources").is_none());
        assert!(value.get("protocol_version").is_none());
        assert_eq!(
            serde_json::from_value::<OperationEnvelope>(value).expect("deserialize"),
            operation
        );
    }

    #[test]
    fn create_produces_one_head() {
        let entity = entity_id(1);
        let reduced = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [put(10, entity, &[], "created")],
        )
        .expect("reduce create");

        assert_eq!(reduced.operation_count, 1);
        assert_eq!(reduced.heads.len(), 1);
        assert_eq!(reduced.heads[0].operation_id, operation_id(10));
    }

    #[test]
    fn linear_edit_replaces_the_referenced_head() {
        let entity = entity_id(1);
        let reduced = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [
                put(10, entity, &[], "created"),
                put(11, entity, &[10], "edited"),
            ],
        )
        .expect("reduce edit");

        assert_eq!(reduced.heads.len(), 1);
        assert_eq!(reduced.heads[0].operation_id, operation_id(11));
        assert!(matches!(
            &reduced.heads[0].body,
            OperationBody::Put { document } if document.text.as_deref() == Some("edited")
        ));
    }

    #[test]
    fn concurrent_edits_are_retained_as_stably_ordered_heads() {
        let entity = entity_id(1);
        let reduced = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [
                put(10, entity, &[], "created"),
                put(12, entity, &[10], "branch b"),
                put(11, entity, &[10], "branch a"),
            ],
        )
        .expect("reduce branches");

        assert_eq!(
            reduced
                .heads
                .iter()
                .map(|head| head.operation_id)
                .collect::<Vec<_>>(),
            vec![operation_id(11), operation_id(12)]
        );
    }

    #[test]
    fn merge_referencing_all_heads_collapses_the_conflict() {
        let entity = entity_id(1);
        let reduced = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [
                put(10, entity, &[], "created"),
                put(11, entity, &[10], "branch a"),
                put(12, entity, &[10], "branch b"),
                put(13, entity, &[11, 12], "merged"),
            ],
        )
        .expect("reduce merge");

        assert_eq!(reduced.heads.len(), 1);
        assert_eq!(reduced.heads[0].operation_id, operation_id(13));
    }

    #[test]
    fn tombstone_is_retained_as_a_head() {
        let entity = entity_id(1);
        let reduced = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [
                put(10, entity, &[], "created"),
                tombstone(11, entity, &[10]),
            ],
        )
        .expect("reduce tombstone");

        assert_eq!(reduced.heads.len(), 1);
        assert!(reduced.heads[0].is_tombstone());
    }

    #[test]
    fn rejects_missing_parent_and_therefore_forward_cycles() {
        let entity = entity_id(1);
        let error = reduce_entity(
            entity,
            EntitySchema::RecordV1,
            [put(10, entity, &[11], "cycle first half")],
        )
        .expect_err("parent must preexist");

        assert_eq!(
            error,
            DataModelError::CausalParentNotPreexisting {
                operation_id: operation_id(10),
                parent_id: operation_id(11),
            }
        );
    }

    #[test]
    fn rejects_foreign_entity_duplicate_parent_and_self_parent() {
        let entity = entity_id(1);
        let foreign = entity_id(2);
        let mut reducer = EntityReducer::new(entity, EntitySchema::RecordV1);

        assert!(matches!(
            reducer.apply(put(10, foreign, &[], "foreign")),
            Err(DataModelError::ForeignEntity { .. })
        ));
        assert!(matches!(
            reducer.apply(put(10, entity, &[9, 9], "duplicate parent")),
            Err(DataModelError::DuplicateCausalParent(id)) if id == operation_id(9)
        ));
        assert!(matches!(
            reducer.apply(put(10, entity, &[10], "self parent")),
            Err(DataModelError::SelfCausalParent(id)) if id == operation_id(10)
        ));
    }

    #[test]
    fn validates_record_and_metadata_bounds() {
        let mut invalid_time = document("text");
        invalid_time.end_at_unix_ms = Some(999);
        assert!(matches!(
            invalid_time.validate(),
            Err(DataModelError::RecordEndBeforeStart { .. })
        ));

        let mut deep = Value::Null;
        for _ in 0..=MAX_METADATA_DEPTH {
            deep = json!([deep]);
        }
        let mut invalid_metadata = document("text");
        invalid_metadata.metadata.insert("deep".into(), deep);
        assert!(matches!(
            invalid_metadata.validate(),
            Err(DataModelError::MetadataTooDeep { .. })
        ));
    }

    #[test]
    fn validates_and_serializes_content_resources() {
        let entity = entity_id(1);
        let content_id = fractonica_content::hash_bytes(b"image");
        let resource = ResourceRef {
            content_id,
            byte_length: 5,
            media_type: "image/jpeg".into(),
            role: "photo".into(),
            original_name: Some("eclipse.jpeg".into()),
        };
        let mut operation = put(10, entity, &[], "with image");
        match &mut operation.body {
            OperationBody::Put { document } => document.resources.push(resource.clone()),
            OperationBody::Tombstone => panic!("put fixture"),
        }
        operation.validate().expect("valid resource reference");

        let value = serde_json::to_value(&operation).expect("serialize operation");
        assert_eq!(
            value["body"]["document"]["resources"][0]["contentId"],
            content_id.to_string()
        );
        assert_eq!(
            serde_json::from_value::<OperationEnvelope>(value).expect("deserialize operation"),
            operation
        );

        match &mut operation.body {
            OperationBody::Put { document } => document.resources.push(resource),
            OperationBody::Tombstone => panic!("put fixture"),
        }
        assert_eq!(
            operation.validate(),
            Err(DataModelError::DuplicateResourceContentId(content_id))
        );
    }

    #[test]
    fn rejects_too_many_and_invalid_resources_without_checking_availability() {
        let content_id = fractonica_content::hash_bytes(b"not locally available");
        let valid_missing_resource = ResourceRef {
            content_id,
            byte_length: 21,
            media_type: "application/octet-stream".into(),
            role: "attachment".into(),
            original_name: None,
        };
        let mut value = document("text");
        value.resources.push(valid_missing_resource.clone());
        assert!(value.validate().is_ok());

        value.resources = vec![valid_missing_resource; MAX_RECORD_RESOURCES + 1];
        assert!(matches!(
            value.validate(),
            Err(DataModelError::TooManyResources { .. })
        ));

        value.resources = vec![ResourceRef {
            content_id,
            byte_length: 21,
            media_type: "not a media type".into(),
            role: "attachment".into(),
            original_name: None,
        }];
        assert!(matches!(
            value.validate(),
            Err(DataModelError::InvalidResource { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_duplicate_operation_and_invalid_intrinsic_fields() {
        let entity = entity_id(1);
        let operation = put(10, entity, &[], "created");
        let mut reducer = EntityReducer::new(entity, EntitySchema::RecordV1);
        reducer.apply(operation.clone()).expect("first application");
        assert_eq!(
            reducer.apply(operation),
            Err(DataModelError::DuplicateOperationId(operation_id(10)))
        );

        let mut invalid = put(11, entity, &[10], "invalid");
        invalid.protocol_version = 2;
        assert!(matches!(
            invalid.validate(),
            Err(DataModelError::UnsupportedProtocolVersion { .. })
        ));
        invalid.protocol_version = PROTOCOL_VERSION;
        invalid.occurred_at_unix_ms = -1;
        assert_eq!(
            invalid.validate(),
            Err(DataModelError::NegativeOccurredAt(-1))
        );
    }
}
