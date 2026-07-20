#![forbid(unsafe_code)]
//! Signed, storage-independent operations for Fractonica entities.
//!
//! JSON values in this crate are projections for APIs and storage inspection.
//! The authoritative representation is a deterministic CBOR operation payload
//! carried by an exact COSE Sign1 envelope and verified by `fractonica-trust`.

mod canonical;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fractonica_content::{
    ContentId, ContentValidationError, MAX_CONTENT_BYTE_LENGTH, MAX_RESOURCE_ROLE_BYTES,
    ResourceRef,
};
pub use fractonica_trust::{ActorId, NodeId, OperationId, OperationNonce, SigningKey, SpaceId};
use fractonica_trust::{
    OperationPayload as TrustOperationPayload, SignedOperation as TrustSignedOperation, TrustError,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use canonical::{decode_body, encode_body};

/// Version of the signed operation envelope implemented by this crate.
pub const PROTOCOL_VERSION: u16 = fractonica_trust::OPERATION_PROTOCOL_VERSION as u16;
/// Maximum number of direct causal parents carried by one operation.
pub const MAX_CAUSAL_PARENTS: usize = fractonica_trust::MAX_CAUSAL_PARENTS;
/// Maximum number of capability operations referenced by one operation.
pub const MAX_AUTHORIZATION_REFERENCES: usize = fractonica_trust::MAX_AUTHORIZATION_REFERENCES;
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
/// Maximum number of schema names in one capability grant.
pub const MAX_CAPABILITY_SCHEMAS: usize = 32;
/// Maximum number of content roles in one capability grant.
pub const MAX_CAPABILITY_CONTENT_ROLES: usize = 64;
/// Maximum delegation chain length permitted by a version 1 grant.
pub const MAX_DELEGATION_DEPTH: u8 = 16;
/// Maximum number of Unicode scalar values in a capability label.
pub const MAX_CAPABILITY_LABEL_CHARS: usize = 128;
/// Maximum number of Unicode scalar values in a revocation detail.
pub const MAX_REVOCATION_DETAIL_CHARS: usize = 512;

/// Maximum decoded length of the JSON-projected COSE value.
const MAX_COSE_PROJECTION_BYTES: usize = fractonica_trust::MAX_CANONICAL_BYTES + 256;

/// Identifies one logical entity within a space.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntityId(Uuid);

impl EntityId {
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

impl fmt::Display for EntityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for EntityId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EntityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = EntityId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical lowercase hyphenated non-nil UUID")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let uuid = Uuid::parse_str(value).map_err(E::custom)?;
                if uuid.is_nil() || uuid.to_string() != value {
                    return Err(E::custom(
                        "entity ID must be a canonical lowercase hyphenated non-nil UUID",
                    ));
                }
                Ok(EntityId(uuid))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// Versioned schema interpreted by an operation body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EntitySchema {
    #[serde(rename = "record.v1")]
    RecordV1,
    #[serde(rename = "space.genesis.v1")]
    SpaceGenesisV1,
    #[serde(rename = "capability.grant.v1")]
    CapabilityGrantV1,
    #[serde(rename = "capability.revoke.v1")]
    CapabilityRevokeV1,
}

impl EntitySchema {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordV1 => "record.v1",
            Self::SpaceGenesisV1 => "space.genesis.v1",
            Self::CapabilityGrantV1 => "capability.grant.v1",
            Self::CapabilityRevokeV1 => "capability.revoke.v1",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DataModelError> {
        match value {
            "record.v1" => Ok(Self::RecordV1),
            "space.genesis.v1" => Ok(Self::SpaceGenesisV1),
            "capability.grant.v1" => Ok(Self::CapabilityGrantV1),
            "capability.revoke.v1" => Ok(Self::CapabilityRevokeV1),
            _ => Err(DataModelError::UnsupportedSchema(value.to_owned())),
        }
    }
}

impl fmt::Display for EntitySchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Visibility policy requested by a record document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub metadata: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceRef>,
}

impl RecordDocument {
    /// Validates all record, metadata, and resource bounds without external I/O.
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
            validate_metadata_key(key)?;
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

fn validate_metadata_key(key: &str) -> Result<(), DataModelError> {
    let length = key.chars().count();
    if length == 0 || length > MAX_METADATA_KEY_CHARS || key.chars().any(char::is_control) {
        Err(DataModelError::InvalidMetadataKey {
            key: key.to_owned(),
            maximum: MAX_METADATA_KEY_CHARS,
        })
    } else {
        Ok(())
    }
}

fn validate_metadata_value(value: &Value, depth: usize) -> Result<(), DataModelError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            if number.as_i64().is_some()
                || number.as_u64().is_some()
                || number.as_f64().is_some_and(f64::is_finite)
            {
                Ok(())
            } else {
                Err(DataModelError::UnsupportedMetadataNumber(
                    number.to_string(),
                ))
            }
        }
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
                validate_metadata_key(key)?;
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

/// An action that a capability may grant to its subject actor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityAction {
    AppendOperation,
    IssueCapability,
    RevokeCapability,
    ReadSpace,
    WriteContent,
}

/// Bounded capability statement carried by `capability.grant.v1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityGrant {
    pub subject: ActorId,
    pub actions: Vec<CapabilityAction>,
    pub schemas: Vec<EntitySchema>,
    pub record_visibilities: Vec<RecordVisibility>,
    pub content_roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resource_byte_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    pub delegation_depth: u8,
    pub label: String,
}

impl CapabilityGrant {
    /// Sorts set-valued inputs into their one canonical projection order.
    pub fn normalize(&mut self) {
        self.actions.sort_unstable();
        self.schemas.sort_by_key(|schema| schema.as_str());
        self.record_visibilities.sort_unstable();
        self.content_roles.sort_unstable();
    }

    pub fn validate(&self) -> Result<(), DataModelError> {
        self.subject.public_key()?;
        validate_nonempty_sorted_set("actions", &self.actions, CapabilityAction::cmp)?;
        if self.schemas.len() > MAX_CAPABILITY_SCHEMAS {
            return Err(DataModelError::CapabilitySetTooLarge {
                field: "schemas",
                count: self.schemas.len(),
                maximum: MAX_CAPABILITY_SCHEMAS,
            });
        }
        validate_sorted_by("schemas", &self.schemas, |left, right| {
            left.as_str().cmp(right.as_str())
        })?;
        validate_sorted_set("recordVisibilities", &self.record_visibilities)?;
        if self.content_roles.len() > MAX_CAPABILITY_CONTENT_ROLES {
            return Err(DataModelError::CapabilitySetTooLarge {
                field: "contentRoles",
                count: self.content_roles.len(),
                maximum: MAX_CAPABILITY_CONTENT_ROLES,
            });
        }
        validate_sorted_set("contentRoles", &self.content_roles)?;
        for role in &self.content_roles {
            validate_content_role(role)?;
        }

        if self.delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(DataModelError::DelegationTooDeep {
                found: self.delegation_depth,
                maximum: MAX_DELEGATION_DEPTH,
            });
        }
        validate_bounded_label(
            "capability label",
            &self.label,
            MAX_CAPABILITY_LABEL_CHARS,
            false,
        )?;
        validate_optional_time("notBeforeUnixMs", self.not_before_unix_ms)?;
        validate_optional_time("expiresAtUnixMs", self.expires_at_unix_ms)?;
        if let (Some(start), Some(end)) = (self.not_before_unix_ms, self.expires_at_unix_ms)
            && end <= start
        {
            return Err(DataModelError::InvalidCapabilityWindow { start, end });
        }

        let append = self.actions.contains(&CapabilityAction::AppendOperation);
        if append != !self.schemas.is_empty() {
            return Err(DataModelError::CapabilityScopeMismatch(
                "appendOperation requires a nonempty schemas set, and schemas require appendOperation",
            ));
        }
        let records = self.schemas.contains(&EntitySchema::RecordV1);
        if records != !self.record_visibilities.is_empty() {
            return Err(DataModelError::CapabilityScopeMismatch(
                "record.v1 requires a nonempty recordVisibilities set, and recordVisibilities require record.v1",
            ));
        }

        let write_content = self.actions.contains(&CapabilityAction::WriteContent);
        if write_content
            != (!self.content_roles.is_empty() && self.max_resource_byte_length.is_some())
        {
            return Err(DataModelError::CapabilityScopeMismatch(
                "writeContent requires nonempty contentRoles and maxResourceByteLength, and those constraints require writeContent",
            ));
        }
        if let Some(maximum) = self.max_resource_byte_length
            && maximum > MAX_CONTENT_BYTE_LENGTH
        {
            return Err(DataModelError::CapabilityResourceLimitTooLarge {
                found: maximum,
                maximum: MAX_CONTENT_BYTE_LENGTH,
            });
        }
        Ok(())
    }
}

/// Machine-readable reason for revoking one grant operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityRevocationReason {
    KeyCompromised,
    DeviceLost,
    KeyRotated,
    ScopeChanged,
    Administrative,
}

/// Bounded revocation carried by `capability.revoke.v1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityRevocation {
    pub grant_id: OperationId,
    pub reason: CapabilityRevocationReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl CapabilityRevocation {
    pub fn validate(&self) -> Result<(), DataModelError> {
        if let Some(detail) = &self.detail {
            validate_bounded_label(
                "revocation detail",
                detail,
                MAX_REVOCATION_DETAIL_CHARS,
                false,
            )?;
        }
        Ok(())
    }
}

/// Typed body carried by one signed operation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationBody {
    Put { document: RecordDocument },
    Tombstone,
    SpaceGenesis { controller: ActorId },
    CapabilityGrant { grant: CapabilityGrant },
    CapabilityRevoke { revocation: CapabilityRevocation },
}

impl OperationBody {
    fn validate_for(
        &self,
        schema: EntitySchema,
        actor_id: ActorId,
        causal_parents: &[OperationId],
        authorization: &[OperationId],
    ) -> Result<(), DataModelError> {
        if schema != EntitySchema::SpaceGenesisV1 && authorization.is_empty() {
            return Err(DataModelError::MissingAuthorization);
        }
        match (schema, self) {
            (EntitySchema::RecordV1, Self::Put { document }) => document.validate(),
            (EntitySchema::RecordV1, Self::Tombstone) => Ok(()),
            (EntitySchema::SpaceGenesisV1, Self::SpaceGenesis { controller }) => {
                controller.public_key()?;
                if *controller != actor_id {
                    return Err(DataModelError::GenesisControllerMismatch {
                        controller: *controller,
                        actor: actor_id,
                    });
                }
                if !causal_parents.is_empty() || !authorization.is_empty() {
                    return Err(DataModelError::GenesisMustBeRoot);
                }
                Ok(())
            }
            (EntitySchema::CapabilityGrantV1, Self::CapabilityGrant { grant }) => grant.validate(),
            (EntitySchema::CapabilityRevokeV1, Self::CapabilityRevoke { revocation }) => {
                revocation.validate()
            }
            _ => Err(DataModelError::SchemaBodyMismatch { schema }),
        }
    }
}

/// Strict JSON projection of one authoritative signed operation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedOperationEnvelope {
    pub protocol_version: u16,
    pub operation_id: OperationId,
    pub space_id: SpaceId,
    pub actor_id: ActorId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub causal_parents: Vec<OperationId>,
    pub authorization: Vec<OperationId>,
    pub occurred_at_unix_ms: i64,
    #[serde(with = "nonce_hex")]
    pub nonce: OperationNonce,
    pub body: OperationBody,
    #[serde(with = "cose_base64url")]
    pub cose_sign1: Vec<u8>,
}

/// Compatibility name for the version 2 signed envelope within this crate.
pub type OperationEnvelope = SignedOperationEnvelope;

impl SignedOperationEnvelope {
    /// Builds, signs, verifies, and projects one version 2 operation.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        space_id: SpaceId,
        entity_id: EntityId,
        schema: EntitySchema,
        causal_parents: Vec<OperationId>,
        authorization: Vec<OperationId>,
        occurred_at_unix_ms: i64,
        nonce: OperationNonce,
        body: OperationBody,
        signing_key: &SigningKey,
    ) -> Result<Self, DataModelError> {
        if entity_id.as_uuid().is_nil() {
            return Err(DataModelError::NilEntityId);
        }
        body.validate_for(
            schema,
            signing_key.actor_id(),
            &causal_parents,
            &authorization,
        )?;
        let canonical_body = encode_body(schema, &body)?;
        let payload = TrustOperationPayload::new(
            space_id,
            signing_key.actor_id(),
            entity_id.as_uuid(),
            schema.as_str(),
            causal_parents,
            authorization,
            occurred_at_unix_ms,
            nonce,
            canonical_body,
        )?;
        Self::from_trust_signed(payload.sign(signing_key)?)
    }

    /// Parses canonical COSE, verifies its signature, and builds its JSON projection.
    pub fn from_cose_sign1(cose_sign1: &[u8]) -> Result<Self, DataModelError> {
        let signed = TrustSignedOperation::from_cose_sign1(cose_sign1)?;
        Self::from_trust_signed(signed)
    }

    fn from_trust_signed(signed: TrustSignedOperation) -> Result<Self, DataModelError> {
        signed.verify()?;
        let payload = signed.decode_payload()?;
        let schema = EntitySchema::parse(payload.schema())?;
        let body = decode_body(schema, payload.body())?;
        let envelope = Self {
            protocol_version: PROTOCOL_VERSION,
            operation_id: signed.operation_id(),
            space_id: payload.space_id(),
            actor_id: payload.actor_id(),
            entity_id: EntityId::new(payload.entity_id()),
            schema,
            causal_parents: payload.causal_parents().to_vec(),
            authorization: payload.authorization().to_vec(),
            occurred_at_unix_ms: payload.occurred_at_unix_ms(),
            nonce: payload.nonce(),
            body,
            cose_sign1: signed.to_cose_sign1()?,
        };
        envelope.verify()?;
        Ok(envelope)
    }

    /// Verifies canonical COSE and proves every JSON field matches signed bytes.
    pub fn verify(&self) -> Result<(), DataModelError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(DataModelError::UnsupportedProtocolVersion {
                found: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        if self.entity_id.as_uuid().is_nil() {
            return Err(DataModelError::NilEntityId);
        }
        validate_sorted_set("causalParents", &self.causal_parents)?;
        validate_sorted_set("authorization", &self.authorization)?;
        if self.causal_parents.contains(&self.operation_id) {
            return Err(DataModelError::SelfCausalParent(self.operation_id));
        }

        let signed = TrustSignedOperation::from_cose_sign1(&self.cose_sign1)?;
        signed.verify()?;
        if signed.to_cose_sign1()? != self.cose_sign1 {
            return Err(DataModelError::NonCanonicalCoseProjection);
        }
        let payload = signed.decode_payload()?;
        let signed_schema = EntitySchema::parse(payload.schema())?;
        let signed_body = decode_body(signed_schema, payload.body())?;

        require_projection("operationId", self.operation_id == signed.operation_id())?;
        require_projection("spaceId", self.space_id == payload.space_id())?;
        require_projection("actorId", self.actor_id == payload.actor_id())?;
        require_projection("entityId", self.entity_id.as_uuid() == payload.entity_id())?;
        require_projection("schema", self.schema == signed_schema)?;
        require_projection(
            "causalParents",
            self.causal_parents == payload.causal_parents(),
        )?;
        require_projection(
            "authorization",
            self.authorization == payload.authorization(),
        )?;
        require_projection(
            "occurredAtUnixMs",
            self.occurred_at_unix_ms == payload.occurred_at_unix_ms(),
        )?;
        require_projection("nonce", self.nonce == payload.nonce())?;
        require_projection("body", self.body == signed_body)?;

        let projected_body = encode_body(self.schema, &self.body)?
            .to_canonical_cbor()
            .map_err(TrustError::from)?;
        let signed_body_bytes = payload
            .body()
            .to_canonical_cbor()
            .map_err(TrustError::from)?;
        require_projection("body", projected_body == signed_body_bytes)?;
        self.body.validate_for(
            self.schema,
            self.actor_id,
            &self.causal_parents,
            &self.authorization,
        )
    }

    /// Returns canonical URL-safe base64 without padding for transport projection.
    #[must_use]
    pub fn cose_sign1_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.cose_sign1)
    }
}

fn require_projection(field: &'static str, matches: bool) -> Result<(), DataModelError> {
    if matches {
        Ok(())
    } else {
        Err(DataModelError::ProjectionMismatch { field })
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
    pub space_id: SpaceId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: usize,
    pub heads: Vec<EntityHead>,
}

/// Incremental deterministic reducer for one entity, schema, and space.
#[derive(Clone, Debug)]
pub struct EntityReducer {
    space_id: SpaceId,
    entity_id: EntityId,
    schema: EntitySchema,
    operations: BTreeMap<OperationId, SignedOperationEnvelope>,
    heads: BTreeSet<OperationId>,
}

impl EntityReducer {
    #[must_use]
    pub const fn new(space_id: SpaceId, entity_id: EntityId, schema: EntitySchema) -> Self {
        Self {
            space_id,
            entity_id,
            schema,
            operations: BTreeMap::new(),
            heads: BTreeSet::new(),
        }
    }

    /// Verifies and applies one operation after all parents have been applied.
    pub fn apply(&mut self, operation: SignedOperationEnvelope) -> Result<(), DataModelError> {
        operation.verify()?;
        if operation.space_id != self.space_id {
            return Err(DataModelError::ForeignSpace {
                expected: self.space_id,
                found: operation.space_id,
            });
        }
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
            if parent.space_id != operation.space_id
                || parent.entity_id != operation.entity_id
                || parent.schema != operation.schema
            {
                return Err(DataModelError::ForeignCausalParent {
                    parent_id: *parent_id,
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
            space_id: self.space_id,
            entity_id: self.entity_id,
            schema: self.schema,
            operation_count: self.operations.len(),
            heads,
        }
    }
}

/// Reduces a topologically ordered stream for exactly one space and entity.
pub fn reduce_entity(
    space_id: SpaceId,
    entity_id: EntityId,
    schema: EntitySchema,
    operations: impl IntoIterator<Item = SignedOperationEnvelope>,
) -> Result<ReducedEntity, DataModelError> {
    let mut reducer = EntityReducer::new(space_id, entity_id, schema);
    for operation in operations {
        reducer.apply(operation)?;
    }
    Ok(reducer.finish())
}

fn validate_content_role(role: &str) -> Result<(), DataModelError> {
    let valid = !role.is_empty()
        && role.len() <= MAX_RESOURCE_ROLE_BYTES
        && role.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(DataModelError::InvalidCapabilityContentRole(
            role.to_owned(),
        ))
    }
}

fn validate_optional_time(field: &'static str, value: Option<i64>) -> Result<(), DataModelError> {
    if let Some(value) = value
        && value < 0
    {
        return Err(DataModelError::NegativeCapabilityTime { field, value });
    }
    Ok(())
}

fn validate_bounded_label(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), DataModelError> {
    let count = value.chars().count();
    if (!allow_empty && count == 0) || count > maximum || value.chars().any(char::is_control) {
        Err(DataModelError::InvalidBoundedLabel {
            field,
            count,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn validate_nonempty_sorted_set<T>(
    field: &'static str,
    values: &[T],
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<(), DataModelError> {
    if values.is_empty() {
        return Err(DataModelError::EmptyCapabilitySet { field });
    }
    validate_sorted_by(field, values, compare)
}

fn validate_sorted_set<T: Ord>(field: &'static str, values: &[T]) -> Result<(), DataModelError> {
    validate_sorted_by(field, values, Ord::cmp)
}

fn validate_sorted_by<T>(
    field: &'static str,
    values: &[T],
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<(), DataModelError> {
    if values
        .windows(2)
        .all(|pair| compare(&pair[0], &pair[1]).is_lt())
    {
        Ok(())
    } else {
        Err(DataModelError::CapabilitySetNotStrictlySorted { field })
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DataModelError {
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("unsupported operation protocol version {found}; this build supports {supported}")]
    UnsupportedProtocolVersion { found: u16, supported: u16 },
    #[error("unsupported entity schema {0:?}")]
    UnsupportedSchema(String),
    #[error("entity ID must not be the nil UUID")]
    NilEntityId,
    #[error("JSON projection field {field} does not match the signed payload")]
    ProjectionMismatch { field: &'static str },
    #[error("COSE projection is not the exact canonical COSE Sign1 encoding")]
    NonCanonicalCoseProjection,
    #[error("schema {schema} cannot carry this operation body")]
    SchemaBodyMismatch { schema: EntitySchema },
    #[error("signed schema body is not canonical {schema}: {detail}")]
    InvalidCanonicalBody {
        schema: EntitySchema,
        detail: &'static str,
    },
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
    #[error("operation has {count} authorization references; maximum is {maximum}")]
    TooManyAuthorizationReferences { count: usize, maximum: usize },
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
    #[error("unsupported JSON metadata number {0}")]
    UnsupportedMetadataNumber(String),
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
    #[error("capability set {field} must not be empty")]
    EmptyCapabilitySet { field: &'static str },
    #[error("capability set {field} is not unique and strictly sorted")]
    CapabilitySetNotStrictlySorted { field: &'static str },
    #[error("capability set {field} has {count} entries; maximum is {maximum}")]
    CapabilitySetTooLarge {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    #[error("capability scope is inconsistent: {0}")]
    CapabilityScopeMismatch(&'static str),
    #[error("capability content role is invalid: {0:?}")]
    InvalidCapabilityContentRole(String),
    #[error("capability resource limit {found} exceeds maximum {maximum}")]
    CapabilityResourceLimitTooLarge { found: u64, maximum: u64 },
    #[error("capability delegation depth {found} exceeds maximum {maximum}")]
    DelegationTooDeep { found: u8, maximum: u8 },
    #[error("capability field {field} must be nonnegative, got {value}")]
    NegativeCapabilityTime { field: &'static str, value: i64 },
    #[error("capability expiration {end} must be after not-before {start}")]
    InvalidCapabilityWindow { start: i64, end: i64 },
    #[error("{field} contains {count} characters; expected 1..={maximum} non-control characters")]
    InvalidBoundedLabel {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    #[error("space genesis controller {controller} does not match signer {actor}")]
    GenesisControllerMismatch { controller: ActorId, actor: ActorId },
    #[error("space genesis must have no causal parents or authorization references")]
    GenesisMustBeRoot,
    #[error("every non-genesis operation must reference at least one capability grant")]
    MissingAuthorization,
    #[error("operation ID was already applied: {0}")]
    DuplicateOperationId(OperationId),
    #[error("operation belongs to space {found}, expected {expected}")]
    ForeignSpace { expected: SpaceId, found: SpaceId },
    #[error("operation belongs to entity {found}, expected {expected}")]
    ForeignEntity { expected: EntityId, found: EntityId },
    #[error("operation uses schema {found}, expected {expected}")]
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
    #[error("causal parent {parent_id} belongs to another space, entity, or schema")]
    ForeignCausalParent { parent_id: OperationId },
}

mod nonce_hex {
    use super::*;

    pub fn serialize<S>(nonce: &OperationNonce, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(32);
        for byte in nonce.as_bytes() {
            use fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OperationNonce, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 32 {
            return Err(de::Error::custom(
                "nonce must be exactly 32 lowercase hex digits",
            ));
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = decode_lower_hex(pair[0])
                .ok_or_else(|| de::Error::custom("nonce must contain only lowercase hex digits"))?
                << 4
                | decode_lower_hex(pair[1]).ok_or_else(|| {
                    de::Error::custom("nonce must contain only lowercase hex digits")
                })?;
        }
        Ok(OperationNonce::from_bytes(bytes))
    }

    const fn decode_lower_hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
}

mod cose_base64url {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let maximum_encoded = MAX_COSE_PROJECTION_BYTES.div_ceil(3) * 4;
        if value.len() > maximum_encoded {
            return Err(de::Error::custom("COSE base64url projection is too large"));
        }
        let bytes = URL_SAFE_NO_PAD.decode(&value).map_err(de::Error::custom)?;
        if bytes.len() > MAX_COSE_PROJECTION_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(de::Error::custom(
                "COSE must be bounded canonical base64url without padding",
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
