use std::collections::BTreeMap;

use fractonica_content::{ContentId, ResourceRef};
use fractonica_trust::CanonicalValue;
use serde_json::{Map, Number, Value};
use uuid::Uuid;

use super::{
    ActorId, CapabilityAction, CapabilityGrant, CapabilityRevocation, CapabilityRevocationReason,
    DataModelError, EncryptedPayload, EncryptionAlgorithm, EntityId, EntityReference, EntitySchema,
    EventDocument, OperationBody, OperationId, ProfileDocument, ProtectedDocument, RecordDocument,
    ReferenceTarget, SpaceId, TagDocument, Visibility,
};

const BODY_TOMBSTONE: u64 = 0;
const BODY_RECORD_PUT: u64 = 1;
const BODY_TAG_PUT: u64 = 2;
const BODY_EVENT_PUT: u64 = 3;
const BODY_PROFILE_PUT: u64 = 4;
const BODY_SPACE_GENESIS: u64 = 5;
const BODY_CAPABILITY_GRANT: u64 = 6;
const BODY_CAPABILITY_REVOKE: u64 = 7;

pub(super) fn encode_body(
    schema: EntitySchema,
    body: &OperationBody,
) -> Result<CanonicalValue, DataModelError> {
    match (schema, body) {
        (
            EntitySchema::Record | EntitySchema::Tag | EntitySchema::Event | EntitySchema::Profile,
            OperationBody::Tombstone,
        ) => Ok(CanonicalValue::Array(vec![CanonicalValue::Unsigned(
            BODY_TOMBSTONE,
        )])),
        (EntitySchema::Record, OperationBody::PutRecord { payload }) => {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(BODY_RECORD_PUT),
                encode_protected(payload, encode_record_document)?,
            ]))
        }
        (EntitySchema::Tag, OperationBody::PutTag { payload }) => Ok(CanonicalValue::Array(vec![
            CanonicalValue::Unsigned(BODY_TAG_PUT),
            encode_protected(payload, encode_tag_document)?,
        ])),
        (EntitySchema::Event, OperationBody::PutEvent { payload }) => {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(BODY_EVENT_PUT),
                encode_protected(payload, encode_event_document)?,
            ]))
        }
        (EntitySchema::Profile, OperationBody::PutProfile { document }) => {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(BODY_PROFILE_PUT),
                encode_profile_document(document)?,
            ]))
        }
        (EntitySchema::SpaceGenesis, OperationBody::SpaceGenesis { controller }) => {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(BODY_SPACE_GENESIS),
                CanonicalValue::Bytes(controller.as_bytes().to_vec()),
            ]))
        }
        (EntitySchema::CapabilityGrant, OperationBody::CapabilityGrant { grant }) => {
            encode_capability_grant(grant)
        }
        (EntitySchema::CapabilityRevoke, OperationBody::CapabilityRevoke { revocation }) => {
            encode_capability_revocation(revocation)
        }
        _ => Err(DataModelError::SchemaBodyMismatch { schema }),
    }
}

pub(super) fn decode_body(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<OperationBody, DataModelError> {
    let fields = body_array(schema, value)?;
    let kind = unsigned(schema, fields.first(), "body kind")?;
    match (schema, kind) {
        (
            EntitySchema::Record | EntitySchema::Tag | EntitySchema::Event | EntitySchema::Profile,
            BODY_TOMBSTONE,
        ) if fields.len() == 1 => Ok(OperationBody::Tombstone),
        (EntitySchema::Record, BODY_RECORD_PUT) if fields.len() == 2 => {
            Ok(OperationBody::PutRecord {
                payload: decode_protected(schema, fields.get(1), decode_record_document)?,
            })
        }
        (EntitySchema::Tag, BODY_TAG_PUT) if fields.len() == 2 => Ok(OperationBody::PutTag {
            payload: decode_protected(schema, fields.get(1), decode_tag_document)?,
        }),
        (EntitySchema::Event, BODY_EVENT_PUT) if fields.len() == 2 => Ok(OperationBody::PutEvent {
            payload: decode_protected(schema, fields.get(1), decode_event_document)?,
        }),
        (EntitySchema::Profile, BODY_PROFILE_PUT) if fields.len() == 2 => {
            Ok(OperationBody::PutProfile {
                document: decode_profile_document(schema, fields.get(1))?,
            })
        }
        (EntitySchema::SpaceGenesis, BODY_SPACE_GENESIS) if fields.len() == 2 => {
            let controller =
                ActorId::from_bytes(fixed_bytes(schema, fields.get(1), "genesis controller")?);
            controller.public_key()?;
            Ok(OperationBody::SpaceGenesis { controller })
        }
        (EntitySchema::CapabilityGrant, BODY_CAPABILITY_GRANT) => {
            decode_capability_grant(schema, fields)
        }
        (EntitySchema::CapabilityRevoke, BODY_CAPABILITY_REVOKE) => {
            decode_capability_revocation(schema, fields)
        }
        _ => invalid(schema, "body kind does not match schema"),
    }
}

fn encode_protected<T>(
    payload: &ProtectedDocument<T>,
    encode_public: impl FnOnce(&T) -> Result<CanonicalValue, DataModelError>,
) -> Result<CanonicalValue, DataModelError> {
    match payload {
        ProtectedDocument::Public { document } => Ok(CanonicalValue::Array(vec![
            CanonicalValue::Unsigned(0),
            encode_public(document)?,
            CanonicalValue::Array(vec![]),
        ])),
        ProtectedDocument::Private {
            envelope,
            resources,
        } => Ok(CanonicalValue::Array(vec![
            CanonicalValue::Unsigned(1),
            encode_encrypted_payload(envelope),
            CanonicalValue::Array(resources.iter().map(encode_resource).collect()),
        ])),
    }
}

fn decode_protected<T>(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    decode_public: impl FnOnce(EntitySchema, &CanonicalValue) -> Result<T, DataModelError>,
) -> Result<ProtectedDocument<T>, DataModelError> {
    let CanonicalValue::Array(fields) = required(schema, value, "protected document")? else {
        return invalid(schema, "protected document must be an array");
    };
    if fields.len() != 3 {
        return invalid(schema, "protected document must contain three fields");
    }
    let CanonicalValue::Array(resources) = required(schema, fields.get(2), "protected resources")?
    else {
        return invalid(schema, "protected resources must be an array");
    };
    match unsigned(schema, fields.first(), "document visibility")? {
        0 if resources.is_empty() => Ok(ProtectedDocument::Public {
            document: decode_public(schema, required(schema, fields.get(1), "public document")?)?,
        }),
        1 => Ok(ProtectedDocument::Private {
            envelope: decode_encrypted_payload(schema, fields.get(1))?,
            resources: resources
                .iter()
                .map(|value| decode_resource(schema, value))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        _ => invalid(schema, "invalid protected-document visibility or resources"),
    }
}

fn encode_encrypted_payload(envelope: &EncryptedPayload) -> CanonicalValue {
    let algorithm = match envelope.algorithm {
        EncryptionAlgorithm::Aes256Gcm => 0,
    };
    CanonicalValue::Array(vec![
        CanonicalValue::Unsigned(algorithm),
        CanonicalValue::Text(envelope.key_id.clone()),
        CanonicalValue::Text(envelope.nonce_base64url.clone()),
        CanonicalValue::Text(envelope.ciphertext_base64url.clone()),
    ])
}

fn decode_encrypted_payload(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<EncryptedPayload, DataModelError> {
    let CanonicalValue::Array(fields) = required(schema, value, "encrypted payload")? else {
        return invalid(schema, "encrypted payload must be an array");
    };
    if fields.len() != 4 || unsigned(schema, fields.first(), "encryption algorithm")? != 0 {
        return invalid(schema, "unsupported encrypted payload");
    }
    Ok(EncryptedPayload {
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        key_id: text(schema, fields.get(1), "encryption key ID")?,
        nonce_base64url: text(schema, fields.get(2), "encryption nonce")?,
        ciphertext_base64url: text(schema, fields.get(3), "encrypted ciphertext")?,
    })
}

fn encode_record_document(document: &RecordDocument) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Array(vec![
        nonnegative_integer(document.start_at_unix_ms)?,
        optional_nonnegative_integer(document.end_at_unix_ms)?,
        optional_text(document.emoji.as_deref()),
        optional_text(document.text.as_deref()),
        encode_metadata_object(&document.metadata)?,
        CanonicalValue::Array(document.resources.iter().map(encode_resource).collect()),
        encode_references(&document.references),
    ]))
}

fn decode_record_document(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<RecordDocument, DataModelError> {
    let fields = exact_array(schema, value, 7, "record document")?;
    Ok(RecordDocument {
        start_at_unix_ms: nonnegative_i64(schema, fields.first(), "record start")?,
        end_at_unix_ms: optional_nonnegative_i64(schema, fields.get(1), "record end")?,
        emoji: decode_optional_text(schema, fields.get(2), "record emoji")?,
        text: decode_optional_text(schema, fields.get(3), "record text")?,
        metadata: decode_metadata_object(schema, fields.get(4))?,
        resources: decode_resources(schema, fields.get(5))?,
        references: decode_references(schema, fields.get(6))?,
    })
}

fn encode_tag_document(document: &TagDocument) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Array(vec![
        CanonicalValue::Text(document.name.clone()),
        optional_text(document.emoji.as_deref()),
        optional_text(document.notes.as_deref()),
        optional_text(document.color_hex.as_deref()),
        encode_metadata_object(&document.metadata)?,
        encode_references(&document.references),
    ]))
}

fn decode_tag_document(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<TagDocument, DataModelError> {
    let fields = exact_array(schema, value, 6, "tag document")?;
    Ok(TagDocument {
        name: text(schema, fields.first(), "tag name")?,
        emoji: decode_optional_text(schema, fields.get(1), "tag emoji")?,
        notes: decode_optional_text(schema, fields.get(2), "tag notes")?,
        color_hex: decode_optional_text(schema, fields.get(3), "tag color")?,
        metadata: decode_metadata_object(schema, fields.get(4))?,
        references: decode_references(schema, fields.get(5))?,
    })
}

fn encode_event_document(document: &EventDocument) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Array(vec![
        nonnegative_integer(document.start_at_unix_ms)?,
        optional_nonnegative_integer(document.end_at_unix_ms)?,
        CanonicalValue::Text(document.label.clone()),
        signed_integer(document.type_number),
        encode_metadata_object(&document.metadata)?,
        encode_references(&document.references),
    ]))
}

fn decode_event_document(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<EventDocument, DataModelError> {
    let fields = exact_array(schema, value, 6, "event document")?;
    Ok(EventDocument {
        start_at_unix_ms: nonnegative_i64(schema, fields.first(), "event start")?,
        end_at_unix_ms: optional_nonnegative_i64(schema, fields.get(1), "event end")?,
        label: text(schema, fields.get(2), "event label")?,
        type_number: decode_signed_integer(schema, fields.get(3), "event type")?,
        metadata: decode_metadata_object(schema, fields.get(4))?,
        references: decode_references(schema, fields.get(5))?,
    })
}

fn encode_profile_document(document: &ProfileDocument) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Array(vec![
        CanonicalValue::Text(document.handle.clone()),
        CanonicalValue::Text(document.display_name.clone()),
        CanonicalValue::Unsigned(u64::from(document.saros_anchor)),
        document
            .avatar
            .as_ref()
            .map_or(CanonicalValue::Null, encode_resource),
        encode_metadata_object(&document.metadata)?,
    ]))
}

fn decode_profile_document(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<ProfileDocument, DataModelError> {
    let fields = exact_array(
        schema,
        required(schema, value, "profile document")?,
        5,
        "profile document",
    )?;
    let avatar = match required(schema, fields.get(3), "profile avatar")? {
        CanonicalValue::Null => None,
        value => Some(decode_resource(schema, value)?),
    };
    Ok(ProfileDocument {
        handle: text(schema, fields.first(), "profile handle")?,
        display_name: text(schema, fields.get(1), "profile display name")?,
        saros_anchor: u16::try_from(unsigned(schema, fields.get(2), "profile Saros anchor")?)
            .map_err(|_| DataModelError::InvalidCanonicalBody {
                schema,
                detail: "profile Saros anchor exceeds u16",
            })?,
        avatar,
        metadata: decode_metadata_object(schema, fields.get(4))?,
    })
}

fn encode_references(references: &[EntityReference]) -> CanonicalValue {
    CanonicalValue::Array(
        references
            .iter()
            .map(|reference| {
                let target = match &reference.target {
                    ReferenceTarget::Actor { actor_id } => CanonicalValue::Array(vec![
                        CanonicalValue::Unsigned(0),
                        CanonicalValue::Bytes(actor_id.as_bytes().to_vec()),
                    ]),
                    ReferenceTarget::Entity {
                        space_id,
                        entity_id,
                        operation_id,
                    } => CanonicalValue::Array(vec![
                        CanonicalValue::Unsigned(1),
                        CanonicalValue::Bytes(space_id.as_bytes().to_vec()),
                        CanonicalValue::Bytes(entity_id.as_uuid().as_bytes().to_vec()),
                        operation_id.as_ref().map_or(CanonicalValue::Null, |value| {
                            CanonicalValue::Bytes(value.as_bytes().to_vec())
                        }),
                    ]),
                };
                CanonicalValue::Array(vec![
                    CanonicalValue::Text(reference.relation.clone()),
                    target,
                ])
            })
            .collect(),
    )
}

fn decode_references(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<Vec<EntityReference>, DataModelError> {
    decode_array(schema, value, "entity references", |value| {
        let fields = exact_array(schema, value, 2, "entity reference")?;
        let relation = text(schema, fields.first(), "reference relation")?;
        let target_fields =
            body_array(schema, required(schema, fields.get(1), "reference target")?)?;
        let target = match unsigned(schema, target_fields.first(), "reference target kind")? {
            0 if target_fields.len() == 2 => ReferenceTarget::Actor {
                actor_id: ActorId::from_bytes(fixed_bytes(
                    schema,
                    target_fields.get(1),
                    "referenced actor",
                )?),
            },
            1 if target_fields.len() == 4 => {
                let operation_id =
                    match required(schema, target_fields.get(3), "referenced operation")? {
                        CanonicalValue::Null => None,
                        value => Some(OperationId::from_bytes(fixed_bytes(
                            schema,
                            Some(value),
                            "referenced operation",
                        )?)),
                    };
                ReferenceTarget::Entity {
                    space_id: SpaceId::from_bytes(fixed_bytes(
                        schema,
                        target_fields.get(1),
                        "referenced space",
                    )?),
                    entity_id: EntityId::new(Uuid::from_bytes(fixed_bytes(
                        schema,
                        target_fields.get(2),
                        "referenced entity",
                    )?)),
                    operation_id,
                }
            }
            _ => return invalid(schema, "invalid reference target"),
        };
        Ok(EntityReference { relation, target })
    })
}

fn decode_resources(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<Vec<ResourceRef>, DataModelError> {
    decode_array(schema, value, "resources", |value| {
        decode_resource(schema, value)
    })
}

fn exact_array<'a>(
    schema: EntitySchema,
    value: &'a CanonicalValue,
    length: usize,
    detail: &'static str,
) -> Result<&'a [CanonicalValue], DataModelError> {
    let CanonicalValue::Array(fields) = value else {
        return invalid(schema, detail);
    };
    if fields.len() != length {
        return invalid(schema, detail);
    }
    Ok(fields)
}

fn encode_resource(resource: &ResourceRef) -> CanonicalValue {
    CanonicalValue::Array(vec![
        CanonicalValue::Bytes(resource.content_id.as_bytes().to_vec()),
        CanonicalValue::Unsigned(resource.byte_length),
        CanonicalValue::Text(resource.media_type.clone()),
        CanonicalValue::Text(resource.role.clone()),
        optional_text(resource.original_name.as_deref()),
    ])
}

fn decode_resource(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<ResourceRef, DataModelError> {
    let CanonicalValue::Array(fields) = value else {
        return invalid(schema, "resource reference must be an array");
    };
    if fields.len() != 5 {
        return invalid(
            schema,
            "resource reference must contain exactly five fields",
        );
    }
    Ok(ResourceRef {
        content_id: ContentId::new(fixed_bytes(schema, fields.first(), "resource content ID")?),
        byte_length: unsigned(schema, fields.get(1), "resource byte length")?,
        media_type: text(schema, fields.get(2), "resource media type")?,
        role: text(schema, fields.get(3), "resource role")?,
        original_name: decode_optional_text(schema, fields.get(4), "resource original name")?,
    })
}

fn encode_capability_grant(grant: &CapabilityGrant) -> Result<CanonicalValue, DataModelError> {
    let actions = grant
        .actions
        .iter()
        .map(|action| CanonicalValue::Unsigned(action_code(*action)))
        .collect();
    let schemas = grant
        .schemas
        .iter()
        .map(|schema| CanonicalValue::Text(schema.as_str().to_owned()))
        .collect();
    let visibilities = grant
        .visibilities
        .iter()
        .map(|visibility| CanonicalValue::Unsigned(visibility_code(*visibility)))
        .collect();
    let roles = grant
        .content_roles
        .iter()
        .cloned()
        .map(CanonicalValue::Text)
        .collect();
    Ok(CanonicalValue::Array(vec![
        CanonicalValue::Unsigned(BODY_CAPABILITY_GRANT),
        CanonicalValue::Bytes(grant.subject.as_bytes().to_vec()),
        CanonicalValue::Array(actions),
        CanonicalValue::Array(schemas),
        CanonicalValue::Array(visibilities),
        CanonicalValue::Array(roles),
        optional_unsigned(grant.max_resource_byte_length),
        optional_nonnegative_integer(grant.not_before_unix_ms)?,
        optional_nonnegative_integer(grant.expires_at_unix_ms)?,
        CanonicalValue::Unsigned(u64::from(grant.delegation_depth)),
        CanonicalValue::Text(grant.label.clone()),
    ]))
}

fn decode_capability_grant(
    schema: EntitySchema,
    fields: &[CanonicalValue],
) -> Result<OperationBody, DataModelError> {
    if fields.len() != 11 {
        return invalid(
            schema,
            "capability grant must contain exactly eleven fields",
        );
    }
    let subject = ActorId::from_bytes(fixed_bytes(schema, fields.get(1), "grant subject")?);
    subject.public_key()?;
    let actions = decode_array(schema, fields.get(2), "grant actions", |value| {
        decode_action(schema, Some(value), "grant action")
    })?;
    let schemas = decode_array(schema, fields.get(3), "grant schemas", |value| {
        EntitySchema::parse(&text(schema, Some(value), "grant schema")?)
    })?;
    let visibilities = decode_array(
        schema,
        fields.get(4),
        "grant record visibilities",
        |value| decode_visibility(schema, Some(value), "grant visibility"),
    )?;
    let content_roles = decode_array(schema, fields.get(5), "grant content roles", |value| {
        text(schema, Some(value), "grant content role")
    })?;
    let max_resource_byte_length =
        decode_optional_unsigned(schema, fields.get(6), "grant resource limit")?;
    let not_before_unix_ms = optional_nonnegative_i64(schema, fields.get(7), "grant not-before")?;
    let expires_at_unix_ms = optional_nonnegative_i64(schema, fields.get(8), "grant expiration")?;
    let delegation_depth = u8::try_from(unsigned(schema, fields.get(9), "grant delegation depth")?)
        .map_err(|_| DataModelError::InvalidCanonicalBody {
            schema,
            detail: "grant delegation depth is outside u8",
        })?;
    let label = text(schema, fields.get(10), "grant label")?;
    Ok(OperationBody::CapabilityGrant {
        grant: CapabilityGrant {
            subject,
            actions,
            schemas,
            visibilities,
            content_roles,
            max_resource_byte_length,
            not_before_unix_ms,
            expires_at_unix_ms,
            delegation_depth,
            label,
        },
    })
}

fn encode_capability_revocation(
    revocation: &CapabilityRevocation,
) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Array(vec![
        CanonicalValue::Unsigned(BODY_CAPABILITY_REVOKE),
        CanonicalValue::Bytes(revocation.grant_id.as_bytes().to_vec()),
        CanonicalValue::Unsigned(revocation_reason_code(revocation.reason)),
        optional_text(revocation.detail.as_deref()),
    ]))
}

fn decode_capability_revocation(
    schema: EntitySchema,
    fields: &[CanonicalValue],
) -> Result<OperationBody, DataModelError> {
    if fields.len() != 4 {
        return invalid(
            schema,
            "capability revocation must contain exactly four fields",
        );
    }
    let grant_id = OperationId::from_bytes(fixed_bytes(schema, fields.get(1), "revoked grant ID")?);
    let reason = decode_revocation_reason(schema, fields.get(2))?;
    let detail = decode_optional_text(schema, fields.get(3), "revocation detail")?;
    Ok(OperationBody::CapabilityRevoke {
        revocation: CapabilityRevocation {
            grant_id,
            reason,
            detail,
        },
    })
}

fn encode_metadata_object(
    values: &BTreeMap<String, Value>,
) -> Result<CanonicalValue, DataModelError> {
    Ok(CanonicalValue::Map(
        values
            .iter()
            .map(|(key, value)| Ok((CanonicalValue::Text(key.clone()), encode_json_value(value)?)))
            .collect::<Result<Vec<_>, DataModelError>>()?,
    ))
}

fn encode_json_value(value: &Value) -> Result<CanonicalValue, DataModelError> {
    match value {
        Value::Null => Ok(CanonicalValue::Null),
        Value::Bool(value) => Ok(CanonicalValue::Bool(*value)),
        Value::Number(number) => {
            if let Some(value) = number.as_i64()
                && value < 0
            {
                return Ok(CanonicalValue::Integer(value));
            }
            if let Some(value) = number.as_u64() {
                return Ok(CanonicalValue::Unsigned(value));
            }
            let value = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| DataModelError::UnsupportedMetadataNumber(number.to_string()))?;
            Ok(CanonicalValue::Float(value))
        }
        Value::String(value) => Ok(CanonicalValue::Text(value.clone())),
        Value::Array(values) => Ok(CanonicalValue::Array(
            values
                .iter()
                .map(encode_json_value)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(values) => Ok(CanonicalValue::Map(
            values
                .iter()
                .map(|(key, value)| {
                    Ok((CanonicalValue::Text(key.clone()), encode_json_value(value)?))
                })
                .collect::<Result<Vec<_>, DataModelError>>()?,
        )),
    }
}

fn decode_metadata_object(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<BTreeMap<String, Value>, DataModelError> {
    let CanonicalValue::Map(entries) = required(schema, value, "record metadata")? else {
        return invalid(schema, "record metadata must be a map");
    };
    entries
        .iter()
        .map(|(key, value)| {
            let CanonicalValue::Text(key) = key else {
                return invalid(schema, "record metadata keys must be text");
            };
            Ok((key.clone(), decode_json_value(schema, value)?))
        })
        .collect()
}

fn decode_json_value(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<Value, DataModelError> {
    match value {
        CanonicalValue::Null => Ok(Value::Null),
        CanonicalValue::Bool(value) => Ok(Value::Bool(*value)),
        CanonicalValue::Integer(value) => Ok(Value::Number(Number::from(*value))),
        CanonicalValue::Unsigned(value) => Ok(Value::Number(Number::from(*value))),
        CanonicalValue::Float(value) => Number::from_f64(*value).map(Value::Number).ok_or(
            DataModelError::InvalidCanonicalBody {
                schema,
                detail: "metadata contains a non-finite number",
            },
        ),
        CanonicalValue::Text(value) => Ok(Value::String(value.clone())),
        CanonicalValue::Array(values) => Ok(Value::Array(
            values
                .iter()
                .map(|value| decode_json_value(schema, value))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        CanonicalValue::Map(entries) => {
            let mut values = Map::new();
            for (key, value) in entries {
                let CanonicalValue::Text(key) = key else {
                    return invalid(schema, "metadata map keys must be text");
                };
                if values
                    .insert(key.clone(), decode_json_value(schema, value)?)
                    .is_some()
                {
                    return invalid(schema, "metadata map keys must be unique");
                }
            }
            Ok(Value::Object(values))
        }
        CanonicalValue::Bytes(_) => invalid(schema, "metadata cannot contain byte strings"),
    }
}

fn body_array(
    schema: EntitySchema,
    value: &CanonicalValue,
) -> Result<&[CanonicalValue], DataModelError> {
    let CanonicalValue::Array(fields) = value else {
        return invalid(schema, "schema body must be an array");
    };
    if fields.is_empty() {
        return invalid(schema, "schema body must include a kind code");
    }
    Ok(fields)
}

fn decode_array<T>(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    field: &'static str,
    decode: impl Fn(&CanonicalValue) -> Result<T, DataModelError>,
) -> Result<Vec<T>, DataModelError> {
    let CanonicalValue::Array(values) = required(schema, value, field)? else {
        return invalid(schema, "expected an array");
    };
    values.iter().map(decode).collect()
}

fn required<'a>(
    schema: EntitySchema,
    value: Option<&'a CanonicalValue>,
    detail: &'static str,
) -> Result<&'a CanonicalValue, DataModelError> {
    value.ok_or(DataModelError::InvalidCanonicalBody { schema, detail })
}

fn unsigned(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<u64, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Unsigned(value) => Ok(*value),
        _ => invalid(schema, detail),
    }
}

fn nonnegative_i64(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<i64, DataModelError> {
    i64::try_from(unsigned(schema, value, detail)?).map_err(|_| {
        DataModelError::InvalidCanonicalBody {
            schema,
            detail: "nonnegative integer exceeds i64",
        }
    })
}

fn optional_nonnegative_i64(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<Option<i64>, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value)
                .map(Some)
                .map_err(|_| DataModelError::InvalidCanonicalBody {
                    schema,
                    detail: "optional timestamp exceeds i64",
                })
        }
        _ => invalid(schema, detail),
    }
}

fn decode_optional_unsigned(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<Option<u64>, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Unsigned(value) => Ok(Some(*value)),
        _ => invalid(schema, detail),
    }
}

fn text(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<String, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Text(value) => Ok(value.clone()),
        _ => invalid(schema, detail),
    }
}

fn decode_optional_text(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<Option<String>, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Text(value) => Ok(Some(value.clone())),
        _ => invalid(schema, detail),
    }
}

fn fixed_bytes<const N: usize>(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<[u8; N], DataModelError> {
    let CanonicalValue::Bytes(value) = required(schema, value, detail)? else {
        return invalid(schema, detail);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| DataModelError::InvalidCanonicalBody { schema, detail })
}

fn nonnegative_integer(value: i64) -> Result<CanonicalValue, DataModelError> {
    let value = u64::try_from(value).map_err(|_| DataModelError::NegativeOccurredAt(value))?;
    Ok(CanonicalValue::Unsigned(value))
}

const fn signed_integer(value: i64) -> CanonicalValue {
    if value < 0 {
        CanonicalValue::Integer(value)
    } else {
        CanonicalValue::Unsigned(value as u64)
    }
}

fn decode_signed_integer(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<i64, DataModelError> {
    match required(schema, value, detail)? {
        CanonicalValue::Integer(value) => Ok(*value),
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| DataModelError::InvalidCanonicalBody {
                schema,
                detail: "signed integer exceeds i64",
            })
        }
        _ => invalid(schema, detail),
    }
}

fn optional_nonnegative_integer(value: Option<i64>) -> Result<CanonicalValue, DataModelError> {
    value.map_or(Ok(CanonicalValue::Null), nonnegative_integer)
}

fn optional_unsigned(value: Option<u64>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, CanonicalValue::Unsigned)
}

fn optional_text(value: Option<&str>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, |value| {
        CanonicalValue::Text(value.to_owned())
    })
}

const fn visibility_code(visibility: Visibility) -> u64 {
    match visibility {
        Visibility::Public => 0,
        Visibility::Private => 1,
    }
}

fn decode_visibility(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<Visibility, DataModelError> {
    match unsigned(schema, value, detail)? {
        0 => Ok(Visibility::Public),
        1 => Ok(Visibility::Private),
        _ => invalid(schema, "unknown visibility code"),
    }
}

const fn action_code(action: CapabilityAction) -> u64 {
    match action {
        CapabilityAction::AppendOperation => 0,
        CapabilityAction::IssueCapability => 1,
        CapabilityAction::RevokeCapability => 2,
        CapabilityAction::ReadSpace => 3,
        CapabilityAction::WriteContent => 4,
        CapabilityAction::LinkWorkspace => 5,
    }
}

fn decode_action(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<CapabilityAction, DataModelError> {
    match unsigned(schema, value, detail)? {
        0 => Ok(CapabilityAction::AppendOperation),
        1 => Ok(CapabilityAction::IssueCapability),
        2 => Ok(CapabilityAction::RevokeCapability),
        3 => Ok(CapabilityAction::ReadSpace),
        4 => Ok(CapabilityAction::WriteContent),
        5 => Ok(CapabilityAction::LinkWorkspace),
        _ => invalid(schema, "unknown capability action code"),
    }
}

const fn revocation_reason_code(reason: CapabilityRevocationReason) -> u64 {
    match reason {
        CapabilityRevocationReason::KeyCompromised => 0,
        CapabilityRevocationReason::DeviceLost => 1,
        CapabilityRevocationReason::KeyRotated => 2,
        CapabilityRevocationReason::ScopeChanged => 3,
        CapabilityRevocationReason::Administrative => 4,
    }
}

fn decode_revocation_reason(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
) -> Result<CapabilityRevocationReason, DataModelError> {
    match unsigned(schema, value, "revocation reason")? {
        0 => Ok(CapabilityRevocationReason::KeyCompromised),
        1 => Ok(CapabilityRevocationReason::DeviceLost),
        2 => Ok(CapabilityRevocationReason::KeyRotated),
        3 => Ok(CapabilityRevocationReason::ScopeChanged),
        4 => Ok(CapabilityRevocationReason::Administrative),
        _ => invalid(schema, "unknown revocation reason code"),
    }
}

fn invalid<T>(schema: EntitySchema, detail: &'static str) -> Result<T, DataModelError> {
    Err(DataModelError::InvalidCanonicalBody { schema, detail })
}
