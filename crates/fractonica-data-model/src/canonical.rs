use std::collections::BTreeMap;

use fractonica_content::{ContentId, ResourceRef};
use fractonica_trust::CanonicalValue;
use serde_json::{Map, Number, Value};

use super::{
    ActorId, CapabilityAction, CapabilityGrant, CapabilityRevocation, CapabilityRevocationReason,
    DataModelError, EntitySchema, OperationBody, OperationId, RecordDocument, RecordVisibility,
};

const BODY_TOMBSTONE: u64 = 0;
const BODY_RECORD_PUT: u64 = 1;
const BODY_SPACE_GENESIS: u64 = 2;
const BODY_CAPABILITY_GRANT: u64 = 3;
const BODY_CAPABILITY_REVOKE: u64 = 4;

pub(super) fn encode_body(
    schema: EntitySchema,
    body: &OperationBody,
) -> Result<CanonicalValue, DataModelError> {
    match (schema, body) {
        (EntitySchema::RecordV1, OperationBody::Tombstone) => {
            Ok(CanonicalValue::Array(vec![CanonicalValue::Unsigned(
                BODY_TOMBSTONE,
            )]))
        }
        (EntitySchema::RecordV1, OperationBody::Put { document }) => encode_record_put(document),
        (EntitySchema::SpaceGenesisV1, OperationBody::SpaceGenesis { controller }) => {
            Ok(CanonicalValue::Array(vec![
                CanonicalValue::Unsigned(BODY_SPACE_GENESIS),
                CanonicalValue::Bytes(controller.as_bytes().to_vec()),
            ]))
        }
        (EntitySchema::CapabilityGrantV1, OperationBody::CapabilityGrant { grant }) => {
            encode_capability_grant(grant)
        }
        (EntitySchema::CapabilityRevokeV1, OperationBody::CapabilityRevoke { revocation }) => {
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
        (EntitySchema::RecordV1, BODY_TOMBSTONE) if fields.len() == 1 => {
            Ok(OperationBody::Tombstone)
        }
        (EntitySchema::RecordV1, BODY_RECORD_PUT) => decode_record_put(schema, fields),
        (EntitySchema::SpaceGenesisV1, BODY_SPACE_GENESIS) if fields.len() == 2 => {
            let controller =
                ActorId::from_bytes(fixed_bytes(schema, fields.get(1), "genesis controller")?);
            controller.public_key()?;
            Ok(OperationBody::SpaceGenesis { controller })
        }
        (EntitySchema::CapabilityGrantV1, BODY_CAPABILITY_GRANT) => {
            decode_capability_grant(schema, fields)
        }
        (EntitySchema::CapabilityRevokeV1, BODY_CAPABILITY_REVOKE) => {
            decode_capability_revocation(schema, fields)
        }
        _ => invalid(schema, "body kind does not match schema"),
    }
}

fn encode_record_put(document: &RecordDocument) -> Result<CanonicalValue, DataModelError> {
    let resources = document
        .resources
        .iter()
        .map(encode_resource)
        .collect::<Vec<_>>();
    Ok(CanonicalValue::Array(vec![
        CanonicalValue::Unsigned(BODY_RECORD_PUT),
        nonnegative_integer(document.start_at_unix_ms)?,
        optional_nonnegative_integer(document.end_at_unix_ms)?,
        CanonicalValue::Unsigned(visibility_code(document.visibility)),
        optional_text(document.emoji.as_deref()),
        optional_text(document.text.as_deref()),
        encode_metadata_object(&document.metadata)?,
        CanonicalValue::Array(resources),
    ]))
}

fn decode_record_put(
    schema: EntitySchema,
    fields: &[CanonicalValue],
) -> Result<OperationBody, DataModelError> {
    if fields.len() != 8 {
        return invalid(schema, "record put must contain exactly eight fields");
    }
    let start_at_unix_ms = nonnegative_i64(schema, fields.get(1), "record start")?;
    let end_at_unix_ms = optional_nonnegative_i64(schema, fields.get(2), "record end")?;
    let visibility = decode_visibility(schema, fields.get(3), "record visibility")?;
    let emoji = decode_optional_text(schema, fields.get(4), "record emoji")?;
    let text = decode_optional_text(schema, fields.get(5), "record text")?;
    let metadata = decode_metadata_object(schema, fields.get(6))?;
    let CanonicalValue::Array(resources) = required(schema, fields.get(7), "record resources")?
    else {
        return invalid(schema, "record resources must be an array");
    };
    let resources = resources
        .iter()
        .map(|resource| decode_resource(schema, resource))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationBody::Put {
        document: RecordDocument {
            start_at_unix_ms,
            end_at_unix_ms,
            visibility,
            emoji,
            text,
            metadata,
            resources,
        },
    })
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
        .record_visibilities
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
    let record_visibilities = decode_array(
        schema,
        fields.get(4),
        "grant record visibilities",
        |value| decode_visibility(schema, Some(value), "grant record visibility"),
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
            record_visibilities,
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

const fn visibility_code(visibility: RecordVisibility) -> u64 {
    match visibility {
        RecordVisibility::Public => 0,
        RecordVisibility::Private => 1,
    }
}

fn decode_visibility(
    schema: EntitySchema,
    value: Option<&CanonicalValue>,
    detail: &'static str,
) -> Result<RecordVisibility, DataModelError> {
    match unsigned(schema, value, detail)? {
        0 => Ok(RecordVisibility::Public),
        1 => Ok(RecordVisibility::Private),
        _ => invalid(schema, "unknown record visibility code"),
    }
}

const fn action_code(action: CapabilityAction) -> u64 {
    match action {
        CapabilityAction::AppendOperation => 0,
        CapabilityAction::IssueCapability => 1,
        CapabilityAction::RevokeCapability => 2,
        CapabilityAction::ReadSpace => 3,
        CapabilityAction::WriteContent => 4,
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
