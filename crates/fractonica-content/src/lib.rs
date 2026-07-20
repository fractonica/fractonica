#![forbid(unsafe_code)]
//! Pure content identities and bounded resource-reference values.
//!
//! This crate identifies immutable bytes. It deliberately does not know
//! whether those bytes are available on a filesystem, over a network, or in a
//! particular node's local content store.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Algorithm tag accepted by content identifiers.
pub const CONTENT_ALGORITHM: &str = "sha-256";
/// Number of digest bytes in a content identifier.
pub const CONTENT_ID_BYTES: usize = 32;
/// Exact byte length of `sha-256:` followed by 64 lowercase hexadecimal digits.
pub const CONTENT_ID_WIRE_LENGTH: usize = 72;
/// Maximum byte length representable by a resource reference (1 TiB).
pub const MAX_CONTENT_BYTE_LENGTH: u64 = 1_099_511_627_776;
/// Maximum byte length of a canonical media type.
pub const MAX_MEDIA_TYPE_BYTES: usize = 127;
/// Maximum byte length of a resource role token.
pub const MAX_RESOURCE_ROLE_BYTES: usize = 64;
/// Maximum number of Unicode scalar values in an original-name label.
pub const MAX_ORIGINAL_NAME_CHARS: usize = 255;

const CONTENT_ID_PREFIX: &str = "sha-256:";

/// A SHA-256 identity for immutable content bytes.
///
/// Its JSON representation is always one string in the exact form
/// `sha-256:` followed by 64 lowercase hexadecimal digits.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentId([u8; CONTENT_ID_BYTES]);

impl ContentId {
    #[must_use]
    pub const fn new(digest: [u8; CONTENT_ID_BYTES]) -> Self {
        Self(digest)
    }

    pub fn parse(value: &str) -> Result<Self, ContentIdParseError> {
        value.parse()
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTENT_ID_BYTES] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; CONTENT_ID_BYTES] {
        self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(CONTENT_ID_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ContentId {
    type Err = ContentIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((algorithm, digest)) = value.split_once(':') else {
            return Err(ContentIdParseError::MissingAlgorithmSeparator);
        };
        if algorithm != CONTENT_ALGORITHM {
            return Err(ContentIdParseError::UnsupportedAlgorithm(
                algorithm.to_owned(),
            ));
        }
        if value.len() != CONTENT_ID_WIRE_LENGTH || digest.len() != CONTENT_ID_BYTES * 2 {
            return Err(ContentIdParseError::InvalidLength {
                found: value.len(),
                expected: CONTENT_ID_WIRE_LENGTH,
            });
        }

        let mut bytes = [0_u8; CONTENT_ID_BYTES];
        for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] =
                (decode_hex(pair[0], index * 2)? << 4) | decode_hex(pair[1], index * 2 + 1)?;
        }
        Ok(Self(bytes))
    }
}

fn decode_hex(byte: u8, index: usize) -> Result<u8, ContentIdParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(ContentIdParseError::UppercaseHex { index }),
        _ => Err(ContentIdParseError::InvalidHex { index, byte }),
    }
}

impl Serialize for ContentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ContentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentIdVisitor;

        impl de::Visitor<'_> for ContentIdVisitor {
            type Value = ContentId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a lowercase sha-256 content identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ContentId::parse(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ContentIdVisitor)
    }
}

/// Computes the canonical identity of `bytes`.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> ContentId {
    ContentId::new(Sha256::digest(bytes).into())
}

/// Identity and asserted length of immutable content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentDescriptor {
    pub content_id: ContentId,
    pub byte_length: u64,
}

impl ContentDescriptor {
    pub fn validate(&self) -> Result<(), ContentValidationError> {
        validate_byte_length(self.byte_length)
    }
}

/// A record's semantic reference to immutable content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRef {
    pub content_id: ContentId,
    pub byte_length: u64,
    pub media_type: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
}

impl ResourceRef {
    #[must_use]
    pub const fn descriptor(&self) -> ContentDescriptor {
        ContentDescriptor {
            content_id: self.content_id,
            byte_length: self.byte_length,
        }
    }

    pub fn validate(&self) -> Result<(), ContentValidationError> {
        self.descriptor().validate()?;
        validate_media_type(&self.media_type)?;
        validate_role(&self.role)?;
        if let Some(original_name) = &self.original_name {
            validate_original_name(original_name)?;
        }
        Ok(())
    }
}

fn validate_byte_length(byte_length: u64) -> Result<(), ContentValidationError> {
    if byte_length > MAX_CONTENT_BYTE_LENGTH {
        Err(ContentValidationError::ContentTooLarge {
            byte_length,
            maximum: MAX_CONTENT_BYTE_LENGTH,
        })
    } else {
        Ok(())
    }
}

fn validate_media_type(media_type: &str) -> Result<(), ContentValidationError> {
    if media_type.is_empty() || media_type.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(ContentValidationError::InvalidMediaType {
            value: media_type.to_owned(),
            maximum: MAX_MEDIA_TYPE_BYTES,
        });
    }
    let bytes = media_type.as_bytes();
    if !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(ContentValidationError::InvalidMediaType {
            value: media_type.to_owned(),
            maximum: MAX_MEDIA_TYPE_BYTES,
        });
    }
    let mut components = media_type.split('/');
    let Some(r#type) = components.next() else {
        return Err(ContentValidationError::InvalidMediaType {
            value: media_type.to_owned(),
            maximum: MAX_MEDIA_TYPE_BYTES,
        });
    };
    let Some(subtype) = components.next() else {
        return Err(ContentValidationError::InvalidMediaType {
            value: media_type.to_owned(),
            maximum: MAX_MEDIA_TYPE_BYTES,
        });
    };
    if components.next().is_some()
        || r#type.is_empty()
        || subtype.is_empty()
        || !r#type.bytes().all(is_media_token_byte)
        || !subtype.bytes().all(is_media_token_byte)
    {
        return Err(ContentValidationError::InvalidMediaType {
            value: media_type.to_owned(),
            maximum: MAX_MEDIA_TYPE_BYTES,
        });
    }
    Ok(())
}

const fn is_media_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_role(role: &str) -> Result<(), ContentValidationError> {
    if role.is_empty()
        || role.len() > MAX_RESOURCE_ROLE_BYTES
        || !role.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ContentValidationError::InvalidRole {
            value: role.to_owned(),
            maximum: MAX_RESOURCE_ROLE_BYTES,
        });
    }
    Ok(())
}

fn validate_original_name(original_name: &str) -> Result<(), ContentValidationError> {
    let length = original_name.chars().count();
    if length == 0
        || length > MAX_ORIGINAL_NAME_CHARS
        || original_name == "."
        || original_name == ".."
        || original_name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        return Err(ContentValidationError::InvalidOriginalName {
            value: original_name.to_owned(),
            maximum: MAX_ORIGINAL_NAME_CHARS,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContentIdParseError {
    #[error("content ID must contain an algorithm separator")]
    MissingAlgorithmSeparator,
    #[error("unsupported content ID algorithm {0:?}; Fractonica accepts only sha-256")]
    UnsupportedAlgorithm(String),
    #[error("content ID has {found} bytes; expected exactly {expected}")]
    InvalidLength { found: usize, expected: usize },
    #[error("content ID contains uppercase hexadecimal at digest offset {index}")]
    UppercaseHex { index: usize },
    #[error("content ID contains invalid byte 0x{byte:02x} at digest offset {index}")]
    InvalidHex { index: usize, byte: u8 },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContentValidationError {
    #[error("content length {byte_length} exceeds maximum {maximum}")]
    ContentTooLarge { byte_length: u64, maximum: u64 },
    #[error("media type {value:?} must be a visible ASCII type/subtype of at most {maximum} bytes")]
    InvalidMediaType { value: String, maximum: usize },
    #[error("resource role {value:?} must be a lowercase ASCII token of at most {maximum} bytes")]
    InvalidRole { value: String, maximum: usize },
    #[error(
        "original name {value:?} must be a path-free label of 1..={maximum} non-control characters"
    )]
    InvalidOriginalName { value: String, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EMPTY_SHA256: &str =
        "sha-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn resource() -> ResourceRef {
        ResourceRef {
            content_id: hash_bytes(b"photo"),
            byte_length: 5,
            media_type: "image/jpeg".into(),
            role: "primary-photo".into(),
            original_name: Some("eclipse photo.jpeg".into()),
        }
    }

    #[test]
    fn hash_and_wire_form_match_the_sha256_fixture() {
        let id = hash_bytes(b"");
        assert_eq!(id.to_string(), EMPTY_SHA256);
        assert_eq!(ContentId::parse(EMPTY_SHA256), Ok(id));
        assert_eq!(id.as_bytes().len(), CONTENT_ID_BYTES);
    }

    #[test]
    fn serde_is_exactly_one_transparent_string() {
        let id = hash_bytes(b"");
        assert_eq!(
            serde_json::to_value(id).expect("serialize"),
            json!(EMPTY_SHA256)
        );
        assert_eq!(
            serde_json::from_value::<ContentId>(json!(EMPTY_SHA256)).expect("deserialize"),
            id
        );
        assert!(serde_json::from_value::<ContentId>(json!({ "digest": EMPTY_SHA256 })).is_err());
    }

    #[test]
    fn parser_rejects_unknown_algorithm_uppercase_and_malformed_lengths() {
        assert!(matches!(
            ContentId::parse(&EMPTY_SHA256.replacen("sha-256", "blake3", 1)),
            Err(ContentIdParseError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            ContentId::parse(&EMPTY_SHA256.to_ascii_uppercase()),
            Err(ContentIdParseError::UnsupportedAlgorithm(_))
        ));
        let uppercase_digest = EMPTY_SHA256.replacen('e', "E", 1);
        assert!(matches!(
            ContentId::parse(&uppercase_digest),
            Err(ContentIdParseError::UppercaseHex { .. })
        ));
        assert!(matches!(
            ContentId::parse("sha-256:00"),
            Err(ContentIdParseError::InvalidLength { .. })
        ));
        assert!(matches!(
            ContentId::parse(&EMPTY_SHA256.replace('e', "g")),
            Err(ContentIdParseError::InvalidHex { .. })
        ));
    }

    #[test]
    fn descriptor_and_resource_serde_are_camel_case() {
        let resource = resource();
        assert_eq!(resource.descriptor().byte_length, 5);
        let value = serde_json::to_value(&resource).expect("serialize resource");
        assert_eq!(value["contentId"], resource.content_id.to_string());
        assert_eq!(value["byteLength"], 5);
        assert_eq!(value["mediaType"], "image/jpeg");
        assert_eq!(value["role"], "primary-photo");
        assert_eq!(value["originalName"], "eclipse photo.jpeg");
        assert_eq!(
            serde_json::from_value::<ResourceRef>(value).expect("deserialize resource"),
            resource
        );
    }

    #[test]
    fn validates_media_type_role_name_and_length_strictly() {
        assert!(resource().validate().is_ok());

        for invalid in [
            "image",
            "image/",
            "/jpeg",
            "image/jpeg/extra",
            "image/jpeg; q=1",
            "image /jpeg",
        ] {
            let mut value = resource();
            value.media_type = invalid.into();
            assert!(matches!(
                value.validate(),
                Err(ContentValidationError::InvalidMediaType { .. })
            ));
        }

        let mut uppercase_role = resource();
        uppercase_role.role = "Primary".into();
        assert!(matches!(
            uppercase_role.validate(),
            Err(ContentValidationError::InvalidRole { .. })
        ));

        for invalid in [
            "../photo.jpg",
            "folder/photo.jpg",
            "folder\\photo.jpg",
            "C:photo.jpg",
        ] {
            let mut value = resource();
            value.original_name = Some(invalid.into());
            assert!(matches!(
                value.validate(),
                Err(ContentValidationError::InvalidOriginalName { .. })
            ));
        }

        let mut too_large = resource();
        too_large.byte_length = MAX_CONTENT_BYTE_LENGTH + 1;
        assert!(matches!(
            too_large.validate(),
            Err(ContentValidationError::ContentTooLarge { .. })
        ));
    }

    #[test]
    fn empty_content_is_valid() {
        assert!(
            ContentDescriptor {
                content_id: hash_bytes(b""),
                byte_length: 0,
            }
            .validate()
            .is_ok()
        );
    }
}
