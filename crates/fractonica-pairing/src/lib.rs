#![forbid(unsafe_code)]
//! Bounded, domain-separated Fractonica pairing primitives.
//!
//! This crate owns deterministic QR/claim/receipt messages and the fixed Noise
//! handshake adapter. It deliberately does not own HTTP, persistence,
//! capability admission, user confirmation, or network exposure.

use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fractonica_data_model::{CapabilityAction, CapabilityGrant, EntitySchema, Visibility};
use fractonica_trust::{
    ActorId, CanonicalCborError, CanonicalValue, DetachedSignature, DetachedSignatureDomain,
    NodeId, OperationId, SigningKey, SpaceId, TrustError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use thiserror::Error;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroize;

pub const PAIRING_PROTOCOL_VERSION: u64 = 1;
pub const INVITATION_VERSION: u64 = 1;
pub const NOISE_PROTOCOL_NAME: &str = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";
pub const QR_PREFIX: &str = "fractonica-pairing:v1:";
pub const MAX_QR_CBOR_BYTES: usize = 4 * 1_024;
pub const MAX_CANONICAL_MESSAGE_BYTES: usize = 4 * 1_024;
pub const MAX_NOISE_FRAME_BYTES: usize = 8 * 1_024;
pub const MAX_ENDPOINT_HINTS: usize = 3;
pub const MAX_ENDPOINT_HINT_BYTES: usize = 256;
pub const MIN_INVITATION_LIFETIME_MS: i64 = 1_000;
pub const MAX_INVITATION_LIFETIME_MS: i64 = 10 * 60 * 1_000;

const DIGEST_BYTES: usize = 32;
const INVITATION_ID_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;
const CONFIRMATION_DOMAIN: &[u8] = b"org.fractonica.pairing.confirmation.v1";
const RESPONDER_SECRET_VERSION: u8 = 1;
const RESPONDER_SECRET_BYTES: usize =
    1 + INVITATION_ID_BYTES + DIGEST_BYTES + SECRET_BYTES + SECRET_BYTES;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvitationId([u8; INVITATION_ID_BYTES]);

impl InvitationId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; INVITATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; INVITATION_ID_BYTES] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self, PairingError> {
        if value.len() != INVITATION_ID_BYTES * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PairingError::InvalidField("invitationId"));
        }
        let mut bytes = [0_u8; INVITATION_ID_BYTES];
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| PairingError::InvalidField("invitationId"))?;
        }
        if bytes == [0; INVITATION_ID_BYTES] {
            return Err(PairingError::InvalidField("invitationId"));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for InvitationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for InvitationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Capability fields fixed by an invitation before the joining actor is known.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityGrantTemplate {
    pub actions: Vec<CapabilityAction>,
    pub schemas: Vec<EntitySchema>,
    pub visibilities: Vec<Visibility>,
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

impl CapabilityGrantTemplate {
    pub fn normalize(&mut self) {
        self.actions.sort_unstable();
        self.schemas.sort_by_key(|schema| schema.as_str());
        self.visibilities.sort_unstable();
        self.content_roles.sort_unstable();
    }

    pub fn to_grant(&self, subject: ActorId) -> Result<CapabilityGrant, PairingError> {
        let grant = CapabilityGrant {
            subject,
            actions: self.actions.clone(),
            schemas: self.schemas.clone(),
            visibilities: self.visibilities.clone(),
            content_roles: self.content_roles.clone(),
            max_resource_byte_length: self.max_resource_byte_length,
            not_before_unix_ms: self.not_before_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            delegation_depth: self.delegation_depth,
            label: self.label.clone(),
        };
        grant.validate()?;
        Ok(grant)
    }

    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                key(0),
                CanonicalValue::Array(
                    self.actions
                        .iter()
                        .map(|action| CanonicalValue::Unsigned(action_code(*action)))
                        .collect(),
                ),
            ),
            (
                key(1),
                CanonicalValue::Array(
                    self.schemas
                        .iter()
                        .map(|schema| CanonicalValue::Text(schema.as_str().to_owned()))
                        .collect(),
                ),
            ),
            (
                key(2),
                CanonicalValue::Array(
                    self.visibilities
                        .iter()
                        .map(|visibility| CanonicalValue::Unsigned(visibility_code(*visibility)))
                        .collect(),
                ),
            ),
            (
                key(3),
                CanonicalValue::Array(
                    self.content_roles
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Text)
                        .collect(),
                ),
            ),
            (key(4), optional_unsigned(self.max_resource_byte_length)),
            (key(5), optional_integer(self.not_before_unix_ms)),
            (key(6), optional_integer(self.expires_at_unix_ms)),
            (
                key(7),
                CanonicalValue::Unsigned(u64::from(self.delegation_depth)),
            ),
            (key(8), CanonicalValue::Text(self.label.clone())),
        ])
    }

    fn from_canonical(value: CanonicalValue) -> Result<Self, PairingError> {
        let mut map = exact_map(value, 9)?;
        let mut template = Self {
            actions: array(take(&mut map, 0)?)?
                .into_iter()
                .map(|value| action_from_code(unsigned(value)?))
                .collect::<Result<_, _>>()?,
            schemas: array(take(&mut map, 1)?)?
                .into_iter()
                .map(|value| schema_from_text(text(value)?))
                .collect::<Result<_, _>>()?,
            visibilities: array(take(&mut map, 2)?)?
                .into_iter()
                .map(|value| visibility_from_code(unsigned(value)?))
                .collect::<Result<_, _>>()?,
            content_roles: array(take(&mut map, 3)?)?
                .into_iter()
                .map(text)
                .collect::<Result<_, _>>()?,
            max_resource_byte_length: optional_unsigned_from(take(&mut map, 4)?)?,
            not_before_unix_ms: optional_integer_from(take(&mut map, 5)?)?,
            expires_at_unix_ms: optional_integer_from(take(&mut map, 6)?)?,
            delegation_depth: unsigned(take(&mut map, 7)?)?
                .try_into()
                .map_err(|_| PairingError::InvalidField("delegation depth"))?,
            label: text(take(&mut map, 8)?)?,
        };
        let original = template.clone();
        template.normalize();
        if template != original {
            return Err(PairingError::NonCanonicalSet("capability template"));
        }
        Ok(template)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationDescriptor {
    pub invitation_id: InvitationId,
    pub responder_node_id: NodeId,
    pub responder_noise_static: [u8; DIGEST_BYTES],
    pub space_id: SpaceId,
    pub genesis_operation_id: OperationId,
    pub expires_at_unix_ms: i64,
    pub endpoint_hints: Vec<String>,
    pub capability: CapabilityGrantTemplate,
    pub secret_commitment: [u8; DIGEST_BYTES],
}

impl InvitationDescriptor {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = self.canonical_value().to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    /// Decodes an exact standalone descriptor from deterministic CBOR.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        ensure_canonical_bound(bytes)?;
        Self::from_canonical(CanonicalValue::from_canonical_cbor(bytes)?)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; DIGEST_BYTES] {
        Sha256::digest(
            self.canonical_bytes()
                .expect("validated descriptor remains encodable"),
        )
        .into()
    }

    fn validate(&self) -> Result<(), PairingError> {
        self.responder_node_id.public_key()?;
        SpaceId::parse(&self.space_id.to_string())
            .map_err(|_| PairingError::InvalidField("spaceId"))?;
        if self.invitation_id.as_bytes() == &[0; INVITATION_ID_BYTES] {
            return Err(PairingError::InvalidField("invitationId"));
        }
        if self.responder_noise_static == [0; DIGEST_BYTES] {
            return Err(PairingError::InvalidField("responderNoiseStatic"));
        }
        if self.expires_at_unix_ms < 0 {
            return Err(PairingError::InvalidField("expiresAtUnixMs"));
        }
        validate_endpoint_hints(&self.endpoint_hints)?;
        self.capability
            .to_grant(ActorId::from_bytes(*self.responder_node_id.as_bytes()))?;
        self.canonical_bytes()?;
        Ok(())
    }

    fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (key(0), CanonicalValue::Unsigned(PAIRING_PROTOCOL_VERSION)),
            (key(1), CanonicalValue::Unsigned(INVITATION_VERSION)),
            (
                key(2),
                CanonicalValue::Bytes(self.invitation_id.as_bytes().to_vec()),
            ),
            (key(3), CanonicalValue::Text(NOISE_PROTOCOL_NAME.to_owned())),
            (
                key(4),
                CanonicalValue::Bytes(self.responder_node_id.as_bytes().to_vec()),
            ),
            (
                key(5),
                CanonicalValue::Bytes(self.responder_noise_static.to_vec()),
            ),
            (
                key(6),
                CanonicalValue::Bytes(self.space_id.as_bytes().to_vec()),
            ),
            (
                key(7),
                CanonicalValue::Bytes(self.genesis_operation_id.as_bytes().to_vec()),
            ),
            (key(8), CanonicalValue::Integer(self.expires_at_unix_ms)),
            (
                key(9),
                CanonicalValue::Array(
                    self.endpoint_hints
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Text)
                        .collect(),
                ),
            ),
            (key(10), self.capability.canonical_value()),
            (
                key(11),
                CanonicalValue::Bytes(self.secret_commitment.to_vec()),
            ),
        ])
    }

    fn from_canonical(value: CanonicalValue) -> Result<Self, PairingError> {
        let mut map = exact_map(value, 12)?;
        require_version(unsigned(take(&mut map, 0)?)?, PAIRING_PROTOCOL_VERSION)?;
        require_version(unsigned(take(&mut map, 1)?)?, INVITATION_VERSION)?;
        let descriptor = Self {
            invitation_id: InvitationId::from_bytes(fixed_bytes(take(&mut map, 2)?)?),
            responder_node_id: NodeId::from_bytes(fixed_bytes(take(&mut map, 4)?)?),
            responder_noise_static: fixed_bytes(take(&mut map, 5)?)?,
            space_id: SpaceId::from_bytes(fixed_bytes(take(&mut map, 6)?)?),
            genesis_operation_id: OperationId::from_bytes(fixed_bytes(take(&mut map, 7)?)?),
            expires_at_unix_ms: integer(take(&mut map, 8)?)?,
            endpoint_hints: array(take(&mut map, 9)?)?
                .into_iter()
                .map(text)
                .collect::<Result<_, _>>()?,
            capability: CapabilityGrantTemplate::from_canonical(take(&mut map, 10)?)?,
            secret_commitment: fixed_bytes(take(&mut map, 11)?)?,
        };
        if text(take(&mut map, 3)?)? != NOISE_PROTOCOL_NAME {
            return Err(PairingError::UnsupportedNoiseProtocol);
        }
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// Canonical proof that the joining device owns distinct node and actor keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinerClaim {
    pub invitation_id: InvitationId,
    pub descriptor_digest: [u8; DIGEST_BYTES],
    pub responder_node_id: NodeId,
    pub space_id: SpaceId,
    pub genesis_operation_id: OperationId,
    pub joiner_node_id: NodeId,
    pub subject_actor_id: ActorId,
    pub nonce: [u8; DIGEST_BYTES],
    node_signature: DetachedSignature,
    actor_signature: DetachedSignature,
}

impl JoinerClaim {
    #[must_use]
    pub fn sign(
        descriptor: &InvitationDescriptor,
        joiner_node_key: &SigningKey,
        subject_actor_key: &SigningKey,
        nonce: [u8; DIGEST_BYTES],
    ) -> Self {
        let mut claim = Self {
            invitation_id: descriptor.invitation_id,
            descriptor_digest: descriptor.digest(),
            responder_node_id: descriptor.responder_node_id,
            space_id: descriptor.space_id,
            genesis_operation_id: descriptor.genesis_operation_id,
            joiner_node_id: joiner_node_key.node_id(),
            subject_actor_id: subject_actor_key.actor_id(),
            nonce,
            node_signature: DetachedSignature::from_bytes([0; 64]),
            actor_signature: DetachedSignature::from_bytes([0; 64]),
        };
        let unsigned = claim
            .unsigned_bytes()
            .expect("fixed-size claim remains canonically encodable");
        claim.node_signature =
            joiner_node_key.sign_detached(DetachedSignatureDomain::PairingJoinerClaimV1, &unsigned);
        claim.actor_signature = subject_actor_key
            .sign_detached(DetachedSignatureDomain::PairingJoinerClaimV1, &unsigned);
        claim
    }

    pub fn verify_for(&self, descriptor: &InvitationDescriptor) -> Result<(), PairingError> {
        if self.invitation_id != descriptor.invitation_id
            || self.descriptor_digest != descriptor.digest()
            || self.responder_node_id != descriptor.responder_node_id
            || self.space_id != descriptor.space_id
            || self.genesis_operation_id != descriptor.genesis_operation_id
        {
            return Err(PairingError::ClaimInvitationMismatch);
        }
        if self.nonce == [0; DIGEST_BYTES] {
            return Err(PairingError::InvalidField("claim nonce"));
        }
        let unsigned = self.unsigned_bytes()?;
        self.joiner_node_id.verify_detached(
            DetachedSignatureDomain::PairingJoinerClaimV1,
            &unsigned,
            &self.node_signature,
        )?;
        self.subject_actor_id.verify_detached(
            DetachedSignatureDomain::PairingJoinerClaimV1,
            &unsigned,
            &self.actor_signature,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = CanonicalValue::Map(vec![
            (key(0), self.unsigned_value()),
            (
                key(1),
                CanonicalValue::Bytes(self.node_signature.as_bytes().to_vec()),
            ),
            (
                key(2),
                CanonicalValue::Bytes(self.actor_signature.as_bytes().to_vec()),
            ),
        ])
        .to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        ensure_canonical_bound(bytes)?;
        let mut envelope = exact_map(CanonicalValue::from_canonical_cbor(bytes)?, 3)?;
        let mut fields = exact_map(take(&mut envelope, 0)?, 9)?;
        require_version(unsigned(take(&mut fields, 0)?)?, PAIRING_PROTOCOL_VERSION)?;
        let claim = Self {
            invitation_id: InvitationId::from_bytes(fixed_bytes(take(&mut fields, 1)?)?),
            descriptor_digest: fixed_bytes(take(&mut fields, 2)?)?,
            responder_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 3)?)?),
            space_id: SpaceId::from_bytes(fixed_bytes(take(&mut fields, 4)?)?),
            genesis_operation_id: OperationId::from_bytes(fixed_bytes(take(&mut fields, 5)?)?),
            joiner_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 6)?)?),
            subject_actor_id: ActorId::from_bytes(fixed_bytes(take(&mut fields, 7)?)?),
            nonce: fixed_bytes(take(&mut fields, 8)?)?,
            node_signature: DetachedSignature::from_bytes(fixed_bytes(take(&mut envelope, 1)?)?),
            actor_signature: DetachedSignature::from_bytes(fixed_bytes(take(&mut envelope, 2)?)?),
        };
        claim.joiner_node_id.public_key()?;
        claim.subject_actor_id.public_key()?;
        if claim.nonce == [0; DIGEST_BYTES] {
            return Err(PairingError::InvalidField("claim nonce"));
        }
        Ok(claim)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; DIGEST_BYTES] {
        Sha256::digest(
            self.canonical_bytes()
                .expect("validated claim remains canonically encodable"),
        )
        .into()
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = self.unsigned_value().to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (key(0), CanonicalValue::Unsigned(PAIRING_PROTOCOL_VERSION)),
            (
                key(1),
                CanonicalValue::Bytes(self.invitation_id.as_bytes().to_vec()),
            ),
            (
                key(2),
                CanonicalValue::Bytes(self.descriptor_digest.to_vec()),
            ),
            (
                key(3),
                CanonicalValue::Bytes(self.responder_node_id.as_bytes().to_vec()),
            ),
            (
                key(4),
                CanonicalValue::Bytes(self.space_id.as_bytes().to_vec()),
            ),
            (
                key(5),
                CanonicalValue::Bytes(self.genesis_operation_id.as_bytes().to_vec()),
            ),
            (
                key(6),
                CanonicalValue::Bytes(self.joiner_node_id.as_bytes().to_vec()),
            ),
            (
                key(7),
                CanonicalValue::Bytes(self.subject_actor_id.as_bytes().to_vec()),
            ),
            (key(8), CanonicalValue::Bytes(self.nonce.to_vec())),
        ])
    }
}

/// Responder identity proof bound to the completed Noise transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingReceipt {
    pub invitation_id: InvitationId,
    pub descriptor_digest: [u8; DIGEST_BYTES],
    pub claim_digest: [u8; DIGEST_BYTES],
    pub handshake_hash: [u8; DIGEST_BYTES],
    pub responder_node_id: NodeId,
    pub joiner_node_id: NodeId,
    peer_access_token: [u8; 32],
    signature: DetachedSignature,
}

impl std::fmt::Debug for PairingReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingReceipt")
            .field("invitation_id", &self.invitation_id)
            .field("descriptor_digest", &self.descriptor_digest)
            .field("claim_digest", &self.claim_digest)
            .field("handshake_hash", &self.handshake_hash)
            .field("responder_node_id", &self.responder_node_id)
            .field("joiner_node_id", &self.joiner_node_id)
            .field("peer_access_token", &"[REDACTED]")
            .field("signature", &self.signature)
            .finish()
    }
}

impl PairingReceipt {
    #[must_use]
    pub fn sign(
        descriptor: &InvitationDescriptor,
        claim: &JoinerClaim,
        handshake_hash: [u8; DIGEST_BYTES],
        peer_access_token: [u8; 32],
        responder_node_key: &SigningKey,
    ) -> Self {
        let mut receipt = Self {
            invitation_id: descriptor.invitation_id,
            descriptor_digest: descriptor.digest(),
            claim_digest: claim.digest(),
            handshake_hash,
            responder_node_id: responder_node_key.node_id(),
            joiner_node_id: claim.joiner_node_id,
            peer_access_token,
            signature: DetachedSignature::from_bytes([0; 64]),
        };
        receipt.signature = responder_node_key.sign_detached(
            DetachedSignatureDomain::PairingReceiptV1,
            &receipt
                .unsigned_bytes()
                .expect("fixed-size receipt remains canonically encodable"),
        );
        receipt
    }

    /// Returns the random transport credential delivered only inside the
    /// encrypted Noise session. Callers must never log or display these bytes.
    #[must_use]
    pub const fn peer_access_token(&self) -> &[u8; 32] {
        &self.peer_access_token
    }

    pub fn verify_for(
        &self,
        descriptor: &InvitationDescriptor,
        claim: &JoinerClaim,
        handshake_hash: &[u8; DIGEST_BYTES],
    ) -> Result<(), PairingError> {
        if self.invitation_id != descriptor.invitation_id
            || self.descriptor_digest != descriptor.digest()
            || self.claim_digest != claim.digest()
            || &self.handshake_hash != handshake_hash
            || self.responder_node_id != descriptor.responder_node_id
            || self.joiner_node_id != claim.joiner_node_id
        {
            return Err(PairingError::ReceiptTranscriptMismatch);
        }
        self.responder_node_id.verify_detached(
            DetachedSignatureDomain::PairingReceiptV1,
            &self.unsigned_bytes()?,
            &self.signature,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = CanonicalValue::Map(vec![
            (key(0), self.unsigned_value()),
            (
                key(1),
                CanonicalValue::Bytes(self.signature.as_bytes().to_vec()),
            ),
        ])
        .to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        ensure_canonical_bound(bytes)?;
        let mut envelope = exact_map(CanonicalValue::from_canonical_cbor(bytes)?, 2)?;
        let mut fields = exact_map(take(&mut envelope, 0)?, 8)?;
        require_version(unsigned(take(&mut fields, 0)?)?, PAIRING_PROTOCOL_VERSION)?;
        Ok(Self {
            invitation_id: InvitationId::from_bytes(fixed_bytes(take(&mut fields, 1)?)?),
            descriptor_digest: fixed_bytes(take(&mut fields, 2)?)?,
            claim_digest: fixed_bytes(take(&mut fields, 3)?)?,
            handshake_hash: fixed_bytes(take(&mut fields, 4)?)?,
            responder_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 5)?)?),
            joiner_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 6)?)?),
            peer_access_token: fixed_bytes(take(&mut fields, 7)?)?,
            signature: DetachedSignature::from_bytes(fixed_bytes(take(&mut envelope, 1)?)?),
        })
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = self.unsigned_value().to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (key(0), CanonicalValue::Unsigned(PAIRING_PROTOCOL_VERSION)),
            (
                key(1),
                CanonicalValue::Bytes(self.invitation_id.as_bytes().to_vec()),
            ),
            (
                key(2),
                CanonicalValue::Bytes(self.descriptor_digest.to_vec()),
            ),
            (key(3), CanonicalValue::Bytes(self.claim_digest.to_vec())),
            (key(4), CanonicalValue::Bytes(self.handshake_hash.to_vec())),
            (
                key(5),
                CanonicalValue::Bytes(self.responder_node_id.as_bytes().to_vec()),
            ),
            (
                key(6),
                CanonicalValue::Bytes(self.joiner_node_id.as_bytes().to_vec()),
            ),
            (
                key(7),
                CanonicalValue::Bytes(self.peer_access_token.to_vec()),
            ),
        ])
    }
}

/// Dual-signed human acceptance of the exact Noise transcript shown on both
/// devices. Possession of the QR secret can claim an invitation, but cannot
/// admit its planned capability grant without this second, domain-separated
/// proof from the joining node and actor keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingAcceptance {
    pub invitation_id: InvitationId,
    pub claim_digest: [u8; DIGEST_BYTES],
    pub handshake_hash: [u8; DIGEST_BYTES],
    pub responder_node_id: NodeId,
    pub space_id: SpaceId,
    pub joiner_node_id: NodeId,
    pub subject_actor_id: ActorId,
    pub grant_operation_id: OperationId,
    pub nonce: [u8; DIGEST_BYTES],
    node_signature: DetachedSignature,
    actor_signature: DetachedSignature,
}

impl PairingAcceptance {
    #[must_use]
    pub fn sign(
        invitation_id: InvitationId,
        claim_digest: [u8; DIGEST_BYTES],
        handshake_hash: [u8; DIGEST_BYTES],
        responder_node_id: NodeId,
        space_id: SpaceId,
        grant_operation_id: OperationId,
        joiner_node_key: &SigningKey,
        subject_actor_key: &SigningKey,
        nonce: [u8; DIGEST_BYTES],
    ) -> Self {
        let mut acceptance = Self {
            invitation_id,
            claim_digest,
            handshake_hash,
            responder_node_id,
            space_id,
            joiner_node_id: joiner_node_key.node_id(),
            subject_actor_id: subject_actor_key.actor_id(),
            grant_operation_id,
            nonce,
            node_signature: DetachedSignature::from_bytes([0; 64]),
            actor_signature: DetachedSignature::from_bytes([0; 64]),
        };
        let unsigned = acceptance
            .unsigned_bytes()
            .expect("fixed-size acceptance remains canonically encodable");
        acceptance.node_signature =
            joiner_node_key.sign_detached(DetachedSignatureDomain::PairingAcceptanceV1, &unsigned);
        acceptance.actor_signature = subject_actor_key
            .sign_detached(DetachedSignatureDomain::PairingAcceptanceV1, &unsigned);
        acceptance
    }

    pub fn verify_for(
        &self,
        descriptor: &InvitationDescriptor,
        claim_digest: &[u8; DIGEST_BYTES],
        handshake_hash: &[u8; DIGEST_BYTES],
        joiner_node_id: NodeId,
        subject_actor_id: ActorId,
        grant_operation_id: OperationId,
    ) -> Result<(), PairingError> {
        if self.invitation_id != descriptor.invitation_id
            || &self.claim_digest != claim_digest
            || &self.handshake_hash != handshake_hash
            || self.responder_node_id != descriptor.responder_node_id
            || self.space_id != descriptor.space_id
            || self.joiner_node_id != joiner_node_id
            || self.subject_actor_id != subject_actor_id
            || self.grant_operation_id != grant_operation_id
            || self.nonce == [0; DIGEST_BYTES]
        {
            return Err(PairingError::AcceptanceMismatch);
        }
        let unsigned = self.unsigned_bytes()?;
        self.joiner_node_id.verify_detached(
            DetachedSignatureDomain::PairingAcceptanceV1,
            &unsigned,
            &self.node_signature,
        )?;
        self.subject_actor_id.verify_detached(
            DetachedSignatureDomain::PairingAcceptanceV1,
            &unsigned,
            &self.actor_signature,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = CanonicalValue::Map(vec![
            (key(0), self.unsigned_value()),
            (
                key(1),
                CanonicalValue::Bytes(self.node_signature.as_bytes().to_vec()),
            ),
            (
                key(2),
                CanonicalValue::Bytes(self.actor_signature.as_bytes().to_vec()),
            ),
        ])
        .to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        ensure_canonical_bound(bytes)?;
        let mut envelope = exact_map(CanonicalValue::from_canonical_cbor(bytes)?, 3)?;
        let mut fields = exact_map(take(&mut envelope, 0)?, 10)?;
        require_version(unsigned(take(&mut fields, 0)?)?, PAIRING_PROTOCOL_VERSION)?;
        let acceptance = Self {
            invitation_id: InvitationId::from_bytes(fixed_bytes(take(&mut fields, 1)?)?),
            claim_digest: fixed_bytes(take(&mut fields, 2)?)?,
            handshake_hash: fixed_bytes(take(&mut fields, 3)?)?,
            responder_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 4)?)?),
            space_id: SpaceId::from_bytes(fixed_bytes(take(&mut fields, 5)?)?),
            joiner_node_id: NodeId::from_bytes(fixed_bytes(take(&mut fields, 6)?)?),
            subject_actor_id: ActorId::from_bytes(fixed_bytes(take(&mut fields, 7)?)?),
            grant_operation_id: OperationId::from_bytes(fixed_bytes(take(&mut fields, 8)?)?),
            nonce: fixed_bytes(take(&mut fields, 9)?)?,
            node_signature: DetachedSignature::from_bytes(fixed_bytes(take(&mut envelope, 1)?)?),
            actor_signature: DetachedSignature::from_bytes(fixed_bytes(take(&mut envelope, 2)?)?),
        };
        acceptance.joiner_node_id.public_key()?;
        acceptance.subject_actor_id.public_key()?;
        if acceptance.nonce == [0; DIGEST_BYTES] {
            return Err(PairingError::InvalidField("acceptance nonce"));
        }
        Ok(acceptance)
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, PairingError> {
        let bytes = self.unsigned_value().to_canonical_cbor()?;
        ensure_canonical_bound(&bytes)?;
        Ok(bytes)
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (key(0), CanonicalValue::Unsigned(PAIRING_PROTOCOL_VERSION)),
            (
                key(1),
                CanonicalValue::Bytes(self.invitation_id.as_bytes().to_vec()),
            ),
            (key(2), CanonicalValue::Bytes(self.claim_digest.to_vec())),
            (key(3), CanonicalValue::Bytes(self.handshake_hash.to_vec())),
            (
                key(4),
                CanonicalValue::Bytes(self.responder_node_id.as_bytes().to_vec()),
            ),
            (
                key(5),
                CanonicalValue::Bytes(self.space_id.as_bytes().to_vec()),
            ),
            (
                key(6),
                CanonicalValue::Bytes(self.joiner_node_id.as_bytes().to_vec()),
            ),
            (
                key(7),
                CanonicalValue::Bytes(self.subject_actor_id.as_bytes().to_vec()),
            ),
            (
                key(8),
                CanonicalValue::Bytes(self.grant_operation_id.as_bytes().to_vec()),
            ),
            (key(9), CanonicalValue::Bytes(self.nonce.to_vec())),
        ])
    }
}

pub struct PairingInvitation {
    descriptor: InvitationDescriptor,
    signature: DetachedSignature,
    one_time_secret: [u8; SECRET_BYTES],
}

impl PairingInvitation {
    pub fn issue(
        responder_node_key: &SigningKey,
        parameters: InvitationParameters,
    ) -> Result<IssuedInvitation, PairingError> {
        let mut invitation_id = [0_u8; INVITATION_ID_BYTES];
        let mut one_time_secret = [0_u8; SECRET_BYTES];
        let mut noise_private = [0_u8; SECRET_BYTES];
        getrandom::fill(&mut invitation_id).map_err(|_| PairingError::RandomUnavailable)?;
        getrandom::fill(&mut one_time_secret).map_err(|_| PairingError::RandomUnavailable)?;
        getrandom::fill(&mut noise_private).map_err(|_| PairingError::RandomUnavailable)?;
        Self::issue_with_material(
            responder_node_key,
            parameters,
            InvitationMaterial {
                invitation_id,
                one_time_secret,
                noise_private,
            },
        )
    }

    pub fn issue_with_material(
        responder_node_key: &SigningKey,
        mut parameters: InvitationParameters,
        mut material: InvitationMaterial,
    ) -> Result<IssuedInvitation, PairingError> {
        validate_lifetime(parameters.now_unix_ms, parameters.expires_at_unix_ms)?;
        parameters.capability.normalize();
        let noise_public = x25519(material.noise_private, X25519_BASEPOINT_BYTES);
        let secret_commitment = Sha256::digest(material.one_time_secret).into();
        let descriptor = InvitationDescriptor {
            invitation_id: InvitationId::from_bytes(material.invitation_id),
            responder_node_id: responder_node_key.node_id(),
            responder_noise_static: noise_public,
            space_id: parameters.space_id,
            genesis_operation_id: parameters.genesis_operation_id,
            expires_at_unix_ms: parameters.expires_at_unix_ms,
            endpoint_hints: parameters.endpoint_hints,
            capability: parameters.capability,
            secret_commitment,
        };
        descriptor.validate()?;
        let descriptor_bytes = descriptor.canonical_bytes()?;
        let signature = responder_node_key.sign_detached(
            DetachedSignatureDomain::PairingInvitationV1,
            &descriptor_bytes,
        );
        let invitation = Self {
            descriptor,
            signature,
            one_time_secret: material.one_time_secret,
        };
        let secret = ResponderInvitationSecret {
            invitation_id: invitation.descriptor.invitation_id,
            descriptor_digest: invitation.descriptor.digest(),
            one_time_secret: material.one_time_secret,
            noise_static_private: material.noise_private,
        };
        material.one_time_secret.zeroize();
        material.noise_private.zeroize();
        Ok(IssuedInvitation { invitation, secret })
    }

    pub fn decode(qr: &str, now_unix_ms: i64) -> Result<Self, PairingError> {
        let encoded = qr
            .strip_prefix(QR_PREFIX)
            .ok_or(PairingError::InvalidQrPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| PairingError::InvalidBase64)?;
        if bytes.len() > MAX_QR_CBOR_BYTES {
            return Err(PairingError::QrTooLarge(bytes.len()));
        }
        let mut map = exact_map(CanonicalValue::from_canonical_cbor(&bytes)?, 3)?;
        let descriptor = InvitationDescriptor::from_canonical(take(&mut map, 0)?)?;
        let signature = DetachedSignature::from_bytes(fixed_bytes(take(&mut map, 1)?)?);
        let one_time_secret = fixed_bytes(take(&mut map, 2)?)?;
        let invitation = Self {
            descriptor,
            signature,
            one_time_secret,
        };
        invitation.verify(now_unix_ms)?;
        Ok(invitation)
    }

    pub fn verify(&self, now_unix_ms: i64) -> Result<(), PairingError> {
        self.descriptor.validate()?;
        if now_unix_ms < 0 || now_unix_ms >= self.descriptor.expires_at_unix_ms {
            return Err(PairingError::InvitationExpired);
        }
        if Sha256::digest(self.one_time_secret).as_slice() != self.descriptor.secret_commitment {
            return Err(PairingError::SecretCommitmentMismatch);
        }
        self.descriptor.responder_node_id.verify_detached(
            DetachedSignatureDomain::PairingInvitationV1,
            &self.descriptor.canonical_bytes()?,
            &self.signature,
        )?;
        Ok(())
    }

    pub fn to_qr_string(&self) -> Result<String, PairingError> {
        let bytes = CanonicalValue::Map(vec![
            (key(0), self.descriptor.canonical_value()),
            (
                key(1),
                CanonicalValue::Bytes(self.signature.as_bytes().to_vec()),
            ),
            (key(2), CanonicalValue::Bytes(self.one_time_secret.to_vec())),
        ])
        .to_canonical_cbor()?;
        if bytes.len() > MAX_QR_CBOR_BYTES {
            return Err(PairingError::QrTooLarge(bytes.len()));
        }
        Ok(format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    #[must_use]
    pub const fn descriptor(&self) -> &InvitationDescriptor {
        &self.descriptor
    }

    pub fn start_initiator(&self, now_unix_ms: i64) -> Result<PairingHandshake, PairingError> {
        self.verify(now_unix_ms)?;
        let params = noise_params()?;
        let digest = self.descriptor.digest();
        let state = Builder::new(params)
            .psk(0, &self.one_time_secret)?
            .remote_public_key(&self.descriptor.responder_noise_static)?
            .prologue(&digest)?
            .build_initiator()?;
        Ok(PairingHandshake { state })
    }
}

impl fmt::Debug for PairingInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingInvitation")
            .field("descriptor", &self.descriptor)
            .field("signature", &self.signature)
            .field("one_time_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PairingInvitation {
    fn drop(&mut self) {
        self.one_time_secret.zeroize();
    }
}

pub struct IssuedInvitation {
    pub invitation: PairingInvitation,
    pub secret: ResponderInvitationSecret,
}

pub struct ResponderInvitationSecret {
    invitation_id: InvitationId,
    descriptor_digest: [u8; DIGEST_BYTES],
    one_time_secret: [u8; SECRET_BYTES],
    noise_static_private: [u8; SECRET_BYTES],
}

impl ResponderInvitationSecret {
    #[must_use]
    pub const fn invitation_id(&self) -> InvitationId {
        self.invitation_id
    }

    #[must_use]
    pub const fn descriptor_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.descriptor_digest
    }

    pub fn start_responder(&self) -> Result<PairingHandshake, PairingError> {
        let params = noise_params()?;
        let state = Builder::new(params)
            .psk(0, &self.one_time_secret)?
            .local_private_key(&self.noise_static_private)?
            .prologue(&self.descriptor_digest)?
            .build_responder()?;
        Ok(PairingHandshake { state })
    }

    /// Produces the fixed-width secret-store representation.
    ///
    /// The returned buffer zeroizes on drop and must only cross into a
    /// protected platform secret backend. It is never a network wire format.
    #[must_use]
    pub fn protected_store_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(RESPONDER_SECRET_BYTES));
        bytes.push(RESPONDER_SECRET_VERSION);
        bytes.extend_from_slice(self.invitation_id.as_bytes());
        bytes.extend_from_slice(&self.descriptor_digest);
        bytes.extend_from_slice(&self.one_time_secret);
        bytes.extend_from_slice(&self.noise_static_private);
        bytes
    }

    /// Reconstructs secret material read from a protected platform backend.
    pub fn from_protected_store_bytes(mut bytes: Vec<u8>) -> Result<Self, PairingError> {
        if bytes.len() != RESPONDER_SECRET_BYTES || bytes[0] != RESPONDER_SECRET_VERSION {
            bytes.zeroize();
            return Err(PairingError::InvalidProtectedSecret);
        }
        let result = Self {
            invitation_id: InvitationId::from_bytes(bytes[1..17].try_into().expect("fixed slice")),
            descriptor_digest: bytes[17..49].try_into().expect("fixed slice"),
            one_time_secret: bytes[49..81].try_into().expect("fixed slice"),
            noise_static_private: bytes[81..113].try_into().expect("fixed slice"),
        };
        bytes.zeroize();
        if result.invitation_id.as_bytes() == &[0; INVITATION_ID_BYTES]
            || result.one_time_secret == [0; SECRET_BYTES]
            || result.noise_static_private == [0; SECRET_BYTES]
        {
            return Err(PairingError::InvalidProtectedSecret);
        }
        Ok(result)
    }
}

impl fmt::Debug for ResponderInvitationSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponderInvitationSecret")
            .field("invitation_id", &self.invitation_id)
            .field("descriptor_digest", &"[REDACTED]")
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ResponderInvitationSecret {
    fn drop(&mut self) {
        self.descriptor_digest.zeroize();
        self.one_time_secret.zeroize();
        self.noise_static_private.zeroize();
    }
}

pub struct PairingHandshake {
    state: HandshakeState,
}

impl PairingHandshake {
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, PairingError> {
        ensure_message_bound(payload)?;
        let mut output = vec![0_u8; MAX_NOISE_FRAME_BYTES];
        let written = self.state.write_message(payload, &mut output)?;
        output.truncate(written);
        ensure_frame_bound(&output)?;
        Ok(output)
    }

    pub fn read_message(&mut self, frame: &[u8]) -> Result<Vec<u8>, PairingError> {
        ensure_frame_bound(frame)?;
        let mut output = vec![0_u8; MAX_CANONICAL_MESSAGE_BYTES];
        let read = self.state.read_message(frame, &mut output)?;
        output.truncate(read);
        ensure_message_bound(&output)?;
        Ok(output)
    }

    pub fn finish(self) -> Result<PairingTransport, PairingError> {
        if !self.state.is_handshake_finished() {
            return Err(PairingError::HandshakeIncomplete);
        }
        let handshake_hash: [u8; DIGEST_BYTES] = self
            .state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| PairingError::InvalidHandshakeHash)?;
        let confirmation = confirmation_octal(&handshake_hash);
        let state = self.state.into_transport_mode()?;
        Ok(PairingTransport {
            state,
            handshake_hash,
            confirmation,
        })
    }
}

impl fmt::Debug for PairingHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingHandshake([REDACTED])")
    }
}

pub struct PairingTransport {
    state: TransportState,
    handshake_hash: [u8; DIGEST_BYTES],
    confirmation: String,
}

impl PairingTransport {
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; DIGEST_BYTES] {
        &self.handshake_hash
    }

    #[must_use]
    pub fn confirmation_octal(&self) -> &str {
        &self.confirmation
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, PairingError> {
        ensure_message_bound(payload)?;
        let mut output = vec![0_u8; payload.len() + 16];
        let written = self.state.write_message(payload, &mut output)?;
        output.truncate(written);
        ensure_frame_bound(&output)?;
        Ok(output)
    }

    pub fn read_message(&mut self, frame: &[u8]) -> Result<Vec<u8>, PairingError> {
        ensure_frame_bound(frame)?;
        let mut output = vec![0_u8; frame.len()];
        let read = self.state.read_message(frame, &mut output)?;
        output.truncate(read);
        ensure_message_bound(&output)?;
        Ok(output)
    }
}

impl fmt::Debug for PairingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingTransport")
            .field("handshake_hash", &"[REDACTED]")
            .field("confirmation", &self.confirmation)
            .field("cipher_state", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PairingTransport {
    fn drop(&mut self) {
        self.handshake_hash.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct InvitationParameters {
    pub space_id: SpaceId,
    pub genesis_operation_id: OperationId,
    pub now_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub endpoint_hints: Vec<String>,
    pub capability: CapabilityGrantTemplate,
}

pub struct InvitationMaterial {
    pub invitation_id: [u8; INVITATION_ID_BYTES],
    pub one_time_secret: [u8; SECRET_BYTES],
    pub noise_private: [u8; SECRET_BYTES],
}

impl fmt::Debug for InvitationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationMaterial([REDACTED])")
    }
}

impl Drop for InvitationMaterial {
    fn drop(&mut self) {
        self.one_time_secret.zeroize();
        self.noise_private.zeroize();
    }
}

#[must_use]
pub fn confirmation_octal(handshake_hash: &[u8; DIGEST_BYTES]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONFIRMATION_DOMAIN);
    hasher.update(handshake_hash);
    let digest: [u8; DIGEST_BYTES] = hasher.finalize().into();
    let value = u32::from_be_bytes(digest[..4].try_into().expect("four-byte prefix")) >> 2;
    format!("{value:010o}")
}

fn noise_params() -> Result<NoiseParams, PairingError> {
    NOISE_PROTOCOL_NAME
        .parse()
        .map_err(|_| PairingError::UnsupportedNoiseProtocol)
}

fn validate_lifetime(now: i64, expires: i64) -> Result<(), PairingError> {
    if now < 0 || expires < 0 {
        return Err(PairingError::InvalidField("invitation time"));
    }
    let lifetime = expires
        .checked_sub(now)
        .ok_or(PairingError::InvalidField("invitation lifetime"))?;
    if !(MIN_INVITATION_LIFETIME_MS..=MAX_INVITATION_LIFETIME_MS).contains(&lifetime) {
        return Err(PairingError::InvalidInvitationLifetime(lifetime));
    }
    Ok(())
}

fn validate_endpoint_hints(hints: &[String]) -> Result<(), PairingError> {
    if hints.len() > MAX_ENDPOINT_HINTS {
        return Err(PairingError::TooManyEndpointHints(hints.len()));
    }
    for hint in hints {
        if hint.is_empty()
            || hint.len() > MAX_ENDPOINT_HINT_BYTES
            || !hint.is_ascii()
            || !(hint.starts_with("http://") || hint.starts_with("https://"))
        {
            return Err(PairingError::InvalidEndpointHint);
        }
    }
    Ok(())
}

fn ensure_canonical_bound(bytes: &[u8]) -> Result<(), PairingError> {
    if bytes.len() > MAX_CANONICAL_MESSAGE_BYTES {
        Err(PairingError::CanonicalMessageTooLarge(bytes.len()))
    } else {
        Ok(())
    }
}

fn ensure_message_bound(bytes: &[u8]) -> Result<(), PairingError> {
    ensure_canonical_bound(bytes)
}

fn ensure_frame_bound(bytes: &[u8]) -> Result<(), PairingError> {
    if bytes.len() > MAX_NOISE_FRAME_BYTES {
        Err(PairingError::NoiseFrameTooLarge(bytes.len()))
    } else {
        Ok(())
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

fn action_from_code(code: u64) -> Result<CapabilityAction, PairingError> {
    match code {
        0 => Ok(CapabilityAction::AppendOperation),
        1 => Ok(CapabilityAction::IssueCapability),
        2 => Ok(CapabilityAction::RevokeCapability),
        3 => Ok(CapabilityAction::ReadSpace),
        4 => Ok(CapabilityAction::WriteContent),
        5 => Ok(CapabilityAction::LinkWorkspace),
        _ => Err(PairingError::InvalidField("capability action")),
    }
}

const fn visibility_code(visibility: Visibility) -> u64 {
    match visibility {
        Visibility::Public => 0,
        Visibility::Private => 1,
    }
}

fn visibility_from_code(code: u64) -> Result<Visibility, PairingError> {
    match code {
        0 => Ok(Visibility::Public),
        1 => Ok(Visibility::Private),
        _ => Err(PairingError::InvalidField("visibility")),
    }
}

fn schema_from_text(value: String) -> Result<EntitySchema, PairingError> {
    EntitySchema::parse(&value).map_err(|_| PairingError::InvalidField("entity schema"))
}

const fn key(value: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(value)
}

fn optional_unsigned(value: Option<u64>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, CanonicalValue::Unsigned)
}

fn optional_integer(value: Option<i64>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, CanonicalValue::Integer)
}

fn exact_map(
    value: CanonicalValue,
    expected: usize,
) -> Result<BTreeMap<u64, CanonicalValue>, PairingError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(PairingError::InvalidField("canonical map"));
    };
    if entries.len() != expected {
        return Err(PairingError::InvalidMapSize {
            expected,
            found: entries.len(),
        });
    }
    let mut map = BTreeMap::new();
    for (key, value) in entries {
        let CanonicalValue::Unsigned(key) = key else {
            return Err(PairingError::InvalidField("canonical map key"));
        };
        if map.insert(key, value).is_some() {
            return Err(PairingError::InvalidField("duplicate canonical map key"));
        }
    }
    Ok(map)
}

fn take(map: &mut BTreeMap<u64, CanonicalValue>, key: u64) -> Result<CanonicalValue, PairingError> {
    map.remove(&key)
        .ok_or(PairingError::MissingCanonicalField(key))
}

fn array(value: CanonicalValue) -> Result<Vec<CanonicalValue>, PairingError> {
    let CanonicalValue::Array(value) = value else {
        return Err(PairingError::InvalidField("canonical array"));
    };
    Ok(value)
}

fn text(value: CanonicalValue) -> Result<String, PairingError> {
    let CanonicalValue::Text(value) = value else {
        return Err(PairingError::InvalidField("canonical text"));
    };
    Ok(value)
}

fn unsigned(value: CanonicalValue) -> Result<u64, PairingError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(PairingError::InvalidField("canonical unsigned integer"));
    };
    Ok(value)
}

fn integer(value: CanonicalValue) -> Result<i64, PairingError> {
    match value {
        CanonicalValue::Integer(value) => Ok(value),
        CanonicalValue::Unsigned(value) => value
            .try_into()
            .map_err(|_| PairingError::InvalidField("canonical signed integer")),
        _ => Err(PairingError::InvalidField("canonical signed integer")),
    }
}

fn optional_unsigned_from(value: CanonicalValue) -> Result<Option<u64>, PairingError> {
    match value {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Unsigned(value) => Ok(Some(value)),
        _ => Err(PairingError::InvalidField("optional unsigned integer")),
    }
}

fn optional_integer_from(value: CanonicalValue) -> Result<Option<i64>, PairingError> {
    match value {
        CanonicalValue::Null => Ok(None),
        value => integer(value).map(Some),
    }
}

fn fixed_bytes<const N: usize>(value: CanonicalValue) -> Result<[u8; N], PairingError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(PairingError::InvalidField("canonical bytes"));
    };
    value
        .try_into()
        .map_err(|_| PairingError::InvalidField("fixed byte length"))
}

fn require_version(found: u64, expected: u64) -> Result<(), PairingError> {
    if found == expected {
        Ok(())
    } else {
        Err(PairingError::UnsupportedVersion { expected, found })
    }
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("cryptographic random source is unavailable")]
    RandomUnavailable,
    #[error("pairing QR prefix is invalid")]
    InvalidQrPrefix,
    #[error("pairing QR base64url is invalid")]
    InvalidBase64,
    #[error("pairing QR canonical payload is too large: {0} bytes")]
    QrTooLarge(usize),
    #[error("canonical pairing message is too large: {0} bytes")]
    CanonicalMessageTooLarge(usize),
    #[error("Noise frame is too large: {0} bytes")]
    NoiseFrameTooLarge(usize),
    #[error("unsupported pairing version {found}; expected {expected}")]
    UnsupportedVersion { expected: u64, found: u64 },
    #[error("unsupported Noise protocol")]
    UnsupportedNoiseProtocol,
    #[error("invalid pairing field: {0}")]
    InvalidField(&'static str),
    #[error("canonical map has {found} fields; expected {expected}")]
    InvalidMapSize { expected: usize, found: usize },
    #[error("canonical map is missing field {0}")]
    MissingCanonicalField(u64),
    #[error("{0} is not in canonical set order")]
    NonCanonicalSet(&'static str),
    #[error("invitation has invalid lifetime of {0} milliseconds")]
    InvalidInvitationLifetime(i64),
    #[error("invitation has too many endpoint hints: {0}")]
    TooManyEndpointHints(usize),
    #[error("invitation endpoint hint is invalid")]
    InvalidEndpointHint,
    #[error("invitation has expired")]
    InvitationExpired,
    #[error("invitation secret does not match its signed commitment")]
    SecretCommitmentMismatch,
    #[error("joiner claim does not match the invitation")]
    ClaimInvitationMismatch,
    #[error("pairing receipt does not match the authenticated transcript")]
    ReceiptTranscriptMismatch,
    #[error("pairing acceptance does not match the claimed transcript")]
    AcceptanceMismatch,
    #[error("protected pairing secret is corrupt or unsupported")]
    InvalidProtectedSecret,
    #[error("Noise handshake is not complete")]
    HandshakeIncomplete,
    #[error("Noise handshake hash has an unexpected size")]
    InvalidHandshakeHash,
    #[error(transparent)]
    Canonical(#[from] CanonicalCborError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error(transparent)]
    DataModel(#[from] fractonica_data_model::DataModelError),
    #[error("Noise protocol failure")]
    Noise(#[from] snow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn parameters() -> InvitationParameters {
        InvitationParameters {
            space_id: SpaceId::from_bytes([3; 32]),
            genesis_operation_id: OperationId::from_bytes([4; 32]),
            now_unix_ms: NOW,
            expires_at_unix_ms: NOW + 60_000,
            endpoint_hints: vec!["http://127.0.0.1:8789".to_owned()],
            capability: CapabilityGrantTemplate {
                actions: vec![
                    CapabilityAction::ReadSpace,
                    CapabilityAction::AppendOperation,
                    CapabilityAction::WriteContent,
                ],
                schemas: vec![EntitySchema::Record],
                visibilities: vec![Visibility::Public],
                content_roles: vec!["record.attachment".to_owned()],
                max_resource_byte_length: Some(1_048_576),
                not_before_unix_ms: Some(NOW),
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: "paired device".to_owned(),
            },
        }
    }

    fn issue() -> IssuedInvitation {
        PairingInvitation::issue_with_material(
            &SigningKey::from_seed([1; 32]),
            parameters(),
            InvitationMaterial {
                invitation_id: [5; 16],
                one_time_secret: [6; 32],
                noise_private: [7; 32],
            },
        )
        .expect("fixed invitation is valid")
    }

    #[test]
    fn invitation_qr_is_deterministic_strict_and_redacted() {
        let issued = issue();
        let qr = issued.invitation.to_qr_string().expect("encode QR");
        let decoded = PairingInvitation::decode(&qr, NOW).expect("decode QR");
        assert_eq!(decoded.descriptor(), issued.invitation.descriptor());
        assert_eq!(decoded.to_qr_string().expect("re-encode"), qr);
        assert!(!format!("{:?}", decoded).contains(&URL_SAFE_NO_PAD.encode([6; 32])));
        assert!(!format!("{:?}", issued.secret).contains("060606"));

        assert!(matches!(
            PairingInvitation::decode(&qr, NOW + 60_000),
            Err(PairingError::InvitationExpired)
        ));
        assert!(matches!(
            PairingInvitation::decode(qr.trim_start_matches(QR_PREFIX), NOW),
            Err(PairingError::InvalidQrPrefix)
        ));

        let restored = ResponderInvitationSecret::from_protected_store_bytes(
            issued.secret.protected_store_bytes().to_vec(),
        )
        .expect("restore protected secret");
        assert_eq!(restored.invitation_id(), issued.secret.invitation_id());
        assert_eq!(
            restored.descriptor_digest(),
            issued.secret.descriptor_digest()
        );
        assert!(matches!(
            ResponderInvitationSecret::from_protected_store_bytes(vec![1; 112]),
            Err(PairingError::InvalidProtectedSecret)
        ));
    }

    #[test]
    fn signed_descriptor_and_secret_commitment_reject_tampering() {
        let issued = issue();
        let qr = issued.invitation.to_qr_string().expect("encode QR");
        let encoded = qr.strip_prefix(QR_PREFIX).expect("prefix");
        let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("base64url");
        let mut map = exact_map(
            CanonicalValue::from_canonical_cbor(&bytes).expect("CBOR"),
            3,
        )
        .expect("map");
        let descriptor = take(&mut map, 0).expect("descriptor");
        let signature = take(&mut map, 1).expect("signature");
        let mut secret: [u8; 32] =
            fixed_bytes(take(&mut map, 2).expect("secret")).expect("32 bytes");
        secret[0] ^= 1;
        let tampered = CanonicalValue::Map(vec![
            (key(0), descriptor),
            (key(1), signature),
            (key(2), CanonicalValue::Bytes(secret.to_vec())),
        ])
        .to_canonical_cbor()
        .expect("encode tampered QR");
        let tampered = format!("{QR_PREFIX}{}", URL_SAFE_NO_PAD.encode(tampered));
        assert!(matches!(
            PairingInvitation::decode(&tampered, NOW),
            Err(PairingError::SecretCommitmentMismatch)
        ));
    }

    #[test]
    fn noise_handshake_binds_invitation_and_establishes_matching_transport() {
        let issued = issue();
        let responder_key = SigningKey::from_seed([1; 32]);
        let joiner_node_key = SigningKey::from_seed([2; 32]);
        let actor_key = SigningKey::from_seed([3; 32]);
        let claim = JoinerClaim::sign(
            issued.invitation.descriptor(),
            &joiner_node_key,
            &actor_key,
            [8; 32],
        );
        claim
            .verify_for(issued.invitation.descriptor())
            .expect("dual identity proof");
        let claim_bytes = claim.canonical_bytes().expect("claim bytes");
        let mut initiator = issued.invitation.start_initiator(NOW).expect("initiator");
        let mut responder = issued.secret.start_responder().expect("responder");

        let first = initiator.write_message(&claim_bytes).expect("message 1");
        assert_eq!(
            JoinerClaim::from_canonical_bytes(&responder.read_message(&first).expect("read 1"))
                .expect("decode claim"),
            claim
        );
        let second = responder.write_message(b"").expect("message 2");
        assert_eq!(initiator.read_message(&second).expect("read 2"), b"");

        let mut initiator = initiator.finish().expect("initiator transport");
        let mut responder = responder.finish().expect("responder transport");
        assert_eq!(initiator.handshake_hash(), responder.handshake_hash());
        assert_eq!(
            initiator.confirmation_octal(),
            responder.confirmation_octal()
        );
        assert_eq!(initiator.confirmation_octal().len(), 10);
        assert!(
            initiator
                .confirmation_octal()
                .bytes()
                .all(|byte| (b'0'..=b'7').contains(&byte))
        );

        let receipt = PairingReceipt::sign(
            issued.invitation.descriptor(),
            &claim,
            *responder.handshake_hash(),
            [17; 32],
            &responder_key,
        );
        let receipt_frame = responder
            .write_message(&receipt.canonical_bytes().expect("receipt bytes"))
            .expect("encrypt receipt");
        let decoded_receipt = PairingReceipt::from_canonical_bytes(
            &initiator
                .read_message(&receipt_frame)
                .expect("decrypt receipt"),
        )
        .expect("decode receipt");
        assert_eq!(decoded_receipt.peer_access_token(), &[17; 32]);
        decoded_receipt
            .verify_for(
                issued.invitation.descriptor(),
                &claim,
                initiator.handshake_hash(),
            )
            .expect("receipt transcript proof");

        let frame = initiator
            .write_message(b"encrypted application payload")
            .expect("encrypt");
        assert_ne!(frame, b"encrypted application payload");
        assert_eq!(
            responder.read_message(&frame).expect("decrypt"),
            b"encrypted application payload"
        );
    }

    #[test]
    fn wrong_one_time_secret_cannot_complete_handshake() {
        let issued = issue();
        let mut initiator = issued.invitation.start_initiator(NOW).expect("initiator");
        let mut wrong_secret = ResponderInvitationSecret {
            invitation_id: issued.secret.invitation_id,
            descriptor_digest: issued.secret.descriptor_digest,
            one_time_secret: [9; 32],
            noise_static_private: issued.secret.noise_static_private,
        };
        let mut responder = wrong_secret.start_responder().expect("responder state");
        let first = initiator.write_message(b"claim").expect("first frame");
        assert!(responder.read_message(&first).is_err());
        wrong_secret.one_time_secret.zeroize();
    }

    #[test]
    fn message_and_frame_bounds_are_enforced_before_noise() {
        let issued = issue();
        let mut initiator = issued.invitation.start_initiator(NOW).expect("initiator");
        assert!(matches!(
            initiator.write_message(&vec![0; MAX_CANONICAL_MESSAGE_BYTES + 1]),
            Err(PairingError::CanonicalMessageTooLarge(_))
        ));
        assert!(matches!(
            initiator.read_message(&vec![0; MAX_NOISE_FRAME_BYTES + 1]),
            Err(PairingError::NoiseFrameTooLarge(_))
        ));
    }
}
