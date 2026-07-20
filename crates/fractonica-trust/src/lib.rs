#![no_std]
#![forbid(unsafe_code)]
//! Cryptographic identities and deterministic operation signatures.
//!
//! This crate is deliberately below Fractonica's data model. It owns the wire
//! identities, deterministic CBOR vocabulary, Ed25519 keys, and exact
//! COSE_Sign1 envelope. Higher layers map their documents into
//! [`CanonicalValue`] and supply that value as an [`OperationPayload`] body.
//! JSON serialization is never part of the signed representation.

extern crate alloc;

use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use core::{cmp::Ordering, fmt, str::FromStr};

use ed25519_dalek::{Signature, Signer, Verifier};
use half::f16;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

/// Signed-operation protocol implemented by this crate.
///
/// Version 1 operations are intentionally not accepted or reinterpreted.
pub const OPERATION_PROTOCOL_VERSION: u64 = 2;
/// Domain value encoded into every version 2 operation payload.
pub const OPERATION_DOMAIN: &str = "org.fractonica.operation.v2";
/// Maximum direct causal parents carried by one operation.
pub const MAX_CAUSAL_PARENTS: usize = 64;
/// Maximum capability-grant operation references carried by one operation.
pub const MAX_AUTHORIZATION_REFERENCES: usize = 64;
/// Maximum ASCII byte length of an entity schema token.
pub const MAX_SCHEMA_BYTES: usize = 64;
/// Maximum depth accepted by the canonical CBOR vocabulary.
pub const MAX_CANONICAL_DEPTH: usize = 32;
/// Maximum elements in one canonical array or map.
pub const MAX_CANONICAL_CONTAINER_ITEMS: usize = 4_096;
/// Maximum encoded size of a signed operation payload (2 MiB).
pub const MAX_CANONICAL_BYTES: usize = 2 * 1_024 * 1_024;

const KEY_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const ACTOR_PREFIX: &str = "actor:ed25519:";
const NODE_PREFIX: &str = "node:ed25519:";
const SPACE_PREFIX: &str = "space:";
const OPERATION_PREFIX: &str = "sha-256:";
const PUBLIC_KEY_PREFIX: &str = "ed25519:";
const DETACHED_SIGNATURE_CONTEXT: &[u8] = b"org.fractonica.detached-signature.v1\0";

// Deterministic protected header { 1: -8 }, where 1 is `alg` and -8 is EdDSA.
const COSE_PROTECTED_HEADER: [u8; 3] = [0xa1, 0x01, 0x27];

macro_rules! fixed_hex_id {
    ($name:ident, $prefix:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }

            pub fn parse(value: &str) -> Result<Self, IdentifierParseError> {
                value.parse()
            }
        }

        impl FromStr for $name {
            type Err = IdentifierParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_prefixed_hex(value, $prefix).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($prefix)?;
                write_lower_hex(formatter, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct Visitor;

                impl de::Visitor<'_> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "{} followed by 64 lowercase hexadecimal digits",
                            $prefix
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

fixed_hex_id!(
    ActorId,
    ACTOR_PREFIX,
    "Self-certifying actor identity containing its Ed25519 public key."
);
fixed_hex_id!(
    NodeId,
    NODE_PREFIX,
    "Self-certifying node identity containing its Ed25519 public key."
);
fixed_hex_id!(
    SpaceId,
    SPACE_PREFIX,
    "Opaque 256-bit authorization and replication-space identity."
);
fixed_hex_id!(
    OperationId,
    OPERATION_PREFIX,
    "SHA-256 identity of one canonical version 2 operation payload."
);
fixed_hex_id!(
    Ed25519PublicKey,
    PUBLIC_KEY_PREFIX,
    "Strict wire representation of an Ed25519 public key."
);

impl ActorId {
    pub fn public_key(self) -> Result<Ed25519PublicKey, TrustError> {
        Ed25519PublicKey::from_bytes(self.0).validate()?;
        Ok(Ed25519PublicKey::from_bytes(self.0))
    }

    pub fn verify_detached(
        self,
        domain: DetachedSignatureDomain,
        message: &[u8],
        signature: &DetachedSignature,
    ) -> Result<(), TrustError> {
        self.public_key()?
            .verify_detached(domain, message, signature)
    }
}

impl NodeId {
    pub fn public_key(self) -> Result<Ed25519PublicKey, TrustError> {
        Ed25519PublicKey::from_bytes(self.0).validate()?;
        Ok(Ed25519PublicKey::from_bytes(self.0))
    }

    pub fn verify_detached(
        self,
        domain: DetachedSignatureDomain,
        message: &[u8],
        signature: &DetachedSignature,
    ) -> Result<(), TrustError> {
        self.public_key()?
            .verify_detached(domain, message, signature)
    }
}

impl SpaceId {
    pub fn validate(self) -> Result<(), TrustError> {
        if self.0 == [0; DIGEST_BYTES] {
            Err(TrustError::NilSpaceId)
        } else {
            Ok(())
        }
    }
}

impl Ed25519PublicKey {
    pub fn validate(self) -> Result<(), TrustError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|_| TrustError::InvalidPublicKey)?;
        if key.is_weak() {
            Err(TrustError::InvalidPublicKey)
        } else {
            Ok(())
        }
    }

    fn verifying_key(self) -> Result<ed25519_dalek::VerifyingKey, TrustError> {
        self.validate()?;
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).map_err(|_| TrustError::InvalidPublicKey)
    }

    pub fn verify_detached(
        self,
        domain: DetachedSignatureDomain,
        message: &[u8],
        signature: &DetachedSignature,
    ) -> Result<(), TrustError> {
        let digest = detached_signature_digest(domain, message);
        self.verifying_key()?
            .verify(&digest, &Signature::from_bytes(signature.as_bytes()))
            .map_err(|_| TrustError::SignatureVerificationFailed)
    }
}

/// Closed protocol domains for detached Ed25519 identity proofs.
///
/// Callers cannot supply an arbitrary string, preventing one protocol's
/// signature from being reinterpreted by another protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachedSignatureDomain {
    PairingInvitationV1,
    PairingJoinerClaimV1,
    PairingReceiptV1,
    PeerNodeRequestV1,
    PeerActorRequestV1,
}

impl DetachedSignatureDomain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::PairingInvitationV1 => b"pairing-invitation-v1",
            Self::PairingJoinerClaimV1 => b"pairing-joiner-claim-v1",
            Self::PairingReceiptV1 => b"pairing-receipt-v1",
            Self::PeerNodeRequestV1 => b"peer-node-request-v1",
            Self::PeerActorRequestV1 => b"peer-actor-request-v1",
        }
    }
}

/// Exact 64-byte Ed25519 signature over a domain-separated message digest.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DetachedSignature([u8; SIGNATURE_BYTES]);

impl DetachedSignature {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.0
    }
}

impl fmt::Debug for DetachedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DetachedSignature([REDACTED])")
    }
}

/// In-memory Ed25519 signing key.
///
/// The debug representation is always redacted. Persisting or protecting the
/// seed is the responsibility of the platform keystore adapter.
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

/// Concise public name for the platform-supplied Ed25519 signing key.
pub type SigningKey = Ed25519SigningKey;
/// Concise public name for the strict Ed25519 public-key wire value.
pub type PublicKey = Ed25519PublicKey;

impl Ed25519SigningKey {
    /// Reconstructs a key from its exact 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(mut seed: [u8; KEY_BYTES]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self(signing_key)
    }

    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn actor_id(&self) -> ActorId {
        ActorId::from_bytes(self.0.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(self.0.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign_detached(
        &self,
        domain: DetachedSignatureDomain,
        message: &[u8],
    ) -> DetachedSignature {
        let digest = detached_signature_digest(domain, message);
        DetachedSignature::from_bytes(self.0.sign(&digest).to_bytes())
    }
}

fn detached_signature_digest(
    domain: DetachedSignatureDomain,
    message: &[u8],
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(DETACHED_SIGNATURE_CONTEXT);
    hasher.update(domain.label());
    hasher.update([0]);
    hasher.update(
        u64::try_from(message.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(message);
    hasher.finalize().into()
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519SigningKey([REDACTED])")
    }
}

/// A bounded semantic value with one deterministic RFC 8949 CBOR encoding.
#[derive(Clone, Debug, PartialEq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
}

impl CanonicalValue {
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CanonicalCborError> {
        let mut output = Vec::new();
        encode_value(self, 0, &mut output)?;
        Ok(output)
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CanonicalCborError> {
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CanonicalCborError::EncodedTooLarge {
                bytes: bytes.len(),
                maximum: MAX_CANONICAL_BYTES,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let value = decoder.decode_value(0)?;
        if !decoder.is_finished() {
            return Err(CanonicalCborError::TrailingData);
        }
        let encoded = value.to_canonical_cbor()?;
        if encoded != bytes {
            return Err(CanonicalCborError::NonCanonical);
        }
        Ok(value)
    }
}

/// Random or deterministically assigned operation uniqueness material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationNonce([u8; 16]);

impl OperationNonce {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Version 2 fields which are signed for one immutable operation.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationPayload {
    space_id: SpaceId,
    actor_id: ActorId,
    entity_id: Uuid,
    schema: String,
    causal_parents: Vec<OperationId>,
    authorization: Vec<OperationId>,
    occurred_at_unix_ms: i64,
    nonce: OperationNonce,
    body: CanonicalValue,
}

impl OperationPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        space_id: SpaceId,
        actor_id: ActorId,
        entity_id: Uuid,
        schema: impl Into<String>,
        mut causal_parents: Vec<OperationId>,
        mut authorization: Vec<OperationId>,
        occurred_at_unix_ms: i64,
        nonce: OperationNonce,
        body: CanonicalValue,
    ) -> Result<Self, TrustError> {
        space_id.validate()?;
        actor_id.public_key()?;
        if entity_id.is_nil() {
            return Err(TrustError::NilEntityId);
        }
        let schema = schema.into();
        validate_schema(&schema)?;
        if occurred_at_unix_ms < 0 {
            return Err(TrustError::NegativeOccurredAt(occurred_at_unix_ms));
        }
        normalize_digest_set(&mut causal_parents, DigestSet::CausalParents)?;
        normalize_digest_set(&mut authorization, DigestSet::Authorization)?;

        let payload = Self {
            space_id,
            actor_id,
            entity_id,
            schema,
            causal_parents,
            authorization,
            occurred_at_unix_ms,
            nonce,
            body,
        };
        payload.canonical_bytes()?;
        Ok(payload)
    }

    #[must_use]
    pub const fn space_id(&self) -> SpaceId {
        self.space_id
    }

    #[must_use]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    #[must_use]
    pub const fn entity_id(&self) -> Uuid {
        self.entity_id
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn causal_parents(&self) -> &[OperationId] {
        &self.causal_parents
    }

    #[must_use]
    pub fn authorization(&self) -> &[OperationId] {
        &self.authorization
    }

    #[must_use]
    pub const fn occurred_at_unix_ms(&self) -> i64 {
        self.occurred_at_unix_ms
    }

    #[must_use]
    pub const fn nonce(&self) -> OperationNonce {
        self.nonce
    }

    #[must_use]
    pub const fn body(&self) -> &CanonicalValue {
        &self.body
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustError> {
        let parents = self
            .causal_parents
            .iter()
            .map(|parent| CanonicalValue::Bytes(parent.0.to_vec()))
            .collect();
        let authorization = self
            .authorization
            .iter()
            .map(|grant| CanonicalValue::Bytes(grant.0.to_vec()))
            .collect();
        let value = CanonicalValue::Array(vec![
            CanonicalValue::Text(OPERATION_DOMAIN.to_owned()),
            CanonicalValue::Unsigned(OPERATION_PROTOCOL_VERSION),
            CanonicalValue::Bytes(self.space_id.0.to_vec()),
            CanonicalValue::Bytes(self.actor_id.0.to_vec()),
            CanonicalValue::Bytes(self.entity_id.as_bytes().to_vec()),
            CanonicalValue::Text(self.schema.clone()),
            CanonicalValue::Array(parents),
            CanonicalValue::Array(authorization),
            CanonicalValue::Integer(self.occurred_at_unix_ms),
            CanonicalValue::Bytes(self.nonce.0.to_vec()),
            self.body.clone(),
        ]);
        value.to_canonical_cbor().map_err(TrustError::from)
    }

    pub fn operation_id(&self) -> Result<OperationId, TrustError> {
        Ok(hash_operation_payload(&self.canonical_bytes()?))
    }

    pub fn sign(&self, signing_key: &Ed25519SigningKey) -> Result<SignedOperation, TrustError> {
        if signing_key.actor_id() != self.actor_id {
            return Err(TrustError::SigningActorMismatch {
                payload: self.actor_id,
                key: signing_key.actor_id(),
            });
        }
        let payload = self.canonical_bytes()?;
        SignedOperation::sign_canonical(payload, signing_key)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let value = CanonicalValue::from_canonical_cbor(bytes)?;
        decode_operation_value(value)
    }
}

/// Detached typed view of a deterministic COSE_Sign1 operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedOperation {
    operation_id: OperationId,
    payload: Vec<u8>,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedOperation {
    fn sign_canonical(
        payload: Vec<u8>,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, TrustError> {
        OperationPayload::from_canonical_bytes(&payload)?;
        let signature_input = cose_signature_structure(&payload)?;
        let signature = signing_key.0.sign(&signature_input).to_bytes();
        Ok(Self {
            operation_id: hash_operation_payload(&payload),
            payload,
            signature,
        })
    }

    pub fn from_cose_sign1(bytes: &[u8]) -> Result<Self, TrustError> {
        let (payload, signature) = decode_exact_cose_sign1(bytes)?;
        OperationPayload::from_canonical_bytes(&payload)?;
        Ok(Self {
            operation_id: hash_operation_payload(&payload),
            payload,
            signature,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn signature_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    pub fn decode_payload(&self) -> Result<OperationPayload, TrustError> {
        OperationPayload::from_canonical_bytes(&self.payload)
    }

    pub fn verify(&self) -> Result<VerifiedOperation, TrustError> {
        if hash_operation_payload(&self.payload) != self.operation_id {
            return Err(TrustError::OperationIdMismatch);
        }
        let payload = self.decode_payload()?;
        let verifying_key = payload.actor_id.public_key()?.verifying_key()?;
        let signature = Signature::from_bytes(&self.signature);
        let signature_input = cose_signature_structure(&self.payload)?;
        verifying_key
            .verify_strict(&signature_input, &signature)
            .map_err(|_| TrustError::SignatureVerificationFailed)?;
        Ok(VerifiedOperation {
            operation_id: self.operation_id,
            actor_id: payload.actor_id,
            space_id: payload.space_id,
        })
    }

    pub fn verify_for_actor(&self, expected: ActorId) -> Result<VerifiedOperation, TrustError> {
        let verified = self.verify()?;
        if verified.actor_id != expected {
            return Err(TrustError::UnexpectedActor {
                expected,
                found: verified.actor_id,
            });
        }
        Ok(verified)
    }

    pub fn to_cose_sign1(&self) -> Result<Vec<u8>, TrustError> {
        let value = CanonicalValue::Array(vec![
            CanonicalValue::Bytes(COSE_PROTECTED_HEADER.to_vec()),
            CanonicalValue::Map(Vec::new()),
            CanonicalValue::Bytes(self.payload.clone()),
            CanonicalValue::Bytes(self.signature.to_vec()),
        ]);
        let untagged = value.to_canonical_cbor()?;
        let mut tagged = Vec::with_capacity(untagged.len() + 1);
        tagged.push(0xd2); // COSE_Sign1 tag 18.
        tagged.extend_from_slice(&untagged);
        Ok(tagged)
    }
}

/// Identities proven by a successfully verified signed operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedOperation {
    pub operation_id: OperationId,
    pub actor_id: ActorId,
    pub space_id: SpaceId,
}

fn hash_operation_payload(payload: &[u8]) -> OperationId {
    OperationId::from_bytes(Sha256::digest(payload).into())
}

fn cose_signature_structure(payload: &[u8]) -> Result<Vec<u8>, TrustError> {
    CanonicalValue::Array(vec![
        CanonicalValue::Text("Signature1".to_owned()),
        CanonicalValue::Bytes(COSE_PROTECTED_HEADER.to_vec()),
        CanonicalValue::Bytes(Vec::new()),
        CanonicalValue::Bytes(payload.to_vec()),
    ])
    .to_canonical_cbor()
    .map_err(TrustError::from)
}

fn decode_operation_value(value: CanonicalValue) -> Result<OperationPayload, TrustError> {
    let CanonicalValue::Array(fields) = value else {
        return Err(TrustError::InvalidOperationPayload("expected an array"));
    };
    let [
        domain,
        version,
        space,
        actor,
        entity,
        schema,
        parents,
        authorization,
        occurred,
        nonce,
        body,
    ]: [CanonicalValue; 11] = fields
        .try_into()
        .map_err(|_| TrustError::InvalidOperationPayload("expected exactly 11 fields"))?;

    if domain != CanonicalValue::Text(OPERATION_DOMAIN.to_owned()) {
        return Err(TrustError::WrongOperationDomain);
    }
    if version != CanonicalValue::Unsigned(OPERATION_PROTOCOL_VERSION) {
        return Err(TrustError::UnsupportedOperationVersion);
    }
    let space_id = SpaceId::from_bytes(take_fixed_bytes(space, "space ID")?);
    let actor_id = ActorId::from_bytes(take_fixed_bytes(actor, "actor ID")?);
    let entity_bytes: [u8; 16] = take_fixed_bytes(entity, "entity ID")?;
    let entity_id = Uuid::from_bytes(entity_bytes);
    let CanonicalValue::Text(schema) = schema else {
        return Err(TrustError::InvalidOperationPayload("schema must be text"));
    };
    let causal_parents = decode_digest_set(parents, DigestSet::CausalParents)?;
    let authorization = decode_digest_set(authorization, DigestSet::Authorization)?;
    let occurred_at_unix_ms = match occurred {
        CanonicalValue::Integer(value) => value,
        CanonicalValue::Unsigned(value) => i64::try_from(value)
            .map_err(|_| TrustError::InvalidOperationPayload("occurred-at is out of range"))?,
        _ => {
            return Err(TrustError::InvalidOperationPayload(
                "occurred-at must be an integer",
            ));
        }
    };
    let nonce = OperationNonce::from_bytes(take_fixed_bytes(nonce, "nonce")?);
    OperationPayload::new(
        space_id,
        actor_id,
        entity_id,
        schema,
        causal_parents,
        authorization,
        occurred_at_unix_ms,
        nonce,
        body,
    )
}

#[derive(Clone, Copy)]
enum DigestSet {
    CausalParents,
    Authorization,
}

fn normalize_digest_set(values: &mut [OperationId], kind: DigestSet) -> Result<(), TrustError> {
    let maximum = match kind {
        DigestSet::CausalParents => MAX_CAUSAL_PARENTS,
        DigestSet::Authorization => MAX_AUTHORIZATION_REFERENCES,
    };
    if values.len() > maximum {
        return Err(match kind {
            DigestSet::CausalParents => TrustError::TooManyCausalParents {
                count: values.len(),
                maximum: MAX_CAUSAL_PARENTS,
            },
            DigestSet::Authorization => TrustError::TooManyAuthorizationReferences {
                count: values.len(),
                maximum: MAX_AUTHORIZATION_REFERENCES,
            },
        });
    }
    values.sort_unstable();
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(match kind {
                DigestSet::CausalParents => TrustError::DuplicateCausalParent(pair[0]),
                DigestSet::Authorization => TrustError::DuplicateAuthorizationReference(pair[0]),
            });
        }
    }
    Ok(())
}

fn decode_digest_set(
    value: CanonicalValue,
    kind: DigestSet,
) -> Result<Vec<OperationId>, TrustError> {
    let CanonicalValue::Array(values) = value else {
        return Err(TrustError::InvalidOperationPayload(match kind {
            DigestSet::CausalParents => "causal parents must be an array",
            DigestSet::Authorization => "authorization must be an array",
        }));
    };
    let maximum = match kind {
        DigestSet::CausalParents => MAX_CAUSAL_PARENTS,
        DigestSet::Authorization => MAX_AUTHORIZATION_REFERENCES,
    };
    if values.len() > maximum {
        return Err(match kind {
            DigestSet::CausalParents => TrustError::TooManyCausalParents {
                count: values.len(),
                maximum: MAX_CAUSAL_PARENTS,
            },
            DigestSet::Authorization => TrustError::TooManyAuthorizationReferences {
                count: values.len(),
                maximum: MAX_AUTHORIZATION_REFERENCES,
            },
        });
    }
    let mut decoded = Vec::with_capacity(values.len());
    for value in values {
        decoded.push(OperationId::from_bytes(take_fixed_bytes(
            value,
            match kind {
                DigestSet::CausalParents => "causal parent",
                DigestSet::Authorization => "authorization reference",
            },
        )?));
    }
    if !decoded.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(match kind {
            DigestSet::CausalParents => TrustError::CausalParentsNotStrictlyAscending,
            DigestSet::Authorization => TrustError::AuthorizationNotStrictlyAscending,
        });
    }
    Ok(decoded)
}

fn take_fixed_bytes<const N: usize>(
    value: CanonicalValue,
    field: &'static str,
) -> Result<[u8; N], TrustError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(TrustError::InvalidOperationPayload(field));
    };
    bytes
        .try_into()
        .map_err(|_| TrustError::InvalidOperationPayload(field))
}

fn validate_schema(schema: &str) -> Result<(), TrustError> {
    let mut bytes = schema.bytes();
    let valid = schema.len() <= MAX_SCHEMA_BYTES
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(TrustError::InvalidSchema(schema.to_owned()))
    }
}

fn encode_value(
    value: &CanonicalValue,
    depth: usize,
    output: &mut Vec<u8>,
) -> Result<(), CanonicalCborError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(CanonicalCborError::TooDeep {
            depth,
            maximum: MAX_CANONICAL_DEPTH,
        });
    }
    match value {
        CanonicalValue::Null => push(output, &[0xf6])?,
        CanonicalValue::Bool(false) => push(output, &[0xf4])?,
        CanonicalValue::Bool(true) => push(output, &[0xf5])?,
        CanonicalValue::Integer(value) if *value >= 0 => {
            encode_head(0, *value as u64, output)?;
        }
        CanonicalValue::Integer(value) => {
            let encoded = (-1_i128 - i128::from(*value)) as u64;
            encode_head(1, encoded, output)?;
        }
        CanonicalValue::Unsigned(value) => encode_head(0, *value, output)?,
        CanonicalValue::Float(value) => encode_float(*value, output)?,
        CanonicalValue::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, output)?;
            push(output, bytes)?;
        }
        CanonicalValue::Text(value) => {
            encode_head(3, value.len() as u64, output)?;
            push(output, value.as_bytes())?;
        }
        CanonicalValue::Array(values) => {
            validate_container(values.len())?;
            encode_head(4, values.len() as u64, output)?;
            for value in values {
                encode_value(value, depth + 1, output)?;
            }
        }
        CanonicalValue::Map(values) => {
            validate_container(values.len())?;
            let mut entries = Vec::with_capacity(values.len());
            let mut total_key_bytes = 0_usize;
            for (key, value) in values {
                let mut encoded_key = Vec::new();
                encode_value(key, depth + 1, &mut encoded_key)?;
                total_key_bytes = total_key_bytes
                    .checked_add(encoded_key.len())
                    .ok_or(CanonicalCborError::LengthOutOfRange)?;
                if total_key_bytes > MAX_CANONICAL_BYTES {
                    return Err(CanonicalCborError::EncodedTooLarge {
                        bytes: total_key_bytes,
                        maximum: MAX_CANONICAL_BYTES,
                    });
                }
                entries.push((encoded_key, value));
            }
            entries.sort_by(|left, right| canonical_key_order(&left.0, &right.0));
            if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CanonicalCborError::DuplicateMapKey);
            }
            encode_head(5, entries.len() as u64, output)?;
            for (key, value) in entries {
                push(output, &key)?;
                encode_value(value, depth + 1, output)?;
            }
        }
    }
    Ok(())
}

fn validate_container(count: usize) -> Result<(), CanonicalCborError> {
    if count > MAX_CANONICAL_CONTAINER_ITEMS {
        Err(CanonicalCborError::ContainerTooLarge {
            count,
            maximum: MAX_CANONICAL_CONTAINER_ITEMS,
        })
    } else {
        Ok(())
    }
}

fn canonical_key_order(left: &[u8], right: &[u8]) -> Ordering {
    left.cmp(right)
}

fn encode_float(value: f64, output: &mut Vec<u8>) -> Result<(), CanonicalCborError> {
    if !value.is_finite() {
        return Err(CanonicalCborError::NonFiniteFloat);
    }
    let half = f16::from_f64(value);
    if half.to_f64().to_bits() == value.to_bits() {
        push(output, &[0xf9])?;
        push(output, &half.to_bits().to_be_bytes())?;
        return Ok(());
    }
    let single = value as f32;
    if f64::from(single).to_bits() == value.to_bits() {
        push(output, &[0xfa])?;
        push(output, &single.to_bits().to_be_bytes())?;
        return Ok(());
    }
    push(output, &[0xfb])?;
    push(output, &value.to_bits().to_be_bytes())
}

fn encode_head(major: u8, value: u64, output: &mut Vec<u8>) -> Result<(), CanonicalCborError> {
    let lead = major << 5;
    match value {
        0..=23 => push(output, &[lead | value as u8]),
        24..=0xff => push(output, &[lead | 24, value as u8]),
        0x100..=0xffff => {
            push(output, &[lead | 25])?;
            push(output, &(value as u16).to_be_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            push(output, &[lead | 26])?;
            push(output, &(value as u32).to_be_bytes())
        }
        _ => {
            push(output, &[lead | 27])?;
            push(output, &value.to_be_bytes())
        }
    }
}

fn push(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CanonicalCborError> {
    if output.len().saturating_add(bytes.len()) > MAX_CANONICAL_BYTES {
        return Err(CanonicalCborError::EncodedTooLarge {
            bytes: output.len().saturating_add(bytes.len()),
            maximum: MAX_CANONICAL_BYTES,
        });
    }
    output.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn decode_value(&mut self, depth: usize) -> Result<CanonicalValue, CanonicalCborError> {
        if depth > MAX_CANONICAL_DEPTH {
            return Err(CanonicalCborError::TooDeep {
                depth,
                maximum: MAX_CANONICAL_DEPTH,
            });
        }
        let lead = self.take_byte()?;
        let major = lead >> 5;
        let additional = lead & 0x1f;
        match major {
            0 => {
                let value = self.decode_argument(additional)?;
                Ok(CanonicalValue::Unsigned(value))
            }
            1 => {
                let encoded = self.decode_argument(additional)?;
                let value = -1_i128 - i128::from(encoded);
                let value =
                    i64::try_from(value).map_err(|_| CanonicalCborError::IntegerOutOfRange)?;
                Ok(CanonicalValue::Integer(value))
            }
            2 => {
                let length = self.decode_length(additional)?;
                Ok(CanonicalValue::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.decode_length(additional)?;
                let value = core::str::from_utf8(self.take(length)?)
                    .map_err(|_| CanonicalCborError::InvalidUtf8)?;
                Ok(CanonicalValue::Text(value.to_owned()))
            }
            4 => {
                let count = self.decode_length(additional)?;
                validate_container(count)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.decode_value(depth + 1)?);
                }
                Ok(CanonicalValue::Array(values))
            }
            5 => {
                let count = self.decode_length(additional)?;
                validate_container(count)?;
                let mut values = Vec::with_capacity(count);
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..count {
                    let key_start = self.offset;
                    let key = self.decode_value(depth + 1)?;
                    let key_bytes = self.bytes[key_start..self.offset].to_vec();
                    if let Some(previous) = &previous_key
                        && canonical_key_order(previous, &key_bytes) != Ordering::Less
                    {
                        return Err(CanonicalCborError::NonCanonicalMapOrder);
                    }
                    previous_key = Some(key_bytes);
                    let value = self.decode_value(depth + 1)?;
                    values.push((key, value));
                }
                Ok(CanonicalValue::Map(values))
            }
            7 => self.decode_simple(additional),
            _ => Err(CanonicalCborError::UnsupportedType),
        }
    }

    fn decode_simple(&mut self, additional: u8) -> Result<CanonicalValue, CanonicalCborError> {
        match additional {
            20 => Ok(CanonicalValue::Bool(false)),
            21 => Ok(CanonicalValue::Bool(true)),
            22 => Ok(CanonicalValue::Null),
            25 => {
                let bits = u16::from_be_bytes(self.take(2)?.try_into().expect("exact length"));
                let value = f16::from_bits(bits).to_f64();
                ensure_finite(value)?;
                Ok(CanonicalValue::Float(value))
            }
            26 => {
                let bits = u32::from_be_bytes(self.take(4)?.try_into().expect("exact length"));
                let value = f64::from(f32::from_bits(bits));
                ensure_finite(value)?;
                if f16::from_f64(value).to_f64().to_bits() == value.to_bits() {
                    return Err(CanonicalCborError::NonCanonical);
                }
                Ok(CanonicalValue::Float(value))
            }
            27 => {
                let bits = u64::from_be_bytes(self.take(8)?.try_into().expect("exact length"));
                let value = f64::from_bits(bits);
                ensure_finite(value)?;
                let single = value as f32;
                if f64::from(single).to_bits() == value.to_bits() {
                    return Err(CanonicalCborError::NonCanonical);
                }
                Ok(CanonicalValue::Float(value))
            }
            _ => Err(CanonicalCborError::UnsupportedType),
        }
    }

    fn decode_length(&mut self, additional: u8) -> Result<usize, CanonicalCborError> {
        let value = self.decode_argument(additional)?;
        usize::try_from(value).map_err(|_| CanonicalCborError::LengthOutOfRange)
    }

    fn decode_argument(&mut self, additional: u8) -> Result<u64, CanonicalCborError> {
        let (value, minimum) = match additional {
            value @ 0..=23 => (u64::from(value), 0),
            24 => (u64::from(self.take_byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("exact length"),
                )),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().expect("exact length"),
                )),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().expect("exact length")),
                0x1_0000_0000,
            ),
            _ => return Err(CanonicalCborError::IndefiniteOrReserved),
        };
        if value < minimum {
            return Err(CanonicalCborError::NonCanonical);
        }
        Ok(value)
    }

    fn take_byte(&mut self) -> Result<u8, CanonicalCborError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(CanonicalCborError::UnexpectedEnd)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalCborError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CanonicalCborError::LengthOutOfRange)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CanonicalCborError::UnexpectedEnd)?;
        self.offset = end;
        Ok(value)
    }
}

fn ensure_finite(value: f64) -> Result<(), CanonicalCborError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(CanonicalCborError::NonFiniteFloat)
    }
}

fn decode_exact_cose_sign1(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 64]), TrustError> {
    if bytes.len() > MAX_CANONICAL_BYTES + 128 {
        return Err(TrustError::InvalidCoseSign1);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take_byte()? != 0xd2 || decoder.take_byte()? != 0x84 {
        return Err(TrustError::InvalidCoseSign1);
    }
    let protected = take_canonical_byte_string(&mut decoder)?;
    if protected != COSE_PROTECTED_HEADER {
        return Err(TrustError::WrongCoseProtectedHeader);
    }
    if decoder.take_byte()? != 0xa0 {
        return Err(TrustError::NonEmptyCoseUnprotectedHeader);
    }
    let payload = take_canonical_byte_string(&mut decoder)?.to_vec();
    let signature: [u8; SIGNATURE_BYTES] = take_canonical_byte_string(&mut decoder)?
        .try_into()
        .map_err(|_| TrustError::InvalidCoseSignatureLength)?;
    if !decoder.is_finished() {
        return Err(TrustError::InvalidCoseSign1);
    }
    Ok((payload, signature))
}

fn take_canonical_byte_string<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], TrustError> {
    let lead = decoder.take_byte()?;
    if lead >> 5 != 2 {
        return Err(TrustError::InvalidCoseSign1);
    }
    let length = decoder.decode_length(lead & 0x1f)?;
    decoder.take(length).map_err(TrustError::from)
}

fn parse_prefixed_hex(
    value: &str,
    expected_prefix: &'static str,
) -> Result<[u8; 32], IdentifierParseError> {
    let Some(hex) = value.strip_prefix(expected_prefix) else {
        return Err(IdentifierParseError::WrongPrefix { expected_prefix });
    };
    if hex.len() != 64 {
        return Err(IdentifierParseError::InvalidLength {
            found: value.len(),
            expected: expected_prefix.len() + 64,
        });
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = decode_hex(pair[0], index * 2)? << 4 | decode_hex(pair[1], index * 2 + 1)?;
    }
    Ok(bytes)
}

fn decode_hex(byte: u8, index: usize) -> Result<u8, IdentifierParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(IdentifierParseError::UppercaseHex { index }),
        _ => Err(IdentifierParseError::InvalidHex { index, byte }),
    }
}

fn write_lower_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentifierParseError {
    #[error("identifier must start with {expected_prefix}")]
    WrongPrefix { expected_prefix: &'static str },
    #[error("identifier is {found} bytes; expected exactly {expected}")]
    InvalidLength { found: usize, expected: usize },
    #[error("uppercase hexadecimal digit at offset {index}")]
    UppercaseHex { index: usize },
    #[error("invalid hexadecimal byte 0x{byte:02x} at offset {index}")]
    InvalidHex { index: usize, byte: u8 },
}

#[derive(Debug, Error, PartialEq)]
pub enum CanonicalCborError {
    #[error("canonical CBOR exceeds {maximum} bytes (attempted {bytes})")]
    EncodedTooLarge { bytes: usize, maximum: usize },
    #[error("canonical value nesting depth {depth} exceeds {maximum}")]
    TooDeep { depth: usize, maximum: usize },
    #[error("container contains {count} items; maximum is {maximum}")]
    ContainerTooLarge { count: usize, maximum: usize },
    #[error("map contains duplicate canonical keys")]
    DuplicateMapKey,
    #[error("map keys are not in deterministic encoded-byte order")]
    NonCanonicalMapOrder,
    #[error("NaN and infinity are not accepted in signed data")]
    NonFiniteFloat,
    #[error("input is not preferred deterministic CBOR")]
    NonCanonical,
    #[error("unexpected end of CBOR input")]
    UnexpectedEnd,
    #[error("trailing bytes after canonical CBOR value")]
    TrailingData,
    #[error("unsupported CBOR type")]
    UnsupportedType,
    #[error("indefinite-length or reserved CBOR encoding is not accepted")]
    IndefiniteOrReserved,
    #[error("CBOR length cannot be represented on this platform")]
    LengthOutOfRange,
    #[error("CBOR integer is outside the supported signed range")]
    IntegerOutOfRange,
    #[error("CBOR text is not valid UTF-8")]
    InvalidUtf8,
}

#[derive(Debug, Error, PartialEq)]
pub enum TrustError {
    #[error(transparent)]
    Identifier(#[from] IdentifierParseError),
    #[error(transparent)]
    CanonicalCbor(#[from] CanonicalCborError),
    #[error("Ed25519 public key is invalid")]
    InvalidPublicKey,
    #[error("space ID cannot be all zeroes")]
    NilSpaceId,
    #[error("entity ID cannot be nil")]
    NilEntityId,
    #[error("invalid entity schema: {0}")]
    InvalidSchema(String),
    #[error("operation timestamp cannot be negative: {0}")]
    NegativeOccurredAt(i64),
    #[error("operation has {count} causal parents; maximum is {maximum}")]
    TooManyCausalParents { count: usize, maximum: usize },
    #[error("operation has {count} authorization references; maximum is {maximum}")]
    TooManyAuthorizationReferences { count: usize, maximum: usize },
    #[error("duplicate causal parent {0}")]
    DuplicateCausalParent(OperationId),
    #[error("duplicate authorization reference {0}")]
    DuplicateAuthorizationReference(OperationId),
    #[error("causal parents are not unique and strictly ascending")]
    CausalParentsNotStrictlyAscending,
    #[error("authorization references are not unique and strictly ascending")]
    AuthorizationNotStrictlyAscending,
    #[error("operation payload actor {payload} does not match signing key actor {key}")]
    SigningActorMismatch { payload: ActorId, key: ActorId },
    #[error("expected actor {expected}, but signature belongs to {found}")]
    UnexpectedActor { expected: ActorId, found: ActorId },
    #[error("operation ID does not match canonical payload")]
    OperationIdMismatch,
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    #[error("signed payload uses the wrong protocol domain")]
    WrongOperationDomain,
    #[error("signed payload does not use operation protocol version 2")]
    UnsupportedOperationVersion,
    #[error("invalid operation payload: {0}")]
    InvalidOperationPayload(&'static str),
    #[error("invalid deterministic COSE_Sign1 envelope")]
    InvalidCoseSign1,
    #[error("COSE protected header must be exactly {{1: -8}}")]
    WrongCoseProtectedHeader,
    #[error("COSE unprotected header must be empty")]
    NonEmptyCoseUnprotectedHeader,
    #[error("COSE signature must be exactly 64 bytes")]
    InvalidCoseSignatureLength,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::{format, string::ToString, vec};
    use core::str::FromStr;

    use serde::Deserialize;

    use super::*;

    const ZERO_SEED_PUBLIC_KEY: &str =
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn fixed_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed([0_u8; 32])
    }

    fn fixture_payload() -> OperationPayload {
        let key = fixed_key();
        OperationPayload::new(
            SpaceId::from_bytes([0x11; 32]),
            key.actor_id(),
            Uuid::parse_str("018f3e7a-5b6c-7d8e-9fab-102030405060").unwrap(),
            "record.v1",
            vec![
                OperationId::from_bytes([0xfe; 32]),
                OperationId::from_bytes([0x01; 32]),
            ],
            vec![OperationId::from_bytes([0x80; 32])],
            1_720_000_000_123,
            OperationNonce::from_bytes([0x22; 16]),
            CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text("hello".into()),
                ),
                (CanonicalValue::Unsigned(0), CanonicalValue::Unsigned(0)),
            ]),
        )
        .unwrap()
    }

    #[test]
    fn self_certifying_ids_embed_the_public_key() {
        let key = fixed_key();
        assert_eq!(hex(key.public_key().as_bytes()), ZERO_SEED_PUBLIC_KEY);
        assert_eq!(key.actor_id().as_bytes(), key.public_key().as_bytes());
        assert_eq!(key.node_id().as_bytes(), key.public_key().as_bytes());
        assert_eq!(
            key.actor_id().to_string(),
            format!("actor:ed25519:{ZERO_SEED_PUBLIC_KEY}")
        );
        assert_eq!(
            key.node_id().to_string(),
            format!("node:ed25519:{ZERO_SEED_PUBLIC_KEY}")
        );
        assert_eq!(key.actor_id().public_key().unwrap(), key.public_key());
    }

    #[test]
    fn identifier_wires_are_strict() {
        let actor = fixed_key().actor_id();
        assert_eq!(ActorId::from_str(&actor.to_string()).unwrap(), actor);
        assert!(matches!(
            ActorId::from_str(&actor.to_string().to_uppercase()),
            Err(IdentifierParseError::WrongPrefix { .. })
                | Err(IdentifierParseError::UppercaseHex { .. })
        ));
        assert!(matches!(
            ActorId::from_str(&actor.to_string().replace("actor:", "node:")),
            Err(IdentifierParseError::WrongPrefix { .. })
        ));
        assert!(matches!(
            SpaceId::from_str("space:00"),
            Err(IdentifierParseError::InvalidLength { .. })
        ));
    }

    #[test]
    fn cbor_uses_core_deterministic_map_order_and_shortest_floats() {
        let value = CanonicalValue::Map(vec![
            (CanonicalValue::Integer(-1), CanonicalValue::Bool(false)),
            (CanonicalValue::Unsigned(100), CanonicalValue::Bool(true)),
        ]);
        // Raw encoded-byte ordering puts 0x18 0x64 before 0x20. Legacy
        // length-first ordering would do the opposite.
        assert_eq!(
            value.to_canonical_cbor().unwrap(),
            hex_bytes("a21864f520f4")
        );
        assert_eq!(
            CanonicalValue::Float(1.5).to_canonical_cbor().unwrap(),
            hex_bytes("f93e00")
        );
        assert!(matches!(
            CanonicalValue::Float(f64::NAN).to_canonical_cbor(),
            Err(CanonicalCborError::NonFiniteFloat)
        ));
    }

    #[test]
    fn decoder_rejects_noncanonical_encodings() {
        assert!(matches!(
            CanonicalValue::from_canonical_cbor(&hex_bytes("1817")),
            Err(CanonicalCborError::NonCanonical)
        ));
        assert!(matches!(
            CanonicalValue::from_canonical_cbor(&hex_bytes("a220f41864f5")),
            Err(CanonicalCborError::NonCanonicalMapOrder)
        ));
        assert!(matches!(
            CanonicalValue::from_canonical_cbor(&hex_bytes("fa3fc00000")),
            Err(CanonicalCborError::NonCanonical)
        ));
    }

    #[test]
    fn causal_parents_have_one_canonical_order() {
        let payload = fixture_payload();
        assert_eq!(
            payload.causal_parents()[0],
            OperationId::from_bytes([1; 32])
        );
        assert_eq!(
            payload.causal_parents()[1],
            OperationId::from_bytes([0xfe; 32])
        );

        let duplicate = OperationPayload::new(
            payload.space_id(),
            payload.actor_id(),
            payload.entity_id(),
            payload.schema(),
            vec![OperationId::from_bytes([1; 32]); 2],
            payload.authorization().to_vec(),
            payload.occurred_at_unix_ms(),
            payload.nonce(),
            payload.body().clone(),
        );
        assert!(matches!(
            duplicate,
            Err(TrustError::DuplicateCausalParent(_))
        ));
    }

    #[test]
    fn schema_names_are_bounded_lowercase_ascii_tokens() {
        let payload = fixture_payload();
        for schema in ["", ".record", "Record.v1", "récit.v1", "record/v1"] {
            assert!(matches!(
                OperationPayload::new(
                    payload.space_id(),
                    payload.actor_id(),
                    payload.entity_id(),
                    schema,
                    payload.causal_parents().to_vec(),
                    payload.authorization().to_vec(),
                    payload.occurred_at_unix_ms(),
                    payload.nonce(),
                    payload.body().clone(),
                ),
                Err(TrustError::InvalidSchema(_))
            ));
        }

        assert!(
            OperationPayload::new(
                payload.space_id(),
                payload.actor_id(),
                payload.entity_id(),
                "record.private-v1",
                payload.causal_parents().to_vec(),
                payload.authorization().to_vec(),
                payload.occurred_at_unix_ms(),
                payload.nonce(),
                payload.body().clone(),
            )
            .is_ok()
        );
    }

    #[test]
    fn signs_verifies_and_round_trips_exact_cose_sign1() {
        let payload = fixture_payload();
        let signed = payload.sign(&fixed_key()).unwrap();
        let verified = signed.verify().unwrap();
        assert_eq!(verified.operation_id, payload.operation_id().unwrap());
        assert_eq!(verified.actor_id, payload.actor_id());
        assert_eq!(verified.space_id, payload.space_id());

        let encoded = signed.to_cose_sign1().unwrap();
        assert_eq!(&encoded[..6], &[0xd2, 0x84, 0x43, 0xa1, 0x01, 0x27]);
        let decoded = SignedOperation::from_cose_sign1(&encoded).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.verify().unwrap(), verified);
    }

    #[test]
    fn tampering_any_signed_byte_or_signature_is_detected() {
        let mut signed = fixture_payload().sign(&fixed_key()).unwrap();
        *signed.payload.last_mut().unwrap() ^= 1;
        assert!(matches!(
            signed.verify(),
            Err(TrustError::OperationIdMismatch)
        ));

        let mut signed = fixture_payload().sign(&fixed_key()).unwrap();
        signed.signature[0] ^= 1;
        assert!(matches!(
            signed.verify(),
            Err(TrustError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn domain_and_version_are_enforced_even_with_a_valid_signature() {
        let key = fixed_key();
        let value =
            CanonicalValue::from_canonical_cbor(&fixture_payload().canonical_bytes().unwrap())
                .unwrap();
        let CanonicalValue::Array(mut fields) = value else {
            unreachable!();
        };
        fields[0] = CanonicalValue::Text("org.example.operation.v2".into());
        let wrong_domain = manually_sign(CanonicalValue::Array(fields.clone()), &key);
        assert!(matches!(
            wrong_domain.verify(),
            Err(TrustError::WrongOperationDomain)
        ));

        fields[0] = CanonicalValue::Text(OPERATION_DOMAIN.into());
        fields[1] = CanonicalValue::Unsigned(1);
        let version_one = manually_sign(CanonicalValue::Array(fields), &key);
        assert!(matches!(
            version_one.verify(),
            Err(TrustError::UnsupportedOperationVersion)
        ));
    }

    #[test]
    fn signing_key_must_match_payload_actor() {
        let payload = fixture_payload();
        let other = Ed25519SigningKey::from_seed([1_u8; 32]);
        assert!(matches!(
            payload.sign(&other),
            Err(TrustError::SigningActorMismatch { .. })
        ));
    }

    #[test]
    fn cose_headers_are_exact_not_extensible_ambient_authority() {
        let signed = fixture_payload().sign(&fixed_key()).unwrap();
        let mut encoded = signed.to_cose_sign1().unwrap();
        encoded[5] = 0x26;
        assert!(matches!(
            SignedOperation::from_cose_sign1(&encoded),
            Err(TrustError::WrongCoseProtectedHeader)
        ));
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConformanceFixture {
        domain: String,
        protocol_version: u64,
        protected_header_hex: String,
        seed_hex: String,
        actor_id: String,
        node_id: String,
        space_id: String,
        entity_id: String,
        schema: String,
        causal_parents: Vec<String>,
        authorization: Vec<String>,
        occurred_at_unix_ms: i64,
        nonce_hex: String,
        body_cbor_hex: String,
        payload_cbor_hex: String,
        operation_id: String,
        signature_hex: String,
        cose_sign1_hex: String,
    }

    #[test]
    fn fixed_cross_platform_conformance_vector() {
        let fixture: ConformanceFixture =
            serde_json::from_str(include_str!("../fixtures/operation-v2.json")).unwrap();
        let seed: [u8; 32] = hex_bytes(&fixture.seed_hex).try_into().unwrap();
        let key = Ed25519SigningKey::from_seed(seed);
        assert_eq!(fixture.domain, OPERATION_DOMAIN);
        assert_eq!(fixture.protocol_version, OPERATION_PROTOCOL_VERSION);
        assert_eq!(hex(&COSE_PROTECTED_HEADER), fixture.protected_header_hex);
        assert_eq!(key.actor_id().to_string(), fixture.actor_id);
        assert_eq!(key.node_id().to_string(), fixture.node_id);

        let body = CanonicalValue::from_canonical_cbor(&hex_bytes(&fixture.body_cbor_hex)).unwrap();
        let payload = OperationPayload::new(
            fixture.space_id.parse().unwrap(),
            key.actor_id(),
            fixture.entity_id.parse().unwrap(),
            fixture.schema,
            fixture
                .causal_parents
                .iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            fixture
                .authorization
                .iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            fixture.occurred_at_unix_ms,
            OperationNonce::from_bytes(hex_bytes(&fixture.nonce_hex).try_into().unwrap()),
            body,
        )
        .unwrap();
        let signed = payload.sign(&key).unwrap();
        assert_eq!(hex(signed.payload_bytes()), fixture.payload_cbor_hex);
        assert_eq!(signed.operation_id().to_string(), fixture.operation_id);
        assert_eq!(hex(signed.signature_bytes()), fixture.signature_hex);
        assert_eq!(
            hex(&signed.to_cose_sign1().unwrap()),
            fixture.cose_sign1_hex
        );
        assert_eq!(
            SignedOperation::from_cose_sign1(&hex_bytes(&fixture.cose_sign1_hex))
                .unwrap()
                .verify()
                .unwrap()
                .operation_id,
            signed.operation_id()
        );
    }

    #[test]
    fn detached_identity_proofs_are_domain_separated_and_tamper_evident() {
        let key = fixed_key();
        let message = b"canonical pairing descriptor";
        let signature = key.sign_detached(DetachedSignatureDomain::PairingInvitationV1, message);

        key.node_id()
            .verify_detached(
                DetachedSignatureDomain::PairingInvitationV1,
                message,
                &signature,
            )
            .unwrap();
        assert!(
            key.actor_id()
                .verify_detached(
                    DetachedSignatureDomain::PairingInvitationV1,
                    b"canonical pairing descriptor!",
                    &signature,
                )
                .is_err()
        );
        assert!(
            key.node_id()
                .verify_detached(
                    DetachedSignatureDomain::PairingReceiptV1,
                    message,
                    &signature,
                )
                .is_err()
        );
        assert_eq!(format!("{signature:?}"), "DetachedSignature([REDACTED])");
    }

    #[test]
    #[ignore = "developer helper for regenerating the checked-in vector"]
    fn print_conformance_vector() {
        let payload = fixture_payload();
        let signed = payload.sign(&fixed_key()).unwrap();
        std::println!("actorId={}", payload.actor_id());
        std::println!("nodeId={}", fixed_key().node_id());
        std::println!(
            "bodyCborHex={}",
            hex(&payload.body().to_canonical_cbor().unwrap())
        );
        std::println!("payloadCborHex={}", hex(signed.payload_bytes()));
        std::println!("operationId={}", signed.operation_id());
        std::println!("signatureHex={}", hex(signed.signature_bytes()));
        std::println!("coseSign1Hex={}", hex(&signed.to_cose_sign1().unwrap()));
    }

    fn manually_sign(value: CanonicalValue, key: &Ed25519SigningKey) -> SignedOperation {
        let payload = value.to_canonical_cbor().unwrap();
        let input = cose_signature_structure(&payload).unwrap();
        SignedOperation {
            operation_id: hash_operation_payload(&payload),
            signature: key.0.sign(&input).to_bytes(),
            payload,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
