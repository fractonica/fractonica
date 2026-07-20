#![no_std]
#![forbid(unsafe_code)]
//! Canonical dual-signed proofs for capability-authorized peer requests.
//!
//! This crate authenticates requests; it does not provide confidentiality,
//! discovery, transport resumption, or listener policy.

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{fmt, str::FromStr};

use fractonica_trust::{
    ActorId, CanonicalValue, DetachedSignature, DetachedSignatureDomain, NodeId, OperationId,
    SigningKey, SpaceId, TrustError,
};
use thiserror::Error;

pub const PEER_PROTOCOL_VERSION: u8 = 1;
pub const MAX_PROOF_BYTES: usize = 4 * 1_024;
pub const MIN_REQUEST_LIFETIME_MS: i64 = 1_000;
pub const MAX_REQUEST_LIFETIME_MS: i64 = 30_000;
pub const MAX_FUTURE_SKEW_MS: i64 = 5_000;
pub const MAX_PEER_CHANGE_LIMIT: u16 = 200;

const READ_CHANGES_KIND: u64 = 0;
const FIXED_BYTES: usize = 16;
const SIGNATURE_HEX_BYTES: usize = 128;

macro_rules! fixed_hex_value {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; FIXED_BYTES]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; FIXED_BYTES]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; FIXED_BYTES] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(formatter, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl FromStr for $name {
            type Err = PeerProofError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_fixed_hex(value).map(Self)
            }
        }
    };
}

fixed_hex_value!(
    PeerSessionId,
    "Pairing-scoped identifier bound to one completed pairing lifecycle."
);
fixed_hex_value!(
    PeerRequestNonce,
    "Random 128-bit nonce consumed durably by the receiving node."
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerReadChangesProof {
    pub protocol_version: u8,
    pub session_id: PeerSessionId,
    pub space_id: SpaceId,
    pub node_id: NodeId,
    pub actor_id: ActorId,
    pub grant_operation_id: OperationId,
    pub after: u64,
    pub limit: u16,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub nonce: PeerRequestNonce,
    pub node_signature: DetachedSignature,
    pub actor_signature: DetachedSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerReadChangesFields {
    pub session_id: PeerSessionId,
    pub space_id: SpaceId,
    pub grant_operation_id: OperationId,
    pub after: u64,
    pub limit: u16,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub nonce: PeerRequestNonce,
}

impl PeerReadChangesProof {
    pub fn sign(
        fields: PeerReadChangesFields,
        node_key: &SigningKey,
        actor_key: &SigningKey,
    ) -> Result<Self, PeerProofError> {
        let mut proof = Self {
            protocol_version: PEER_PROTOCOL_VERSION,
            session_id: fields.session_id,
            space_id: fields.space_id,
            node_id: node_key.node_id(),
            actor_id: actor_key.actor_id(),
            grant_operation_id: fields.grant_operation_id,
            after: fields.after,
            limit: fields.limit,
            issued_at_unix_ms: fields.issued_at_unix_ms,
            expires_at_unix_ms: fields.expires_at_unix_ms,
            nonce: fields.nonce,
            node_signature: DetachedSignature::from_bytes([0; 64]),
            actor_signature: DetachedSignature::from_bytes([0; 64]),
        };
        proof.validate_unsigned()?;
        let bytes = proof.canonical_bytes()?;
        proof.node_signature =
            node_key.sign_detached(DetachedSignatureDomain::PeerNodeRequestV1, &bytes);
        proof.actor_signature =
            actor_key.sign_detached(DetachedSignatureDomain::PeerActorRequestV1, &bytes);
        Ok(proof)
    }

    pub fn verify(&self, receiving_now_unix_ms: i64) -> Result<(), PeerProofError> {
        self.validate_unsigned()?;
        if receiving_now_unix_ms < 0
            || receiving_now_unix_ms
                < self
                    .issued_at_unix_ms
                    .checked_sub(MAX_FUTURE_SKEW_MS)
                    .ok_or(PeerProofError::InvalidTime)?
            || receiving_now_unix_ms >= self.expires_at_unix_ms
        {
            return Err(PeerProofError::OutsideRequestWindow);
        }
        let bytes = self.canonical_bytes()?;
        self.node_id.verify_detached(
            DetachedSignatureDomain::PeerNodeRequestV1,
            &bytes,
            &self.node_signature,
        )?;
        self.actor_id.verify_detached(
            DetachedSignatureDomain::PeerActorRequestV1,
            &bytes,
            &self.actor_signature,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PeerProofError> {
        let bytes = CanonicalValue::Map(vec![
            (
                key(0),
                CanonicalValue::Unsigned(u64::from(self.protocol_version)),
            ),
            (key(1), CanonicalValue::Unsigned(READ_CHANGES_KIND)),
            (
                key(2),
                CanonicalValue::Bytes(self.session_id.as_bytes().to_vec()),
            ),
            (
                key(3),
                CanonicalValue::Bytes(self.space_id.as_bytes().to_vec()),
            ),
            (
                key(4),
                CanonicalValue::Bytes(self.node_id.as_bytes().to_vec()),
            ),
            (
                key(5),
                CanonicalValue::Bytes(self.actor_id.as_bytes().to_vec()),
            ),
            (
                key(6),
                CanonicalValue::Bytes(self.grant_operation_id.as_bytes().to_vec()),
            ),
            (key(7), CanonicalValue::Unsigned(self.after)),
            (key(8), CanonicalValue::Unsigned(u64::from(self.limit))),
            (key(9), CanonicalValue::Integer(self.issued_at_unix_ms)),
            (key(10), CanonicalValue::Integer(self.expires_at_unix_ms)),
            (
                key(11),
                CanonicalValue::Bytes(self.nonce.as_bytes().to_vec()),
            ),
        ])
        .to_canonical_cbor()?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(PeerProofError::ProofTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    #[must_use]
    pub fn node_signature_hex(&self) -> String {
        bytes_hex(self.node_signature.as_bytes())
    }

    #[must_use]
    pub fn actor_signature_hex(&self) -> String {
        bytes_hex(self.actor_signature.as_bytes())
    }

    pub fn parse_signature_hex(value: &str) -> Result<DetachedSignature, PeerProofError> {
        if value.len() != SIGNATURE_HEX_BYTES || !value.bytes().all(is_lower_hex) {
            return Err(PeerProofError::InvalidSignatureEncoding);
        }
        let mut bytes = [0_u8; 64];
        decode_hex(value.as_bytes(), &mut bytes)?;
        Ok(DetachedSignature::from_bytes(bytes))
    }

    fn validate_unsigned(&self) -> Result<(), PeerProofError> {
        if self.protocol_version != PEER_PROTOCOL_VERSION {
            return Err(PeerProofError::UnsupportedVersion(self.protocol_version));
        }
        self.space_id.validate()?;
        self.node_id.public_key()?;
        self.actor_id.public_key()?;
        if self.limit == 0 || self.limit > MAX_PEER_CHANGE_LIMIT || self.after > i64::MAX as u64 {
            return Err(PeerProofError::InvalidPage);
        }
        if self.issued_at_unix_ms < 0 || self.expires_at_unix_ms < 0 {
            return Err(PeerProofError::InvalidTime);
        }
        let lifetime = self
            .expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms)
            .ok_or(PeerProofError::InvalidTime)?;
        if !(MIN_REQUEST_LIFETIME_MS..=MAX_REQUEST_LIFETIME_MS).contains(&lifetime) {
            return Err(PeerProofError::InvalidLifetime(lifetime));
        }
        Ok(())
    }
}

const fn key(value: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(value)
}

fn parse_fixed_hex(value: &str) -> Result<[u8; FIXED_BYTES], PeerProofError> {
    if value.len() != FIXED_BYTES * 2 || !value.bytes().all(is_lower_hex) {
        return Err(PeerProofError::InvalidFixedHex);
    }
    let mut bytes = [0_u8; FIXED_BYTES];
    decode_hex(value.as_bytes(), &mut bytes)?;
    Ok(bytes)
}

fn decode_hex(input: &[u8], output: &mut [u8]) -> Result<(), PeerProofError> {
    if input.len() != output.len() * 2 {
        return Err(PeerProofError::InvalidFixedHex);
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(input[index * 2])? << 4) | hex_nibble(input[index * 2 + 1])?;
    }
    Ok(())
}

fn hex_nibble(value: u8) -> Result<u8, PeerProofError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(PeerProofError::InvalidFixedHex),
    }
}

const fn is_lower_hex(value: u8) -> bool {
    matches!(value, b'0'..=b'9' | b'a'..=b'f')
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

fn bytes_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[derive(Debug, Error)]
pub enum PeerProofError {
    #[error("unsupported peer proof version {0}")]
    UnsupportedVersion(u8),
    #[error("peer request page is invalid")]
    InvalidPage,
    #[error("peer request time is invalid")]
    InvalidTime,
    #[error("peer request lifetime {0}ms is invalid")]
    InvalidLifetime(i64),
    #[error("peer request is outside its receiving-node window")]
    OutsideRequestWindow,
    #[error("peer proof has {0} canonical bytes; maximum is {MAX_PROOF_BYTES}")]
    ProofTooLarge(usize),
    #[error("peer session or nonce is not strict lowercase hexadecimal")]
    InvalidFixedHex,
    #[error("peer signature is not strict lowercase hexadecimal")]
    InvalidSignatureEncoding,
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("canonical peer proof is invalid: {0}")]
    Canonical(String),
}

impl From<fractonica_trust::CanonicalCborError> for PeerProofError {
    fn from(error: fractonica_trust::CanonicalCborError) -> Self {
        Self::Canonical(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_784_265_600_000;

    fn fixture() -> PeerReadChangesProof {
        let node = SigningKey::from_seed([7; 32]);
        let actor = SigningKey::from_seed([8; 32]);
        PeerReadChangesProof::sign(
            PeerReadChangesFields {
                session_id: PeerSessionId::from_bytes([1; 16]),
                space_id: SpaceId::from_bytes([2; 32]),
                grant_operation_id: OperationId::from_bytes([3; 32]),
                after: 41,
                limit: 100,
                issued_at_unix_ms: NOW,
                expires_at_unix_ms: NOW + 30_000,
                nonce: PeerRequestNonce::from_bytes([4; 16]),
            },
            &node,
            &actor,
        )
        .unwrap()
    }

    #[test]
    fn dual_signed_proof_binds_every_request_field() {
        let proof = fixture();
        proof.verify(NOW).unwrap();
        let canonical = proof.canonical_bytes().unwrap();
        assert!(!canonical.is_empty());
        assert!(canonical.len() <= MAX_PROOF_BYTES);

        let mut changed = proof.clone();
        changed.after += 1;
        assert!(matches!(changed.verify(NOW), Err(PeerProofError::Trust(_))));

        let mut changed = proof.clone();
        changed.node_id = SigningKey::from_seed([9; 32]).node_id();
        assert!(matches!(changed.verify(NOW), Err(PeerProofError::Trust(_))));
    }

    #[test]
    fn request_window_and_strict_hex_are_bounded() {
        let proof = fixture();
        assert!(matches!(
            proof.verify(NOW - MAX_FUTURE_SKEW_MS - 1),
            Err(PeerProofError::OutsideRequestWindow)
        ));
        assert!(matches!(
            proof.verify(NOW + 30_000),
            Err(PeerProofError::OutsideRequestWindow)
        ));
        assert!(
            "0000000000000000000000000000000A"
                .parse::<PeerRequestNonce>()
                .is_err()
        );
        assert_eq!(
            PeerReadChangesProof::parse_signature_hex(&proof.actor_signature_hex()).unwrap(),
            proof.actor_signature
        );
    }
}
