//! Deterministic construction of trusted personal-space bootstrap anchors.
//!
//! Signing keys come from the keystore boundary. The production material
//! source uses the OS CSPRNG; tests and alternative platforms can inject the
//! same small source port without changing bootstrap semantics.

use fractonica_application::{MAX_SPACE_DISPLAY_NAME_CHARS, TrustedSpaceBootstrapRequest};
use fractonica_data_model::{
    CapabilityAction, CapabilityGrant, DataModelError, EntityId, EntitySchema, OperationBody,
    OperationEnvelope, OperationNonce, Visibility,
};
use fractonica_keystore::IdentityBundle;
use thiserror::Error;
use uuid::Builder;

/// Maximum attempts made when an injected source returns unusable material.
pub const MAX_BOOTSTRAP_COLLISION_ATTEMPTS: usize = 16;
/// Largest millisecond timestamp representable by UUID version 7.
pub const MAX_UUID_V7_UNIX_MS: i64 = (1_i64 << 48) - 1;

const INITIAL_WRITER_GRANT_LABEL: &str = "Initial local writer";

/// Source of UUIDv7 entity IDs and operation nonces.
///
/// Implementations must use cryptographically secure randomness in
/// production. Returning the material through semantic types keeps raw random
/// buffers outside bootstrap construction and makes deterministic tests small.
pub trait BootstrapMaterialSource {
    fn next_entity_id(&mut self, trusted_unix_ms: u64) -> Result<EntityId, BootstrapSourceError>;

    fn next_nonce(&mut self) -> Result<OperationNonce, BootstrapSourceError>;
}

/// OS-backed production source using `getrandom` and RFC 9562 UUIDv7 layout.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsBootstrapMaterialSource;

impl BootstrapMaterialSource for OsBootstrapMaterialSource {
    fn next_entity_id(&mut self, trusted_unix_ms: u64) -> Result<EntityId, BootstrapSourceError> {
        let mut random = [0_u8; 10];
        getrandom::fill(&mut random).map_err(BootstrapSourceError::OsRandom)?;
        let uuid = Builder::from_unix_timestamp_millis(trusted_unix_ms, &random).into_uuid();
        Ok(EntityId::new(uuid))
    }

    fn next_nonce(&mut self) -> Result<OperationNonce, BootstrapSourceError> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(BootstrapSourceError::OsRandom)?;
        Ok(OperationNonce::from_bytes(random))
    }
}

/// Builds the first two signed operations for a new self-owned space.
pub fn build_trusted_space_bootstrap(
    identity: &IdentityBundle,
    display_name: impl Into<String>,
    trusted_current_unix_ms: i64,
) -> Result<TrustedSpaceBootstrapRequest, BootstrapBuildError> {
    let mut source = OsBootstrapMaterialSource;
    build_trusted_space_bootstrap_with_source(
        identity,
        display_name,
        trusted_current_unix_ms,
        &mut source,
    )
}

/// Deterministic core of [`build_trusted_space_bootstrap`].
pub fn build_trusted_space_bootstrap_with_source<S: BootstrapMaterialSource>(
    identity: &IdentityBundle,
    display_name: impl Into<String>,
    trusted_current_unix_ms: i64,
    source: &mut S,
) -> Result<TrustedSpaceBootstrapRequest, BootstrapBuildError> {
    let display_name = display_name.into();
    validate_display_name(&display_name)?;
    let trusted_current_unix_ms_u64 = validate_trusted_time(trusted_current_unix_ms)?;

    let genesis_entity_id = next_distinct_entity_id(source, trusted_current_unix_ms_u64, &[])?;
    let grant_entity_id =
        next_distinct_entity_id(source, trusted_current_unix_ms_u64, &[genesis_entity_id])?;
    let genesis_nonce = source.next_nonce()?;
    let initial_grant_nonce = next_distinct_nonce(source, genesis_nonce)?;

    let controller_key = identity.space_controller_key();
    let controller_actor_id = identity.space_controller_actor_id();
    let local_writer_actor_id = identity.local_writer_actor_id();

    let genesis = OperationEnvelope::sign(
        identity.space_id(),
        genesis_entity_id,
        EntitySchema::SpaceGenesis,
        Vec::new(),
        Vec::new(),
        trusted_current_unix_ms,
        genesis_nonce,
        OperationBody::SpaceGenesis {
            controller: controller_actor_id,
        },
        controller_key,
    )?;

    let initial_grant = OperationEnvelope::sign(
        identity.space_id(),
        grant_entity_id,
        EntitySchema::CapabilityGrant,
        Vec::new(),
        vec![genesis.operation_id],
        trusted_current_unix_ms,
        initial_grant_nonce,
        OperationBody::CapabilityGrant {
            grant: CapabilityGrant {
                subject: local_writer_actor_id,
                actions: vec![
                    CapabilityAction::AppendOperation,
                    CapabilityAction::ReadSpace,
                ],
                schemas: vec![
                    EntitySchema::Event,
                    EntitySchema::Profile,
                    EntitySchema::Record,
                    EntitySchema::Tag,
                ],
                visibilities: vec![Visibility::Public, Visibility::Private],
                content_roles: Vec::new(),
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: INITIAL_WRITER_GRANT_LABEL.to_owned(),
            },
        },
        controller_key,
    )?;

    Ok(TrustedSpaceBootstrapRequest {
        display_name,
        genesis,
        initial_grant,
        received_at_unix_ms: trusted_current_unix_ms,
    })
}

fn validate_display_name(display_name: &str) -> Result<(), BootstrapBuildError> {
    let characters = display_name.chars().count();
    if characters == 0
        || characters > MAX_SPACE_DISPLAY_NAME_CHARS
        || display_name.chars().any(char::is_control)
    {
        Err(BootstrapBuildError::InvalidDisplayName {
            characters,
            maximum: MAX_SPACE_DISPLAY_NAME_CHARS,
        })
    } else {
        Ok(())
    }
}

fn validate_trusted_time(value: i64) -> Result<u64, BootstrapBuildError> {
    if !(0..=MAX_UUID_V7_UNIX_MS).contains(&value) {
        Err(BootstrapBuildError::InvalidTrustedTime {
            found: value,
            maximum: MAX_UUID_V7_UNIX_MS,
        })
    } else {
        Ok(value as u64)
    }
}

fn next_distinct_entity_id<S: BootstrapMaterialSource>(
    source: &mut S,
    trusted_unix_ms: u64,
    excluded: &[EntityId],
) -> Result<EntityId, BootstrapBuildError> {
    for _ in 0..MAX_BOOTSTRAP_COLLISION_ATTEMPTS {
        let candidate = source.next_entity_id(trusted_unix_ms)?;
        if !candidate.as_uuid().is_nil() && !excluded.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(BootstrapBuildError::EntityIdCollisionExhausted)
}

fn next_distinct_nonce<S: BootstrapMaterialSource>(
    source: &mut S,
    first: OperationNonce,
) -> Result<OperationNonce, BootstrapBuildError> {
    for _ in 0..MAX_BOOTSTRAP_COLLISION_ATTEMPTS {
        let candidate = source.next_nonce()?;
        if candidate != first {
            return Ok(candidate);
        }
    }
    Err(BootstrapBuildError::NonceCollisionExhausted)
}

#[derive(Debug, Error)]
pub enum BootstrapSourceError {
    #[error("OS cryptographic random source failed: {0}")]
    OsRandom(getrandom::Error),
    #[error("bootstrap material source is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum BootstrapBuildError {
    #[error("invalid space display name length {characters}; maximum is {maximum}")]
    InvalidDisplayName { characters: usize, maximum: usize },
    #[error("trusted Unix time {found}ms is outside UUIDv7 range 0..={maximum}")]
    InvalidTrustedTime { found: i64, maximum: i64 },
    #[error("could not obtain a distinct non-nil entity ID after bounded retries")]
    EntityIdCollisionExhausted,
    #[error("could not obtain distinct operation nonces after bounded retries")]
    NonceCollisionExhausted,
    #[error(transparent)]
    Source(#[from] BootstrapSourceError),
    #[error(transparent)]
    DataModel(#[from] DataModelError),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use fractonica_data_model::{SigningKey, SpaceId};
    use fractonica_keystore::IdentityBundle;
    use uuid::{Uuid, Version};

    use super::*;

    const NOW: i64 = 1_720_000_000_123;

    struct DeterministicSource {
        entity_ids: VecDeque<EntityId>,
        nonces: VecDeque<OperationNonce>,
        entity_calls: usize,
        nonce_calls: usize,
    }

    impl BootstrapMaterialSource for DeterministicSource {
        fn next_entity_id(
            &mut self,
            _trusted_unix_ms: u64,
        ) -> Result<EntityId, BootstrapSourceError> {
            self.entity_calls += 1;
            self.entity_ids
                .pop_front()
                .ok_or(BootstrapSourceError::Unavailable)
        }

        fn next_nonce(&mut self) -> Result<OperationNonce, BootstrapSourceError> {
            self.nonce_calls += 1;
            self.nonces
                .pop_front()
                .ok_or(BootstrapSourceError::Unavailable)
        }
    }

    #[test]
    fn deterministic_bootstrap_has_exact_trust_relationships() {
        let identity = identity();
        let genesis_entity = entity(1);
        let grant_entity = entity(2);
        let genesis_nonce = nonce(3);
        let grant_nonce = nonce(4);
        let mut source = source([genesis_entity, grant_entity], [genesis_nonce, grant_nonce]);

        let request = build_trusted_space_bootstrap_with_source(
            &identity,
            "Personal space",
            NOW,
            &mut source,
        )
        .unwrap();

        assert_eq!(request.display_name, "Personal space");
        assert_eq!(request.received_at_unix_ms, NOW);
        assert_eq!(request.genesis.space_id, identity.space_id());
        assert_eq!(request.genesis.entity_id, genesis_entity);
        assert_eq!(request.genesis.schema, EntitySchema::SpaceGenesis);
        assert_eq!(
            request.genesis.actor_id,
            identity.space_controller_actor_id()
        );
        assert!(request.genesis.causal_parents.is_empty());
        assert!(request.genesis.authorization.is_empty());
        assert_eq!(request.genesis.nonce, genesis_nonce);
        assert_eq!(
            request.genesis.body,
            OperationBody::SpaceGenesis {
                controller: identity.space_controller_actor_id()
            }
        );
        request.genesis.verify().unwrap();

        assert_eq!(request.initial_grant.space_id, identity.space_id());
        assert_eq!(request.initial_grant.entity_id, grant_entity);
        assert_ne!(request.initial_grant.entity_id, request.genesis.entity_id);
        assert_eq!(request.initial_grant.schema, EntitySchema::CapabilityGrant);
        assert_eq!(
            request.initial_grant.actor_id,
            identity.space_controller_actor_id()
        );
        assert!(request.initial_grant.causal_parents.is_empty());
        assert_eq!(
            request.initial_grant.authorization,
            vec![request.genesis.operation_id]
        );
        assert_eq!(request.initial_grant.nonce, grant_nonce);
        assert_ne!(
            request.genesis.operation_id,
            request.initial_grant.operation_id
        );
        request.initial_grant.verify().unwrap();

        let OperationBody::CapabilityGrant { grant } = &request.initial_grant.body else {
            panic!("initial operation must carry a capability grant");
        };
        assert_eq!(grant.subject, identity.local_writer_actor_id());
        assert_ne!(grant.subject, identity.space_controller_actor_id());
        assert_eq!(
            grant.actions,
            vec![
                CapabilityAction::AppendOperation,
                CapabilityAction::ReadSpace
            ]
        );
        assert_eq!(
            grant.schemas,
            vec![
                EntitySchema::Event,
                EntitySchema::Profile,
                EntitySchema::Record,
                EntitySchema::Tag,
            ]
        );
        assert_eq!(
            grant.visibilities,
            vec![Visibility::Public, Visibility::Private]
        );
        assert!(grant.content_roles.is_empty());
        assert_eq!(grant.max_resource_byte_length, None);
        assert_eq!(grant.not_before_unix_ms, None);
        assert_eq!(grant.expires_at_unix_ms, None);
        assert_eq!(grant.delegation_depth, 0);
        assert_eq!(grant.label, INITIAL_WRITER_GRANT_LABEL);
        assert!(!grant.actions.contains(&CapabilityAction::WriteContent));
    }

    #[test]
    fn retries_nil_and_colliding_ids_and_nonces() {
        let identity = identity();
        let first = entity(10);
        let second = entity(11);
        let first_nonce = nonce(12);
        let second_nonce = nonce(13);
        let mut source = source(
            [EntityId::new(Uuid::nil()), first, first, second],
            [first_nonce, first_nonce, second_nonce],
        );

        let request =
            build_trusted_space_bootstrap_with_source(&identity, "Space", NOW, &mut source)
                .unwrap();

        assert_eq!(request.genesis.entity_id, first);
        assert_eq!(request.initial_grant.entity_id, second);
        assert_eq!(request.genesis.nonce, first_nonce);
        assert_eq!(request.initial_grant.nonce, second_nonce);
        assert_eq!(source.entity_calls, 4);
        assert_eq!(source.nonce_calls, 3);
    }

    #[test]
    fn collision_retry_is_bounded() {
        let identity = identity();
        let mut exhausted_source = source(
            [EntityId::new(Uuid::nil()); MAX_BOOTSTRAP_COLLISION_ATTEMPTS],
            [nonce(1), nonce(2)],
        );
        assert!(matches!(
            build_trusted_space_bootstrap_with_source(
                &identity,
                "Space",
                NOW,
                &mut exhausted_source
            ),
            Err(BootstrapBuildError::EntityIdCollisionExhausted)
        ));
        assert_eq!(
            exhausted_source.entity_calls,
            MAX_BOOTSTRAP_COLLISION_ATTEMPTS
        );
        assert_eq!(exhausted_source.nonce_calls, 0);

        let same_nonce = nonce(9);
        let mut source = source(
            [entity(1), entity(2)],
            std::iter::once(same_nonce).chain(std::iter::repeat_n(
                same_nonce,
                MAX_BOOTSTRAP_COLLISION_ATTEMPTS,
            )),
        );
        assert!(matches!(
            build_trusted_space_bootstrap_with_source(&identity, "Space", NOW, &mut source),
            Err(BootstrapBuildError::NonceCollisionExhausted)
        ));
        assert_eq!(source.nonce_calls, MAX_BOOTSTRAP_COLLISION_ATTEMPTS + 1);
    }

    #[test]
    fn invalid_label_and_time_do_not_consume_randomness() {
        let identity = identity();
        for name in [
            String::new(),
            "bad\nname".to_owned(),
            "x".repeat(MAX_SPACE_DISPLAY_NAME_CHARS + 1),
        ] {
            let mut source = source([], []);
            assert!(matches!(
                build_trusted_space_bootstrap_with_source(&identity, name, NOW, &mut source),
                Err(BootstrapBuildError::InvalidDisplayName { .. })
            ));
            assert_eq!((source.entity_calls, source.nonce_calls), (0, 0));
        }

        for time in [-1, MAX_UUID_V7_UNIX_MS + 1] {
            let mut source = source([], []);
            assert!(matches!(
                build_trusted_space_bootstrap_with_source(&identity, "Space", time, &mut source),
                Err(BootstrapBuildError::InvalidTrustedTime { .. })
            ));
            assert_eq!((source.entity_calls, source.nonce_calls), (0, 0));
        }
    }

    #[test]
    fn os_source_creates_uuid_v7_entities() {
        let identity = identity();
        let request = build_trusted_space_bootstrap(&identity, "Space", NOW).unwrap();
        assert_eq!(
            request.genesis.entity_id.as_uuid().get_version(),
            Some(Version::SortRand)
        );
        assert_eq!(
            request.initial_grant.entity_id.as_uuid().get_version(),
            Some(Version::SortRand)
        );
        for entity_id in [request.genesis.entity_id, request.initial_grant.entity_id] {
            let (seconds, nanoseconds) = entity_id
                .as_uuid()
                .get_timestamp()
                .expect("UUIDv7 timestamp")
                .to_unix();
            assert_eq!(
                seconds * 1_000 + u64::from(nanoseconds) / 1_000_000,
                NOW as u64
            );
        }
        assert!(!request.genesis.entity_id.as_uuid().is_nil());
        assert_ne!(request.genesis.entity_id, request.initial_grant.entity_id);
        assert_ne!(request.genesis.nonce, request.initial_grant.nonce);
    }

    fn identity() -> IdentityBundle {
        IdentityBundle::from_keys(
            SigningKey::from_seed([1; 32]),
            SigningKey::from_seed([2; 32]),
            SigningKey::from_seed([3; 32]),
            SpaceId::from_bytes([4; 32]),
        )
        .unwrap()
    }

    fn entity(value: u128) -> EntityId {
        EntityId::new(Uuid::from_u128(value))
    }

    fn nonce(value: u8) -> OperationNonce {
        OperationNonce::from_bytes([value; 16])
    }

    fn source(
        entity_ids: impl IntoIterator<Item = EntityId>,
        nonces: impl IntoIterator<Item = OperationNonce>,
    ) -> DeterministicSource {
        DeterministicSource {
            entity_ids: entity_ids.into_iter().collect(),
            nonces: nonces.into_iter().collect(),
            entity_calls: 0,
            nonce_calls: 0,
        }
    }
}
