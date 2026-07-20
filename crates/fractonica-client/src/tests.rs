use std::{collections::BTreeMap, sync::Mutex};

use fractonica_data_model::{
    OperationBody, ProfileDocument, ProtectedDocument, RecordDocument, Visibility,
};

use super::*;

struct FixedRuntime {
    entity: EntityId,
    now: i64,
    nonces: Mutex<Vec<OperationNonce>>,
}

impl AuthoringRuntime for FixedRuntime {
    fn now_unix_ms(&self) -> Result<i64, RuntimeError> {
        Ok(self.now)
    }

    fn new_entity_id(&self) -> Result<EntityId, RuntimeError> {
        Ok(self.entity)
    }

    fn new_nonce(&self) -> Result<OperationNonce, RuntimeError> {
        self.nonces
            .lock()
            .expect("nonce fixture lock")
            .pop()
            .ok_or_else(|| RuntimeError::Entropy("fixture exhausted".into()))
    }
}

fn author() -> OperationAuthor<SoftwareActorKey, FixedRuntime> {
    OperationAuthor::new(
        AuthoringContext::new(
            SpaceId::from_bytes([1; 32]),
            vec![OperationId::from_bytes([0xa0; 32])],
        )
        .unwrap(),
        SoftwareActorKey::new(SigningKey::from_seed([7; 32])),
        FixedRuntime {
            entity: EntityId::new(Uuid::from_bytes([3; 16])),
            now: 1_800_000_000_000,
            nonces: Mutex::new(vec![
                OperationNonce::from_bytes([12; 16]),
                OperationNonce::from_bytes([11; 16]),
                OperationNonce::from_bytes([10; 16]),
            ]),
        },
    )
}

fn record(text: &str) -> ProtectedDocument<RecordDocument> {
    ProtectedDocument::Public {
        document: RecordDocument {
            start_at_unix_ms: 1_700_000_000_000,
            end_at_unix_ms: None,
            emoji: Some("🌀".into()),
            text: Some(text.into()),
            metadata: BTreeMap::new(),
            resources: Vec::new(),
            references: Vec::new(),
        },
    }
}

#[test]
fn creates_offline_record_without_network_or_server_identity() {
    let author = author();
    let operation = author.create_record(record("created offline")).unwrap();
    operation.verify().unwrap();
    assert_eq!(operation.space_id, author.context().space_id);
    assert_eq!(
        operation.entity_id,
        EntityId::new(Uuid::from_bytes([3; 16]))
    );
    assert_eq!(operation.causal_parents, Vec::<OperationId>::new());
    assert_eq!(
        operation.authorization,
        vec![OperationId::from_bytes([0xa0; 32])]
    );
    assert_eq!(
        operation.body.declared_visibility(),
        Some(Visibility::Public)
    );
}

#[test]
fn update_merges_every_locally_observed_head_and_delete_advances_it() {
    let author = author();
    let entity = ObservedEntity::new(
        author.context().space_id,
        EntityId::new(Uuid::from_bytes([3; 16])),
        EntitySchema::Record,
        vec![
            OperationId::from_bytes([9; 32]),
            OperationId::from_bytes([8; 32]),
        ],
    )
    .unwrap();
    let update = author
        .update_record(&entity, record("merged edit"))
        .unwrap();
    assert_eq!(
        update.causal_parents,
        vec![
            OperationId::from_bytes([8; 32]),
            OperationId::from_bytes([9; 32])
        ]
    );

    let advanced = ObservedEntity::new(
        author.context().space_id,
        entity.entity_id,
        EntitySchema::Record,
        vec![update.operation_id],
    )
    .unwrap();
    let deletion = author.delete(&advanced).unwrap();
    assert_eq!(deletion.causal_parents, vec![update.operation_id]);
    assert!(matches!(deletion.body, OperationBody::Tombstone));
}

#[test]
fn profile_identity_is_derived_from_the_signing_actor() {
    let author = author();
    let profile = author
        .put_profile(
            None,
            ProfileDocument {
                handle: "dimaswift".into(),
                display_name: "Dima".into(),
                saros_anchor: 141,
                avatar: None,
                metadata: BTreeMap::new(),
            },
        )
        .unwrap();
    assert_eq!(profile.entity_id, profile_entity_id(profile.actor_id));
}

struct WrongSigner {
    key: SigningKey,
}

impl ActorKeyCustody for WrongSigner {
    fn actor_id(&self) -> ActorId {
        self.key.actor_id()
    }

    fn sign_operation(&self, draft: &OperationDraft) -> Result<OperationEnvelope, KeyCustodyError> {
        let mut changed = draft.clone();
        changed.occurred_at_unix_ms += 1;
        OperationEnvelope::sign(
            changed.space_id,
            changed.entity_id,
            changed.schema,
            changed.causal_parents,
            changed.authorization,
            changed.occurred_at_unix_ms,
            changed.nonce,
            changed.body,
            &self.key,
        )
        .map_err(KeyCustodyError::from)
    }
}

#[test]
fn rejects_key_custody_that_signs_a_different_draft() {
    let base = author();
    let author = OperationAuthor::new(
        base.context,
        WrongSigner {
            key: SigningKey::from_seed([7; 32]),
        },
        base.runtime,
    );
    assert!(matches!(
        author.create_record(record("wrong")),
        Err(ClientError::SignerProjectionMismatch)
    ));
}
