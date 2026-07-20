use super::*;
use fractonica_content::ResourceRef;
use fractonica_trust::CanonicalValue;
use serde_json::json;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_seed([byte; 32])
}

fn space(byte: u8) -> SpaceId {
    SpaceId::from_bytes([byte; 32])
}

fn entity(value: u128) -> EntityId {
    EntityId::new(Uuid::from_u128(value))
}

fn digest(byte: u8) -> OperationId {
    OperationId::from_bytes([byte; 32])
}

fn nonce(byte: u8) -> OperationNonce {
    OperationNonce::from_bytes([byte; 16])
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

fn put(
    key: &SigningKey,
    space_id: SpaceId,
    entity_id: EntityId,
    parents: Vec<OperationId>,
    nonce_byte: u8,
    text: &str,
) -> SignedOperationEnvelope {
    SignedOperationEnvelope::sign(
        space_id,
        entity_id,
        EntitySchema::RecordV1,
        parents,
        vec![digest(0xa0)],
        2_000 + i64::from(nonce_byte),
        nonce(nonce_byte),
        OperationBody::Put {
            document: document(text),
        },
        key,
    )
    .expect("sign record put")
}

fn tombstone(
    key: &SigningKey,
    space_id: SpaceId,
    entity_id: EntityId,
    parent: OperationId,
    nonce_byte: u8,
) -> SignedOperationEnvelope {
    SignedOperationEnvelope::sign(
        space_id,
        entity_id,
        EntitySchema::RecordV1,
        vec![parent],
        vec![digest(0xa0)],
        2_000 + i64::from(nonce_byte),
        nonce(nonce_byte),
        OperationBody::Tombstone,
        key,
    )
    .expect("sign record tombstone")
}

fn valid_grant(subject: ActorId) -> CapabilityGrant {
    CapabilityGrant {
        subject,
        actions: vec![
            CapabilityAction::AppendOperation,
            CapabilityAction::ReadSpace,
            CapabilityAction::WriteContent,
        ],
        schemas: vec![EntitySchema::RecordV1],
        record_visibilities: vec![RecordVisibility::Public, RecordVisibility::Private],
        content_roles: vec!["attachment".into(), "photo".into()],
        max_resource_byte_length: Some(4_194_304),
        not_before_unix_ms: Some(1_000),
        expires_at_unix_ms: Some(9_000),
        delegation_depth: 2,
        label: "Phone writer".into(),
    }
}

#[test]
fn signed_record_round_trips_through_strict_json_and_cose() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 3, "created");
    operation.verify().expect("verify signed record");

    let json = serde_json::to_value(&operation).expect("serialize projection");
    assert_eq!(json["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(json["schema"], "record.v1");
    assert_eq!(json["nonce"], "03030303030303030303030303030303");
    assert_eq!(json["body"]["kind"], "put");
    assert!(json["coseSign1"].as_str().is_some_and(|value| {
        !value.contains('=')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }));

    let decoded: SignedOperationEnvelope =
        serde_json::from_value(json).expect("deserialize strict projection");
    assert_eq!(decoded, operation);
    decoded.verify().expect("verify deserialized projection");
    assert_eq!(
        SignedOperationEnvelope::from_cose_sign1(&operation.cose_sign1)
            .expect("project canonical COSE"),
        operation
    );
}

#[test]
fn projection_drift_and_signature_tampering_are_rejected() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 4, "created");

    let mut time = operation.clone();
    time.occurred_at_unix_ms += 1;
    assert_eq!(
        time.verify(),
        Err(DataModelError::ProjectionMismatch {
            field: "occurredAtUnixMs"
        })
    );

    let mut text = operation.clone();
    let OperationBody::Put { document } = &mut text.body else {
        panic!("put fixture")
    };
    document.text = Some("tampered".into());
    assert_eq!(
        text.verify(),
        Err(DataModelError::ProjectionMismatch { field: "body" })
    );

    let mut identifier = operation.clone();
    identifier.operation_id = digest(0xff);
    assert_eq!(
        identifier.verify(),
        Err(DataModelError::ProjectionMismatch {
            field: "operationId"
        })
    );

    let mut cose = operation.clone();
    let last = cose.cose_sign1.len() - 1;
    cose.cose_sign1[last] ^= 1;
    assert!(matches!(cose.verify(), Err(DataModelError::Trust(_))));
}

#[test]
fn every_redundant_projection_identity_field_is_bound_to_signed_bytes() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 4, "created");

    let mut space_id = operation.clone();
    space_id.space_id = space(2);
    assert_eq!(
        space_id.verify(),
        Err(DataModelError::ProjectionMismatch { field: "spaceId" })
    );

    let mut actor = operation.clone();
    actor.actor_id = key(9).actor_id();
    assert_eq!(
        actor.verify(),
        Err(DataModelError::ProjectionMismatch { field: "actorId" })
    );

    let mut entity_id = operation.clone();
    entity_id.entity_id = entity(2);
    assert_eq!(
        entity_id.verify(),
        Err(DataModelError::ProjectionMismatch { field: "entityId" })
    );

    let mut schema = operation.clone();
    schema.schema = EntitySchema::CapabilityGrantV1;
    assert_eq!(
        schema.verify(),
        Err(DataModelError::ProjectionMismatch { field: "schema" })
    );

    let mut parents = operation.clone();
    parents.causal_parents = vec![digest(1)];
    assert_eq!(
        parents.verify(),
        Err(DataModelError::ProjectionMismatch {
            field: "causalParents"
        })
    );

    let mut authorization = operation.clone();
    authorization.authorization = vec![digest(0xa1)];
    assert_eq!(
        authorization.verify(),
        Err(DataModelError::ProjectionMismatch {
            field: "authorization"
        })
    );

    let mut projected_nonce = operation;
    projected_nonce.nonce = nonce(5);
    assert_eq!(
        projected_nonce.verify(),
        Err(DataModelError::ProjectionMismatch { field: "nonce" })
    );
}

#[test]
fn json_projection_rejects_v1_noncanonical_nonce_and_padded_base64() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 5, "created");
    let mut value = serde_json::to_value(operation).expect("serialize projection");

    for noncanonical in [
        "00000000-0000-0000-0000-000000000000",
        "00000000000000000000000000000001",
        "00000000-0000-0000-0000-00000000000A",
    ] {
        let mut invalid_entity = value.clone();
        invalid_entity["entityId"] = json!(noncanonical);
        assert!(serde_json::from_value::<SignedOperationEnvelope>(invalid_entity).is_err());
    }

    value["protocolVersion"] = json!(1);
    let version: SignedOperationEnvelope =
        serde_json::from_value(value.clone()).expect("version is structurally JSON-valid");
    assert!(matches!(
        version.verify(),
        Err(DataModelError::UnsupportedProtocolVersion { found: 1, .. })
    ));

    value["protocolVersion"] = json!(PROTOCOL_VERSION);
    value["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(serde_json::from_value::<SignedOperationEnvelope>(value.clone()).is_err());

    value["nonce"] = json!("05050505050505050505050505050505");
    let padded = format!("{}=", value["coseSign1"].as_str().expect("COSE string"));
    value["coseSign1"] = json!(padded);
    assert!(serde_json::from_value::<SignedOperationEnvelope>(value).is_err());
}

#[test]
fn json_projection_rejects_omitted_fields_that_canonical_serialization_emits() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 5, "created");
    let mut record = serde_json::to_value(operation).expect("serialize record projection");
    record["body"]["document"]
        .as_object_mut()
        .expect("record document")
        .remove("metadata");
    assert!(serde_json::from_value::<SignedOperationEnvelope>(record).is_err());

    let signing_key = key(7);
    let grant = SignedOperationEnvelope::sign(
        space(1),
        entity(2),
        EntitySchema::CapabilityGrantV1,
        Vec::new(),
        vec![digest(0xa0)],
        2_000,
        nonce(6),
        OperationBody::CapabilityGrant {
            grant: valid_grant(key(8).actor_id()),
        },
        &signing_key,
    )
    .expect("sign grant");
    let grant = serde_json::to_value(grant).expect("serialize grant projection");
    for field in ["schemas", "recordVisibilities", "contentRoles"] {
        let mut missing = grant.clone();
        missing["body"]["grant"]
            .as_object_mut()
            .expect("grant projection")
            .remove(field);
        assert!(
            serde_json::from_value::<SignedOperationEnvelope>(missing).is_err(),
            "missing {field} must be rejected"
        );
    }
}

#[test]
fn arbitrary_or_noncanonical_schema_bodies_are_not_typed_records() {
    let signing_key = key(7);
    let payload = TrustOperationPayload::new(
        space(1),
        signing_key.actor_id(),
        entity(1).as_uuid(),
        EntitySchema::RecordV1.as_str(),
        Vec::new(),
        vec![digest(0xa0)],
        2_000,
        nonce(6),
        CanonicalValue::Bytes(vec![1, 2, 3]),
    )
    .expect("trust layer accepts schema-opaque canonical value");
    let cose = payload
        .sign(&signing_key)
        .expect("sign opaque body")
        .to_cose_sign1()
        .expect("encode COSE");
    assert!(matches!(
        SignedOperationEnvelope::from_cose_sign1(&cose),
        Err(DataModelError::InvalidCanonicalBody {
            schema: EntitySchema::RecordV1,
            ..
        })
    ));

    let mut trailing = put(&signing_key, space(1), entity(1), Vec::new(), 7, "created").cose_sign1;
    trailing.push(0);
    assert!(matches!(
        SignedOperationEnvelope::from_cose_sign1(&trailing),
        Err(DataModelError::Trust(_))
    ));
}

#[test]
fn record_canonical_mapping_preserves_metadata_and_resources() {
    let content_id = fractonica_content::hash_bytes(b"image");
    let mut value = document("with resource");
    value.end_at_unix_ms = Some(1_500);
    value.visibility = RecordVisibility::Private;
    value.metadata = BTreeMap::from([
        ("float".into(), json!(1.5)),
        ("negative".into(), json!(-7)),
        ("nested".into(), json!({"array": [true, null, u64::MAX]})),
    ]);
    value.resources.push(ResourceRef {
        content_id,
        byte_length: 5,
        media_type: "image/jpeg".into(),
        role: "photo".into(),
        original_name: Some("eclipse.jpeg".into()),
    });
    let operation = SignedOperationEnvelope::sign(
        space(1),
        entity(1),
        EntitySchema::RecordV1,
        Vec::new(),
        vec![digest(0xa0)],
        2_000,
        nonce(8),
        OperationBody::Put {
            document: value.clone(),
        },
        &key(7),
    )
    .expect("sign complete record");

    let recovered = SignedOperationEnvelope::from_cose_sign1(&operation.cose_sign1)
        .expect("decode canonical record");
    assert_eq!(recovered.body, OperationBody::Put { document: value });
}

#[test]
fn record_validation_retains_temporal_metadata_and_resource_bounds() {
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

    let resource = ResourceRef {
        content_id: fractonica_content::hash_bytes(b"missing is still valid"),
        byte_length: 22,
        media_type: "application/octet-stream".into(),
        role: "attachment".into(),
        original_name: None,
    };
    let mut duplicated = document("text");
    duplicated.resources = vec![resource.clone(), resource];
    assert!(matches!(
        duplicated.validate(),
        Err(DataModelError::DuplicateResourceContentId(_))
    ));
}

#[test]
fn genesis_grant_and_revocation_have_typed_signed_mappings() {
    let controller = key(7);
    let subject = key(9);
    let space_id = space(2);
    let genesis = SignedOperationEnvelope::sign(
        space_id,
        entity(10),
        EntitySchema::SpaceGenesisV1,
        Vec::new(),
        Vec::new(),
        1_000,
        nonce(1),
        OperationBody::SpaceGenesis {
            controller: controller.actor_id(),
        },
        &controller,
    )
    .expect("sign genesis");

    let grant = SignedOperationEnvelope::sign(
        space_id,
        entity(11),
        EntitySchema::CapabilityGrantV1,
        Vec::new(),
        vec![genesis.operation_id],
        1_100,
        nonce(2),
        OperationBody::CapabilityGrant {
            grant: valid_grant(subject.actor_id()),
        },
        &controller,
    )
    .expect("sign capability grant");

    let revocation = SignedOperationEnvelope::sign(
        space_id,
        entity(12),
        EntitySchema::CapabilityRevokeV1,
        Vec::new(),
        vec![genesis.operation_id],
        1_200,
        nonce(3),
        OperationBody::CapabilityRevoke {
            revocation: CapabilityRevocation {
                grant_id: grant.operation_id,
                reason: CapabilityRevocationReason::KeyRotated,
                detail: Some("Replaced by phone key 2".into()),
            },
        },
        &controller,
    )
    .expect("sign capability revocation");

    for operation in [genesis, grant, revocation] {
        operation.verify().expect("verify system operation");
        let json = serde_json::to_vec(&operation).expect("serialize system projection");
        let decoded: SignedOperationEnvelope =
            serde_json::from_slice(&json).expect("deserialize system projection");
        assert_eq!(decoded, operation);
    }
}

#[test]
fn system_schema_pairing_and_capability_bounds_are_enforced() {
    let controller = key(7);
    let subject = key(9);
    let mut grant = valid_grant(subject.actor_id());
    grant.actions.swap(0, 1);
    assert!(matches!(
        grant.validate(),
        Err(DataModelError::CapabilitySetNotStrictlySorted { field: "actions" })
    ));

    let mut invalid_window = valid_grant(subject.actor_id());
    invalid_window.expires_at_unix_ms = invalid_window.not_before_unix_ms;
    assert!(matches!(
        invalid_window.validate(),
        Err(DataModelError::InvalidCapabilityWindow { .. })
    ));

    assert!(matches!(
        SignedOperationEnvelope::sign(
            space(1),
            entity(1),
            EntitySchema::SpaceGenesisV1,
            Vec::new(),
            Vec::new(),
            1_000,
            nonce(1),
            OperationBody::SpaceGenesis {
                controller: subject.actor_id()
            },
            &controller,
        ),
        Err(DataModelError::GenesisControllerMismatch { .. })
    ));

    assert!(matches!(
        SignedOperationEnvelope::sign(
            space(1),
            entity(1),
            EntitySchema::RecordV1,
            Vec::new(),
            Vec::new(),
            1_000,
            nonce(1),
            OperationBody::Tombstone,
            &controller,
        ),
        Err(DataModelError::MissingAuthorization)
    ));

    assert!(matches!(
        SignedOperationEnvelope::sign(
            space(1),
            entity(1),
            EntitySchema::CapabilityGrantV1,
            Vec::new(),
            vec![digest(1)],
            1_000,
            nonce(1),
            OperationBody::Tombstone,
            &controller,
        ),
        Err(DataModelError::SchemaBodyMismatch { .. })
    ));
}

#[test]
fn constructor_normalizes_parent_and_authorization_sets() {
    let signing_key = key(7);
    let operation = SignedOperationEnvelope::sign(
        space(1),
        entity(1),
        EntitySchema::RecordV1,
        vec![digest(3), digest(1), digest(2)],
        vec![digest(9), digest(7), digest(8)],
        2_000,
        nonce(9),
        OperationBody::Tombstone,
        &signing_key,
    )
    .expect("trust constructor sorts digest sets");
    assert_eq!(
        operation.causal_parents,
        vec![digest(1), digest(2), digest(3)]
    );
    assert_eq!(
        operation.authorization,
        vec![digest(7), digest(8), digest(9)]
    );

    let mut unsorted = operation;
    unsorted.causal_parents.swap(0, 1);
    assert!(matches!(
        unsorted.verify(),
        Err(DataModelError::CapabilitySetNotStrictlySorted {
            field: "causalParents"
        })
    ));
}

#[test]
fn reducer_preserves_linear_concurrent_merge_and_tombstone_semantics() {
    let signing_key = key(7);
    let space_id = space(1);
    let entity_id = entity(1);
    let root = put(&signing_key, space_id, entity_id, Vec::new(), 10, "root");
    let branch_a = put(
        &signing_key,
        space_id,
        entity_id,
        vec![root.operation_id],
        11,
        "branch a",
    );
    let branch_b = put(
        &signing_key,
        space_id,
        entity_id,
        vec![root.operation_id],
        12,
        "branch b",
    );
    let merge = put(
        &signing_key,
        space_id,
        entity_id,
        vec![branch_b.operation_id, branch_a.operation_id],
        13,
        "merged",
    );
    let deleted = tombstone(&signing_key, space_id, entity_id, merge.operation_id, 14);

    let reduced = reduce_entity(
        space_id,
        entity_id,
        EntitySchema::RecordV1,
        [root, branch_a, branch_b, merge, deleted],
    )
    .expect("reduce signed graph");
    assert_eq!(reduced.operation_count, 5);
    assert_eq!(reduced.heads.len(), 1);
    assert!(reduced.heads[0].is_tombstone());
}

#[test]
fn reducer_is_space_scoped_and_requires_topological_parents() {
    let signing_key = key(7);
    let entity_id = entity(1);
    let foreign = put(&signing_key, space(2), entity_id, Vec::new(), 20, "foreign");
    let mut reducer = EntityReducer::new(space(1), entity_id, EntitySchema::RecordV1);
    assert!(matches!(
        reducer.apply(foreign),
        Err(DataModelError::ForeignSpace { .. })
    ));

    let missing = put(
        &signing_key,
        space(1),
        entity_id,
        vec![digest(0x55)],
        21,
        "missing parent",
    );
    assert!(matches!(
        reducer.apply(missing),
        Err(DataModelError::CausalParentNotPreexisting { .. })
    ));
}

#[test]
fn fixed_seed_record_has_stable_operation_and_cose_vectors() {
    let operation = put(&key(7), space(1), entity(1), Vec::new(), 3, "created");
    assert_eq!(
        operation.operation_id.to_string(),
        "sha-256:97184131cac96c99cf9cb8543387d4cf956bcdffffa6963e1501ac3479a66d75"
    );
    assert_eq!(
        operation.cose_sign1_base64url(),
        "0oRDoQEnoFjYi3gbb3JnLmZyYWN0b25pY2Eub3BlcmF0aW9uLnYyAlggAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFYIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIsUAAAAAAAAAAAAAAAAAAAAAFpcmVjb3JkLnYxgIFYIKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgGQfTUAMDAwMDAwMDAwMDAwMDAwOIARkD6PYAZPCfjJJnY3JlYXRlZKFmc291cmNlZHRlc3SAWECaMvTr65C7ZA8lOhzpbxU6IxVAtxgPl5EQubU3Y6W1uI-DigNSC6vCWJ9SkFMRsAGtW4GxO0QDKjOemTdW-cEH"
    );
}
