use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use fractonica_core::{InstallationId, InstallationMetadata};
use fractonica_data_model::{
    CapabilityAction, CapabilityGrant, OperationNonce, RecordDocument, SigningKey, Visibility,
};
use serde_json::json;

use super::*;

#[derive(Default)]
struct Calls {
    submit_spaces: Vec<SpaceId>,
    operation_spaces: Vec<SpaceId>,
    entity_spaces: Vec<SpaceId>,
    change_spaces: Vec<SpaceId>,
    bootstrap_spaces: Vec<SpaceId>,
}

struct StubRepository {
    calls: Mutex<Calls>,
    submits: AtomicUsize,
    replay_submit: AtomicBool,
}

impl Default for StubRepository {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Calls::default()),
            submits: AtomicUsize::new(0),
            replay_submit: AtomicBool::new(false),
        }
    }
}

impl StubRepository {
    fn descriptor(request: &TrustedSpaceBootstrapRequest) -> SpaceDescriptor {
        let OperationBody::SpaceGenesis { controller } = &request.genesis.body else {
            panic!("validated genesis fixture")
        };
        let OperationBody::CapabilityGrant { grant } = &request.initial_grant.body else {
            panic!("validated initial grant fixture")
        };
        SpaceDescriptor {
            space_id: request.genesis.space_id,
            display_name: request.display_name.clone(),
            genesis_operation_id: request.genesis.operation_id,
            initial_grant_operation_id: request.initial_grant.operation_id,
            controller_actor_id: *controller,
            local_writer_actor_id: grant.subject,
            created_at_unix_ms: request.received_at_unix_ms,
        }
    }
}

impl OperationRepository for StubRepository {
    fn readiness(&self) -> Result<RepositoryReadiness, RepositoryError> {
        Ok(RepositoryReadiness { schema_version: 4 })
    }

    fn installation(&self) -> Result<InstallationMetadata, RepositoryError> {
        Ok(InstallationMetadata {
            installation_id: InstallationId::new(Uuid::from_u128(1)),
            created_at_unix_ms: 1_000,
        })
    }

    fn space(&self, _space_id: SpaceId) -> Result<Option<SpaceDescriptor>, RepositoryError> {
        Ok(None)
    }

    fn spaces(&self) -> Result<Vec<SpaceDescriptor>, RepositoryError> {
        Ok(Vec::new())
    }

    fn bootstrap_trusted_space(
        &self,
        request: &TrustedSpaceBootstrapRequest,
    ) -> Result<TrustedSpaceBootstrapResult, RepositoryError> {
        self.calls
            .lock()
            .expect("calls lock")
            .bootstrap_spaces
            .push(request.genesis.space_id);
        Ok(TrustedSpaceBootstrapResult {
            space: Self::descriptor(request),
            genesis: StoredOperation {
                local_sequence: 1,
                received_at_unix_ms: request.received_at_unix_ms,
                operation: request.genesis.clone(),
            },
            initial_grant: StoredOperation {
                local_sequence: 2,
                received_at_unix_ms: request.received_at_unix_ms,
                operation: request.initial_grant.clone(),
            },
            replayed: false,
        })
    }

    fn submit_operation(
        &self,
        space_id: SpaceId,
        request: &SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, RepositoryError> {
        self.submits.fetch_add(1, Ordering::Relaxed);
        self.calls
            .lock()
            .expect("calls lock")
            .submit_spaces
            .push(space_id);
        Ok(SubmitOperationResult {
            operation: StoredOperation {
                local_sequence: 7,
                received_at_unix_ms: request.received_at_unix_ms,
                operation: request.operation.clone(),
            },
            replayed: self.replay_submit.load(Ordering::Relaxed),
        })
    }

    fn operation(
        &self,
        space_id: SpaceId,
        _operation_id: OperationId,
    ) -> Result<Option<StoredOperation>, RepositoryError> {
        self.calls
            .lock()
            .expect("calls lock")
            .operation_spaces
            .push(space_id);
        Ok(None)
    }

    fn entity_state(
        &self,
        space_id: SpaceId,
        _entity_id: EntityId,
    ) -> Result<Option<EntityState>, RepositoryError> {
        self.calls
            .lock()
            .expect("calls lock")
            .entity_spaces
            .push(space_id);
        Ok(None)
    }

    fn changes_after(
        &self,
        space_id: SpaceId,
        after_local_sequence: u64,
        _limit: usize,
    ) -> Result<OperationChangePage, RepositoryError> {
        self.calls
            .lock()
            .expect("calls lock")
            .change_spaces
            .push(space_id);
        Ok(OperationChangePage {
            space_id,
            operations: Vec::new(),
            next_after: after_local_sequence,
            has_more: false,
        })
    }
}

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

fn record_operation(space_id: SpaceId) -> OperationEnvelope {
    let signing_key = key(7);
    OperationEnvelope::sign(
        space_id,
        entity(1),
        EntitySchema::RecordV1,
        Vec::new(),
        vec![digest(0xa0)],
        2_000,
        nonce(1),
        OperationBody::Put {
            document: RecordDocument {
                start_at_unix_ms: 1_000,
                end_at_unix_ms: None,
                visibility: Visibility::Public,
                emoji: Some("🌒".into()),
                text: Some("signed".into()),
                metadata: std::collections::BTreeMap::from([("source".into(), json!("test"))]),
                resources: Vec::new(),
            },
        },
        &signing_key,
    )
    .expect("sign record")
}

fn bootstrap() -> TrustedSpaceBootstrapRequest {
    let controller = key(7);
    let local_writer = key(8);
    let space_id = space(1);
    let genesis = OperationEnvelope::sign(
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
    let initial_grant = OperationEnvelope::sign(
        space_id,
        entity(11),
        EntitySchema::CapabilityGrantV1,
        Vec::new(),
        vec![genesis.operation_id],
        1_001,
        nonce(2),
        OperationBody::CapabilityGrant {
            grant: CapabilityGrant {
                subject: local_writer.actor_id(),
                actions: vec![
                    CapabilityAction::AppendOperation,
                    CapabilityAction::ReadSpace,
                ],
                schemas: vec![
                    EntitySchema::EventV1,
                    EntitySchema::ProfileV1,
                    EntitySchema::RecordV1,
                    EntitySchema::RecordV2,
                    EntitySchema::TagV1,
                ],
                visibilities: vec![Visibility::Public, Visibility::Private],
                content_roles: Vec::new(),
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: "Initial local writer".into(),
            },
        },
        &controller,
    )
    .expect("sign initial grant");
    TrustedSpaceBootstrapRequest {
        display_name: "My Fractonica".into(),
        genesis,
        initial_grant,
        received_at_unix_ms: 1_100,
    }
}

#[test]
fn rejects_v1_and_projection_drift_before_repository_submission() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let space_id = space(1);

    let mut version_one = record_operation(space_id);
    version_one.protocol_version = 1;
    assert!(matches!(
        service.submit_operation(
            space_id,
            SubmitOperationRequest {
                operation: version_one,
                received_at_unix_ms: 2_100,
            },
        ),
        Err(ApplicationError::InvalidOperation(
            DataModelError::UnsupportedProtocolVersion { found: 1, .. }
        ))
    ));

    let mut drifted = record_operation(space_id);
    drifted.occurred_at_unix_ms += 1;
    assert!(matches!(
        service.submit_operation(
            space_id,
            SubmitOperationRequest {
                operation: drifted,
                received_at_unix_ms: 2_100,
            },
        ),
        Err(ApplicationError::InvalidOperation(
            DataModelError::ProjectionMismatch { .. }
        ))
    ));
    assert_eq!(repository.submits.load(Ordering::Relaxed), 0);
}

#[test]
fn rejects_space_path_mismatch_and_generic_genesis() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let operation = record_operation(space(1));
    assert!(matches!(
        service.submit_operation(
            space(2),
            SubmitOperationRequest {
                operation,
                received_at_unix_ms: 2_100,
            },
        ),
        Err(ApplicationError::SpacePathMismatch { .. })
    ));

    let request = bootstrap();
    assert!(matches!(
        service.submit_operation(
            request.genesis.space_id,
            SubmitOperationRequest {
                operation: request.genesis,
                received_at_unix_ms: 2_100,
            },
        ),
        Err(ApplicationError::GenericGenesisForbidden)
    ));
    assert_eq!(repository.submits.load(Ordering::Relaxed), 0);
}

#[test]
fn operation_digest_replay_result_passes_through_without_an_idempotency_key() {
    let repository = Arc::new(StubRepository::default());
    repository.replay_submit.store(true, Ordering::Relaxed);
    let service = ApplicationService::new(repository.clone());
    let space_id = space(1);
    let operation = record_operation(space_id);
    let operation_id = operation.operation_id;
    let result = service
        .submit_operation(
            space_id,
            SubmitOperationRequest {
                operation,
                received_at_unix_ms: 2_100,
            },
        )
        .expect("repository replay");

    assert!(result.replayed);
    assert_eq!(result.operation.operation.operation_id, operation_id);
    assert_eq!(result.operation.received_at_unix_ms, 2_100);
    assert_eq!(repository.submits.load(Ordering::Relaxed), 1);
}

#[test]
fn validates_limits_and_forwards_space_scope_to_every_read() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let space_id = space(3);

    assert!(matches!(
        service.changes_after(space_id, 0, 0),
        Err(ApplicationError::InvalidChangeLimit)
    ));
    assert!(matches!(
        service.changes_after(space_id, 0, MAX_CHANGE_LIMIT + 1),
        Err(ApplicationError::InvalidChangeLimit)
    ));
    service
        .changes_after(space_id, 7, DEFAULT_CHANGE_LIMIT)
        .expect("scoped changes");
    service
        .entity_state(space_id, entity(1))
        .expect("scoped entity state");
    service
        .operation(space_id, digest(1))
        .expect("scoped operation lookup");

    let calls = repository.calls.lock().expect("calls lock");
    assert_eq!(calls.change_spaces, vec![space_id]);
    assert_eq!(calls.entity_spaces, vec![space_id]);
    assert_eq!(calls.operation_spaces, vec![space_id]);
}

#[test]
fn trusted_bootstrap_is_validated_then_forwarded_atomically() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let request = bootstrap();
    let space_id = request.genesis.space_id;
    let result = service
        .bootstrap_trusted_space(request)
        .expect("trusted bootstrap");

    assert_eq!(result.space.space_id, space_id);
    assert_eq!(result.space.display_name, "My Fractonica");
    assert_eq!(result.space.local_writer_actor_id, key(8).actor_id());
    assert_eq!(result.genesis.local_sequence, 1);
    assert_eq!(result.initial_grant.local_sequence, 2);
    assert_eq!(
        repository
            .calls
            .lock()
            .expect("calls lock")
            .bootstrap_spaces,
        vec![space_id]
    );
}

#[test]
fn trusted_bootstrap_requires_controller_signature_and_distinct_writer() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let mut request = bootstrap();
    let controller = key(7);
    request.initial_grant = OperationEnvelope::sign(
        request.genesis.space_id,
        entity(11),
        EntitySchema::CapabilityGrantV1,
        Vec::new(),
        vec![request.genesis.operation_id],
        1_001,
        nonce(3),
        OperationBody::CapabilityGrant {
            grant: CapabilityGrant {
                subject: controller.actor_id(),
                actions: vec![CapabilityAction::ReadSpace],
                schemas: Vec::new(),
                visibilities: Vec::new(),
                content_roles: Vec::new(),
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 0,
                label: "Invalid self grant".into(),
            },
        },
        &controller,
    )
    .expect("sign foreign initial grant");

    assert!(matches!(
        service.bootstrap_trusted_space(request),
        Err(ApplicationError::InvalidTrustedBootstrap(_))
    ));
    assert!(
        repository
            .calls
            .lock()
            .expect("calls lock")
            .bootstrap_spaces
            .is_empty()
    );
}

#[test]
fn trusted_bootstrap_rejects_a_broader_writer_scope() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let controller = key(7);
    let mut request = bootstrap();
    request.initial_grant = OperationEnvelope::sign(
        request.genesis.space_id,
        request.initial_grant.entity_id,
        EntitySchema::CapabilityGrantV1,
        Vec::new(),
        vec![request.genesis.operation_id],
        1_001,
        nonce(2),
        OperationBody::CapabilityGrant {
            grant: CapabilityGrant {
                subject: key(8).actor_id(),
                actions: vec![
                    CapabilityAction::AppendOperation,
                    CapabilityAction::IssueCapability,
                    CapabilityAction::ReadSpace,
                ],
                schemas: vec![EntitySchema::RecordV1],
                visibilities: vec![Visibility::Public, Visibility::Private],
                content_roles: Vec::new(),
                max_resource_byte_length: None,
                not_before_unix_ms: None,
                expires_at_unix_ms: None,
                delegation_depth: 1,
                label: "Overbroad writer".into(),
            },
        },
        &controller,
    )
    .expect("sign overbroad writer grant");
    assert!(matches!(
        service.bootstrap_trusted_space(request),
        Err(ApplicationError::InvalidTrustedBootstrap(_))
    ));

    assert!(
        repository
            .calls
            .lock()
            .expect("calls lock")
            .bootstrap_spaces
            .is_empty()
    );
}

#[test]
fn trusted_bootstrap_rejects_invalid_display_name() {
    let repository = Arc::new(StubRepository::default());
    let service = ApplicationService::new(repository.clone());
    let mut request = bootstrap();
    request.display_name = "\n".into();

    assert!(matches!(
        service.bootstrap_trusted_space(request),
        Err(ApplicationError::InvalidTrustedBootstrap(_))
    ));
    assert!(
        repository
            .calls
            .lock()
            .expect("calls lock")
            .bootstrap_spaces
            .is_empty()
    );
}

#[test]
fn authorization_failures_remain_structurally_distinct_repository_errors() {
    let revoked = RepositoryError::Authorization(AuthorizationError::Revoked(digest(8)));
    assert!(matches!(
        revoked,
        RepositoryError::Authorization(AuthorizationError::Revoked(id)) if id == digest(8)
    ));
    assert!(matches!(
        RepositoryError::MissingAuthorization(digest(9)),
        RepositoryError::MissingAuthorization(id) if id == digest(9)
    ));
    assert!(matches!(
        RepositoryError::CrossSpaceAuthorization(digest(10)),
        RepositoryError::CrossSpaceAuthorization(id) if id == digest(10)
    ));
}
