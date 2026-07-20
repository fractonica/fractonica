use fractonica_application::{
    EntityState, MAX_CHANGE_LIMIT, MAX_ENTITY_HEADS, OperationChangePage, OperationRepository,
    PeerReadChangesRequest, RepositoryError, RepositoryReadiness, SpaceDescriptor, StoredOperation,
    SubmitOperationRequest, SubmitOperationResult, TrustedSpaceBootstrapRequest,
    TrustedSpaceBootstrapResult,
    authorization::{
        CapabilityView, CapabilityViewError, authorize_capability_action, authorize_operation,
        authorize_operation_for_visibility,
    },
};
use fractonica_core::InstallationMetadata;
use fractonica_data_model::{
    CapabilityAction, CapabilityRevocationReason, EntityId, EntitySchema, OperationBody,
    OperationEnvelope, OperationId, SpaceId, Visibility,
};
use fractonica_trust::SignedOperation as TrustSignedOperation;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use super::{SqliteStore, positive_u64, repository_sqlite, repository_unavailable};

const STORED_COLUMNS: &str = "local_sequence, operation_id, protocol_version, space_id, entity_id, \
    schema_id, actor_id, occurred_at_unix_ms, received_at_unix_ms, nonce, canonical_payload, \
    cose_sign1, projection_json";
const MAX_TRUSTED_SPACES: usize = 4_096;
const MAX_ACTIVE_PEER_NONCES_PER_SESSION: i64 = 4_096;
const PEER_NONCE_CLEANUP_BATCH: i64 = 1_024;

impl OperationRepository for SqliteStore {
    fn readiness(&self) -> Result<RepositoryReadiness, RepositoryError> {
        SqliteStore::readiness(self)
            .map(|ready| RepositoryReadiness {
                schema_version: ready.schema_version,
            })
            .map_err(repository_unavailable)
    }

    fn installation(&self) -> Result<InstallationMetadata, RepositoryError> {
        SqliteStore::installation(self).map_err(repository_unavailable)
    }

    fn space(&self, space_id: SpaceId) -> Result<Option<SpaceDescriptor>, RepositoryError> {
        let connection = lock(self)?;
        load_space(&connection, space_id)
    }

    fn spaces(&self) -> Result<Vec<SpaceDescriptor>, RepositoryError> {
        let connection = lock(self)?;
        let mut statement = connection
            .prepare(
                "SELECT space_id, display_name, genesis_operation_id,
                        initial_grant_operation_id, controller_actor_id,
                        local_writer_actor_id, created_at_unix_ms
                 FROM spaces ORDER BY created_at_unix_ms, space_id LIMIT 4097",
            )
            .map_err(repository_sqlite)?;
        let mut rows = statement.query([]).map_err(repository_sqlite)?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(repository_sqlite)? {
            result.push(decode_space(row)?);
        }
        if result.len() > MAX_TRUSTED_SPACES {
            return Err(corrupt(format!(
                "trusted space count exceeds the {MAX_TRUSTED_SPACES}-space API bound"
            )));
        }
        Ok(result)
    }

    fn bootstrap_trusted_space(
        &self,
        request: &TrustedSpaceBootstrapRequest,
    ) -> Result<TrustedSpaceBootstrapResult, RepositoryError> {
        verify_envelope(&request.genesis)?;
        verify_envelope(&request.initial_grant)?;
        validate_bootstrap(request)?;

        let space_id = request.genesis.space_id;
        let controller = request.genesis.actor_id;
        let writer = match &request.initial_grant.body {
            OperationBody::CapabilityGrant { grant } => grant.subject,
            _ => unreachable!("validated bootstrap grant"),
        };
        let mut expected = SpaceDescriptor {
            space_id,
            display_name: request.display_name.clone(),
            genesis_operation_id: request.genesis.operation_id,
            initial_grant_operation_id: request.initial_grant.operation_id,
            controller_actor_id: controller,
            local_writer_actor_id: writer,
            created_at_unix_ms: request.received_at_unix_ms,
        };

        let mut connection = lock_mut(self)?;
        let effective_received_at =
            advance_admission_clock(&mut connection, request.received_at_unix_ms)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(repository_sqlite)?;
        let effective_received_at = effective_received_at.max(read_admission_clock(&transaction)?);
        expected.created_at_unix_ms = effective_received_at;
        if let Some(existing) = load_space(&transaction, space_id)? {
            let same_anchor = existing.display_name == expected.display_name
                && existing.genesis_operation_id == expected.genesis_operation_id
                && existing.initial_grant_operation_id == expected.initial_grant_operation_id
                && existing.controller_actor_id == expected.controller_actor_id
                && existing.local_writer_actor_id == expected.local_writer_actor_id;
            if !same_anchor {
                return Err(RepositoryError::GenesisConflict(space_id));
            }
            let genesis = load_stored(&transaction, request.genesis.operation_id)?
                .ok_or_else(|| corrupt(format!("space {space_id} references a missing genesis")))?;
            let initial_grant = load_stored(&transaction, request.initial_grant.operation_id)?
                .ok_or_else(|| corrupt(format!("space {space_id} references a missing grant")))?;
            if canonical_payload(&genesis.operation)? != canonical_payload(&request.genesis)?
                || canonical_payload(&initial_grant.operation)?
                    != canonical_payload(&request.initial_grant)?
            {
                return Err(RepositoryError::GenesisConflict(space_id));
            }
            transaction.commit().map_err(repository_sqlite)?;
            return Ok(TrustedSpaceBootstrapResult {
                space: existing,
                genesis,
                initial_grant,
                replayed: true,
            });
        }

        transaction
            .execute(
                "INSERT INTO spaces (
                    space_id, genesis_operation_id, controller_actor_id,
                    initial_grant_operation_id, local_writer_actor_id,
                    display_name, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    space_id.to_string(),
                    request.genesis.operation_id.to_string(),
                    controller.to_string(),
                    request.initial_grant.operation_id.to_string(),
                    writer.to_string(),
                    request.display_name,
                    effective_received_at,
                ],
            )
            .map_err(repository_sqlite)?;

        let genesis = insert_operation(&transaction, &request.genesis, effective_received_at)?;
        let view = SqliteCapabilityView(&transaction);
        authorize_operation(&request.initial_grant, effective_received_at, &view)?;
        let initial_grant =
            insert_operation(&transaction, &request.initial_grant, effective_received_at)?;
        transaction.commit().map_err(repository_sqlite)?;
        Ok(TrustedSpaceBootstrapResult {
            space: expected,
            genesis,
            initial_grant,
            replayed: false,
        })
    }

    fn submit_operation(
        &self,
        space_id: SpaceId,
        request: &SubmitOperationRequest,
    ) -> Result<SubmitOperationResult, RepositoryError> {
        verify_envelope(&request.operation)?;
        if request.operation.space_id != space_id {
            return Err(RepositoryError::InvalidTopology(format!(
                "operation belongs to {}, not selected space {space_id}",
                request.operation.space_id
            )));
        }
        if request.received_at_unix_ms < 0 {
            return Err(RepositoryError::InvalidTopology(
                "receivedAtUnixMs must be nonnegative".into(),
            ));
        }
        if matches!(request.operation.body, OperationBody::SpaceGenesis { .. }) {
            return Err(RepositoryError::InvalidTopology(
                "space genesis requires trusted bootstrap".into(),
            ));
        }

        let mut connection = lock_mut(self)?;
        require_space(&connection, space_id)?;
        let effective_received_at =
            advance_admission_clock(&mut connection, request.received_at_unix_ms)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(repository_sqlite)?;
        let effective_received_at = effective_received_at.max(read_admission_clock(&transaction)?);

        if let Some(existing) = load_stored(&transaction, request.operation.operation_id)? {
            let incoming_payload = canonical_payload(&request.operation)?;
            let stored_payload = canonical_payload(&existing.operation)?;
            if incoming_payload != stored_payload {
                return Err(RepositoryError::OperationConflict(
                    request.operation.operation_id,
                ));
            }
            transaction.commit().map_err(repository_sqlite)?;
            return Ok(SubmitOperationResult {
                operation: existing,
                replayed: true,
            });
        }

        validate_references(&transaction, &request.operation)?;
        validate_topology(&transaction, &request.operation)?;
        let visibility = visibility_for_admission(&transaction, &request.operation)?;
        if let OperationBody::CapabilityRevoke { revocation } = &request.operation.body {
            let exists = transaction
                .query_row(
                    "SELECT 1 FROM capability_grants
                     WHERE space_id = ?1 AND grant_operation_id = ?2",
                    params![space_id.to_string(), revocation.grant_id.to_string()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(repository_sqlite)?
                .is_some();
            if !exists {
                return Err(RepositoryError::InvalidTopology(format!(
                    "revocation target {} is not an admitted grant in this space",
                    revocation.grant_id
                )));
            }
        }
        let view = SqliteCapabilityView(&transaction);
        authorize_operation_for_visibility(
            &request.operation,
            effective_received_at,
            &view,
            visibility,
        )?;
        let stored = insert_operation(&transaction, &request.operation, effective_received_at)?;
        transaction.commit().map_err(repository_sqlite)?;
        Ok(SubmitOperationResult {
            operation: stored,
            replayed: false,
        })
    }

    fn operation(
        &self,
        space_id: SpaceId,
        operation_id: OperationId,
    ) -> Result<Option<StoredOperation>, RepositoryError> {
        let connection = lock(self)?;
        require_space(&connection, space_id)?;
        let result = load_stored(&connection, operation_id)?;
        Ok(result.filter(|stored| stored.operation.space_id == space_id))
    }

    fn entity_state(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
    ) -> Result<Option<EntityState>, RepositoryError> {
        let connection = lock(self)?;
        require_space(&connection, space_id)?;
        let summary = connection
            .query_row(
                "SELECT min(schema_id), count(*), count(DISTINCT schema_id) FROM operations
                 WHERE space_id = ?1 AND entity_id = ?2",
                params![space_id.to_string(), entity_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(repository_sqlite)?;
        let (schema_text, count, schema_count) = summary;
        let Some(schema_text) = schema_text else {
            return Ok(None);
        };
        if schema_count != 1 {
            return Err(corrupt(format!(
                "entity {entity_id} has {schema_count} stored schemas"
            )));
        }
        let schema = parse_schema(&schema_text)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {STORED_COLUMNS} FROM operations
                 WHERE space_id = ?1 AND operation_id IN (
                    SELECT operation_id FROM entity_heads
                    WHERE space_id = ?1 AND entity_id = ?2 AND schema_id = ?3
                 ) ORDER BY operation_id"
            ))
            .map_err(repository_sqlite)?;
        let mut rows = statement
            .query(params![
                space_id.to_string(),
                entity_id.to_string(),
                schema_text
            ])
            .map_err(repository_sqlite)?;
        let mut heads = Vec::new();
        while let Some(row) = rows.next().map_err(repository_sqlite)? {
            heads.push(decode_stored(row)?);
        }
        if heads.is_empty() {
            return Err(corrupt(format!(
                "entity {entity_id} has history but no heads"
            )));
        }
        if heads.len() > MAX_ENTITY_HEADS {
            return Err(corrupt(format!(
                "entity {entity_id} exceeds the {MAX_ENTITY_HEADS}-head limit"
            )));
        }
        Ok(Some(EntityState {
            space_id,
            entity_id,
            schema,
            operation_count: positive_u64(count)?,
            heads,
        }))
    }

    fn changes_after(
        &self,
        space_id: SpaceId,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<OperationChangePage, RepositoryError> {
        if !(1..=MAX_CHANGE_LIMIT).contains(&limit) {
            return Err(RepositoryError::InvalidTopology(format!(
                "change limit must be between 1 and {MAX_CHANGE_LIMIT}"
            )));
        }
        let connection = lock(self)?;
        load_changes(&connection, space_id, after_local_sequence, limit)
    }

    fn peer_changes(
        &self,
        request: &PeerReadChangesRequest,
    ) -> Result<OperationChangePage, RepositoryError> {
        let mut connection = lock_mut(self)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(repository_sqlite)?;
        request
            .proof
            .verify(request.received_at_unix_ms)
            .map_err(|_| RepositoryError::PeerUnauthorized)?;
        let proof = &request.proof;
        let pairing_matches = transaction
            .query_row(
                "SELECT 1 FROM pairing_sessions
                 WHERE invitation_id = ?1 AND state = 'completed'
                   AND space_id = ?2 AND joiner_node_id = ?3
                   AND subject_actor_id = ?4 AND grant_operation_id = ?5",
                params![
                    proof.session_id.as_bytes().as_slice(),
                    proof.space_id.to_string(),
                    proof.node_id.as_bytes().as_slice(),
                    proof.actor_id.as_bytes().as_slice(),
                    proof.grant_operation_id.to_string(),
                ],
                |_| Ok(()),
            )
            .optional()
            .map_err(repository_sqlite)?
            .is_some();
        if !pairing_matches {
            return Err(RepositoryError::PeerUnauthorized);
        }

        let view = SqliteCapabilityView(&transaction);
        authorize_capability_action(
            proof.space_id,
            proof.actor_id,
            &[proof.grant_operation_id],
            CapabilityAction::ReadSpace,
            request.received_at_unix_ms,
            &view,
        )
        .map_err(|_| RepositoryError::PeerUnauthorized)?;

        transaction
            .execute(
                "DELETE FROM peer_request_nonces
                 WHERE (invitation_id, nonce) IN (
                    SELECT invitation_id, nonce FROM peer_request_nonces
                    WHERE expires_at_unix_ms <= ?1
                    ORDER BY expires_at_unix_ms LIMIT ?2
                 )",
                params![request.received_at_unix_ms, PEER_NONCE_CLEANUP_BATCH],
            )
            .map_err(repository_sqlite)?;
        let replayed = transaction
            .query_row(
                "SELECT 1 FROM peer_request_nonces
                 WHERE invitation_id = ?1 AND nonce = ?2",
                params![
                    proof.session_id.as_bytes().as_slice(),
                    proof.nonce.as_bytes().as_slice()
                ],
                |_| Ok(()),
            )
            .optional()
            .map_err(repository_sqlite)?
            .is_some();
        if replayed {
            return Err(RepositoryError::PeerReplay);
        }
        let active: i64 = transaction
            .query_row(
                "SELECT count(*) FROM peer_request_nonces
                 WHERE invitation_id = ?1 AND expires_at_unix_ms > ?2",
                params![
                    proof.session_id.as_bytes().as_slice(),
                    request.received_at_unix_ms
                ],
                |row| row.get(0),
            )
            .map_err(repository_sqlite)?;
        if active >= MAX_ACTIVE_PEER_NONCES_PER_SESSION {
            return Err(RepositoryError::PeerUnauthorized);
        }
        transaction
            .execute(
                "INSERT INTO peer_request_nonces (
                    invitation_id, nonce, expires_at_unix_ms, consumed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    proof.session_id.as_bytes().as_slice(),
                    proof.nonce.as_bytes().as_slice(),
                    proof.expires_at_unix_ms,
                    request.received_at_unix_ms,
                ],
            )
            .map_err(repository_sqlite)?;
        let page = load_changes(
            &transaction,
            proof.space_id,
            proof.after,
            usize::from(proof.limit),
        )?;
        transaction.commit().map_err(repository_sqlite)?;
        Ok(page)
    }
}

fn load_changes(
    connection: &Connection,
    space_id: SpaceId,
    after_local_sequence: u64,
    limit: usize,
) -> Result<OperationChangePage, RepositoryError> {
    if !(1..=MAX_CHANGE_LIMIT).contains(&limit) {
        return Err(RepositoryError::InvalidTopology(format!(
            "change limit must be between 1 and {MAX_CHANGE_LIMIT}"
        )));
    }
    require_space(connection, space_id)?;
    let Ok(after) = i64::try_from(after_local_sequence) else {
        return Ok(OperationChangePage {
            space_id,
            operations: Vec::new(),
            next_after: after_local_sequence,
            has_more: false,
        });
    };
    let fetch = i64::try_from(limit + 1)
        .map_err(|_| RepositoryError::InvalidTopology("change limit overflow".into()))?;
    let mut statement = connection
        .prepare(&format!(
            "SELECT {STORED_COLUMNS} FROM operations
                 WHERE space_id = ?1 AND local_sequence > ?2
                 ORDER BY local_sequence LIMIT ?3"
        ))
        .map_err(repository_sqlite)?;
    let mut rows = statement
        .query(params![space_id.to_string(), after, fetch])
        .map_err(repository_sqlite)?;
    let mut operations = Vec::with_capacity(limit + 1);
    while let Some(row) = rows.next().map_err(repository_sqlite)? {
        operations.push(decode_stored(row)?);
    }
    let has_more = operations.len() > limit;
    if has_more {
        operations.pop();
    }
    let next_after = operations
        .last()
        .map_or(after_local_sequence, |stored| stored.local_sequence);
    Ok(OperationChangePage {
        space_id,
        operations,
        next_after,
        has_more,
    })
}

fn lock(store: &SqliteStore) -> Result<std::sync::MutexGuard<'_, Connection>, RepositoryError> {
    store
        .connection
        .lock()
        .map_err(|_| RepositoryError::Unavailable("node database lock was poisoned".into()))
}

fn lock_mut(store: &SqliteStore) -> Result<std::sync::MutexGuard<'_, Connection>, RepositoryError> {
    lock(store)
}

fn advance_admission_clock(
    connection: &mut Connection,
    sampled_unix_ms: i64,
) -> Result<i64, RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(repository_sqlite)?;
    let persisted = read_admission_clock(&transaction)?;
    let effective = persisted.max(sampled_unix_ms);
    let updated = transaction
        .execute(
            "UPDATE node_admission_clock SET high_water_unix_ms = ?1 WHERE singleton = 1",
            params![effective],
        )
        .map_err(repository_sqlite)?;
    if updated != 1 {
        return Err(corrupt("node admission clock singleton is not unique"));
    }
    transaction.commit().map_err(repository_sqlite)?;
    Ok(effective)
}

fn read_admission_clock(connection: &Connection) -> Result<i64, RepositoryError> {
    let persisted = connection
        .query_row(
            "SELECT high_water_unix_ms FROM node_admission_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(repository_sqlite)?
        .ok_or_else(|| corrupt("node admission clock singleton is missing"))?;
    if persisted < 0 {
        Err(corrupt("node admission clock is negative"))
    } else {
        Ok(persisted)
    }
}

fn verify_envelope(operation: &OperationEnvelope) -> Result<(), RepositoryError> {
    operation
        .verify()
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    TrustSignedOperation::from_cose_sign1(&operation.cose_sign1)
        .and_then(|signed| signed.verify().map(|_| ()))
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))
}

fn canonical_payload(operation: &OperationEnvelope) -> Result<Vec<u8>, RepositoryError> {
    let signed = TrustSignedOperation::from_cose_sign1(&operation.cose_sign1)
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    signed
        .verify()
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    Ok(signed.payload_bytes().to_vec())
}

fn validate_bootstrap(request: &TrustedSpaceBootstrapRequest) -> Result<(), RepositoryError> {
    if request.received_at_unix_ms < 0 {
        return Err(RepositoryError::InvalidTopology(
            "bootstrap receipt time must be nonnegative".into(),
        ));
    }
    let display_len = request.display_name.chars().count();
    if display_len == 0 || display_len > 128 || request.display_name.chars().any(char::is_control) {
        return Err(RepositoryError::InvalidTopology(
            "space display name must contain 1..=128 non-control scalars".into(),
        ));
    }
    let OperationBody::SpaceGenesis { controller } = request.genesis.body else {
        return Err(RepositoryError::InvalidTopology(
            "invalid bootstrap genesis".into(),
        ));
    };
    let OperationBody::CapabilityGrant { ref grant } = request.initial_grant.body else {
        return Err(RepositoryError::InvalidTopology(
            "invalid initial writer grant".into(),
        ));
    };
    let exact_grant = grant.subject != controller
        && grant.actions
            == [
                CapabilityAction::AppendOperation,
                CapabilityAction::ReadSpace,
            ]
        && grant.schemas
            == [
                EntitySchema::EventV1,
                EntitySchema::ProfileV1,
                EntitySchema::RecordV1,
                EntitySchema::RecordV2,
                EntitySchema::TagV1,
            ]
        && grant.visibilities == [Visibility::Public, Visibility::Private]
        && grant.content_roles.is_empty()
        && grant.max_resource_byte_length.is_none()
        && grant.not_before_unix_ms.is_none()
        && grant.expires_at_unix_ms.is_none()
        && grant.delegation_depth == 0;
    if request.genesis.space_id != request.initial_grant.space_id
        || request.initial_grant.actor_id != controller
        || !request.initial_grant.causal_parents.is_empty()
        || request.initial_grant.authorization != [request.genesis.operation_id]
        || request.initial_grant.schema != EntitySchema::CapabilityGrantV1
        || request.initial_grant.entity_id == request.genesis.entity_id
        || !exact_grant
    {
        return Err(RepositoryError::InvalidTopology(
            "bootstrap operations do not form the canonical controller/writer anchor".into(),
        ));
    }
    Ok(())
}

fn load_space(
    connection: &Connection,
    space_id: SpaceId,
) -> Result<Option<SpaceDescriptor>, RepositoryError> {
    connection
        .query_row(
            "SELECT space_id, display_name, genesis_operation_id,
                    initial_grant_operation_id, controller_actor_id,
                    local_writer_actor_id, created_at_unix_ms
             FROM spaces WHERE space_id = ?1",
            params![space_id.to_string()],
            |row| {
                let values = (
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                );
                Ok(values)
            },
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(decode_space_values)
        .transpose()
}

fn decode_space(row: &Row<'_>) -> Result<SpaceDescriptor, RepositoryError> {
    decode_space_values((
        row.get(0).map_err(repository_sqlite)?,
        row.get(1).map_err(repository_sqlite)?,
        row.get(2).map_err(repository_sqlite)?,
        row.get(3).map_err(repository_sqlite)?,
        row.get(4).map_err(repository_sqlite)?,
        row.get(5).map_err(repository_sqlite)?,
        row.get(6).map_err(repository_sqlite)?,
    ))
}

fn decode_space_values(
    values: (String, String, String, String, String, String, i64),
) -> Result<SpaceDescriptor, RepositoryError> {
    let space_id = SpaceId::parse(&values.0).map_err(|error| corrupt(error.to_string()))?;
    if space_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(corrupt("stored space ID is nil"));
    }
    let controller_actor_id = fractonica_data_model::ActorId::parse(&values.4)
        .map_err(|error| corrupt(error.to_string()))?;
    controller_actor_id
        .public_key()
        .map_err(|error| corrupt(format!("invalid controller actor key: {error}")))?;
    let local_writer_actor_id = fractonica_data_model::ActorId::parse(&values.5)
        .map_err(|error| corrupt(error.to_string()))?;
    local_writer_actor_id
        .public_key()
        .map_err(|error| corrupt(format!("invalid local writer actor key: {error}")))?;
    let descriptor = SpaceDescriptor {
        space_id,
        display_name: values.1,
        genesis_operation_id: OperationId::parse(&values.2)
            .map_err(|error| corrupt(error.to_string()))?,
        initial_grant_operation_id: OperationId::parse(&values.3)
            .map_err(|error| corrupt(error.to_string()))?,
        controller_actor_id,
        local_writer_actor_id,
        created_at_unix_ms: values.6,
    };
    let display_len = descriptor.display_name.chars().count();
    if display_len == 0
        || display_len > 128
        || descriptor.display_name.chars().any(char::is_control)
        || descriptor.created_at_unix_ms < 0
        || descriptor.genesis_operation_id == descriptor.initial_grant_operation_id
        || descriptor.controller_actor_id == descriptor.local_writer_actor_id
    {
        return Err(corrupt(format!(
            "space {} has an invalid stored descriptor",
            descriptor.space_id
        )));
    }
    Ok(descriptor)
}

fn require_space(connection: &Connection, space_id: SpaceId) -> Result<(), RepositoryError> {
    if load_space(connection, space_id)?.is_some() {
        Ok(())
    } else {
        Err(RepositoryError::SpaceNotFound(space_id))
    }
}

fn load_stored(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StoredOperation>, RepositoryError> {
    connection
        .query_row(
            &format!("SELECT {STORED_COLUMNS} FROM operations WHERE operation_id = ?1"),
            params![operation_id.to_string()],
            decode_stored_sql,
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(decode_stored_values)
        .transpose()
}

type StoredValues = (
    i64,
    String,
    i64,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
);

fn decode_stored_sql(row: &Row<'_>) -> rusqlite::Result<StoredValues> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn decode_stored(row: &Row<'_>) -> Result<StoredOperation, RepositoryError> {
    decode_stored_values(decode_stored_sql(row).map_err(repository_sqlite)?)
}

fn decode_stored_values(value: StoredValues) -> Result<StoredOperation, RepositoryError> {
    let operation: OperationEnvelope = serde_json::from_str(&value.12)
        .map_err(|error| corrupt(format!("invalid operation projection JSON: {error}")))?;
    let normalized = serde_json::to_string(&operation)
        .map_err(|error| corrupt(format!("cannot normalize operation projection: {error}")))?;
    if normalized != value.12 {
        return Err(corrupt(
            "stored operation projection is not deterministic JSON",
        ));
    }
    operation
        .verify()
        .map_err(|error| corrupt(format!("stored operation does not verify: {error}")))?;
    let signed = TrustSignedOperation::from_cose_sign1(&value.11)
        .map_err(|error| corrupt(format!("invalid stored COSE: {error}")))?;
    signed
        .verify()
        .map_err(|error| corrupt(format!("stored signature fails: {error}")))?;
    let columns_match = operation.operation_id.to_string() == value.1
        && i64::from(operation.protocol_version) == value.2
        && operation.space_id.to_string() == value.3
        && operation.entity_id.to_string() == value.4
        && operation.schema.as_str() == value.5
        && operation.actor_id.to_string() == value.6
        && operation.occurred_at_unix_ms == value.7
        && operation.nonce.as_bytes().as_slice() == value.9
        && operation.cose_sign1 == value.11
        && signed.operation_id() == operation.operation_id
        && signed.payload_bytes() == value.10;
    if !columns_match {
        return Err(corrupt(format!(
            "stored scalar or authoritative bytes disagree for operation {}",
            operation.operation_id
        )));
    }
    Ok(StoredOperation {
        local_sequence: positive_u64(value.0)?,
        received_at_unix_ms: value.8,
        operation,
    })
}

fn insert_operation(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
    received_at_unix_ms: i64,
) -> Result<StoredOperation, RepositoryError> {
    let signed = TrustSignedOperation::from_cose_sign1(&operation.cose_sign1)
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    signed
        .verify()
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    let projection = serde_json::to_string(operation)
        .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO operations (
                operation_id, protocol_version, space_id, entity_id, schema_id, actor_id,
                occurred_at_unix_ms, received_at_unix_ms, nonce, canonical_payload,
                cose_sign1, projection_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                operation.operation_id.to_string(),
                i64::from(operation.protocol_version),
                operation.space_id.to_string(),
                operation.entity_id.to_string(),
                operation.schema.as_str(),
                operation.actor_id.to_string(),
                operation.occurred_at_unix_ms,
                received_at_unix_ms,
                operation.nonce.as_bytes().as_slice(),
                signed.payload_bytes(),
                operation.cose_sign1,
                projection,
            ],
        )
        .map_err(repository_sqlite)?;
    let local_sequence = positive_u64(transaction.last_insert_rowid())?;

    if operation.causal_parents.is_empty()
        && let Some(visibility) = operation.body.declared_visibility()
    {
        transaction
            .execute(
                "INSERT INTO client_entity_visibility (
                    space_id, entity_id, schema_id, origin_operation_id, visibility
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    operation.space_id.to_string(),
                    operation.entity_id.to_string(),
                    operation.schema.as_str(),
                    operation.operation_id.to_string(),
                    visibility_key(visibility),
                ],
            )
            .map_err(repository_sqlite)?;
    }

    for (position, parent) in operation.causal_parents.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO operation_parents (
                space_id, entity_id, schema_id, operation_id, parent_operation_id, position
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    operation.space_id.to_string(),
                    operation.entity_id.to_string(),
                    operation.schema.as_str(),
                    operation.operation_id.to_string(),
                    parent.to_string(),
                    index(position)?
                ],
            )
            .map_err(repository_sqlite)?;
        transaction
            .execute(
                "DELETE FROM entity_heads WHERE space_id = ?1 AND operation_id = ?2",
                params![operation.space_id.to_string(), parent.to_string()],
            )
            .map_err(repository_sqlite)?;
    }
    for (position, authorization) in operation.authorization.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO operation_authorization_refs (
                space_id, operation_id, authorization_operation_id, position
             ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.operation_id.to_string(),
                    authorization.to_string(),
                    index(position)?
                ],
            )
            .map_err(repository_sqlite)?;
    }
    transaction
        .execute(
            "INSERT INTO entity_heads (space_id, entity_id, schema_id, operation_id)
         VALUES (?1, ?2, ?3, ?4)",
            params![
                operation.space_id.to_string(),
                operation.entity_id.to_string(),
                operation.schema.as_str(),
                operation.operation_id.to_string()
            ],
        )
        .map_err(repository_sqlite)?;

    {
        for (position, resource) in operation.body.resources().iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO operation_resources (
                    space_id, operation_id, position, content_id, byte_length,
                    media_type, role, original_name
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        operation.space_id.to_string(),
                        operation.operation_id.to_string(),
                        index(position)?,
                        resource.content_id.to_string(),
                        i64::try_from(resource.byte_length)
                            .map_err(|_| corrupt("resource length overflow"))?,
                        resource.media_type,
                        resource.role,
                        resource.original_name
                    ],
                )
                .map_err(repository_sqlite)?;
        }
    }
    match &operation.body {
        OperationBody::CapabilityGrant { grant } => insert_grant(transaction, operation, grant)?,
        OperationBody::CapabilityRevoke { revocation } => {
            transaction
                .execute(
                    "INSERT INTO capability_grant_revocations (
                    space_id, revocation_operation_id, revoker_actor_id,
                    grant_operation_id, reason, detail
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        operation.space_id.to_string(),
                        operation.operation_id.to_string(),
                        operation.actor_id.to_string(),
                        revocation.grant_id.to_string(),
                        revocation_reason_key(revocation.reason),
                        revocation.detail
                    ],
                )
                .map_err(repository_sqlite)?;
        }
        _ => {}
    }
    Ok(StoredOperation {
        local_sequence,
        received_at_unix_ms,
        operation: operation.clone(),
    })
}

fn insert_grant(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
    grant: &fractonica_data_model::CapabilityGrant,
) -> Result<(), RepositoryError> {
    transaction
        .execute(
            "INSERT INTO capability_grants (
            space_id, grant_operation_id, issuer_actor_id, subject_actor_id,
            delegation_depth, not_before_unix_ms, expires_at_unix_ms,
            max_resource_byte_length, label
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                operation.space_id.to_string(),
                operation.operation_id.to_string(),
                operation.actor_id.to_string(),
                grant.subject.to_string(),
                i64::from(grant.delegation_depth),
                grant.not_before_unix_ms,
                grant.expires_at_unix_ms,
                grant
                    .max_resource_byte_length
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|_| corrupt("grant resource limit overflow"))?,
                grant.label
            ],
        )
        .map_err(repository_sqlite)?;
    for (position, action) in grant.actions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO capability_grant_actions
                (space_id, grant_operation_id, position, action) VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.operation_id.to_string(),
                    index(position)?,
                    action_key(*action)
                ],
            )
            .map_err(repository_sqlite)?;
    }
    for (position, schema) in grant.schemas.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO capability_grant_schema_scopes
                (space_id, grant_operation_id, position, schema_id) VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.operation_id.to_string(),
                    index(position)?,
                    schema.as_str()
                ],
            )
            .map_err(repository_sqlite)?;
    }
    for (position, visibility) in grant.visibilities.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO capability_grant_visibilities
                (space_id, grant_operation_id, position, visibility) VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.operation_id.to_string(),
                    index(position)?,
                    visibility_key(*visibility)
                ],
            )
            .map_err(repository_sqlite)?;
    }
    for (position, role) in grant.content_roles.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO capability_grant_content_roles
                (space_id, grant_operation_id, position, role) VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.operation_id.to_string(),
                    index(position)?,
                    role
                ],
            )
            .map_err(repository_sqlite)?;
    }
    Ok(())
}

fn validate_references(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), RepositoryError> {
    for parent in &operation.causal_parents {
        match operation_space(transaction, *parent)? {
            None => return Err(RepositoryError::MissingParent(*parent)),
            Some(space) if space != operation.space_id => {
                return Err(RepositoryError::CrossSpaceParent(*parent));
            }
            Some(_) => {}
        }
    }
    for authorization in &operation.authorization {
        match operation_space(transaction, *authorization)? {
            None => return Err(RepositoryError::MissingAuthorization(*authorization)),
            Some(space) if space != operation.space_id => {
                return Err(RepositoryError::CrossSpaceAuthorization(*authorization));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn operation_space(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<SpaceId>, RepositoryError> {
    connection
        .query_row(
            "SELECT space_id FROM operations WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(|value| SpaceId::parse(&value).map_err(|error| corrupt(error.to_string())))
        .transpose()
}

fn validate_topology(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), RepositoryError> {
    for parent in &operation.causal_parents {
        let projection = transaction
            .query_row(
                "SELECT entity_id, schema_id FROM operations WHERE operation_id = ?1",
                params![parent.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(repository_sqlite)?;
        if projection.0 != operation.entity_id.to_string()
            || projection.1 != operation.schema.as_str()
        {
            return Err(RepositoryError::ParentMismatch { parent: *parent });
        }
    }
    let existing_count: i64 = transaction
        .query_row(
            "SELECT count(*) FROM operations WHERE space_id = ?1 AND entity_id = ?2",
            params![
                operation.space_id.to_string(),
                operation.entity_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(repository_sqlite)?;
    let current_heads: i64 = transaction
        .query_row(
            "SELECT count(*) FROM entity_heads WHERE space_id = ?1 AND entity_id = ?2",
            params![
                operation.space_id.to_string(),
                operation.entity_id.to_string()
            ],
            |row| row.get(0),
        )
        .map_err(repository_sqlite)?;
    if existing_count > 0 && current_heads == 0 {
        return Err(corrupt(format!(
            "entity {} has history but no current heads",
            operation.entity_id
        )));
    }
    if existing_count > 0 && operation.causal_parents.is_empty() {
        return Err(RepositoryError::EntityAlreadyExists(operation.entity_id));
    }
    if existing_count == 0 && matches!(operation.body, OperationBody::Tombstone) {
        return Err(RepositoryError::InvalidTopology(
            "an entity cannot begin with a tombstone".into(),
        ));
    }
    let consumed_heads: i64 = transaction
        .query_row(
            "SELECT count(*) FROM entity_heads
         WHERE space_id = ?1 AND entity_id = ?2
           AND operation_id IN (SELECT value FROM json_each(?3))",
            params![
                operation.space_id.to_string(),
                operation.entity_id.to_string(),
                serde_json::to_string(&operation.causal_parents)
                    .map_err(|error| RepositoryError::InvalidTopology(error.to_string()))?
            ],
            |row| row.get(0),
        )
        .map_err(repository_sqlite)?;
    let resulting = current_heads - consumed_heads + 1;
    if resulting > i64::try_from(MAX_ENTITY_HEADS).unwrap_or(i64::MAX) {
        return Err(RepositoryError::InvalidTopology(format!(
            "operation would exceed the {MAX_ENTITY_HEADS}-head entity limit"
        )));
    }
    Ok(())
}

fn visibility_for_admission(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<Option<Visibility>, RepositoryError> {
    if !matches!(
        operation.schema,
        EntitySchema::RecordV1
            | EntitySchema::RecordV2
            | EntitySchema::TagV1
            | EntitySchema::EventV1
            | EntitySchema::ProfileV1
    ) {
        return Ok(None);
    }
    let stored = transaction
        .query_row(
            "SELECT visibility FROM client_entity_visibility
             WHERE space_id = ?1 AND entity_id = ?2",
            params![
                operation.space_id.to_string(),
                operation.entity_id.to_string()
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(repository_sqlite)?
        .map(|value| parse_visibility(&value))
        .transpose()?;

    if operation.causal_parents.is_empty() {
        return match (
            operation.body.declared_visibility(),
            &operation.body,
            stored,
        ) {
            (Some(visibility), _, None) => Ok(Some(visibility)),
            (Some(_), _, Some(_)) => Err(corrupt(format!(
                "new client entity {} already has materialized visibility",
                operation.entity_id
            ))),
            (None, OperationBody::Tombstone, _) => Err(RepositoryError::InvalidTopology(
                "an entity cannot begin with a tombstone".into(),
            )),
            _ => Err(corrupt("client schema has a non-client body")),
        };
    }

    let Some(current) = stored else {
        return Err(corrupt(format!(
            "record entity {} has history but no materialized visibility",
            operation.entity_id
        )));
    };
    for parent_id in &operation.causal_parents {
        let parent = load_stored(transaction, *parent_id)?
            .ok_or_else(|| corrupt(format!("validated record parent {parent_id} disappeared")))?;
        if let Some(parent_visibility) = parent.operation.body.declared_visibility()
            && parent_visibility != current
        {
            return Err(corrupt(format!(
                "record parent {parent_id} disagrees with materialized visibility"
            )));
        }
    }
    if let Some(incoming_visibility) = operation.body.declared_visibility()
        && incoming_visibility != current
    {
        // Deliberately return the generic authorization denial: callers must
        // not learn a private entity's visibility through an admission oracle.
        return Err(RepositoryError::Authorization(
            fractonica_application::authorization::AuthorizationError::Denied,
        ));
    }
    Ok(Some(current))
}

struct SqliteCapabilityView<'a>(&'a Connection);

impl CapabilityView for SqliteCapabilityView<'_> {
    fn trusted_genesis(
        &self,
        space_id: SpaceId,
    ) -> Result<Option<OperationId>, CapabilityViewError> {
        self.0
            .query_row(
                "SELECT genesis_operation_id FROM spaces WHERE space_id = ?1",
                params![space_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| CapabilityViewError::new(error.to_string()))?
            .map(|value| {
                OperationId::parse(&value).map_err(|error| {
                    CapabilityViewError::new(format!(
                        "invalid trusted genesis operation ID: {error}"
                    ))
                })
            })
            .transpose()
    }

    fn operation(
        &self,
        space_id: SpaceId,
        operation_id: OperationId,
    ) -> Result<Option<OperationEnvelope>, CapabilityViewError> {
        load_stored(self.0, operation_id)
            .map(|stored| {
                stored.and_then(|value| {
                    (value.operation.space_id == space_id).then_some(value.operation)
                })
            })
            .map_err(|error| CapabilityViewError::new(error.to_string()))
    }

    fn is_revoked(
        &self,
        space_id: SpaceId,
        grant_id: OperationId,
    ) -> Result<bool, CapabilityViewError> {
        self.0
            .query_row(
                "SELECT 1 FROM capability_grant_revocations
             WHERE space_id = ?1 AND grant_operation_id = ?2 LIMIT 1",
                params![space_id.to_string(), grant_id.to_string()],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(|error| CapabilityViewError::new(error.to_string()))
    }
}

fn parse_schema(value: &str) -> Result<EntitySchema, RepositoryError> {
    EntitySchema::parse(value).map_err(|error| corrupt(error.to_string()))
}

fn parse_visibility(value: &str) -> Result<Visibility, RepositoryError> {
    match value {
        "public" => Ok(Visibility::Public),
        "private" => Ok(Visibility::Private),
        _ => Err(corrupt(format!("unknown stored visibility {value}"))),
    }
}

fn index(value: usize) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .map_err(|_| RepositoryError::InvalidTopology("projection index overflow".into()))
}

const fn action_key(value: CapabilityAction) -> &'static str {
    match value {
        CapabilityAction::AppendOperation => "appendOperation",
        CapabilityAction::IssueCapability => "issueCapability",
        CapabilityAction::RevokeCapability => "revokeCapability",
        CapabilityAction::ReadSpace => "readSpace",
        CapabilityAction::WriteContent => "writeContent",
    }
}

const fn visibility_key(value: Visibility) -> &'static str {
    match value {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

const fn revocation_reason_key(value: CapabilityRevocationReason) -> &'static str {
    match value {
        CapabilityRevocationReason::KeyCompromised => "keyCompromised",
        CapabilityRevocationReason::DeviceLost => "deviceLost",
        CapabilityRevocationReason::KeyRotated => "keyRotated",
        CapabilityRevocationReason::ScopeChanged => "scopeChanged",
        CapabilityRevocationReason::Administrative => "administrative",
    }
}

fn corrupt(detail: impl Into<String>) -> RepositoryError {
    RepositoryError::Corrupt(detail.into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fractonica_application::ContentRepository;
    use fractonica_data_model::{
        CapabilityGrant, CapabilityRevocation, OperationNonce, RecordDocument, SigningKey,
    };
    use fractonica_peer::{
        PeerReadChangesFields, PeerReadChangesProof, PeerRequestNonce, PeerSessionId,
    };
    use rusqlite::Connection;
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;

    struct Fixture {
        store: SqliteStore,
        space_id: SpaceId,
        controller: SigningKey,
        writer: SigningKey,
        genesis: OperationEnvelope,
        writer_grant: OperationEnvelope,
    }

    impl Fixture {
        fn new() -> Self {
            let store = SqliteStore::open_in_memory().unwrap();
            let space_id = SpaceId::from_bytes([9; 32]);
            let controller = SigningKey::from_seed([1; 32]);
            let writer = SigningKey::from_seed([2; 32]);
            let genesis = sign(
                space_id,
                EntitySchema::SpaceGenesisV1,
                vec![],
                vec![],
                OperationBody::SpaceGenesis {
                    controller: controller.actor_id(),
                },
                &controller,
                1,
            );
            let writer_grant = sign(
                space_id,
                EntitySchema::CapabilityGrantV1,
                vec![],
                vec![genesis.operation_id],
                OperationBody::CapabilityGrant {
                    grant: CapabilityGrant {
                        subject: writer.actor_id(),
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
                        content_roles: vec![],
                        max_resource_byte_length: None,
                        not_before_unix_ms: None,
                        expires_at_unix_ms: None,
                        delegation_depth: 0,
                        label: "local writer".into(),
                    },
                },
                &controller,
                2,
            );
            let result = store
                .bootstrap_trusted_space(&TrustedSpaceBootstrapRequest {
                    display_name: "Test space".into(),
                    genesis: genesis.clone(),
                    initial_grant: writer_grant.clone(),
                    received_at_unix_ms: 10,
                })
                .unwrap();
            assert!(!result.replayed);
            Self {
                store,
                space_id,
                controller,
                writer,
                genesis,
                writer_grant,
            }
        }

        fn record(
            &self,
            entity_id: EntityId,
            parents: Vec<OperationId>,
            seed: u8,
        ) -> OperationEnvelope {
            OperationEnvelope::sign(
                self.space_id,
                entity_id,
                EntitySchema::RecordV1,
                parents,
                vec![self.writer_grant.operation_id],
                100 + i64::from(seed),
                OperationNonce::from_bytes([seed; 16]),
                OperationBody::Put {
                    document: RecordDocument {
                        start_at_unix_ms: 100,
                        end_at_unix_ms: None,
                        visibility: Visibility::Public,
                        emoji: None,
                        text: Some(format!("record {seed}")),
                        metadata: BTreeMap::new(),
                        resources: vec![],
                    },
                },
                &self.writer,
            )
            .unwrap()
        }

        fn install_completed_pairing(
            &self,
            session_id: PeerSessionId,
            node_id: fractonica_data_model::NodeId,
        ) {
            self.store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO pairing_sessions (
                        invitation_id, descriptor_cbor, descriptor_digest, space_id,
                        responder_node_id, expires_at_unix_ms, state, created_at_unix_ms,
                        claimed_at_unix_ms, claimed_expires_at_unix_ms,
                        confirmed_at_unix_ms, completed_at_unix_ms, terminal_at_unix_ms,
                        claim_digest, handshake_hash, joiner_node_id, subject_actor_id,
                        planned_grant_operation_id, planned_grant_json,
                        grant_planned_at_unix_ms, grant_operation_id
                     ) VALUES (
                        ?1, x'01', ?2, ?3, ?4, 100000, 'completed', 1,
                        2, 90000, 3, 4, 4, ?5, ?6, ?7, ?8, ?9, '{}', 3, ?9
                     )",
                    params![
                        session_id.as_bytes().as_slice(),
                        [6_u8; 32].as_slice(),
                        self.space_id.to_string(),
                        [7_u8; 32].as_slice(),
                        [8_u8; 32].as_slice(),
                        [9_u8; 32].as_slice(),
                        node_id.as_bytes().as_slice(),
                        self.writer.actor_id().as_bytes().as_slice(),
                        self.writer_grant.operation_id.to_string(),
                    ],
                )
                .unwrap();
        }
    }

    #[test]
    fn paired_read_consumes_nonce_atomically_and_rejects_replay() {
        let fixture = Fixture::new();
        let node = SigningKey::from_seed([11; 32]);
        let session_id = PeerSessionId::from_bytes([12; 16]);
        fixture.install_completed_pairing(session_id, node.node_id());
        let proof = PeerReadChangesProof::sign(
            PeerReadChangesFields {
                session_id,
                space_id: fixture.space_id,
                grant_operation_id: fixture.writer_grant.operation_id,
                after: 0,
                limit: 10,
                issued_at_unix_ms: 20,
                expires_at_unix_ms: 30_020,
                nonce: PeerRequestNonce::from_bytes([13; 16]),
            },
            &node,
            &fixture.writer,
        )
        .unwrap();
        let request = PeerReadChangesRequest {
            proof,
            received_at_unix_ms: 20,
        };

        let page = fixture.store.peer_changes(&request).unwrap();
        assert_eq!(page.space_id, fixture.space_id);
        assert_eq!(page.operations.len(), 2);
        assert!(matches!(
            fixture.store.peer_changes(&request),
            Err(RepositoryError::PeerReplay)
        ));
        assert_eq!(
            fixture
                .store
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM peer_request_nonces", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );

        let revocation = sign(
            fixture.space_id,
            EntitySchema::CapabilityRevokeV1,
            vec![],
            vec![fixture.genesis.operation_id],
            OperationBody::CapabilityRevoke {
                revocation: CapabilityRevocation {
                    grant_id: fixture.writer_grant.operation_id,
                    reason: CapabilityRevocationReason::Administrative,
                    detail: None,
                },
            },
            &fixture.controller,
            14,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: revocation,
                    received_at_unix_ms: 30,
                },
            )
            .unwrap();
        let revoked_proof = PeerReadChangesProof::sign(
            PeerReadChangesFields {
                session_id,
                space_id: fixture.space_id,
                grant_operation_id: fixture.writer_grant.operation_id,
                after: 0,
                limit: 10,
                issued_at_unix_ms: 31,
                expires_at_unix_ms: 30_031,
                nonce: PeerRequestNonce::from_bytes([15; 16]),
            },
            &node,
            &fixture.writer,
        )
        .unwrap();
        assert!(matches!(
            fixture.store.peer_changes(&PeerReadChangesRequest {
                proof: revoked_proof,
                received_at_unix_ms: 31,
            }),
            Err(RepositoryError::PeerUnauthorized)
        ));
        assert_eq!(
            fixture
                .store
                .connection
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM peer_request_nonces", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1,
            "a rejected request must not consume replay capacity"
        );
    }

    fn sign(
        space_id: SpaceId,
        schema: EntitySchema,
        parents: Vec<OperationId>,
        authorization: Vec<OperationId>,
        body: OperationBody,
        key: &SigningKey,
        seed: u8,
    ) -> OperationEnvelope {
        OperationEnvelope::sign(
            space_id,
            EntityId::new(Uuid::from_bytes([seed; 16])),
            schema,
            parents,
            authorization,
            i64::from(seed),
            OperationNonce::from_bytes([seed; 16]),
            body,
            key,
        )
        .unwrap()
    }

    fn bootstrap_space(
        store: &SqliteStore,
        space_seed: u8,
        controller_seed: u8,
        writer_seed: u8,
    ) -> (
        SpaceId,
        SigningKey,
        SigningKey,
        OperationEnvelope,
        OperationEnvelope,
    ) {
        let space_id = SpaceId::from_bytes([space_seed; 32]);
        let controller = SigningKey::from_seed([controller_seed; 32]);
        let writer = SigningKey::from_seed([writer_seed; 32]);
        let genesis = sign(
            space_id,
            EntitySchema::SpaceGenesisV1,
            vec![],
            vec![],
            OperationBody::SpaceGenesis {
                controller: controller.actor_id(),
            },
            &controller,
            space_seed,
        );
        let grant = sign(
            space_id,
            EntitySchema::CapabilityGrantV1,
            vec![],
            vec![genesis.operation_id],
            OperationBody::CapabilityGrant {
                grant: CapabilityGrant {
                    subject: writer.actor_id(),
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
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 0,
                    label: format!("writer {space_seed}"),
                },
            },
            &controller,
            space_seed.saturating_add(64),
        );
        store
            .bootstrap_trusted_space(&TrustedSpaceBootstrapRequest {
                display_name: format!("Space {space_seed}"),
                genesis: genesis.clone(),
                initial_grant: grant.clone(),
                received_at_unix_ms: 10,
            })
            .unwrap();
        (space_id, controller, writer, genesis, grant)
    }

    #[test]
    fn bootstrap_submit_replay_and_reduce_signed_operations() {
        let fixture = Fixture::new();
        assert_eq!(fixture.store.spaces().unwrap().len(), 1);
        assert_eq!(
            fixture
                .store
                .space(fixture.space_id)
                .unwrap()
                .unwrap()
                .genesis_operation_id,
            fixture.genesis.operation_id
        );

        let entity_id = EntityId::new(Uuid::from_bytes([44; 16]));
        let first = fixture.record(entity_id, vec![], 3);
        let admitted = fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: first.clone(),
                    received_at_unix_ms: 500,
                },
            )
            .unwrap();
        assert!(!admitted.replayed);
        assert_eq!(admitted.operation.received_at_unix_ms, 500);

        let replayed = fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: first.clone(),
                    received_at_unix_ms: 999,
                },
            )
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.operation.received_at_unix_ms, 500);

        let second = fixture.record(entity_id, vec![first.operation_id], 4);
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: second.clone(),
                    received_at_unix_ms: 501,
                },
            )
            .unwrap();
        let state = fixture
            .store
            .entity_state(fixture.space_id, entity_id)
            .unwrap()
            .unwrap();
        assert_eq!(state.operation_count, 2);
        assert_eq!(state.heads.len(), 1);
        assert_eq!(state.heads[0].operation.operation_id, second.operation_id);

        let page = fixture.store.changes_after(fixture.space_id, 0, 3).unwrap();
        assert_eq!(page.operations.len(), 3);
        assert!(page.has_more);
        assert!(
            page.operations
                .iter()
                .all(|stored| stored.operation.space_id == fixture.space_id)
        );
    }

    #[test]
    fn rejects_missing_and_mismatched_parents_without_partial_writes() {
        let fixture = Fixture::new();
        let entity_id = EntityId::new(Uuid::from_bytes([55; 16]));
        let first = fixture.record(entity_id, vec![], 5);
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: first.clone(),
                    received_at_unix_ms: 600,
                },
            )
            .unwrap();

        let other_entity = fixture.record(
            EntityId::new(Uuid::from_bytes([56; 16])),
            vec![first.operation_id],
            6,
        );
        assert!(matches!(
            fixture.store.submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: other_entity,
                    received_at_unix_ms: 601
                },
            ),
            Err(RepositoryError::ParentMismatch { .. })
        ));
        assert_eq!(
            fixture
                .store
                .entity_state(fixture.space_id, entity_id)
                .unwrap()
                .unwrap()
                .operation_count,
            1
        );
    }

    #[test]
    fn bootstrap_is_atomic_and_exactly_replayable() {
        let fixture = Fixture::new();
        let request = TrustedSpaceBootstrapRequest {
            display_name: "Test space".into(),
            genesis: fixture.genesis.clone(),
            initial_grant: fixture.writer_grant.clone(),
            received_at_unix_ms: 10,
        };
        let mut retry = request.clone();
        retry.received_at_unix_ms = 999;
        let replay = fixture.store.bootstrap_trusted_space(&retry).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.space.created_at_unix_ms, 10);
        assert_eq!(replay.genesis.received_at_unix_ms, 10);

        let mut conflict = request;
        conflict.display_name = "Other".into();
        assert!(matches!(
            fixture.store.bootstrap_trusted_space(&conflict),
            Err(RepositoryError::GenesisConflict(_))
        ));
        assert_eq!(fixture.store.spaces().unwrap().len(), 1);
        let _ = fixture.controller.actor_id();
    }

    #[test]
    fn delegated_grants_are_rechecked_after_ancestor_revocation() {
        let fixture = Fixture::new();
        let delegator = SigningKey::from_seed([7; 32]);
        let worker = SigningKey::from_seed([8; 32]);
        let parent_grant = sign(
            fixture.space_id,
            EntitySchema::CapabilityGrantV1,
            vec![],
            vec![fixture.genesis.operation_id],
            OperationBody::CapabilityGrant {
                grant: CapabilityGrant {
                    subject: delegator.actor_id(),
                    actions: vec![
                        CapabilityAction::AppendOperation,
                        CapabilityAction::IssueCapability,
                    ],
                    schemas: vec![EntitySchema::RecordV1],
                    visibilities: vec![Visibility::Public, Visibility::Private],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 1,
                    label: "delegating writer".into(),
                },
            },
            &fixture.controller,
            11,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: parent_grant.clone(),
                    received_at_unix_ms: 700,
                },
            )
            .unwrap();

        let child_grant = sign(
            fixture.space_id,
            EntitySchema::CapabilityGrantV1,
            vec![],
            vec![parent_grant.operation_id],
            OperationBody::CapabilityGrant {
                grant: CapabilityGrant {
                    subject: worker.actor_id(),
                    actions: vec![CapabilityAction::AppendOperation],
                    schemas: vec![EntitySchema::RecordV1],
                    visibilities: vec![Visibility::Public],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 0,
                    label: "public writer".into(),
                },
            },
            &delegator,
            12,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: child_grant.clone(),
                    received_at_unix_ms: 701,
                },
            )
            .unwrap();

        let entity_id = EntityId::new(Uuid::from_bytes([90; 16]));
        let first = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![],
            vec![child_grant.operation_id],
            702,
            OperationNonce::from_bytes([13; 16]),
            OperationBody::Put {
                document: RecordDocument {
                    start_at_unix_ms: 702,
                    end_at_unix_ms: None,
                    visibility: Visibility::Public,
                    emoji: None,
                    text: Some("authorized through two grants".into()),
                    metadata: BTreeMap::new(),
                    resources: vec![],
                },
            },
            &worker,
        )
        .unwrap();
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: first.clone(),
                    received_at_unix_ms: 702,
                },
            )
            .unwrap();

        let revoke = sign(
            fixture.space_id,
            EntitySchema::CapabilityRevokeV1,
            vec![],
            vec![fixture.genesis.operation_id],
            OperationBody::CapabilityRevoke {
                revocation: fractonica_data_model::CapabilityRevocation {
                    grant_id: parent_grant.operation_id,
                    reason: CapabilityRevocationReason::Administrative,
                    detail: Some("test".into()),
                },
            },
            &fixture.controller,
            14,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: revoke,
                    received_at_unix_ms: 703,
                },
            )
            .unwrap();

        let second = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![first.operation_id],
            vec![child_grant.operation_id],
            704,
            OperationNonce::from_bytes([15; 16]),
            OperationBody::Tombstone,
            &worker,
        )
        .unwrap();
        assert!(matches!(
            fixture.store.submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: second,
                    received_at_unix_ms: 704
                },
            ),
            Err(RepositoryError::Authorization(_))
        ));
        assert_eq!(
            fixture
                .store
                .entity_state(fixture.space_id, entity_id)
                .unwrap()
                .unwrap()
                .operation_count,
            1
        );
    }

    #[test]
    fn refuses_nonempty_legacy_log_without_destroying_it() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("legacy.sqlite3");
        let connection = Connection::open(&path).unwrap();
        for migration in &super::super::MIGRATIONS[..2] {
            connection.execute_batch(migration.sql).unwrap();
        }
        connection
            .execute(
                "INSERT INTO operations (
                operation_id, protocol_version, entity_id, schema_id, actor_id,
                kind, occurred_at_unix_ms, received_at_unix_ms, payload
             ) VALUES ('legacy-op', 1, 'legacy-entity', 'record.v1', 'legacy-actor',
                       'put', 1, 2, x'7b7d')",
                [],
            )
            .unwrap();
        drop(connection);
        make_legacy_fixture_private(temporary.path(), &path);

        assert!(matches!(
            SqliteStore::open(&path),
            Err(super::super::StoreError::LegacyMigrationRequired)
        ));
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM operations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'blobs'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn v4_migration_preserves_content_and_upload_metadata() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("content.sqlite3");
        let content_id = fractonica_content::hash_bytes(b"preserved");
        let upload_id = fractonica_application::UploadId::new(Uuid::from_bytes([31; 16]));
        let connection = Connection::open(&path).unwrap();
        for migration in &super::super::MIGRATIONS[..3] {
            connection.execute_batch(migration.sql).unwrap();
        }
        connection
            .execute(
                "INSERT INTO blobs (content_id, byte_length, stored_at_unix_ms)
             VALUES (?1, 9, 10)",
                params![content_id.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO upload_sessions (
                upload_id, upload_length, upload_offset, state,
                created_at_unix_ms, expires_at_unix_ms
             ) VALUES (?1, 12, 4, 'active', 10, 20)",
                params![upload_id.to_string()],
            )
            .unwrap();
        drop(connection);
        make_legacy_fixture_private(temporary.path(), &path);

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            store.readiness().unwrap().schema_version,
            super::super::SCHEMA_VERSION
        );
        assert_eq!(store.content(content_id).unwrap().unwrap().byte_length, 9);
        let upload = store.upload(upload_id).unwrap().unwrap();
        assert_eq!(upload.upload_length, 12);
        assert_eq!(upload.upload_offset, 4);
    }

    fn make_legacy_fixture_private(directory: &std::path::Path, database: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::{fs, os::unix::fs::PermissionsExt};
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(database, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn branches_merge_to_one_tombstone_head() {
        let fixture = Fixture::new();
        let entity_id = EntityId::new(Uuid::from_bytes([61; 16]));
        let root = fixture.record(entity_id, vec![], 21);
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: root.clone(),
                    received_at_unix_ms: 800,
                },
            )
            .unwrap();
        let left = fixture.record(entity_id, vec![root.operation_id], 22);
        let right = fixture.record(entity_id, vec![root.operation_id], 23);
        for operation in [&left, &right] {
            fixture
                .store
                .submit_operation(
                    fixture.space_id,
                    &SubmitOperationRequest {
                        operation: operation.clone(),
                        received_at_unix_ms: 801,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            fixture
                .store
                .entity_state(fixture.space_id, entity_id)
                .unwrap()
                .unwrap()
                .heads
                .len(),
            2
        );
        let mut parents = vec![left.operation_id, right.operation_id];
        parents.sort_unstable();
        let tombstone = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            parents,
            vec![fixture.writer_grant.operation_id],
            802,
            OperationNonce::from_bytes([24; 16]),
            OperationBody::Tombstone,
            &fixture.writer,
        )
        .unwrap();
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: tombstone.clone(),
                    received_at_unix_ms: 802,
                },
            )
            .unwrap();
        let state = fixture
            .store
            .entity_state(fixture.space_id, entity_id)
            .unwrap()
            .unwrap();
        assert_eq!(state.operation_count, 4);
        assert_eq!(state.heads.len(), 1);
        assert_eq!(
            state.heads[0].operation.operation_id,
            tombstone.operation_id
        );
        assert!(matches!(
            state.heads[0].operation.body,
            OperationBody::Tombstone
        ));
    }

    #[test]
    fn detects_corrupt_operation_projection_on_read() {
        let fixture = Fixture::new();
        let entity_id = EntityId::new(Uuid::from_bytes([62; 16]));
        let operation = fixture.record(entity_id, vec![], 25);
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: operation.clone(),
                    received_at_unix_ms: 900,
                },
            )
            .unwrap();
        fixture
            .store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE operations SET projection_json = '{}' WHERE operation_id = ?1",
                params![operation.operation_id.to_string()],
            )
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .operation(fixture.space_id, operation.operation_id),
            Err(RepositoryError::Corrupt(_))
        ));
    }

    #[test]
    fn isolates_same_entity_and_change_cursor_between_spaces() {
        let store = SqliteStore::open_in_memory().unwrap();
        let (space_a, _controller_a, writer_a, _genesis_a, grant_a) =
            bootstrap_space(&store, 41, 42, 43);
        let (space_b, _controller_b, writer_b, _genesis_b, grant_b) =
            bootstrap_space(&store, 51, 52, 53);
        let entity_id = EntityId::new(Uuid::from_bytes([77; 16]));
        let record = |space_id, authorization, key: &SigningKey, nonce| {
            OperationEnvelope::sign(
                space_id,
                entity_id,
                EntitySchema::RecordV1,
                vec![],
                vec![authorization],
                1_000,
                OperationNonce::from_bytes([nonce; 16]),
                OperationBody::Put {
                    document: RecordDocument {
                        start_at_unix_ms: 1_000,
                        end_at_unix_ms: None,
                        visibility: Visibility::Public,
                        emoji: None,
                        text: Some(format!("space {nonce}")),
                        metadata: BTreeMap::new(),
                        resources: vec![],
                    },
                },
                key,
            )
            .unwrap()
        };
        let operation_a = record(space_a, grant_a.operation_id, &writer_a, 71);
        let operation_b = record(space_b, grant_b.operation_id, &writer_b, 72);
        for (space_id, operation) in [
            (space_a, operation_a.clone()),
            (space_b, operation_b.clone()),
        ] {
            store
                .submit_operation(
                    space_id,
                    &SubmitOperationRequest {
                        operation,
                        received_at_unix_ms: 1_000,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            store
                .entity_state(space_a, entity_id)
                .unwrap()
                .unwrap()
                .operation_count,
            1
        );
        assert_eq!(
            store
                .entity_state(space_b, entity_id)
                .unwrap()
                .unwrap()
                .operation_count,
            1
        );
        let page_a = store.changes_after(space_a, 0, MAX_CHANGE_LIMIT).unwrap();
        let page_b = store.changes_after(space_b, 0, MAX_CHANGE_LIMIT).unwrap();
        assert_eq!(page_a.operations.len(), 3);
        assert_eq!(page_b.operations.len(), 3);
        assert!(
            page_a
                .operations
                .iter()
                .all(|stored| stored.operation.space_id == space_a)
        );
        assert!(
            page_b
                .operations
                .iter()
                .all(|stored| stored.operation.space_id == space_b)
        );

        let cross_parent = OperationEnvelope::sign(
            space_b,
            entity_id,
            EntitySchema::RecordV1,
            vec![operation_a.operation_id],
            vec![grant_b.operation_id],
            1_001,
            OperationNonce::from_bytes([73; 16]),
            OperationBody::Tombstone,
            &writer_b,
        )
        .unwrap();
        assert!(matches!(
            store.submit_operation(
                space_b,
                &SubmitOperationRequest { operation: cross_parent, received_at_unix_ms: 1_001 },
            ),
            Err(RepositoryError::CrossSpaceParent(id)) if id == operation_a.operation_id
        ));
    }

    #[test]
    fn public_only_capability_cannot_revise_or_tombstone_a_private_record() {
        let fixture = Fixture::new();
        let public_writer = SigningKey::from_seed([81; 32]);
        let public_grant = sign(
            fixture.space_id,
            EntitySchema::CapabilityGrantV1,
            vec![],
            vec![fixture.genesis.operation_id],
            OperationBody::CapabilityGrant {
                grant: CapabilityGrant {
                    subject: public_writer.actor_id(),
                    actions: vec![CapabilityAction::AppendOperation],
                    schemas: vec![EntitySchema::RecordV1],
                    visibilities: vec![Visibility::Public],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 0,
                    label: "public only".into(),
                },
            },
            &fixture.controller,
            82,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: public_grant.clone(),
                    received_at_unix_ms: 1_100,
                },
            )
            .unwrap();

        let entity_id = EntityId::new(Uuid::from_bytes([83; 16]));
        let private = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![],
            vec![fixture.writer_grant.operation_id],
            1_101,
            OperationNonce::from_bytes([83; 16]),
            OperationBody::Put {
                document: RecordDocument {
                    start_at_unix_ms: 1_101,
                    end_at_unix_ms: None,
                    visibility: Visibility::Private,
                    emoji: None,
                    text: Some("private".into()),
                    metadata: BTreeMap::new(),
                    resources: vec![],
                },
            },
            &fixture.writer,
        )
        .unwrap();
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: private.clone(),
                    received_at_unix_ms: 1_101,
                },
            )
            .unwrap();

        let public_put = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![private.operation_id],
            vec![public_grant.operation_id],
            1_102,
            OperationNonce::from_bytes([84; 16]),
            OperationBody::Put {
                document: RecordDocument {
                    start_at_unix_ms: 1_101,
                    end_at_unix_ms: None,
                    visibility: Visibility::Public,
                    emoji: None,
                    text: Some("visibility oracle attempt".into()),
                    metadata: BTreeMap::new(),
                    resources: vec![],
                },
            },
            &public_writer,
        )
        .unwrap();
        let tombstone = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![private.operation_id],
            vec![public_grant.operation_id],
            1_103,
            OperationNonce::from_bytes([85; 16]),
            OperationBody::Tombstone,
            &public_writer,
        )
        .unwrap();
        for operation in [public_put, tombstone] {
            assert!(matches!(
                fixture.store.submit_operation(
                    fixture.space_id,
                    &SubmitOperationRequest {
                        operation,
                        received_at_unix_ms: 1_104,
                    },
                ),
                Err(RepositoryError::Authorization(
                    fractonica_application::authorization::AuthorizationError::Denied
                ))
            ));
        }
        assert_eq!(
            fixture
                .store
                .entity_state(fixture.space_id, entity_id)
                .unwrap()
                .unwrap()
                .operation_count,
            1
        );
    }

    #[test]
    fn missing_materialized_visibility_fails_closed() {
        let fixture = Fixture::new();
        let entity_id = EntityId::new(Uuid::from_bytes([86; 16]));
        let record = fixture.record(entity_id, vec![], 86);
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: record.clone(),
                    received_at_unix_ms: 1_200,
                },
            )
            .unwrap();
        fixture
            .store
            .connection
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM client_entity_visibility WHERE space_id = ?1 AND entity_id = ?2",
                params![fixture.space_id.to_string(), entity_id.to_string()],
            )
            .unwrap();
        let tombstone = OperationEnvelope::sign(
            fixture.space_id,
            entity_id,
            EntitySchema::RecordV1,
            vec![record.operation_id],
            vec![fixture.writer_grant.operation_id],
            1_201,
            OperationNonce::from_bytes([87; 16]),
            OperationBody::Tombstone,
            &fixture.writer,
        )
        .unwrap();
        assert!(matches!(
            fixture.store.submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: tombstone,
                    received_at_unix_ms: 1_201,
                },
            ),
            Err(RepositoryError::Corrupt(_))
        ));
    }

    #[test]
    fn denied_expired_request_advances_durable_admission_clock() {
        let fixture = Fixture::new();
        let expiring_writer = SigningKey::from_seed([88; 32]);
        let expiring_grant = sign(
            fixture.space_id,
            EntitySchema::CapabilityGrantV1,
            vec![],
            vec![fixture.genesis.operation_id],
            OperationBody::CapabilityGrant {
                grant: CapabilityGrant {
                    subject: expiring_writer.actor_id(),
                    actions: vec![CapabilityAction::AppendOperation],
                    schemas: vec![EntitySchema::RecordV1],
                    visibilities: vec![Visibility::Public],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: Some(1_001),
                    delegation_depth: 0,
                    label: "expiring".into(),
                },
            },
            &fixture.controller,
            89,
        );
        fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: expiring_grant.clone(),
                    received_at_unix_ms: 500,
                },
            )
            .unwrap();
        let attempt = |entity_byte: u8, nonce_byte: u8| {
            OperationEnvelope::sign(
                fixture.space_id,
                EntityId::new(Uuid::from_bytes([entity_byte; 16])),
                EntitySchema::RecordV1,
                vec![],
                vec![expiring_grant.operation_id],
                900,
                OperationNonce::from_bytes([nonce_byte; 16]),
                OperationBody::Put {
                    document: RecordDocument {
                        start_at_unix_ms: 900,
                        end_at_unix_ms: None,
                        visibility: Visibility::Public,
                        emoji: None,
                        text: Some("clock rollback probe".into()),
                        metadata: BTreeMap::new(),
                        resources: vec![],
                    },
                },
                &expiring_writer,
            )
            .unwrap()
        };
        for (operation, sampled) in [(attempt(90, 90), 1_001), (attempt(91, 91), 999)] {
            assert!(matches!(
                fixture.store.submit_operation(
                    fixture.space_id,
                    &SubmitOperationRequest {
                        operation,
                        received_at_unix_ms: sampled,
                    },
                ),
                Err(RepositoryError::Authorization(
                    fractonica_application::authorization::AuthorizationError::OutsideAdmissionWindow {
                        now_unix_ms: 1_001,
                        ..
                    }
                ))
            ));
        }
        assert_eq!(
            fixture
                .store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT high_water_unix_ms FROM node_admission_clock WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1_001
        );
        let accepted = fixture.record(EntityId::new(Uuid::from_bytes([92; 16])), vec![], 92);
        let accepted = fixture
            .store
            .submit_operation(
                fixture.space_id,
                &SubmitOperationRequest {
                    operation: accepted,
                    received_at_unix_ms: 999,
                },
            )
            .unwrap();
        assert_eq!(accepted.operation.received_at_unix_ms, 1_001);
    }
}
