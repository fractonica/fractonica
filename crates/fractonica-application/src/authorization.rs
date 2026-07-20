//! Pure capability-chain evaluation for signed operation admission.
//!
//! Persistence adapters provide a transaction-scoped [`CapabilityView`]. The
//! evaluator never trusts the signer-asserted operation time: capability
//! windows are checked against the receiving node's admission clock.

use std::collections::BTreeSet;

#[cfg(test)]
use fractonica_data_model::RecordDocument;
use fractonica_data_model::{
    ActorId, CapabilityAction, CapabilityGrant, EntitySchema, OperationBody, OperationEnvelope,
    OperationId, RecordVisibility, SpaceId,
};
use thiserror::Error;

/// Bounds hostile or corrupt grant graphs independently of signed CBOR bounds.
pub const MAX_AUTHORIZATION_GRAPH_VISITS: usize = 4_096;

/// Transaction-scoped read access required to evaluate one capability chain.
pub trait CapabilityView {
    /// Returns the one locally anchored genesis digest for the selected space.
    /// A self-signed genesis operation is never root authority by shape alone.
    fn trusted_genesis(
        &self,
        space_id: SpaceId,
    ) -> Result<Option<OperationId>, CapabilityViewError>;

    /// Resolves one already admitted operation in the selected space.
    fn operation(
        &self,
        space_id: SpaceId,
        operation_id: OperationId,
    ) -> Result<Option<OperationEnvelope>, CapabilityViewError>;

    /// Reports whether a grant has an already admitted revocation.
    fn is_revoked(
        &self,
        space_id: SpaceId,
        grant_id: OperationId,
    ) -> Result<bool, CapabilityViewError>;
}

/// Storage-neutral failure returned by a [`CapabilityView`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("capability state is unavailable: {detail}")]
pub struct CapabilityViewError {
    pub detail: String,
}

impl CapabilityViewError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Stable authorization failures which adapters map to API problem codes.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorizationError {
    #[error("non-genesis operations require at least one authorization reference")]
    Required,

    #[error("authorization operation {0} is missing")]
    Missing(OperationId),

    #[error("authorization operation {operation_id} belongs to another space")]
    CrossSpaceReference { operation_id: OperationId },

    #[error("authorization operation {0} is neither a trusted genesis nor a capability grant")]
    NotCapability(OperationId),

    #[error("genesis operation {0} is not the locally anchored root for this space")]
    UntrustedGenesis(OperationId),

    #[error("capability grant {0} has been revoked")]
    Revoked(OperationId),

    #[error("capability grant {grant_id} authorizes {subject}, not operation actor {actor}")]
    SubjectMismatch {
        grant_id: OperationId,
        subject: ActorId,
        actor: ActorId,
    },

    #[error("capability grant {grant_id} is not active at local admission time {now_unix_ms}")]
    OutsideAdmissionWindow {
        grant_id: OperationId,
        now_unix_ms: i64,
    },

    #[error("the referenced capability chain does not authorize this operation")]
    Denied,

    #[error("capability graph contains a cycle at {0}")]
    Cycle(OperationId),

    #[error("capability graph exceeds {MAX_AUTHORIZATION_GRAPH_VISITS} visited operations")]
    GraphTooLarge,

    #[error("stored authorization operation {operation_id} is invalid: {detail}")]
    InvalidStoredOperation {
        operation_id: OperationId,
        detail: String,
    },

    #[error(transparent)]
    View(#[from] CapabilityViewError),
}

/// Verifies that every signed authorization reference resolves to a complete
/// chain which permits the requested operation. Multiple references are a
/// conjunctive attenuation: adding one never broadens authority.
pub fn authorize_operation(
    operation: &OperationEnvelope,
    now_unix_ms: i64,
    view: &impl CapabilityView,
) -> Result<(), AuthorizationError> {
    let record_visibility = match &operation.body {
        OperationBody::Put { document } => Some(document.visibility),
        _ => None,
    };
    authorize_operation_for_record_visibility(operation, now_unix_ms, view, record_visibility)
}

/// Authorizes an operation against a repository-derived record visibility.
///
/// Persistence adapters use this for record revisions and tombstones so an
/// operation cannot change or erase an entity outside the visibility scope of
/// its capability. The caller must derive the value from the transaction's
/// already admitted entity state; `None` retains schema-only behavior for
/// non-record operations.
pub fn authorize_operation_for_record_visibility(
    operation: &OperationEnvelope,
    now_unix_ms: i64,
    view: &impl CapabilityView,
    record_visibility: Option<RecordVisibility>,
) -> Result<(), AuthorizationError> {
    if operation.authorization.is_empty() {
        return Err(AuthorizationError::Required);
    }

    let required = RequiredAuthority::for_operation(operation, record_visibility)?;
    let mut context = EvaluationContext {
        view,
        now_unix_ms,
        visits: 0,
        stack: BTreeSet::new(),
    };
    let authorities = context.resolve_set(
        operation.space_id,
        operation.actor_id,
        &operation.authorization,
    )?;

    if authorities
        .iter()
        .all(|authority| authority.permits(&required))
    {
        Ok(())
    } else {
        Err(AuthorizationError::Denied)
    }
}

/// Authorizes a non-operation action against the same recursively validated
/// capability graph used for operation admission.
///
/// This is intentionally conjunctive: every supplied reference must resolve
/// to an active grant for `subject` and every one must permit `action`.
/// Locally anchored genesis authority is not an ambient data-plane grant.
pub fn authorize_capability_action(
    space_id: SpaceId,
    subject: ActorId,
    references: &[OperationId],
    action: CapabilityAction,
    now_unix_ms: i64,
    view: &impl CapabilityView,
) -> Result<(), AuthorizationError> {
    let mut context = EvaluationContext {
        view,
        now_unix_ms,
        visits: 0,
        stack: BTreeSet::new(),
    };
    let authorities = context.resolve_set(space_id, subject, references)?;
    if authorities
        .iter()
        .all(|authority| authority.permits_action(action))
    {
        Ok(())
    } else {
        Err(AuthorizationError::Denied)
    }
}

#[derive(Clone, Copy)]
enum RequiredAuthority<'a> {
    Append {
        schema: EntitySchema,
        record_visibility: RecordVisibility,
    },
    Issue(&'a CapabilityGrant),
    Revoke,
}

impl<'a> RequiredAuthority<'a> {
    fn for_operation(
        operation: &'a OperationEnvelope,
        record_visibility: Option<RecordVisibility>,
    ) -> Result<Self, AuthorizationError> {
        match (&operation.schema, &operation.body) {
            (EntitySchema::RecordV1, OperationBody::Put { .. })
            | (EntitySchema::RecordV1, OperationBody::Tombstone) => {
                let Some(record_visibility) = record_visibility else {
                    return Err(AuthorizationError::Denied);
                };
                Ok(Self::Append {
                    schema: operation.schema,
                    record_visibility,
                })
            }
            (EntitySchema::CapabilityGrantV1, OperationBody::CapabilityGrant { grant }) => {
                Ok(Self::Issue(grant))
            }
            (EntitySchema::CapabilityRevokeV1, OperationBody::CapabilityRevoke { .. }) => {
                Ok(Self::Revoke)
            }
            (EntitySchema::SpaceGenesisV1, OperationBody::SpaceGenesis { .. }) => {
                Err(AuthorizationError::Denied)
            }
            _ => Err(AuthorizationError::Denied),
        }
    }
}

#[derive(Clone)]
enum EffectiveAuthority {
    /// The locally anchored genesis controller may issue any bounded v1 grant
    /// and revoke grants, but it is not an implicit application-data writer.
    RootController,
    Grant(Box<CapabilityGrant>),
}

impl EffectiveAuthority {
    fn permits_action(&self, action: CapabilityAction) -> bool {
        match self {
            Self::RootController => false,
            Self::Grant(grant) => grant.actions.contains(&action),
        }
    }

    fn permits(&self, required: &RequiredAuthority<'_>) -> bool {
        match (self, required) {
            (Self::RootController, RequiredAuthority::Issue(_))
            | (Self::RootController, RequiredAuthority::Revoke) => true,
            (Self::RootController, RequiredAuthority::Append { .. }) => false,
            (
                Self::Grant(grant),
                RequiredAuthority::Append {
                    schema,
                    record_visibility,
                },
            ) => permits_append(grant, *schema, *record_visibility),
            (Self::Grant(grant), RequiredAuthority::Issue(child)) => {
                permits_delegation(grant, child)
            }
            (Self::Grant(grant), RequiredAuthority::Revoke) => {
                grant.actions.contains(&CapabilityAction::RevokeCapability)
            }
        }
    }
}

struct EvaluationContext<'a, V> {
    view: &'a V,
    now_unix_ms: i64,
    visits: usize,
    stack: BTreeSet<OperationId>,
}

impl<V: CapabilityView> EvaluationContext<'_, V> {
    fn resolve_set(
        &mut self,
        space_id: SpaceId,
        expected_subject: ActorId,
        references: &[OperationId],
    ) -> Result<Vec<EffectiveAuthority>, AuthorizationError> {
        if references.is_empty() {
            return Err(AuthorizationError::Required);
        }
        let mut resolved = Vec::with_capacity(references.len());
        for reference in references {
            resolved.push(self.resolve(space_id, expected_subject, *reference)?);
        }
        Ok(resolved)
    }

    fn resolve(
        &mut self,
        space_id: SpaceId,
        expected_subject: ActorId,
        operation_id: OperationId,
    ) -> Result<EffectiveAuthority, AuthorizationError> {
        self.visits = self.visits.saturating_add(1);
        if self.visits > MAX_AUTHORIZATION_GRAPH_VISITS {
            return Err(AuthorizationError::GraphTooLarge);
        }
        if !self.stack.insert(operation_id) {
            return Err(AuthorizationError::Cycle(operation_id));
        }

        let result = self.resolve_inner(space_id, expected_subject, operation_id);
        self.stack.remove(&operation_id);
        result
    }

    fn resolve_inner(
        &mut self,
        space_id: SpaceId,
        expected_subject: ActorId,
        operation_id: OperationId,
    ) -> Result<EffectiveAuthority, AuthorizationError> {
        let operation = self
            .view
            .operation(space_id, operation_id)?
            .ok_or(AuthorizationError::Missing(operation_id))?;
        operation
            .verify()
            .map_err(|error| AuthorizationError::InvalidStoredOperation {
                operation_id,
                detail: error.to_string(),
            })?;
        if operation.operation_id != operation_id {
            return Err(AuthorizationError::InvalidStoredOperation {
                operation_id,
                detail: "lookup returned a different operation ID".into(),
            });
        }
        if operation.space_id != space_id {
            return Err(AuthorizationError::CrossSpaceReference { operation_id });
        }

        match (&operation.schema, &operation.body) {
            (EntitySchema::SpaceGenesisV1, OperationBody::SpaceGenesis { controller }) => {
                if self.view.trusted_genesis(space_id)? != Some(operation_id) {
                    return Err(AuthorizationError::UntrustedGenesis(operation_id));
                }
                if *controller != expected_subject || operation.actor_id != expected_subject {
                    return Err(AuthorizationError::SubjectMismatch {
                        grant_id: operation_id,
                        subject: *controller,
                        actor: expected_subject,
                    });
                }
                Ok(EffectiveAuthority::RootController)
            }
            (EntitySchema::CapabilityGrantV1, OperationBody::CapabilityGrant { grant }) => {
                if grant.subject != expected_subject {
                    return Err(AuthorizationError::SubjectMismatch {
                        grant_id: operation_id,
                        subject: grant.subject,
                        actor: expected_subject,
                    });
                }
                if self.view.is_revoked(space_id, operation_id)? {
                    return Err(AuthorizationError::Revoked(operation_id));
                }
                if !window_contains(grant, self.now_unix_ms) {
                    return Err(AuthorizationError::OutsideAdmissionWindow {
                        grant_id: operation_id,
                        now_unix_ms: self.now_unix_ms,
                    });
                }

                // Re-evaluate every issuer-chain reference so revoking an
                // ancestor immediately invalidates its delegated descendants.
                let issuers =
                    self.resolve_set(space_id, operation.actor_id, &operation.authorization)?;
                let issuance = RequiredAuthority::Issue(grant);
                if !issuers.iter().all(|issuer| issuer.permits(&issuance)) {
                    return Err(AuthorizationError::Denied);
                }
                Ok(EffectiveAuthority::Grant(Box::new(grant.clone())))
            }
            _ => Err(AuthorizationError::NotCapability(operation_id)),
        }
    }
}

fn window_contains(grant: &CapabilityGrant, now_unix_ms: i64) -> bool {
    grant
        .not_before_unix_ms
        .is_none_or(|start| now_unix_ms >= start)
        && grant.expires_at_unix_ms.is_none_or(|end| now_unix_ms < end)
}

fn permits_append(
    grant: &CapabilityGrant,
    schema: EntitySchema,
    record_visibility: RecordVisibility,
) -> bool {
    if !grant.actions.contains(&CapabilityAction::AppendOperation)
        || !grant.schemas.contains(&schema)
    {
        return false;
    }
    // Referencing immutable content is part of the signed record body. It does
    // not upload, reveal, or mutate those bytes. `writeContent` and its role /
    // byte limits are evaluated by the future space-scoped content endpoint,
    // while record admission is governed by schema and visibility scope.
    grant.record_visibilities.contains(&record_visibility)
}

fn permits_delegation(parent: &CapabilityGrant, child: &CapabilityGrant) -> bool {
    parent.actions.contains(&CapabilityAction::IssueCapability)
        && parent.delegation_depth > 0
        && child.delegation_depth < parent.delegation_depth
        && is_subset(&child.actions, &parent.actions)
        && is_subset_by(&child.schemas, &parent.schemas, |value| value.as_str())
        && is_subset(&child.record_visibilities, &parent.record_visibilities)
        && is_subset(&child.content_roles, &parent.content_roles)
        && maximum_is_narrower(
            child.max_resource_byte_length,
            parent.max_resource_byte_length,
        )
        && lower_bound_is_narrower(child.not_before_unix_ms, parent.not_before_unix_ms)
        && upper_bound_is_narrower(child.expires_at_unix_ms, parent.expires_at_unix_ms)
}

fn is_subset<T: Ord>(child: &[T], parent: &[T]) -> bool {
    child
        .iter()
        .all(|value| parent.binary_search(value).is_ok())
}

fn is_subset_by<T, K: Ord>(child: &[T], parent: &[T], key: impl Fn(&T) -> K) -> bool {
    child.iter().all(|child_value| {
        let child_key = key(child_value);
        parent
            .binary_search_by(|parent_value| key(parent_value).cmp(&child_key))
            .is_ok()
    })
}

const fn maximum_is_narrower(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (None, None) => true,
        (Some(_), None) => true,
        (Some(child), Some(parent)) => child <= parent,
        (None, Some(_)) => false,
    }
}

const fn lower_bound_is_narrower(child: Option<i64>, parent: Option<i64>) -> bool {
    match (child, parent) {
        (None, None) => true,
        (Some(_), None) => true,
        (Some(child), Some(parent)) => child >= parent,
        (None, Some(_)) => false,
    }
}

const fn upper_bound_is_narrower(child: Option<i64>, parent: Option<i64>) -> bool {
    match (child, parent) {
        (None, None) => true,
        (Some(_), None) => true,
        (Some(child), Some(parent)) => child <= parent,
        (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use fractonica_data_model::{
        CapabilityRevocation, CapabilityRevocationReason, EntityId, OperationNonce,
        RecordVisibility, SignedOperationEnvelope, SigningKey,
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    const NOW: i64 = 10_000;

    #[derive(Default)]
    struct MemoryView {
        operations: BTreeMap<OperationId, OperationEnvelope>,
        trusted_genesis: BTreeMap<SpaceId, OperationId>,
        revoked: BTreeSet<OperationId>,
    }

    impl MemoryView {
        fn insert(&mut self, operation: OperationEnvelope) {
            if operation.schema == EntitySchema::SpaceGenesisV1 {
                self.trusted_genesis
                    .insert(operation.space_id, operation.operation_id);
            }
            self.operations.insert(operation.operation_id, operation);
        }
    }

    impl CapabilityView for MemoryView {
        fn trusted_genesis(
            &self,
            space_id: SpaceId,
        ) -> Result<Option<OperationId>, CapabilityViewError> {
            Ok(self.trusted_genesis.get(&space_id).copied())
        }

        fn operation(
            &self,
            _space_id: SpaceId,
            operation_id: OperationId,
        ) -> Result<Option<OperationEnvelope>, CapabilityViewError> {
            Ok(self.operations.get(&operation_id).cloned())
        }

        fn is_revoked(
            &self,
            _space_id: SpaceId,
            grant_id: OperationId,
        ) -> Result<bool, CapabilityViewError> {
            Ok(self.revoked.contains(&grant_id))
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

    fn nonce(byte: u8) -> OperationNonce {
        OperationNonce::from_bytes([byte; 16])
    }

    fn genesis(space_id: SpaceId, controller: &SigningKey) -> OperationEnvelope {
        SignedOperationEnvelope::sign(
            space_id,
            entity(1),
            EntitySchema::SpaceGenesisV1,
            Vec::new(),
            Vec::new(),
            1,
            nonce(1),
            OperationBody::SpaceGenesis {
                controller: controller.actor_id(),
            },
            controller,
        )
        .expect("genesis")
    }

    fn grant(
        space_id: SpaceId,
        issuer: &SigningKey,
        authorization: Vec<OperationId>,
        entity_value: u128,
        nonce_byte: u8,
        grant: CapabilityGrant,
    ) -> OperationEnvelope {
        SignedOperationEnvelope::sign(
            space_id,
            entity(entity_value),
            EntitySchema::CapabilityGrantV1,
            Vec::new(),
            authorization,
            2,
            nonce(nonce_byte),
            OperationBody::CapabilityGrant { grant },
            issuer,
        )
        .expect("grant")
    }

    fn record(
        space_id: SpaceId,
        actor: &SigningKey,
        authorization: Vec<OperationId>,
        visibility: RecordVisibility,
        occurred_at_unix_ms: i64,
    ) -> OperationEnvelope {
        SignedOperationEnvelope::sign(
            space_id,
            entity(100),
            EntitySchema::RecordV1,
            Vec::new(),
            authorization,
            occurred_at_unix_ms,
            nonce(100),
            OperationBody::Put {
                document: RecordDocument {
                    start_at_unix_ms: 5,
                    end_at_unix_ms: None,
                    visibility,
                    emoji: Some("🌒".into()),
                    text: Some("signed".into()),
                    metadata: BTreeMap::from([("source".into(), json!("test"))]),
                    resources: Vec::new(),
                },
            },
            actor,
        )
        .expect("record")
    }

    fn writer_grant(subject: ActorId) -> CapabilityGrant {
        CapabilityGrant {
            subject,
            actions: vec![CapabilityAction::AppendOperation],
            schemas: vec![EntitySchema::RecordV1],
            record_visibilities: vec![RecordVisibility::Public],
            content_roles: Vec::new(),
            max_resource_byte_length: None,
            not_before_unix_ms: None,
            expires_at_unix_ms: None,
            delegation_depth: 0,
            label: "writer".into(),
        }
    }

    #[test]
    fn direct_grant_authorizes_records_and_revocation_stops_new_admission() {
        let space_id = space(1);
        let controller = key(1);
        let writer = key(2);
        let genesis = genesis(space_id, &controller);
        let grant = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            2,
            2,
            writer_grant(writer.actor_id()),
        );
        let record = record(
            space_id,
            &writer,
            vec![grant.operation_id],
            RecordVisibility::Public,
            NOW,
        );
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(grant.clone());

        assert_eq!(authorize_operation(&record, NOW, &view), Ok(()));
        view.revoked.insert(grant.operation_id);
        assert_eq!(
            authorize_operation(&record, NOW, &view),
            Err(AuthorizationError::Revoked(grant.operation_id))
        );
    }

    #[test]
    fn actor_subject_scope_and_root_controller_are_not_ambient_authority() {
        let space_id = space(2);
        let controller = key(3);
        let writer = key(4);
        let stranger = key(5);
        let genesis = genesis(space_id, &controller);
        let grant = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            2,
            2,
            writer_grant(writer.actor_id()),
        );
        let mut view = MemoryView::default();
        view.insert(genesis.clone());
        view.insert(grant.clone());

        let private_record = record(
            space_id,
            &writer,
            vec![grant.operation_id],
            RecordVisibility::Private,
            NOW,
        );
        assert_eq!(
            authorize_operation(&private_record, NOW, &view),
            Err(AuthorizationError::Denied)
        );

        let stranger_record = record(
            space_id,
            &stranger,
            vec![grant.operation_id],
            RecordVisibility::Public,
            NOW,
        );
        assert!(matches!(
            authorize_operation(&stranger_record, NOW, &view),
            Err(AuthorizationError::SubjectMismatch { .. })
        ));

        let controller_record = record(
            space_id,
            &controller,
            vec![genesis.operation_id],
            RecordVisibility::Public,
            NOW,
        );
        assert_eq!(
            authorize_operation(&controller_record, NOW, &view),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn a_self_signed_but_unanchored_genesis_never_becomes_root_authority() {
        let space_id = space(9);
        let trusted_controller = key(20);
        let attacker = key(21);
        let worker = key(22);
        let trusted = genesis(space_id, &trusted_controller);
        let untrusted = SignedOperationEnvelope::sign(
            space_id,
            entity(90),
            EntitySchema::SpaceGenesisV1,
            Vec::new(),
            Vec::new(),
            1,
            nonce(90),
            OperationBody::SpaceGenesis {
                controller: attacker.actor_id(),
            },
            &attacker,
        )
        .expect("untrusted genesis is cryptographically well formed");
        let attacker_grant = grant(
            space_id,
            &attacker,
            vec![untrusted.operation_id],
            91,
            91,
            writer_grant(worker.actor_id()),
        );
        let operation = record(
            space_id,
            &worker,
            vec![attacker_grant.operation_id],
            RecordVisibility::Public,
            NOW,
        );

        let mut view = MemoryView::default();
        view.insert(trusted);
        view.operations
            .insert(untrusted.operation_id, untrusted.clone());
        view.insert(attacker_grant);
        assert_eq!(
            authorize_operation(&operation, NOW, &view),
            Err(AuthorizationError::UntrustedGenesis(untrusted.operation_id))
        );
    }

    #[test]
    fn delegated_scope_is_intersected_and_ancestor_revocation_propagates() {
        let space_id = space(3);
        let controller = key(6);
        let delegator = key(7);
        let sensor = key(8);
        let genesis = genesis(space_id, &controller);
        let parent = CapabilityGrant {
            subject: delegator.actor_id(),
            actions: vec![
                CapabilityAction::AppendOperation,
                CapabilityAction::IssueCapability,
            ],
            schemas: vec![EntitySchema::RecordV1],
            record_visibilities: vec![RecordVisibility::Public],
            content_roles: Vec::new(),
            max_resource_byte_length: None,
            not_before_unix_ms: Some(1_000),
            expires_at_unix_ms: Some(20_000),
            delegation_depth: 2,
            label: "delegator".into(),
        };
        let parent = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            2,
            2,
            parent,
        );
        let child = CapabilityGrant {
            subject: sensor.actor_id(),
            actions: vec![CapabilityAction::AppendOperation],
            schemas: vec![EntitySchema::RecordV1],
            record_visibilities: vec![RecordVisibility::Public],
            content_roles: Vec::new(),
            max_resource_byte_length: None,
            not_before_unix_ms: Some(2_000),
            expires_at_unix_ms: Some(15_000),
            delegation_depth: 1,
            label: "sensor".into(),
        };
        let child = grant(space_id, &delegator, vec![parent.operation_id], 3, 3, child);
        let record = record(
            space_id,
            &sensor,
            vec![child.operation_id],
            RecordVisibility::Public,
            100,
        );
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(parent.clone());
        view.insert(child.clone());

        // The signed occurrence time is before not-before, but local admission
        // time is authoritative for capabilities.
        assert_eq!(authorize_operation(&record, NOW, &view), Ok(()));
        assert!(matches!(
            authorize_operation(&record, 999, &view),
            Err(AuthorizationError::OutsideAdmissionWindow { .. })
        ));

        view.revoked.insert(parent.operation_id);
        assert_eq!(
            authorize_operation(&record, NOW, &view),
            Err(AuthorizationError::Revoked(parent.operation_id))
        );
    }

    #[test]
    fn broader_delegation_and_missing_references_fail_closed() {
        let space_id = space(4);
        let controller = key(9);
        let delegator = key(10);
        let sensor = key(11);
        let genesis = genesis(space_id, &controller);
        let parent = CapabilityGrant {
            delegation_depth: 1,
            actions: vec![
                CapabilityAction::AppendOperation,
                CapabilityAction::IssueCapability,
            ],
            ..writer_grant(delegator.actor_id())
        };
        let parent = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            2,
            2,
            parent,
        );
        let broader = CapabilityGrant {
            subject: sensor.actor_id(),
            actions: vec![CapabilityAction::AppendOperation],
            schemas: vec![EntitySchema::RecordV1],
            record_visibilities: vec![RecordVisibility::Public, RecordVisibility::Private],
            content_roles: Vec::new(),
            max_resource_byte_length: None,
            not_before_unix_ms: None,
            expires_at_unix_ms: None,
            delegation_depth: 0,
            label: "too broad".into(),
        };
        let broader = grant(
            space_id,
            &delegator,
            vec![parent.operation_id],
            3,
            3,
            broader,
        );
        let broader_record = record(
            space_id,
            &sensor,
            vec![broader.operation_id],
            RecordVisibility::Public,
            NOW,
        );
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(parent);
        view.insert(broader);
        assert_eq!(
            authorize_operation(&broader_record, NOW, &view),
            Err(AuthorizationError::Denied)
        );

        let missing = OperationId::from_bytes([0xaa; 32]);
        let missing_record = record(
            space_id,
            &sensor,
            vec![missing],
            RecordVisibility::Public,
            NOW,
        );
        assert_eq!(
            authorize_operation(&missing_record, NOW, &view),
            Err(AuthorizationError::Missing(missing))
        );
    }

    #[test]
    fn revocation_operations_require_revoke_authority() {
        let space_id = space(5);
        let controller = key(12);
        let writer = key(13);
        let genesis = genesis(space_id, &controller);
        let writer_grant = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            2,
            2,
            writer_grant(writer.actor_id()),
        );
        let revocation = SignedOperationEnvelope::sign(
            space_id,
            entity(3),
            EntitySchema::CapabilityRevokeV1,
            Vec::new(),
            vec![writer_grant.operation_id],
            NOW,
            nonce(3),
            OperationBody::CapabilityRevoke {
                revocation: CapabilityRevocation {
                    grant_id: writer_grant.operation_id,
                    reason: CapabilityRevocationReason::Administrative,
                    detail: None,
                },
            },
            &writer,
        )
        .expect("revocation projection");
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(writer_grant);
        assert_eq!(
            authorize_operation(&revocation, NOW, &view),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn every_direct_authorization_reference_must_permit_the_operation() {
        let space_id = space(6);
        let controller = key(14);
        let writer = key(15);
        let genesis = genesis(space_id, &controller);
        let broad = CapabilityGrant {
            record_visibilities: vec![RecordVisibility::Public, RecordVisibility::Private],
            ..writer_grant(writer.actor_id())
        };
        let broad = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            20,
            20,
            broad,
        );
        let private_only = CapabilityGrant {
            record_visibilities: vec![RecordVisibility::Private],
            ..writer_grant(writer.actor_id())
        };
        let private_only = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            21,
            21,
            private_only,
        );
        let mut references = vec![broad.operation_id, private_only.operation_id];
        references.sort_unstable();
        let operation = record(space_id, &writer, references, RecordVisibility::Public, NOW);
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(broad);
        view.insert(private_only);

        assert_eq!(
            authorize_operation(&operation, NOW, &view),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn every_issuer_reference_must_permit_a_delegated_grant() {
        let space_id = space(7);
        let controller = key(16);
        let delegator = key(17);
        let worker = key(18);
        let genesis = genesis(space_id, &controller);
        let permitting = CapabilityGrant {
            actions: vec![
                CapabilityAction::AppendOperation,
                CapabilityAction::IssueCapability,
            ],
            record_visibilities: vec![RecordVisibility::Public, RecordVisibility::Private],
            delegation_depth: 1,
            ..writer_grant(delegator.actor_id())
        };
        let permitting = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            30,
            30,
            permitting,
        );
        let nonpermitting = CapabilityGrant {
            record_visibilities: vec![RecordVisibility::Public, RecordVisibility::Private],
            ..writer_grant(delegator.actor_id())
        };
        let nonpermitting = grant(
            space_id,
            &controller,
            vec![genesis.operation_id],
            31,
            31,
            nonpermitting,
        );
        let mut references = vec![permitting.operation_id, nonpermitting.operation_id];
        references.sort_unstable();
        let child = grant(
            space_id,
            &delegator,
            references,
            32,
            32,
            writer_grant(worker.actor_id()),
        );
        let mut view = MemoryView::default();
        view.insert(genesis);
        view.insert(permitting);
        view.insert(nonpermitting);

        assert_eq!(
            authorize_operation(&child, NOW, &view),
            Err(AuthorizationError::Denied)
        );
    }
}
