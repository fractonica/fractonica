//! Crash-safe coordination between protected pairing secrets and SQLite state.

use std::collections::BTreeSet;

use fractonica_api::{
    PairingControl, PairingControlError, PairingCreateCommand, PairingHandshakeResult,
    PairingInvitationCreated, PairingSessionView, PairingState,
};
use fractonica_application::{OperationRepository, SubmitOperationRequest};
use fractonica_data_model::{
    EntityId, EntitySchema, OperationBody, OperationEnvelope, OperationId, OperationNonce,
};
use fractonica_keystore::IdentityBundle;
use fractonica_keystore::{FilePairingSecretVault, PairingSecretVaultError};
use fractonica_pairing::{
    InvitationId, InvitationParameters, IssuedInvitation, JoinerClaim, PairingInvitation,
    PairingReceipt, confirmation_octal,
};
use fractonica_store_sqlite::{PairingLifecycle, PairingSession, PairingStoreError, SqliteStore};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub struct DurablePairingStore {
    database: SqliteStore,
    secrets: FilePairingSecretVault,
}

impl DurablePairingStore {
    #[must_use]
    pub const fn new(database: SqliteStore, secrets: FilePairingSecretVault) -> Self {
        Self { database, secrets }
    }

    /// Publishes secret material first, then the non-secret index. A crash in
    /// between leaves an orphan secret that [`Self::reconcile`] removes.
    pub fn create(
        &self,
        issued: &IssuedInvitation,
        now_unix_ms: i64,
    ) -> Result<PairingSession, DurablePairingError> {
        let replayed_secret = self.secrets.store(&issued.secret)?;
        match self
            .database
            .create_pairing_session(issued.invitation.descriptor(), now_unix_ms)
        {
            Ok(session) => Ok(session),
            Err(error) => {
                if !replayed_secret {
                    self.secrets.remove(issued.secret.invitation_id())?;
                }
                Err(error.into())
            }
        }
    }

    /// Expires stale sessions, removes orphan/terminal secrets, and fails
    /// closed if any active SQLite session has lost its protected material.
    pub fn reconcile(&self, now_unix_ms: i64) -> Result<ReconcileResult, DurablePairingError> {
        let expired = self.database.expire_pairing_sessions(now_unix_ms)?;
        let active = self.database.active_pairing_sessions()?;
        let active_ids: BTreeSet<_> = active.iter().map(|session| session.invitation_id).collect();
        let secret_ids = self.secrets.invitation_ids()?;
        let secret_set: BTreeSet<_> = secret_ids.iter().copied().collect();
        if let Some(missing) = active_ids.difference(&secret_set).next() {
            return Err(DurablePairingError::MissingActiveSecret(*missing));
        }
        let mut removed = 0;
        for orphan in secret_ids
            .into_iter()
            .filter(|invitation_id| !active_ids.contains(invitation_id))
        {
            removed += usize::from(self.secrets.remove(orphan)?);
        }
        Ok(ReconcileResult {
            expired_sessions: expired,
            removed_secrets: removed,
            active_sessions: active.len(),
        })
    }

    /// Persists cancellation before deleting its secret, so a crash can only
    /// leave harmless material that reconciliation removes.
    pub fn cancel(
        &self,
        invitation_id: InvitationId,
        now_unix_ms: i64,
    ) -> Result<PairingSession, DurablePairingError> {
        let session = self
            .database
            .cancel_pairing_session(invitation_id, now_unix_ms)?;
        self.secrets.remove(invitation_id)?;
        Ok(session)
    }

    pub fn complete(
        &self,
        invitation_id: InvitationId,
        grant_operation_id: OperationId,
        now_unix_ms: i64,
    ) -> Result<PairingSession, DurablePairingError> {
        let session = self.database.complete_pairing_session(
            invitation_id,
            grant_operation_id,
            now_unix_ms,
        )?;
        self.secrets.remove(invitation_id)?;
        Ok(session)
    }

    pub fn invitation_secret(
        &self,
        invitation_id: InvitationId,
    ) -> Result<fractonica_pairing::ResponderInvitationSecret, DurablePairingError> {
        self.secrets
            .load(invitation_id)?
            .ok_or(DurablePairingError::MissingActiveSecret(invitation_id))
    }

    #[must_use]
    pub const fn database(&self) -> &SqliteStore {
        &self.database
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconcileResult {
    pub expired_sessions: usize,
    pub removed_secrets: usize,
    pub active_sessions: usize,
}

#[derive(Debug, Error)]
pub enum DurablePairingError {
    #[error("active pairing {0} has lost its protected secret material")]
    MissingActiveSecret(InvitationId),
    #[error(transparent)]
    Secrets(#[from] PairingSecretVaultError),
    #[error(transparent)]
    Database(#[from] PairingStoreError),
}

impl std::fmt::Debug for DurablePairingStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurablePairingStore")
            .field("database", &self.database.path())
            .field("secrets", &"[PROTECTED]")
            .finish()
    }
}

pub struct NodePairingControl {
    durable: DurablePairingStore,
    identity: std::sync::Arc<IdentityBundle>,
    genesis_operation_id: OperationId,
}

impl NodePairingControl {
    #[must_use]
    pub const fn new(
        durable: DurablePairingStore,
        identity: std::sync::Arc<IdentityBundle>,
        genesis_operation_id: OperationId,
    ) -> Self {
        Self {
            durable,
            identity,
            genesis_operation_id,
        }
    }

    fn view(session: PairingSession) -> PairingSessionView {
        PairingSessionView {
            invitation_id: session.invitation_id,
            space_id: session.descriptor.space_id,
            state: match session.state {
                PairingLifecycle::Created => PairingState::Created,
                PairingLifecycle::Claimed => PairingState::Claimed,
                PairingLifecycle::Confirmed => PairingState::Confirmed,
                PairingLifecycle::Completed => PairingState::Completed,
                PairingLifecycle::Cancelled => PairingState::Cancelled,
                PairingLifecycle::Expired => PairingState::Expired,
            },
            expires_at_unix_ms: session.descriptor.expires_at_unix_ms,
            joiner_node_id: session.joiner_node_id,
            subject_actor_id: session.subject_actor_id,
            confirmation_octal: session.handshake_hash.as_ref().map(confirmation_octal),
            grant_operation_id: session.grant_operation_id,
        }
    }

    fn planned_or_new_grant(
        &self,
        session: &PairingSession,
        now: i64,
    ) -> Result<OperationEnvelope, PairingControlError> {
        if let Some(operation) = &session.planned_grant {
            return Ok(operation.clone());
        }
        let subject = session
            .subject_actor_id
            .ok_or(PairingControlError::Unavailable)?;
        let grant = session
            .descriptor
            .capability
            .to_grant(subject)
            .map_err(protocol_error)?;
        let timestamp: u64 = now
            .try_into()
            .map_err(|_| PairingControlError::Invalid("invalid grant time".into()))?;
        if timestamp > (1_u64 << 48) - 1 {
            return Err(PairingControlError::Invalid(
                "grant time exceeds UUIDv7 range".into(),
            ));
        }
        for _ in 0..16 {
            let mut random = [0_u8; 10];
            getrandom::fill(&mut random).map_err(|_| PairingControlError::Storage)?;
            let entity_id = EntityId::new(
                uuid::Builder::from_unix_timestamp_millis(timestamp, &random).into_uuid(),
            );
            if self
                .durable
                .database()
                .entity_state(session.descriptor.space_id, entity_id)
                .map_err(|_| PairingControlError::Storage)?
                .is_some()
            {
                continue;
            }
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| PairingControlError::Storage)?;
            let operation = OperationEnvelope::sign(
                session.descriptor.space_id,
                entity_id,
                EntitySchema::CapabilityGrantV1,
                vec![],
                vec![session.descriptor.genesis_operation_id],
                now,
                OperationNonce::from_bytes(nonce),
                OperationBody::CapabilityGrant {
                    grant: grant.clone(),
                },
                self.identity.space_controller_key(),
            )
            .map_err(|error| PairingControlError::Invalid(error.to_string()))?;
            let planned = self
                .durable
                .database()
                .plan_pairing_grant(session.invitation_id, &operation, now)
                .map_err(store_error)?;
            return planned.planned_grant.ok_or(PairingControlError::Storage);
        }
        Err(PairingControlError::Storage)
    }
}

impl PairingControl for NodePairingControl {
    fn create_invitation(
        &self,
        request: PairingCreateCommand,
        now: i64,
    ) -> Result<PairingInvitationCreated, PairingControlError> {
        if request.space_id != self.identity.space_id()
            || request.expires_in_ms < fractonica_pairing::MIN_INVITATION_LIFETIME_MS
            || request.expires_in_ms > fractonica_pairing::MAX_INVITATION_LIFETIME_MS
            || request.endpoint_hints.iter().any(|hint| {
                !(hint.starts_with("http://127.0.0.1:") || hint.starts_with("http://localhost:"))
            })
        {
            return Err(PairingControlError::Invalid(
                "invalid invitation scope".into(),
            ));
        }
        let expires = now
            .checked_add(request.expires_in_ms)
            .ok_or_else(|| PairingControlError::Invalid("invalid expiry".into()))?;
        let issued = PairingInvitation::issue(
            self.identity.node_transport_key(),
            InvitationParameters {
                space_id: request.space_id,
                genesis_operation_id: self.genesis_operation_id,
                now_unix_ms: now,
                expires_at_unix_ms: expires,
                endpoint_hints: request.endpoint_hints,
                capability: request.capability,
            },
        )
        .map_err(protocol_error)?;
        let qr = issued.invitation.to_qr_string().map_err(protocol_error)?;
        let session = self.durable.create(&issued, now).map_err(durable_error)?;
        Ok(PairingInvitationCreated {
            qr,
            session: Self::view(session),
        })
    }

    fn invitation(
        &self,
        id: InvitationId,
    ) -> Result<Option<PairingSessionView>, PairingControlError> {
        self.durable
            .database()
            .pairing_session(id)
            .map(|session| session.map(Self::view))
            .map_err(store_error)
    }

    fn handshake(
        &self,
        id: InvitationId,
        first_frame: &[u8],
        now: i64,
    ) -> Result<PairingHandshakeResult, PairingControlError> {
        let session = self
            .durable
            .database()
            .pairing_session(id)
            .map_err(store_error)?
            .ok_or(PairingControlError::NotFound)?;
        if session.state != PairingLifecycle::Created {
            return Err(PairingControlError::Unavailable);
        }
        let secret = self.durable.invitation_secret(id).map_err(durable_error)?;
        let mut responder = secret.start_responder().map_err(protocol_error)?;
        let claim_bytes = responder
            .read_message(first_frame)
            .map_err(|_| PairingControlError::Unavailable)?;
        let claim = JoinerClaim::from_canonical_bytes(&claim_bytes)
            .map_err(|_| PairingControlError::Unavailable)?;
        claim
            .verify_for(&session.descriptor)
            .map_err(|_| PairingControlError::Unavailable)?;
        let response_frame = responder
            .write_message(&[])
            .map_err(|_| PairingControlError::Unavailable)?;
        let mut transport = responder
            .finish()
            .map_err(|_| PairingControlError::Unavailable)?;
        let hash = *transport.handshake_hash();
        let claimed = self
            .durable
            .database()
            .claim_pairing_session(&session.descriptor, &claim, hash, now)
            .map_err(store_error)?;
        let receipt = PairingReceipt::sign(
            &session.descriptor,
            &claim,
            hash,
            self.identity.node_transport_key(),
        );
        let receipt_frame = transport
            .write_message(&receipt.canonical_bytes().map_err(protocol_error)?)
            .map_err(protocol_error)?;
        Ok(PairingHandshakeResult {
            response_frame,
            receipt_frame,
            session: Self::view(claimed),
        })
    }

    fn confirm(
        &self,
        id: InvitationId,
        supplied: &str,
        now: i64,
    ) -> Result<PairingSessionView, PairingControlError> {
        let session = self
            .durable
            .database()
            .pairing_session(id)
            .map_err(store_error)?
            .ok_or(PairingControlError::NotFound)?;
        let hash = session
            .handshake_hash
            .ok_or(PairingControlError::Unavailable)?;
        let expected = confirmation_octal(&hash);
        if supplied.len() != expected.len()
            || !bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
        {
            return Err(PairingControlError::ConfirmationMismatch);
        }
        if session.state == PairingLifecycle::Completed {
            self.durable
                .secrets
                .remove(id)
                .map_err(DurablePairingError::from)
                .map_err(durable_error)?;
            return Ok(Self::view(session));
        }
        let confirmed = match session.state {
            PairingLifecycle::Claimed => self
                .durable
                .database()
                .confirm_pairing_session(id, hash, now)
                .map_err(store_error)?,
            PairingLifecycle::Confirmed => session,
            _ => return Err(PairingControlError::Unavailable),
        };
        let operation = self.planned_or_new_grant(&confirmed, now)?;
        self.durable
            .database()
            .submit_operation(
                confirmed.descriptor.space_id,
                &SubmitOperationRequest {
                    operation: operation.clone(),
                    received_at_unix_ms: now,
                },
            )
            .map_err(|_| PairingControlError::Storage)?;
        self.durable
            .complete(id, operation.operation_id, now)
            .map(Self::view)
            .map_err(durable_error)
    }

    fn cancel(
        &self,
        id: InvitationId,
        now: i64,
    ) -> Result<PairingSessionView, PairingControlError> {
        self.durable
            .cancel(id, now)
            .map(Self::view)
            .map_err(durable_error)
    }
}

fn protocol_error(error: fractonica_pairing::PairingError) -> PairingControlError {
    PairingControlError::Invalid(error.to_string())
}

fn store_error(error: PairingStoreError) -> PairingControlError {
    match error {
        PairingStoreError::NotFound => PairingControlError::NotFound,
        PairingStoreError::Unavailable => PairingControlError::Unavailable,
        PairingStoreError::Conflict
        | PairingStoreError::InvalidTime
        | PairingStoreError::InvalidGrantPlan
        | PairingStoreError::Protocol(_) => PairingControlError::Invalid(error.to_string()),
        PairingStoreError::Corrupt(_)
        | PairingStoreError::Store(_)
        | PairingStoreError::Sqlite(_) => PairingControlError::Storage,
    }
}

fn durable_error(error: DurablePairingError) -> PairingControlError {
    match error {
        DurablePairingError::Database(error) => store_error(error),
        DurablePairingError::MissingActiveSecret(_) | DurablePairingError::Secrets(_) => {
            PairingControlError::Storage
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use fractonica_api::{PairingControl, PairingCreateCommand};
    use fractonica_application::OperationRepository;
    use fractonica_data_model::{CapabilityAction, SigningKey, SpaceId};
    use fractonica_keystore::IdentityBundle;
    use fractonica_pairing::{
        CapabilityGrantTemplate, JoinerClaim, PairingInvitation, PairingReceipt,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::bootstrap::build_trusted_space_bootstrap;

    const NOW: i64 = 1_720_000_000_000;

    fn identity() -> std::sync::Arc<IdentityBundle> {
        std::sync::Arc::new(
            IdentityBundle::from_keys(
                SigningKey::from_seed([1; 32]),
                SigningKey::from_seed([2; 32]),
                SigningKey::from_seed([3; 32]),
                SpaceId::from_bytes([4; 32]),
            )
            .unwrap(),
        )
    }

    #[test]
    fn full_noise_ceremony_claims_once_and_requires_exact_confirmation() {
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = SqliteStore::open(root.path().join("node.sqlite3")).unwrap();
        let identity = identity();
        let bootstrap = build_trusted_space_bootstrap(&identity, "Test", NOW).unwrap();
        let genesis = bootstrap.genesis.operation_id;
        store.bootstrap_trusted_space(&bootstrap).unwrap();
        let control = NodePairingControl::new(
            DurablePairingStore::new(
                store,
                FilePairingSecretVault::new(root.path().join("pairing-secrets")),
            ),
            std::sync::Arc::clone(&identity),
            genesis,
        );
        let created = control
            .create_invitation(
                PairingCreateCommand {
                    space_id: identity.space_id(),
                    expires_in_ms: 60_000,
                    endpoint_hints: vec![],
                    capability: CapabilityGrantTemplate {
                        actions: vec![CapabilityAction::ReadSpace],
                        schemas: vec![],
                        record_visibilities: vec![],
                        content_roles: vec![],
                        max_resource_byte_length: None,
                        not_before_unix_ms: None,
                        expires_at_unix_ms: None,
                        delegation_depth: 0,
                        label: "phone".into(),
                    },
                },
                NOW,
            )
            .unwrap();
        let invitation = PairingInvitation::decode(&created.qr, NOW).unwrap();
        let node_key = SigningKey::from_seed([5; 32]);
        let actor_key = SigningKey::from_seed([6; 32]);
        let claim = JoinerClaim::sign(invitation.descriptor(), &node_key, &actor_key, [7; 32]);
        let mut initiator = invitation.start_initiator(NOW).unwrap();
        let first = initiator
            .write_message(&claim.canonical_bytes().unwrap())
            .unwrap();
        let result = control
            .handshake(created.session.invitation_id, &first, NOW + 1)
            .unwrap();
        assert_eq!(initiator.read_message(&result.response_frame).unwrap(), b"");
        let mut transport = initiator.finish().unwrap();
        let receipt = PairingReceipt::from_canonical_bytes(
            &transport.read_message(&result.receipt_frame).unwrap(),
        )
        .unwrap();
        receipt
            .verify_for(invitation.descriptor(), &claim, transport.handshake_hash())
            .unwrap();
        assert!(matches!(
            control.handshake(created.session.invitation_id, &first, NOW + 2),
            Err(PairingControlError::Unavailable)
        ));
        assert!(matches!(
            control.confirm(created.session.invitation_id, "0000000000", NOW + 2),
            Err(PairingControlError::ConfirmationMismatch)
        ));
        let confirmed = control
            .confirm(
                created.session.invitation_id,
                transport.confirmation_octal(),
                NOW + 2,
            )
            .unwrap();
        assert_eq!(confirmed.state, PairingState::Completed);
        let grant_id = confirmed.grant_operation_id.expect("durable grant binding");
        let admitted = control
            .durable
            .database()
            .operation(identity.space_id(), grant_id)
            .unwrap()
            .expect("admitted grant");
        let OperationBody::CapabilityGrant { grant } = admitted.operation.body else {
            panic!("pairing completion must admit a capability grant");
        };
        assert_eq!(grant.subject, actor_key.actor_id());
        let replayed = control
            .confirm(
                created.session.invitation_id,
                transport.confirmation_octal(),
                NOW + 3,
            )
            .unwrap();
        assert_eq!(replayed.state, PairingState::Completed);
        assert_eq!(replayed.grant_operation_id, Some(grant_id));
        assert!(
            control
                .durable
                .secrets
                .load(created.session.invitation_id)
                .unwrap()
                .is_none()
        );
    }
}
