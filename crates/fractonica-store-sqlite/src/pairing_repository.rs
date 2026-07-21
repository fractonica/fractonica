use fractonica_data_model::{EntitySchema, OperationBody, OperationEnvelope};
use fractonica_pairing::{InvitationDescriptor, InvitationId, JoinerClaim};
use fractonica_trust::{ActorId, NodeId, OperationId};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use thiserror::Error;

use super::{SqliteStore, StoreError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingLifecycle {
    Created,
    Claimed,
    Confirmed,
    Completed,
    Cancelled,
    Expired,
}

impl PairingLifecycle {
    fn parse(value: &str) -> Result<Self, PairingStoreError> {
        match value {
            "created" => Ok(Self::Created),
            "claimed" => Ok(Self::Claimed),
            "confirmed" => Ok(Self::Confirmed),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            _ => Err(PairingStoreError::Corrupt("unknown lifecycle")),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PairingSession {
    pub invitation_id: InvitationId,
    pub descriptor: InvitationDescriptor,
    pub state: PairingLifecycle,
    pub created_at_unix_ms: i64,
    pub claimed_at_unix_ms: Option<i64>,
    pub confirmed_at_unix_ms: Option<i64>,
    pub completed_at_unix_ms: Option<i64>,
    pub terminal_at_unix_ms: Option<i64>,
    pub claim_digest: Option<[u8; 32]>,
    pub handshake_hash: Option<[u8; 32]>,
    pub joiner_node_id: Option<NodeId>,
    pub subject_actor_id: Option<ActorId>,
    pub grant_operation_id: Option<OperationId>,
    pub planned_grant: Option<OperationEnvelope>,
    pub grant_planned_at_unix_ms: Option<i64>,
    pub peer_token_digest: Option<[u8; 32]>,
}

impl SqliteStore {
    pub fn create_pairing_session(
        &self,
        descriptor: &InvitationDescriptor,
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        if now < 0 || now >= descriptor.expires_at_unix_ms {
            return Err(PairingStoreError::InvalidTime);
        }
        let cbor = descriptor.canonical_bytes()?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO pairing_sessions (invitation_id, descriptor_cbor,
             descriptor_digest, space_id, responder_node_id, expires_at_unix_ms,
             state, created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,'created',?7)",
            params![
                descriptor.invitation_id.as_bytes().as_slice(),
                cbor,
                descriptor.digest().as_slice(),
                descriptor.space_id.to_string(),
                descriptor.responder_node_id.as_bytes().as_slice(),
                descriptor.expires_at_unix_ms,
                now
            ],
        )?;
        let session = load(&connection, descriptor.invitation_id)?
            .ok_or(PairingStoreError::Corrupt("insert disappeared"))?;
        if inserted == 0 && session.descriptor != *descriptor {
            return Err(PairingStoreError::Conflict);
        }
        Ok(session)
    }

    pub fn claim_pairing_session(
        &self,
        descriptor: &InvitationDescriptor,
        claim: &JoinerClaim,
        handshake_hash: [u8; 32],
        peer_token_digest: [u8; 32],
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        claim.verify_for(descriptor)?;
        if now < 0 || handshake_hash == [0; 32] || peer_token_digest == [0; 32] {
            return Err(PairingStoreError::InvalidTime);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            load(&transaction, descriptor.invitation_id)?.ok_or(PairingStoreError::NotFound)?;
        if current.descriptor != *descriptor {
            return Err(PairingStoreError::Conflict);
        }
        if now >= descriptor.expires_at_unix_ms {
            if current.state == PairingLifecycle::Created {
                transaction.execute("UPDATE pairing_sessions SET state='expired', terminal_at_unix_ms=?2 WHERE invitation_id=?1 AND state='created'",
                    params![descriptor.invitation_id.as_bytes().as_slice(), now])?;
                transaction.commit()?;
            }
            return Err(PairingStoreError::Unavailable);
        }
        let changed = transaction.execute(
            "UPDATE pairing_sessions SET state='claimed', claimed_at_unix_ms=?2,
             claim_digest=?3, handshake_hash=?4, joiner_node_id=?5, subject_actor_id=?6
             , peer_token_digest=?7
             , claimed_expires_at_unix_ms=min(expires_at_unix_ms, ?2 + 120000)
             WHERE invitation_id=?1 AND state='created'",
            params![
                descriptor.invitation_id.as_bytes().as_slice(),
                now,
                claim.digest().as_slice(),
                handshake_hash.as_slice(),
                claim.joiner_node_id.as_bytes().as_slice(),
                claim.subject_actor_id.as_bytes().as_slice(),
                peer_token_digest.as_slice()
            ],
        )?;
        if changed != 1 {
            return Err(PairingStoreError::Unavailable);
        }
        let result = load(&transaction, descriptor.invitation_id)?
            .ok_or(PairingStoreError::Corrupt("claim disappeared"))?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn confirm_pairing_session(
        &self,
        id: InvitationId,
        hash: [u8; 32],
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        if now < 0 {
            return Err(PairingStoreError::InvalidTime);
        }
        self.transition(id, |db| {
            db.execute(
                "UPDATE pairing_sessions SET state='confirmed', confirmed_at_unix_ms=?3
             WHERE invitation_id=?1 AND state='claimed' AND handshake_hash=?2",
                params![id.as_bytes().as_slice(), hash.as_slice(), now],
            )
        })
    }

    pub fn complete_pairing_session(
        &self,
        id: InvitationId,
        grant: OperationId,
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        if now < 0 {
            return Err(PairingStoreError::InvalidTime);
        }
        self.transition(id, |db| db.execute(
            "UPDATE pairing_sessions AS session SET state='completed', completed_at_unix_ms=?3,
             terminal_at_unix_ms=?3, grant_operation_id=?2 WHERE invitation_id=?1 AND state='confirmed'
             AND planned_grant_operation_id=?2
             AND EXISTS (SELECT 1 FROM capability_grants AS grant WHERE grant.space_id=session.space_id
             AND grant.grant_operation_id=?2
             AND substr(grant.subject_actor_id, 15)=lower(hex(session.subject_actor_id)))",
            params![id.as_bytes().as_slice(), grant.to_string(), now]))
    }

    pub fn cancel_pairing_session(
        &self,
        id: InvitationId,
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        if now < 0 {
            return Err(PairingStoreError::InvalidTime);
        }
        self.transition(id, |db| {
            db.execute(
                "UPDATE pairing_sessions SET state='cancelled', terminal_at_unix_ms=?2
             WHERE invitation_id=?1 AND state IN ('created','claimed')",
                params![id.as_bytes().as_slice(), now],
            )
        })
    }

    pub fn plan_pairing_grant(
        &self,
        id: InvitationId,
        operation: &OperationEnvelope,
        now: i64,
    ) -> Result<PairingSession, PairingStoreError> {
        operation
            .verify()
            .map_err(fractonica_pairing::PairingError::from)?;
        if now < 0 || operation.schema != EntitySchema::CapabilityGrant {
            return Err(PairingStoreError::InvalidGrantPlan);
        }
        let OperationBody::CapabilityGrant { grant } = &operation.body else {
            return Err(PairingStoreError::InvalidGrantPlan);
        };
        let json = serde_json::to_string(operation)
            .map_err(|_| PairingStoreError::Corrupt("grant serialization failed"))?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let current = load(&connection, id)?.ok_or(PairingStoreError::NotFound)?;
        if !matches!(
            current.state,
            PairingLifecycle::Claimed | PairingLifecycle::Confirmed
        ) || current.descriptor.space_id != operation.space_id
            || current.subject_actor_id != Some(grant.subject)
        {
            return Err(PairingStoreError::InvalidGrantPlan);
        }
        if let Some(existing) = &current.planned_grant {
            return if existing == operation {
                Ok(current)
            } else {
                Err(PairingStoreError::Conflict)
            };
        }
        if connection.execute(
            "UPDATE pairing_sessions SET planned_grant_operation_id=?2,
             planned_grant_json=?3, grant_planned_at_unix_ms=?4
             WHERE invitation_id=?1 AND state IN ('claimed','confirmed')
               AND planned_grant_operation_id IS NULL",
            params![
                id.as_bytes().as_slice(),
                operation.operation_id.to_string(),
                json,
                now
            ],
        )? != 1
        {
            return Err(PairingStoreError::Unavailable);
        }
        load(&connection, id)?.ok_or(PairingStoreError::Corrupt("grant plan disappeared"))
    }

    pub fn pairing_session(
        &self,
        id: InvitationId,
    ) -> Result<Option<PairingSession>, PairingStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        load(&connection, id)
    }

    pub fn active_pairing_sessions(&self) -> Result<Vec<PairingSession>, PairingStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT invitation_id, descriptor_cbor, state, created_at_unix_ms,
             claimed_at_unix_ms, confirmed_at_unix_ms, completed_at_unix_ms, terminal_at_unix_ms,
             claim_digest, handshake_hash, joiner_node_id, subject_actor_id, grant_operation_id,
             planned_grant_json, grant_planned_at_unix_ms, peer_token_digest
             FROM pairing_sessions WHERE state IN ('created','claimed','confirmed')
             ORDER BY created_at_unix_ms, invitation_id LIMIT 1025",
        )?;
        let sessions = statement
            .query_map([], decode)?
            .collect::<Result<Vec<_>, _>>()?;
        if sessions.len() > 1_024 {
            return Err(PairingStoreError::Corrupt("too many active pairings"));
        }
        Ok(sessions)
    }

    pub fn expire_pairing_sessions(&self, now: i64) -> Result<usize, PairingStoreError> {
        if now < 0 {
            return Err(PairingStoreError::InvalidTime);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(connection.execute(
            "UPDATE pairing_sessions SET state='expired', terminal_at_unix_ms=?1
            WHERE (state='created' AND expires_at_unix_ms<=?1)
               OR (state='claimed' AND claimed_expires_at_unix_ms<=?1)",
            params![now],
        )?)
    }

    fn transition(
        &self,
        id: InvitationId,
        operation: impl FnOnce(&rusqlite::Connection) -> Result<usize, rusqlite::Error>,
    ) -> Result<PairingSession, PairingStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        if operation(&connection)? != 1 {
            return Err(PairingStoreError::Unavailable);
        }
        load(&connection, id)?.ok_or(PairingStoreError::Corrupt("transition disappeared"))
    }
}

fn load(
    db: &rusqlite::Connection,
    id: InvitationId,
) -> Result<Option<PairingSession>, PairingStoreError> {
    db.query_row(
        "SELECT invitation_id, descriptor_cbor, state, created_at_unix_ms,
        claimed_at_unix_ms, confirmed_at_unix_ms, completed_at_unix_ms, terminal_at_unix_ms,
        claim_digest, handshake_hash, joiner_node_id, subject_actor_id, grant_operation_id,
        planned_grant_json, grant_planned_at_unix_ms, peer_token_digest
        FROM pairing_sessions WHERE invitation_id=?1",
        params![id.as_bytes().as_slice()],
        decode,
    )
    .optional()
    .map_err(PairingStoreError::from)
}

fn decode(row: &Row<'_>) -> Result<PairingSession, rusqlite::Error> {
    let invitation: Vec<u8> = row.get(0)?;
    let descriptor: Vec<u8> = row.get(1)?;
    let state: String = row.get(2)?;
    let claim: Option<Vec<u8>> = row.get(8)?;
    let handshake: Option<Vec<u8>> = row.get(9)?;
    let node: Option<Vec<u8>> = row.get(10)?;
    let actor: Option<Vec<u8>> = row.get(11)?;
    let grant: Option<String> = row.get(12)?;
    let planned_grant: Option<String> = row.get(13)?;
    Ok(PairingSession {
        invitation_id: InvitationId::from_bytes(fixed(invitation)?),
        descriptor: InvitationDescriptor::from_canonical_bytes(&descriptor).map_err(corrupt_sql)?,
        state: PairingLifecycle::parse(&state).map_err(corrupt_sql)?,
        created_at_unix_ms: row.get(3)?,
        claimed_at_unix_ms: row.get(4)?,
        confirmed_at_unix_ms: row.get(5)?,
        completed_at_unix_ms: row.get(6)?,
        terminal_at_unix_ms: row.get(7)?,
        claim_digest: claim.map(fixed).transpose()?,
        handshake_hash: handshake.map(fixed).transpose()?,
        joiner_node_id: node.map(fixed).transpose()?.map(NodeId::from_bytes),
        subject_actor_id: actor.map(fixed).transpose()?.map(ActorId::from_bytes),
        grant_operation_id: grant
            .map(|value| OperationId::parse(&value).map_err(corrupt_sql))
            .transpose()?,
        planned_grant: planned_grant
            .map(|value| serde_json::from_str(&value).map_err(corrupt_sql))
            .transpose()?,
        grant_planned_at_unix_ms: row.get(14)?,
        peer_token_digest: row.get::<_, Option<Vec<u8>>>(15)?.map(fixed).transpose()?,
    })
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    bytes
        .try_into()
        .map_err(|_| corrupt_sql("invalid pairing blob length"))
}

fn corrupt_sql(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

#[derive(Debug, Error)]
pub enum PairingStoreError {
    #[error("pairing session was not found")]
    NotFound,
    #[error("pairing invitation is unavailable")]
    Unavailable,
    #[error("pairing session conflicts with durable state")]
    Conflict,
    #[error("pairing transition time is invalid")]
    InvalidTime,
    #[error("pairing store is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("pairing capability grant plan is invalid")]
    InvalidGrantPlan,
    #[error(transparent)]
    Protocol(#[from] fractonica_pairing::PairingError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use fractonica_data_model::CapabilityAction;
    use fractonica_pairing::{
        CapabilityGrantTemplate, InvitationMaterial, InvitationParameters, PairingInvitation,
    };
    use fractonica_trust::{SigningKey, SpaceId};
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    const NOW: i64 = 1_000;

    fn fixture(store: &SqliteStore) -> (fractonica_pairing::IssuedInvitation, JoinerClaim) {
        let space = SpaceId::from_bytes([2; 32]);
        seed_space(store, space);
        let issued = PairingInvitation::issue_with_material(
            &SigningKey::from_seed([1; 32]),
            InvitationParameters {
                space_id: space,
                genesis_operation_id: OperationId::from_bytes([3; 32]),
                now_unix_ms: NOW,
                expires_at_unix_ms: NOW + 60_000,
                endpoint_hints: vec![],
                capability: CapabilityGrantTemplate {
                    actions: vec![CapabilityAction::ReadSpace],
                    schemas: vec![],
                    visibilities: vec![],
                    content_roles: vec![],
                    max_resource_byte_length: None,
                    not_before_unix_ms: None,
                    expires_at_unix_ms: None,
                    delegation_depth: 0,
                    label: "peer".into(),
                },
            },
            InvitationMaterial {
                invitation_id: [4; 16],
                one_time_secret: [5; 32],
                noise_private: [6; 32],
            },
        )
        .unwrap();
        let claim = JoinerClaim::sign(
            issued.invitation.descriptor(),
            &SigningKey::from_seed([7; 32]),
            &SigningKey::from_seed([8; 32]),
            [9; 32],
        );
        (issued, claim)
    }

    fn seed_space(store: &SqliteStore, space: SpaceId) {
        let db = store.connection.lock().unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        db.execute(
            "INSERT OR IGNORE INTO spaces (space_id, genesis_operation_id, controller_actor_id,
            initial_grant_operation_id, local_writer_actor_id, display_name, created_at_unix_ms)
            VALUES (?1,?2,?3,?4,?5,'test',0)",
            params![
                space.to_string(),
                OperationId::from_bytes([3; 32]).to_string(),
                SigningKey::from_seed([10; 32]).actor_id().to_string(),
                OperationId::from_bytes([11; 32]).to_string(),
                SigningKey::from_seed([12; 32]).actor_id().to_string()
            ],
        )
        .unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    }

    #[test]
    fn one_claim_wins_and_confirmed_state_does_not_reopen() {
        let store = SqliteStore::open_in_memory().unwrap();
        let (issued, claim) = fixture(&store);
        let descriptor = issued.invitation.descriptor();
        assert_eq!(
            store.create_pairing_session(descriptor, NOW).unwrap().state,
            PairingLifecycle::Created
        );
        assert_eq!(
            store.create_pairing_session(descriptor, NOW).unwrap().state,
            PairingLifecycle::Created
        );
        let barrier = Arc::new(Barrier::new(3));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let descriptor = descriptor.clone();
                let claim = claim.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.claim_pairing_session(&descriptor, &claim, [13; 32], [14; 32], NOW + 1)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|value| matches!(value, Err(PairingStoreError::Unavailable)))
                .count(),
            1
        );
        assert_eq!(
            store
                .confirm_pairing_session(descriptor.invitation_id, [13; 32], NOW + 2)
                .unwrap()
                .state,
            PairingLifecycle::Confirmed
        );
        assert!(matches!(
            store.cancel_pairing_session(descriptor.invitation_id, NOW + 3),
            Err(PairingStoreError::Unavailable)
        ));
    }

    #[test]
    fn claim_and_expiry_survive_restart() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("node.sqlite3");
        let store = SqliteStore::open(&path).unwrap();
        let (issued, claim) = fixture(&store);
        let descriptor = issued.invitation.descriptor().clone();
        store.create_pairing_session(&descriptor, NOW).unwrap();
        store
            .claim_pairing_session(&descriptor, &claim, [15; 32], [16; 32], NOW + 1)
            .unwrap();
        drop(store);
        let restarted = SqliteStore::open(&path).unwrap();
        assert_eq!(
            restarted
                .pairing_session(descriptor.invitation_id)
                .unwrap()
                .unwrap()
                .state,
            PairingLifecycle::Claimed
        );
        assert_eq!(restarted.expire_pairing_sessions(NOW + 60_000).unwrap(), 1);
        assert_eq!(
            restarted
                .pairing_session(descriptor.invitation_id)
                .unwrap()
                .unwrap()
                .state,
            PairingLifecycle::Expired
        );
        assert!(matches!(
            restarted.claim_pairing_session(&descriptor, &claim, [15; 32], [16; 32], NOW + 60_001,),
            Err(PairingStoreError::Unavailable)
        ));
    }
}
