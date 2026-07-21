#![forbid(unsafe_code)]
//! Durable local operation storage and per-peer delivery queues.
//!
//! A successful [`ClientSqliteStore::commit_local`] is the client write
//! boundary. Network delivery happens later through bounded, expiring leases.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use fractonica_application::{TrustedSpaceBootstrapRequest, validate_trusted_space_bootstrap};
use fractonica_content::{ContentDescriptor, ContentId, ResourceRef};
use fractonica_data_model::{
    ActorId, EntityId, EntitySchema, MAX_CAUSAL_PARENTS, NodeId, OperationBody, OperationEnvelope,
    OperationId, ProtectedDocument, RecordDocument, SpaceId, Visibility,
};
use fractonica_peer::PeerSessionId;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use thiserror::Error;
use uuid::Uuid;

pub const CLIENT_SCHEMA_VERSION: u32 = 5;
pub const MAX_OUTBOX_BATCH: usize = 100;
pub const MAX_ERROR_BYTES: usize = 2_048;
pub const MAX_ENDPOINT_BYTES: usize = 2_048;
pub const MAX_RESOURCE_TRANSFER_BATCH: usize = 100;
/// Maximum Unicode scalars stored for a record feed preview.
pub const MAX_RECORD_PREVIEW_TEXT_CHARS: usize = 192;

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_client_store.sql"),
    include_str!("../migrations/0002_local_installation.sql"),
    include_str!("../migrations/0003_record_previews.sql"),
    include_str!("../migrations/0004_peer_delivery_policy.sql"),
    include_str!("../migrations/0005_peer_transport_credentials.sql"),
];

#[derive(Clone)]
pub struct ClientSqliteStore {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitSource {
    Local,
    Remote,
    Peer(NodeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitResult {
    pub local_sequence: u64,
    pub operation_id: OperationId,
    pub replayed: bool,
    pub queued_peers: u64,
}

/// Durable public binding between a standalone client's protected identity
/// and the exact authorization anchors in its local operation log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientInstallationBinding {
    pub node_id: NodeId,
    pub space_id: SpaceId,
    pub controller_actor_id: ActorId,
    pub local_writer_actor_id: ActorId,
    pub genesis_operation_id: OperationId,
    pub initial_grant_operation_id: OperationId,
    pub display_name: String,
    pub created_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientInstallation {
    /// No standalone lifecycle has claimed this otherwise-empty client store.
    Unbound,
    /// The database marker is durable; protected identity creation may safely
    /// be started or resumed.
    Initializing,
    /// Identity and exact signed space anchors were committed as one unit.
    Established(Box<ClientInstallationBinding>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstablishLocalSpaceResult {
    pub binding: ClientInstallationBinding,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    pub peer_id: NodeId,
    pub endpoint: String,
    pub enabled: bool,
    /// Whether local operations and media may be queued for this peer.
    pub push_enabled: bool,
    /// Whether media downloads are authorized for this peer.
    pub content_read_enabled: bool,
    /// Opaque pairing-scoped authorization header payload. Supervisor peers
    /// use their separately protected bearer-token map instead.
    pub peer_transport_credential: Option<String>,
    pub added_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSpaceConfig {
    pub peer_id: NodeId,
    pub space_id: SpaceId,
    pub read_mode: PeerReadMode,
    pub start_after: u64,
    pub next_pull_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveWorkspace {
    pub space_id: SpaceId,
    pub authorization_operation_id: OperationId,
    pub peer_id: Option<NodeId>,
    pub activated_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerReadMode {
    SupervisorBearer,
    Paired {
        session_id: PeerSessionId,
        grant_operation_id: OperationId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncTarget {
    pub peer_id: NodeId,
    pub endpoint: String,
    pub space_id: SpaceId,
    pub read_mode: PeerReadMode,
    pub after: u64,
    pub pull_failure_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeliveryLeaseId(Uuid);

impl DeliveryLeaseId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DeliveryLeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeliveryLeaseId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryItem {
    pub operation: OperationEnvelope,
    pub attempt_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResourceTransferLeaseId(Uuid);

impl ResourceTransferLeaseId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ResourceTransferLeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ResourceTransferLeaseId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceTransferDirection {
    Upload,
    Download,
}

impl ResourceTransferDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceTransferItem {
    pub peer: PeerConfig,
    pub resource: ResourceRef,
    pub direction: ResourceTransferDirection,
    pub attempt_count: u32,
    pub remote_upload_url: Option<String>,
    pub transferred_bytes: u64,
}

#[derive(Clone, Copy)]
struct LeasedResourceTransfer {
    peer_id: NodeId,
    content_id: ContentId,
    direction: ResourceTransferDirection,
    lease_id: ResourceTransferLeaseId,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceSyncCounts {
    pub waiting_uploads: u64,
    pub pending_uploads: u64,
    pub pending_downloads: u64,
    pub leased_transfers: u64,
    pub completed_transfers: u64,
    pub rejected_transfers: u64,
    pub transferred_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalEntity {
    pub space_id: SpaceId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub operation_count: u64,
    pub heads: Vec<OperationEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEntitySummary {
    pub operation_id: OperationId,
    pub entity_id: EntityId,
    pub schema: EntitySchema,
    pub visibility: Visibility,
    pub conflicted: bool,
    pub tombstone: bool,
    pub start_at_unix_ms: Option<i64>,
    pub end_at_unix_ms: Option<i64>,
    pub sort_text: Option<String>,
    pub resource_count: u64,
    pub media_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalRecordSummary {
    pub summary: LocalEntitySummary,
    /// Public record content is directly readable. Private content remains an
    /// opaque encrypted envelope until platform key management is connected.
    pub document: Option<RecordDocument>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRecordPreview {
    pub summary: LocalEntitySummary,
    /// Bounded public display fields. Private content is never projected.
    pub emoji: Option<String>,
    pub text_preview: Option<String>,
    pub preview_truncated: bool,
}

/// One current record head read in bounded local-sequence order for an
/// explicit workspace import. The complete protected payload remains native;
/// private envelopes are never projected through JavaScript.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalRecordImport {
    pub local_sequence: u64,
    pub entity_id: EntityId,
    pub payload: ProtectedDocument<RecordDocument>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxCounts {
    pub pending: u64,
    pub leased: u64,
    pub acknowledged: u64,
    pub rejected: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncCounts {
    pub enabled_peers: u64,
    pub spaces: u64,
    pub pending_deliveries: u64,
    pub leased_deliveries: u64,
    pub rejected_deliveries: u64,
    pub due_pulls: u64,
    pub resources: ResourceSyncCounts,
}

#[derive(Debug, Error)]
pub enum ClientStoreError {
    #[error("failed to prepare the client database: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite client store failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("signed operation is invalid: {0}")]
    InvalidOperation(String),
    #[error("client database uses schema {found}, but this binary supports {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("client database migration {expected} completed with schema {found}")]
    MigrationVersionMismatch { expected: u32, found: u32 },
    #[error("client database lock was poisoned")]
    LockPoisoned,
    #[error("stored client data is corrupt: {0}")]
    Corrupt(String),
    #[error("operation {0} conflicts with already stored bytes")]
    OperationConflict(OperationId),
    #[error("operation parent {0} is missing locally")]
    MissingParent(OperationId),
    #[error("authorization operation {0} is missing locally")]
    MissingAuthorization(OperationId),
    #[error("operation parent {0} belongs to another entity or schema")]
    ParentMismatch(OperationId),
    #[error("entity already exists and a new root operation is not allowed")]
    EntityAlreadyExists,
    #[error("an entity cannot begin with a tombstone")]
    InitialTombstone,
    #[error("operation would exceed the {MAX_CAUSAL_PARENTS}-head limit")]
    TooManyHeads,
    #[error("timestamp must be nonnegative")]
    NegativeTimestamp,
    #[error("peer endpoint must be nonempty and no larger than {MAX_ENDPOINT_BYTES} bytes")]
    InvalidPeerEndpoint,
    #[error("peer {0} is not configured")]
    UnknownPeer(NodeId),
    #[error("outbox limit must be between 1 and {MAX_OUTBOX_BATCH}")]
    InvalidOutboxLimit,
    #[error("lease duration must be positive")]
    InvalidLeaseDuration,
    #[error("delivery item is not owned by the supplied active lease")]
    LeaseMismatch,
    #[error("resource transfer is not owned by the supplied active lease")]
    ResourceLeaseMismatch,
    #[error("resource transfer limit must be between 1 and {MAX_RESOURCE_TRANSFER_BATCH}")]
    InvalidResourceTransferLimit,
    #[error("resource descriptor conflicts with an existing content identity")]
    ResourceDescriptorConflict,
    #[error("resource transfer progress is invalid")]
    InvalidResourceProgress,
    #[error("delivery error must be no larger than {MAX_ERROR_BYTES} bytes")]
    DeliveryErrorTooLong,
    #[error("entity query limit must be between 1 and 200")]
    InvalidEntityLimit,
    #[error("sync target limit must be between 1 and 100")]
    InvalidSyncTargetLimit,
    #[error("pull cursor does not match the worker's observed cursor")]
    PullCursorMismatch,
    #[error("pull cursor cannot move backwards or exceed signed 64-bit storage")]
    InvalidPullCursor,
    #[error("trusted local-space bootstrap is invalid: {0}")]
    InvalidBootstrap(String),
    #[error("standalone initialization requires an otherwise-empty client operation log")]
    UntrackedInstallationOperations,
    #[error("standalone installation is not in its initializing phase")]
    InstallationNotInitializing,
    #[error("standalone installation binding or anchor replay differs from established state")]
    InstallationConflict,
}

impl ClientSqliteStore {
    pub fn active_workspace(&self) -> Result<Option<ActiveWorkspace>, ClientStoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT space_id, authorization_operation_id, peer_id, activated_at_unix_ms
                 FROM client_active_workspace WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|row| {
                Ok(ActiveWorkspace {
                    space_id: row
                        .0
                        .parse()
                        .map_err(|error| corrupt(format!("invalid active space ID: {error}")))?,
                    authorization_operation_id: OperationId::parse(&row.1)
                        .map_err(|error| corrupt(error.to_string()))?,
                    peer_id: row
                        .2
                        .map(|value| {
                            NodeId::parse(&value).map_err(|error| corrupt(error.to_string()))
                        })
                        .transpose()?,
                    activated_at_unix_ms: row.3,
                })
            })
            .transpose()
    }

    pub fn set_active_workspace(&self, workspace: ActiveWorkspace) -> Result<(), ClientStoreError> {
        if workspace.activated_at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO client_active_workspace (
                singleton, space_id, authorization_operation_id, peer_id, activated_at_unix_ms
             ) VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                space_id=excluded.space_id,
                authorization_operation_id=excluded.authorization_operation_id,
                peer_id=excluded.peer_id,
                activated_at_unix_ms=excluded.activated_at_unix_ms",
            params![
                workspace.space_id.to_string(),
                workspace.authorization_operation_id.to_string(),
                workspace.peer_id.map(|value| value.to_string()),
                workspace.activated_at_unix_ms,
            ],
        )?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ClientStoreError> {
        let requested_path = path.as_ref().to_path_buf();
        let open_path = nofollow_database_path(&requested_path)?;
        let mut connection = Connection::open_with_flags(
            &open_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&connection, true)?;
        migrate(&mut connection)?;
        secure_sqlite_files(&open_path)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(requested_path),
        })
    }

    pub fn open_in_memory() -> Result<Self, ClientStoreError> {
        let mut connection = Connection::open_in_memory()?;
        configure(&connection, false)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(PathBuf::from(":memory:")),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns the standalone identity/database binding without changing it.
    pub fn installation(&self) -> Result<ClientInstallation, ClientStoreError> {
        let connection = self.lock()?;
        load_installation(&connection)
    }

    /// Durably announces standalone initialization before protected identity
    /// creation is allowed to begin.
    ///
    /// Replaying this method while already initializing is harmless. An
    /// unbound database containing operations is never silently adopted.
    pub fn begin_local_installation(&self) -> Result<ClientInstallation, ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let installation = load_installation(&transaction)?;
        match installation {
            ClientInstallation::Unbound => {
                if operation_count(&transaction)? != 0 {
                    return Err(ClientStoreError::UntrackedInstallationOperations);
                }
                transaction.execute(
                    "INSERT INTO client_local_installation (singleton, phase)
                     VALUES (1, 'initializing')",
                    [],
                )?;
                transaction.commit()?;
                Ok(ClientInstallation::Initializing)
            }
            ClientInstallation::Initializing => {
                transaction.commit()?;
                Ok(ClientInstallation::Initializing)
            }
            established @ ClientInstallation::Established(_) => {
                transaction.commit()?;
                Ok(established)
            }
        }
    }

    /// Atomically commits a standalone client's two trust anchors and the
    /// public identity binding that makes future startup fail closed.
    ///
    /// A crash cannot expose only one newly admitted anchor because both
    /// anchors and the binding share this transaction. The initializing phase
    /// is valid only while the operation log remains empty.
    pub fn establish_local_space(
        &self,
        node_id: NodeId,
        request: &TrustedSpaceBootstrapRequest,
    ) -> Result<EstablishLocalSpaceResult, ClientStoreError> {
        validate_trusted_space_bootstrap(request)
            .map_err(|error| ClientStoreError::InvalidBootstrap(error.to_string()))?;
        let binding = installation_binding(node_id, request)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match load_installation(&transaction)? {
            ClientInstallation::Unbound => {
                return Err(ClientStoreError::InstallationNotInitializing);
            }
            ClientInstallation::Established(existing) => {
                if existing.as_ref() != &binding
                    || !operation_matches(&transaction, &request.genesis)?
                    || !operation_matches(&transaction, &request.initial_grant)?
                {
                    return Err(ClientStoreError::InstallationConflict);
                }
                transaction.commit()?;
                return Ok(EstablishLocalSpaceResult {
                    binding: *existing,
                    replayed: true,
                });
            }
            ClientInstallation::Initializing => {}
        }

        if operation_count(&transaction)? != 0 {
            return Err(ClientStoreError::UntrackedInstallationOperations);
        }
        let genesis = commit_transaction(
            &transaction,
            &request.genesis,
            request.received_at_unix_ms,
            CommitSource::Remote,
        )?;
        let grant = commit_transaction(
            &transaction,
            &request.initial_grant,
            request.received_at_unix_ms,
            CommitSource::Remote,
        )?;
        let changed = transaction.execute(
            "UPDATE client_local_installation SET
                phase = 'established', node_id = ?1, space_id = ?2,
                controller_actor_id = ?3, local_writer_actor_id = ?4,
                genesis_operation_id = ?5, initial_grant_operation_id = ?6,
                display_name = ?7, created_at_unix_ms = ?8
             WHERE singleton = 1 AND phase = 'initializing'",
            params![
                binding.node_id.to_string(),
                binding.space_id.to_string(),
                binding.controller_actor_id.to_string(),
                binding.local_writer_actor_id.to_string(),
                binding.genesis_operation_id.to_string(),
                binding.initial_grant_operation_id.to_string(),
                binding.display_name,
                binding.created_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::InstallationNotInitializing);
        }
        transaction.commit()?;
        Ok(EstablishLocalSpaceResult {
            binding,
            replayed: genesis.replayed || grant.replayed,
        })
    }

    /// Reads one exact locally stored signed operation by its digest identity.
    pub fn operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<OperationEnvelope>, ClientStoreError> {
        let connection = self.lock()?;
        load_operation_row(&connection, operation_id)
            .map(|value| value.map(|(_, operation)| operation))
    }

    pub fn commit_local(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(operation, stored_at_unix_ms, CommitSource::Local)
    }

    pub fn commit_remote(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(operation, stored_at_unix_ms, CommitSource::Remote)
    }

    /// Stores an operation received from one configured peer and queues it for
    /// every other enabled peer. The source is recorded as acknowledged.
    pub fn commit_from_peer(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
        source_peer: NodeId,
    ) -> Result<CommitResult, ClientStoreError> {
        self.commit(
            operation,
            stored_at_unix_ms,
            CommitSource::Peer(source_peer),
        )
    }

    pub fn commit(
        &self,
        operation: &OperationEnvelope,
        stored_at_unix_ms: i64,
        source: CommitSource,
    ) -> Result<CommitResult, ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = commit_transaction(&transaction, operation, stored_at_unix_ms, source)?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn upsert_peer(&self, peer: &PeerConfig) -> Result<(), ClientStoreError> {
        validate_peer(peer)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO client_peers (
                peer_id, endpoint, enabled, push_enabled, content_read_enabled,
                peer_transport_credential, added_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id) DO UPDATE SET endpoint = excluded.endpoint,
                enabled = excluded.enabled, push_enabled = excluded.push_enabled,
                content_read_enabled = excluded.content_read_enabled,
                peer_transport_credential = excluded.peer_transport_credential",
            params![
                peer.peer_id.to_string(),
                peer.endpoint,
                i64::from(peer.enabled),
                i64::from(peer.push_enabled),
                i64::from(peer.content_read_enabled),
                peer.peer_transport_credential,
                peer.added_at_unix_ms,
            ],
        )?;
        if peer.enabled && peer.push_enabled {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT ?1, operation_id, 'pending', ?2 FROM client_operations
                   WHERE schema_id IN ('record', 'event', 'tag', 'profile')
                     AND ((SELECT peer_transport_credential FROM client_peers WHERE peer_id=?1) IS NULL
                       OR EXISTS (
                         SELECT 1 FROM client_peer_spaces space
                          WHERE space.peer_id=?1
                            AND space.space_id=client_operations.space_id
                       ))",
                params![peer.peer_id.to_string(), peer.added_at_unix_ms],
            )?;
            queue_known_resources_for_peer(&transaction, peer.peer_id, peer.added_at_unix_ms)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn peer(&self, peer_id: NodeId) -> Result<Option<PeerConfig>, ClientStoreError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT endpoint, enabled, push_enabled, content_read_enabled,
                        peer_transport_credential, added_at_unix_ms
                   FROM client_peers WHERE peer_id = ?1",
                params![peer_id.to_string()],
                |row| {
                    Ok(PeerConfig {
                        peer_id,
                        endpoint: row.get(0)?,
                        enabled: row.get(1)?,
                        push_enabled: row.get(2)?,
                        content_read_enabled: row.get(3)?,
                        peer_transport_credential: row.get(4)?,
                        added_at_unix_ms: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_peer_enabled(&self, peer_id: NodeId, enabled: bool) -> Result<(), ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE client_peers SET enabled = ?2 WHERE peer_id = ?1",
            params![peer_id.to_string(), i64::from(enabled)],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::UnknownPeer(peer_id));
        }
        let push_enabled = transaction.query_row(
            "SELECT push_enabled FROM client_peers WHERE peer_id = ?1",
            params![peer_id.to_string()],
            |row| row.get::<_, bool>(0),
        )?;
        if enabled && push_enabled {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT ?1, operation_id, 'pending', stored_at_unix_ms
                   FROM client_operations
                  WHERE ((SELECT peer_transport_credential FROM client_peers WHERE peer_id=?1) IS NULL
                      OR EXISTS (
                        SELECT 1 FROM client_peer_spaces space
                         WHERE space.peer_id=?1
                           AND space.space_id=client_operations.space_id
                      ))",
                params![peer_id.to_string()],
            )?;
            queue_known_resources_for_peer(&transaction, peer_id, 0)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn enabled_peers(&self, limit: usize) -> Result<Vec<PeerConfig>, ClientStoreError> {
        if !(1..=100).contains(&limit) {
            return Err(ClientStoreError::InvalidSyncTargetLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT peer_id, endpoint, enabled, push_enabled, content_read_enabled,
                    peer_transport_credential, added_at_unix_ms
             FROM client_peers WHERE enabled = 1 ORDER BY peer_id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit_i64(limit)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        rows.map(|row| {
            let row = row?;
            Ok(PeerConfig {
                peer_id: row
                    .0
                    .parse()
                    .map_err(|error| corrupt(format!("invalid peer ID: {error}")))?,
                endpoint: row.1,
                enabled: row.2,
                push_enabled: row.3,
                content_read_enabled: row.4,
                peer_transport_credential: row.5,
                added_at_unix_ms: row.6,
            })
        })
        .collect()
    }

    pub fn configure_peer_space(&self, config: &PeerSpaceConfig) -> Result<(), ClientStoreError> {
        if config.next_pull_at_unix_ms < 0 || config.start_after > i64::MAX as u64 {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let configured = transaction
            .query_row(
                "SELECT 1 FROM client_peers WHERE peer_id = ?1",
                params![config.peer_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !configured {
            return Err(ClientStoreError::UnknownPeer(config.peer_id));
        }
        let (read_mode, session_id, grant_operation_id) = match &config.read_mode {
            PeerReadMode::SupervisorBearer => ("supervisor_bearer", None, None),
            PeerReadMode::Paired {
                session_id,
                grant_operation_id,
            } => (
                "paired",
                Some(session_id.to_string()),
                Some(grant_operation_id.to_string()),
            ),
        };
        transaction.execute(
            "INSERT INTO client_peer_spaces (
                peer_id, space_id, read_mode, session_id, grant_operation_id,
                pull_after, next_pull_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id, space_id) DO UPDATE SET
                read_mode = excluded.read_mode,
                session_id = excluded.session_id,
                grant_operation_id = excluded.grant_operation_id",
            params![
                config.peer_id.to_string(),
                config.space_id.to_string(),
                read_mode,
                session_id,
                grant_operation_id,
                i64::try_from(config.start_after)
                    .map_err(|_| ClientStoreError::InvalidPullCursor)?,
                config.next_pull_at_unix_ms,
            ],
        )?;
        let push_enabled = transaction.query_row(
            "SELECT enabled AND push_enabled FROM client_peers WHERE peer_id=?1",
            params![config.peer_id.to_string()],
            |row| row.get::<_, bool>(0),
        )?;
        if push_enabled {
            let schema_scope = match &config.read_mode {
                PeerReadMode::SupervisorBearer => {
                    "AND schema_id IN ('record','event','tag','profile')"
                }
                PeerReadMode::Paired { .. } => "",
            };
            transaction.execute(
                &format!(
                    "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT ?1, operation_id, 'pending', ?3 FROM client_operations
                   WHERE space_id=?2 {schema_scope}"
                ),
                params![
                    config.peer_id.to_string(),
                    config.space_id.to_string(),
                    config.next_pull_at_unix_ms,
                ],
            )?;
            queue_known_resources_for_peer_space(
                &transaction,
                config.peer_id,
                config.space_id,
                config.next_pull_at_unix_ms,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reopens durable work that did not receive an acknowledgement from a
    /// peer after a new authenticated session has been installed.
    ///
    /// A rejection is terminal only for the credential/session that produced
    /// it. Re-pairing may replace a revoked credential, so leaving those rows
    /// rejected would permanently strand valid offline operations and media.
    pub fn requeue_unacknowledged_peer_space(
        &self,
        peer_id: NodeId,
        space_id: SpaceId,
        now_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let configured = transaction
            .query_row(
                "SELECT 1 FROM client_peer_spaces WHERE peer_id=?1 AND space_id=?2",
                params![peer_id.to_string(), space_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !configured {
            return Err(ClientStoreError::UnknownPeer(peer_id));
        }

        transaction.execute(
            "INSERT OR IGNORE INTO client_deliveries (
                peer_id, operation_id, state, next_attempt_at_unix_ms
             ) SELECT ?1, operation_id, 'pending', ?3 FROM client_operations
                WHERE space_id=?2
                  AND schema_id IN ('record','event','tag','profile')",
            params![peer_id.to_string(), space_id.to_string(), now_unix_ms,],
        )?;
        transaction.execute(
            "UPDATE client_deliveries SET
                state='pending', attempt_count=0, next_attempt_at_unix_ms=?3,
                lease_id=NULL, lease_expires_at_unix_ms=NULL,
                acknowledged_at_unix_ms=NULL, last_error=NULL
             WHERE peer_id=?1 AND state<>'acknowledged' AND operation_id IN (
                SELECT operation_id FROM client_operations WHERE space_id=?2
             )",
            params![peer_id.to_string(), space_id.to_string(), now_unix_ms,],
        )?;

        queue_known_resources_for_peer_space(&transaction, peer_id, space_id, now_unix_ms)?;
        transaction.execute(
            "UPDATE client_resource_transfers SET
                state=CASE
                    WHEN (SELECT locally_available FROM client_resources resource
                          WHERE resource.content_id=client_resource_transfers.content_id)=1
                    THEN 'pending' ELSE 'waiting_local' END,
                attempt_count=0, next_attempt_at_unix_ms=?3,
                lease_id=NULL, lease_expires_at_unix_ms=NULL,
                remote_upload_url=NULL, transferred_bytes=0,
                completed_at_unix_ms=NULL, last_error=NULL
             WHERE peer_id=?1 AND direction='upload' AND state<>'complete'
               AND content_id IN (
                 SELECT link.content_id FROM client_operation_resources link
                 JOIN client_operations operation USING(operation_id)
                 WHERE operation.space_id=?2
               )",
            params![peer_id.to_string(), space_id.to_string(), now_unix_ms,],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn due_sync_targets(
        &self,
        now_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<SyncTarget>, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if !(1..=100).contains(&limit) {
            return Err(ClientStoreError::InvalidSyncTargetLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT p.peer_id, p.endpoint, s.space_id, s.read_mode, s.session_id,
                    s.grant_operation_id, s.pull_after, s.pull_failure_count
             FROM client_peer_spaces s
             JOIN client_peers p ON p.peer_id = s.peer_id
             WHERE p.enabled = 1 AND s.next_pull_at_unix_ms <= ?1
             ORDER BY s.next_pull_at_unix_ms, p.peer_id, s.space_id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_unix_ms, limit_i64(limit)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?;
        rows.map(|row| {
            let row = row?;
            Ok(SyncTarget {
                peer_id: row
                    .0
                    .parse()
                    .map_err(|error| corrupt(format!("invalid peer ID: {error}")))?,
                endpoint: row.1,
                space_id: row
                    .2
                    .parse()
                    .map_err(|error| corrupt(format!("invalid space ID: {error}")))?,
                read_mode: parse_peer_read_mode(&row.3, row.4.as_deref(), row.5.as_deref())?,
                after: nonnegative_u64(row.6)?,
                pull_failure_count: u32::try_from(row.7)
                    .map_err(|_| corrupt("pull failure count overflow"))?,
            })
        })
        .collect()
    }

    pub fn advance_pull_cursor(
        &self,
        peer_id: NodeId,
        space_id: SpaceId,
        expected_after: u64,
        next_after: u64,
        pulled_at_unix_ms: i64,
        next_pull_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        if pulled_at_unix_ms < 0
            || next_pull_at_unix_ms < 0
            || expected_after > i64::MAX as u64
            || next_after > i64::MAX as u64
            || next_after < expected_after
        {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_peer_spaces SET
                pull_after = ?4, next_pull_at_unix_ms = ?6,
                pull_failure_count = 0, last_pull_error = NULL,
                last_pull_at_unix_ms = ?5
             WHERE peer_id = ?1 AND space_id = ?2 AND pull_after = ?3",
            params![
                peer_id.to_string(),
                space_id.to_string(),
                i64::try_from(expected_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                i64::try_from(next_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                pulled_at_unix_ms,
                next_pull_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::PullCursorMismatch);
        }
        Ok(())
    }

    pub fn record_pull_failure(
        &self,
        peer_id: NodeId,
        space_id: SpaceId,
        expected_after: u64,
        next_pull_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        if next_pull_at_unix_ms < 0 || expected_after > i64::MAX as u64 {
            return Err(ClientStoreError::InvalidPullCursor);
        }
        if error.len() > MAX_ERROR_BYTES {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_peer_spaces SET
                next_pull_at_unix_ms = ?4,
                pull_failure_count = pull_failure_count + 1,
                last_pull_error = ?5
             WHERE peer_id = ?1 AND space_id = ?2 AND pull_after = ?3",
            params![
                peer_id.to_string(),
                space_id.to_string(),
                i64::try_from(expected_after).map_err(|_| ClientStoreError::InvalidPullCursor)?,
                next_pull_at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::PullCursorMismatch);
        }
        Ok(())
    }

    pub fn sync_counts(&self, now_unix_ms: i64) -> Result<SyncCounts, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let connection = self.lock()?;
        let values: (i64, i64, i64, i64, i64, i64) = connection.query_row(
            "SELECT
                (SELECT count(*) FROM client_peers WHERE enabled = 1),
                (SELECT count(*) FROM client_peer_spaces),
                (SELECT count(*) FROM client_deliveries WHERE state = 'pending'),
                (SELECT count(*) FROM client_deliveries WHERE state = 'leased'),
                (SELECT count(*) FROM client_deliveries WHERE state = 'rejected'),
                (SELECT count(*) FROM client_peer_spaces s JOIN client_peers p USING(peer_id)
                 WHERE p.enabled = 1 AND s.next_pull_at_unix_ms <= ?1)",
            params![now_unix_ms],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        let resource_values: (i64, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
            "SELECT
                    count(CASE WHEN direction = 'upload' AND state = 'waiting_local' THEN 1 END),
                    count(CASE WHEN direction = 'upload' AND state = 'pending' THEN 1 END),
                    count(CASE WHEN direction = 'download' AND state = 'pending' THEN 1 END),
                    count(CASE WHEN state = 'leased' THEN 1 END),
                    count(CASE WHEN state = 'complete' THEN 1 END),
                    count(CASE WHEN state = 'rejected' THEN 1 END),
                    coalesce(sum(transferred_bytes), 0),
                    coalesce(sum(r.byte_length), 0)
                 FROM client_resource_transfers t
                 JOIN client_resources r USING(content_id)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?;
        Ok(SyncCounts {
            enabled_peers: nonnegative_u64(values.0)?,
            spaces: nonnegative_u64(values.1)?,
            pending_deliveries: nonnegative_u64(values.2)?,
            leased_deliveries: nonnegative_u64(values.3)?,
            rejected_deliveries: nonnegative_u64(values.4)?,
            due_pulls: nonnegative_u64(values.5)?,
            resources: ResourceSyncCounts {
                waiting_uploads: nonnegative_u64(resource_values.0)?,
                pending_uploads: nonnegative_u64(resource_values.1)?,
                pending_downloads: nonnegative_u64(resource_values.2)?,
                leased_transfers: nonnegative_u64(resource_values.3)?,
                completed_transfers: nonnegative_u64(resource_values.4)?,
                rejected_transfers: nonnegative_u64(resource_values.5)?,
                transferred_bytes: nonnegative_u64(resource_values.6)?,
                total_bytes: nonnegative_u64(resource_values.7)?,
            },
        })
    }

    /// Returns resources that have not yet been reconciled with the local blob
    /// store. Callers verify these descriptors outside the SQLite lock and
    /// report successful verification with [`Self::mark_resource_local`].
    pub fn resource_scan_candidates(
        &self,
        limit: usize,
    ) -> Result<Vec<ContentDescriptor>, ClientStoreError> {
        validate_resource_limit(limit)?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT content_id, byte_length FROM client_resources
             WHERE locally_available = 0 AND local_expected = 1
             ORDER BY discovered_at_unix_ms, content_id LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit_i64(limit)?], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.map(|row| {
            let (content_id, byte_length) = row?;
            Ok(ContentDescriptor {
                content_id: parse_content_id(&content_id)?,
                byte_length: nonnegative_u64(byte_length)?,
            })
        })
        .collect()
    }

    /// Records that immutable bytes are locally verified. Waiting uploads
    /// become eligible and redundant downloads complete atomically.
    pub fn mark_resource_local(
        &self,
        descriptor: ContentDescriptor,
        verified_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        if verified_at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let byte_length = i64::try_from(descriptor.byte_length)
            .map_err(|_| ClientStoreError::InvalidResourceProgress)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE client_resources SET locally_available = 1, local_verified_at_unix_ms = ?3
             WHERE content_id = ?1 AND byte_length = ?2",
            params![
                descriptor.content_id.to_string(),
                byte_length,
                verified_at_unix_ms
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::ResourceDescriptorConflict);
        }
        transaction.execute(
            "UPDATE client_resource_transfers SET
                state = 'complete', transferred_bytes = ?2,
                completed_at_unix_ms = ?3, lease_id = NULL,
                lease_expires_at_unix_ms = NULL, last_error = NULL
             WHERE content_id = ?1 AND direction = 'download' AND state <> 'complete'",
            params![
                descriptor.content_id.to_string(),
                byte_length,
                verified_at_unix_ms
            ],
        )?;
        transaction.execute(
            "UPDATE client_resource_transfers SET
                state = 'pending', next_attempt_at_unix_ms = ?2, last_error = NULL
             WHERE content_id = ?1 AND direction = 'upload' AND state = 'waiting_local'",
            params![descriptor.content_id.to_string(), verified_at_unix_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn lease_due_resources(
        &self,
        now_unix_ms: i64,
        lease_duration: Duration,
        limit: usize,
        lease_id: ResourceTransferLeaseId,
    ) -> Result<Vec<ResourceTransferItem>, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        validate_resource_limit(limit)?;
        let lease_ms = i64::try_from(lease_duration.as_millis())
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let expires = now_unix_ms
            .checked_add(lease_ms)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let keys = {
            let mut statement = transaction.prepare(
                "SELECT t.peer_id, t.content_id, t.direction
                 FROM client_resource_transfers t
                 JOIN client_peers p USING(peer_id)
                 WHERE p.enabled = 1 AND (
                    (t.state = 'pending' AND t.next_attempt_at_unix_ms <= ?1) OR
                    (t.state = 'leased' AND t.lease_expires_at_unix_ms <= ?1)
                 )
                 ORDER BY CASE t.direction WHEN 'download' THEN 0 ELSE 1 END,
                          t.next_attempt_at_unix_ms, t.peer_id, t.content_id
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(params![now_unix_ms, limit_i64(limit)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut items = Vec::with_capacity(keys.len());
        for (peer_id, content_id, direction) in keys {
            let changed = transaction.execute(
                "UPDATE client_resource_transfers SET
                    state = 'leased', attempt_count = attempt_count + 1,
                    lease_id = ?4, lease_expires_at_unix_ms = ?5
                 WHERE peer_id = ?1 AND content_id = ?2 AND direction = ?3",
                params![
                    peer_id,
                    content_id,
                    direction,
                    lease_id.to_string(),
                    expires
                ],
            )?;
            if changed != 1 {
                return Err(corrupt("selected resource transfer disappeared"));
            }
            items.push(load_resource_transfer(
                &transaction,
                &peer_id,
                &content_id,
                &direction,
            )?);
        }
        transaction.commit()?;
        Ok(items)
    }

    pub fn record_resource_progress(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        direction: ResourceTransferDirection,
        lease_id: ResourceTransferLeaseId,
        transferred_bytes: u64,
        remote_upload_url: Option<&str>,
    ) -> Result<(), ClientStoreError> {
        let transferred = i64::try_from(transferred_bytes)
            .map_err(|_| ClientStoreError::InvalidResourceProgress)?;
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_resource_transfers SET
                transferred_bytes = ?5,
                remote_upload_url = CASE WHEN direction = 'upload' THEN ?6 ELSE NULL END
             WHERE peer_id = ?1 AND content_id = ?2 AND direction = ?3
               AND state = 'leased' AND lease_id = ?4
               AND ?5 <= (SELECT byte_length FROM client_resources WHERE content_id = ?2)",
            params![
                peer_id.to_string(),
                content_id.to_string(),
                direction.as_str(),
                lease_id.to_string(),
                transferred,
                remote_upload_url,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::ResourceLeaseMismatch);
        }
        Ok(())
    }

    pub fn complete_resource_transfer(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        direction: ResourceTransferDirection,
        lease_id: ResourceTransferLeaseId,
        completed_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        self.finish_resource_transfer(
            LeasedResourceTransfer {
                peer_id,
                content_id,
                direction,
                lease_id,
            },
            "complete",
            completed_at_unix_ms,
            None,
        )
    }

    pub fn retry_resource_transfer(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        direction: ResourceTransferDirection,
        lease_id: ResourceTransferLeaseId,
        next_attempt_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_resource_transfer(
            LeasedResourceTransfer {
                peer_id,
                content_id,
                direction,
                lease_id,
            },
            "pending",
            next_attempt_at_unix_ms,
            Some(error),
        )
    }

    pub fn continue_resource_transfer(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        direction: ResourceTransferDirection,
        lease_id: ResourceTransferLeaseId,
        next_attempt_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        if next_attempt_at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_resource_transfers SET
                state = 'pending', attempt_count = 0,
                next_attempt_at_unix_ms = ?5,
                lease_id = NULL, lease_expires_at_unix_ms = NULL,
                completed_at_unix_ms = NULL, last_error = NULL
             WHERE peer_id = ?1 AND content_id = ?2 AND direction = ?3
               AND state = 'leased' AND lease_id = ?4",
            params![
                peer_id.to_string(),
                content_id.to_string(),
                direction.as_str(),
                lease_id.to_string(),
                next_attempt_at_unix_ms,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::ResourceLeaseMismatch);
        }
        Ok(())
    }

    pub fn reject_resource_transfer(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        direction: ResourceTransferDirection,
        lease_id: ResourceTransferLeaseId,
        rejected_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_resource_transfer(
            LeasedResourceTransfer {
                peer_id,
                content_id,
                direction,
                lease_id,
            },
            "rejected",
            rejected_at_unix_ms,
            Some(error),
        )
    }

    pub fn wait_for_local_resource(
        &self,
        peer_id: NodeId,
        content_id: ContentId,
        lease_id: ResourceTransferLeaseId,
        next_check_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        if next_check_at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if error.len() > MAX_ERROR_BYTES {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE client_resource_transfers SET
                state = 'waiting_local', next_attempt_at_unix_ms = ?4,
                lease_id = NULL, lease_expires_at_unix_ms = NULL, last_error = ?5
             WHERE peer_id = ?1 AND content_id = ?2 AND direction = 'upload'
               AND state = 'leased' AND lease_id = ?3",
            params![
                peer_id.to_string(),
                content_id.to_string(),
                lease_id.to_string(),
                next_check_at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::ResourceLeaseMismatch);
        }
        transaction.execute(
            "UPDATE client_resources SET locally_available = 0, local_expected = 1,
                    local_verified_at_unix_ms = NULL
             WHERE content_id = ?1",
            params![content_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn finish_resource_transfer(
        &self,
        transfer: LeasedResourceTransfer,
        state: &'static str,
        at_unix_ms: i64,
        error: Option<&str>,
    ) -> Result<(), ClientStoreError> {
        if at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if error.is_some_and(|value| value.len() > MAX_ERROR_BYTES) {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE client_resource_transfers SET
                state = ?5, next_attempt_at_unix_ms = ?6,
                lease_id = NULL, lease_expires_at_unix_ms = NULL,
                transferred_bytes = CASE WHEN ?5 = 'complete' THEN
                    (SELECT byte_length FROM client_resources WHERE content_id = ?2)
                    ELSE transferred_bytes END,
                completed_at_unix_ms = CASE WHEN ?5 = 'complete' THEN ?6 ELSE NULL END,
                last_error = ?7
             WHERE peer_id = ?1 AND content_id = ?2 AND direction = ?3
               AND state = 'leased' AND lease_id = ?4",
            params![
                transfer.peer_id.to_string(),
                transfer.content_id.to_string(),
                transfer.direction.as_str(),
                transfer.lease_id.to_string(),
                state,
                at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::ResourceLeaseMismatch);
        }
        if state == "complete" && transfer.direction == ResourceTransferDirection::Download {
            let descriptor = resource_descriptor(&transaction, transfer.content_id)?;
            transaction.execute(
                "UPDATE client_resources SET locally_available = 1, local_verified_at_unix_ms = ?2
                 WHERE content_id = ?1",
                params![transfer.content_id.to_string(), at_unix_ms],
            )?;
            transaction.execute(
                "UPDATE client_resource_transfers SET
                    state = 'complete', transferred_bytes = ?2,
                    completed_at_unix_ms = ?3, lease_id = NULL,
                    lease_expires_at_unix_ms = NULL, last_error = NULL
                 WHERE content_id = ?1 AND direction = 'download' AND state <> 'complete'",
                params![
                    transfer.content_id.to_string(),
                    i64::try_from(descriptor.byte_length)
                        .map_err(|_| ClientStoreError::InvalidResourceProgress)?,
                    at_unix_ms,
                ],
            )?;
            transaction.execute(
                "UPDATE client_resource_transfers SET
                    state = 'pending', next_attempt_at_unix_ms = ?2, last_error = NULL
                 WHERE content_id = ?1 AND direction = 'upload' AND state = 'waiting_local'",
                params![transfer.content_id.to_string(), at_unix_ms],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn lease_due(
        &self,
        peer_id: NodeId,
        now_unix_ms: i64,
        lease_duration: Duration,
        limit: usize,
        lease_id: DeliveryLeaseId,
    ) -> Result<Vec<DeliveryItem>, ClientStoreError> {
        if now_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if !(1..=MAX_OUTBOX_BATCH).contains(&limit) {
            return Err(ClientStoreError::InvalidOutboxLimit);
        }
        let lease_ms = i64::try_from(lease_duration.as_millis())
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let expires = now_unix_ms
            .checked_add(lease_ms)
            .ok_or(ClientStoreError::InvalidLeaseDuration)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = {
            let mut statement = transaction.prepare(
                "SELECT d.operation_id
                 FROM client_deliveries d
                 JOIN client_peers p ON p.peer_id = d.peer_id
                 JOIN client_operations o ON o.operation_id = d.operation_id
                 WHERE d.peer_id = ?1 AND p.enabled = 1 AND (
                    (d.state = 'pending' AND d.next_attempt_at_unix_ms <= ?2) OR
                    (d.state = 'leased' AND d.lease_expires_at_unix_ms <= ?2)
                 )
                 ORDER BY o.local_sequence LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![peer_id.to_string(), now_unix_ms, limit_i64(limit)?],
                |row| row.get::<_, String>(0),
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            let changed = transaction.execute(
                "UPDATE client_deliveries
                 SET state = 'leased', attempt_count = attempt_count + 1,
                     lease_id = ?3, lease_expires_at_unix_ms = ?4
                 WHERE peer_id = ?1 AND operation_id = ?2",
                params![peer_id.to_string(), id, lease_id.to_string(), expires],
            )?;
            if changed != 1 {
                return Err(corrupt("selected delivery disappeared"));
            }
            let operation_id =
                OperationId::parse(&id).map_err(|error| corrupt(error.to_string()))?;
            let (_, operation) = load_operation_row(&transaction, operation_id)?
                .ok_or_else(|| corrupt("delivery references a missing operation"))?;
            let attempts = transaction.query_row(
                "SELECT attempt_count FROM client_deliveries WHERE peer_id = ?1 AND operation_id = ?2",
                params![peer_id.to_string(), id],
                |row| row.get::<_, i64>(0),
            )?;
            items.push(DeliveryItem {
                operation,
                attempt_count: u32::try_from(attempts)
                    .map_err(|_| corrupt("attempt count overflow"))?,
            });
        }
        transaction.commit()?;
        Ok(items)
    }

    pub fn acknowledge(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        acknowledged_at_unix_ms: i64,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "acknowledged",
            acknowledged_at_unix_ms,
            None,
        )
    }

    /// Returns every still-unattempted item from one batch lease to the
    /// pending queue. Items already acknowledged, retried, or rejected no
    /// longer carry the lease and are left unchanged.
    pub fn release_lease(
        &self,
        peer_id: NodeId,
        lease_id: DeliveryLeaseId,
    ) -> Result<u64, ClientStoreError> {
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_deliveries SET
                state = 'pending', lease_id = NULL, lease_expires_at_unix_ms = NULL
             WHERE peer_id = ?1 AND state = 'leased' AND lease_id = ?2",
            params![peer_id.to_string(), lease_id.to_string()],
        )?;
        u64::try_from(changed).map_err(|_| corrupt("released delivery count overflow"))
    }

    pub fn retry(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        next_attempt_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "pending",
            next_attempt_at_unix_ms,
            Some(error),
        )
    }

    pub fn reject(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        rejected_at_unix_ms: i64,
        error: &str,
    ) -> Result<(), ClientStoreError> {
        self.finish_delivery(
            peer_id,
            operation_id,
            lease_id,
            "rejected",
            rejected_at_unix_ms,
            Some(error),
        )
    }

    fn finish_delivery(
        &self,
        peer_id: NodeId,
        operation_id: OperationId,
        lease_id: DeliveryLeaseId,
        state: &'static str,
        at_unix_ms: i64,
        error: Option<&str>,
    ) -> Result<(), ClientStoreError> {
        if at_unix_ms < 0 {
            return Err(ClientStoreError::NegativeTimestamp);
        }
        if error.is_some_and(|value| value.len() > MAX_ERROR_BYTES) {
            return Err(ClientStoreError::DeliveryErrorTooLong);
        }
        let connection = self.lock()?;
        let changed = connection.execute(
            "UPDATE client_deliveries SET
                state = ?4, next_attempt_at_unix_ms = ?5,
                lease_id = NULL, lease_expires_at_unix_ms = NULL,
                acknowledged_at_unix_ms = CASE WHEN ?4 = 'acknowledged' THEN ?5 ELSE NULL END,
                last_error = ?6
             WHERE peer_id = ?1 AND operation_id = ?2
               AND state = 'leased' AND lease_id = ?3",
            params![
                peer_id.to_string(),
                operation_id.to_string(),
                lease_id.to_string(),
                state,
                at_unix_ms,
                error,
            ],
        )?;
        if changed != 1 {
            return Err(ClientStoreError::LeaseMismatch);
        }
        Ok(())
    }

    pub fn outbox_counts(&self, peer_id: NodeId) -> Result<OutboxCounts, ClientStoreError> {
        let connection = self.lock()?;
        let values = connection.query_row(
            "SELECT
                count(CASE WHEN state = 'pending' THEN 1 END),
                count(CASE WHEN state = 'leased' THEN 1 END),
                count(CASE WHEN state = 'acknowledged' THEN 1 END),
                count(CASE WHEN state = 'rejected' THEN 1 END)
             FROM client_deliveries WHERE peer_id = ?1",
            params![peer_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        Ok(OutboxCounts {
            pending: nonnegative_u64(values.0)?,
            leased: nonnegative_u64(values.1)?,
            acknowledged: nonnegative_u64(values.2)?,
            rejected: nonnegative_u64(values.3)?,
        })
    }

    pub fn entity(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
    ) -> Result<Option<LocalEntity>, ClientStoreError> {
        let connection = self.lock()?;
        let summary = connection.query_row(
            "SELECT min(schema_id), count(*), count(DISTINCT schema_id)
             FROM client_operations WHERE space_id = ?1 AND entity_id = ?2",
            params![space_id.to_string(), entity_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        let Some(schema) = summary.0 else {
            return Ok(None);
        };
        if summary.2 != 1 {
            return Err(corrupt("entity history contains multiple schemas"));
        }
        let schema = EntitySchema::parse(&schema).map_err(|error| corrupt(error.to_string()))?;
        let mut statement = connection.prepare(
            "SELECT o.projection_json FROM client_operations o
             JOIN client_entity_heads h ON h.operation_id = o.operation_id
             WHERE h.space_id = ?1 AND h.entity_id = ?2 ORDER BY o.operation_id",
        )?;
        let rows = statement.query_map(
            params![space_id.to_string(), entity_id.to_string()],
            |row| row.get::<_, String>(0),
        )?;
        let heads = rows
            .map(|row| decode_operation(&row?))
            .collect::<Result<Vec<_>, _>>()?;
        if heads.is_empty() {
            return Err(corrupt("entity history has no heads"));
        }
        Ok(Some(LocalEntity {
            space_id,
            entity_id,
            schema,
            operation_count: positive_u64(summary.1)?,
            heads,
        }))
    }

    pub fn list_entities(
        &self,
        space_id: SpaceId,
        schema: EntitySchema,
        limit: usize,
    ) -> Result<Vec<LocalEntitySummary>, ClientStoreError> {
        if !(1..=200).contains(&limit) {
            return Err(ClientStoreError::InvalidEntityLimit);
        }
        if !is_client_schema(schema) {
            return Ok(Vec::new());
        }
        let temporal = matches!(schema, EntitySchema::Record | EntitySchema::Event);
        let order = if temporal {
            "coalesce(p.start_at_unix_ms, -1) DESC, p.entity_id, p.operation_id"
        } else {
            "coalesce(p.sort_text, ''), p.entity_id, p.operation_id"
        };
        let sql = format!(
            "SELECT p.operation_id, p.entity_id, p.visibility, p.tombstone,
                    p.start_at_unix_ms, p.end_at_unix_ms, p.sort_text,
                    p.resource_count, p.media_bytes,
                    (SELECT count(*) FROM client_entity_heads h2
                     WHERE h2.space_id = p.space_id AND h2.entity_id = p.entity_id) > 1
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = ?2 AND p.tombstone = 0
             ORDER BY {order} LIMIT ?3"
        );
        let connection = self.lock()?;
        let mut statement = connection.prepare(&sql)?;
        let rows = statement.query_map(
            params![space_id.to_string(), schema.as_str(), limit_i64(limit)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, bool>(9)?,
                ))
            },
        )?;
        rows.map(|row| {
            let row = row?;
            Ok(LocalEntitySummary {
                operation_id: OperationId::parse(&row.0)
                    .map_err(|error| corrupt(error.to_string()))?,
                entity_id: EntityId::parse(&row.1).map_err(|error| corrupt(error.to_string()))?,
                schema,
                visibility: parse_visibility(&row.2)?,
                tombstone: row.3,
                start_at_unix_ms: row.4,
                end_at_unix_ms: row.5,
                sort_text: row.6,
                resource_count: nonnegative_u64(row.7)?,
                media_bytes: nonnegative_u64(row.8)?,
                conflicted: row.9,
            })
        })
        .collect()
    }

    pub fn list_records(
        &self,
        space_id: SpaceId,
        limit: usize,
    ) -> Result<Vec<LocalRecordSummary>, ClientStoreError> {
        if !(1..=200).contains(&limit) {
            return Err(ClientStoreError::InvalidEntityLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT p.operation_id, p.entity_id, p.visibility, p.tombstone,
                    p.start_at_unix_ms, p.end_at_unix_ms, p.sort_text,
                    p.resource_count, p.media_bytes,
                    (SELECT count(*) FROM client_entity_heads h2
                     WHERE h2.space_id = p.space_id AND h2.entity_id = p.entity_id) > 1,
                    o.projection_json
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             JOIN client_operations o ON o.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = 'record' AND p.tombstone = 0
             ORDER BY coalesce(p.start_at_unix_ms, -1) DESC, p.entity_id, p.operation_id
             LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![space_id.to_string(), limit_i64(limit)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })?;
        rows.map(|row| {
            let row = row?;
            let operation_id =
                OperationId::parse(&row.0).map_err(|error| corrupt(error.to_string()))?;
            let entity_id = EntityId::parse(&row.1).map_err(|error| corrupt(error.to_string()))?;
            let operation = decode_record_projection(&row.10, space_id, entity_id, operation_id)?;
            Ok(LocalRecordSummary {
                summary: LocalEntitySummary {
                    operation_id,
                    entity_id,
                    schema: EntitySchema::Record,
                    visibility: parse_visibility(&row.2)?,
                    tombstone: row.3,
                    start_at_unix_ms: row.4,
                    end_at_unix_ms: row.5,
                    sort_text: row.6,
                    resource_count: nonnegative_u64(row.7)?,
                    media_bytes: nonnegative_u64(row.8)?,
                    conflicted: row.9,
                },
                document: operation,
            })
        })
        .collect()
    }

    pub fn record_import_count(&self, space_id: SpaceId) -> Result<u64, ClientStoreError> {
        let connection = self.lock()?;
        let count = connection.query_row(
            "SELECT count(*)
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = 'record' AND p.tombstone = 0",
            params![space_id.to_string()],
            |row| row.get::<_, i64>(0),
        )?;
        nonnegative_u64(count)
    }

    pub fn record_import_batch(
        &self,
        space_id: SpaceId,
        after_local_sequence: u64,
        limit: usize,
    ) -> Result<Vec<LocalRecordImport>, ClientStoreError> {
        if !(1..=200).contains(&limit) {
            return Err(ClientStoreError::InvalidEntityLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT o.local_sequence, p.entity_id, o.projection_json
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             JOIN client_operations o ON o.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = 'record' AND p.tombstone = 0
               AND o.local_sequence > ?2
             ORDER BY o.local_sequence
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                space_id.to_string(),
                i64::try_from(after_local_sequence)
                    .map_err(|_| ClientStoreError::InvalidEntityLimit)?,
                limit_i64(limit)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (local_sequence, entity_id, json) = row?;
            let operation = decode_operation(&json)?;
            let entity_id =
                EntityId::parse(&entity_id).map_err(|error| corrupt(error.to_string()))?;
            if operation.space_id != space_id
                || operation.entity_id != entity_id
                || operation.schema != EntitySchema::Record
            {
                return Err(corrupt(
                    "record import projection does not match its operation",
                ));
            }
            let OperationBody::PutRecord { payload } = operation.body else {
                return Err(corrupt("record import projection has a non-record body"));
            };
            Ok(LocalRecordImport {
                local_sequence: positive_u64(local_sequence)?,
                entity_id,
                payload,
            })
        })
        .collect()
    }

    /// Reads bounded display projections without loading full operation JSON.
    /// Mobile bridge code should use this path rather than [`Self::list_records`].
    pub fn list_record_previews(
        &self,
        space_id: SpaceId,
        limit: usize,
    ) -> Result<Vec<LocalRecordPreview>, ClientStoreError> {
        if !(1..=200).contains(&limit) {
            return Err(ClientStoreError::InvalidEntityLimit);
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT p.operation_id, p.entity_id, p.visibility, p.tombstone,
                    p.start_at_unix_ms, p.end_at_unix_ms, p.sort_text,
                    p.resource_count, p.media_bytes,
                    (SELECT count(*) FROM client_entity_heads h2
                     WHERE h2.space_id = p.space_id AND h2.entity_id = p.entity_id) > 1,
                    p.preview_emoji, p.preview_text, p.preview_truncated
             FROM client_projections p
             JOIN client_entity_heads h ON h.operation_id = p.operation_id
             WHERE p.space_id = ?1 AND p.schema_id = 'record' AND p.tombstone = 0
             ORDER BY coalesce(p.start_at_unix_ms, -1) DESC, p.entity_id, p.operation_id
             LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![space_id.to_string(), limit_i64(limit)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, bool>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, bool>(12)?,
                ))
            })?;
        rows.map(|row| {
            let row = row?;
            Ok(LocalRecordPreview {
                summary: LocalEntitySummary {
                    operation_id: OperationId::parse(&row.0)
                        .map_err(|error| corrupt(error.to_string()))?,
                    entity_id: EntityId::parse(&row.1)
                        .map_err(|error| corrupt(error.to_string()))?,
                    schema: EntitySchema::Record,
                    visibility: parse_visibility(&row.2)?,
                    tombstone: row.3,
                    start_at_unix_ms: row.4,
                    end_at_unix_ms: row.5,
                    sort_text: row.6,
                    resource_count: nonnegative_u64(row.7)?,
                    media_bytes: nonnegative_u64(row.8)?,
                    conflicted: row.9,
                },
                emoji: row.10,
                text_preview: row.11,
                preview_truncated: row.12,
            })
        })
        .collect()
    }

    /// Reads one exact live record head selected by both immutable operation
    /// identity and entity identity. Historical and cross-space operations are
    /// deliberately not exposed through this projection lookup.
    pub fn record(
        &self,
        space_id: SpaceId,
        entity_id: EntityId,
        operation_id: OperationId,
    ) -> Result<Option<LocalRecordSummary>, ClientStoreError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT p.visibility, p.tombstone, p.start_at_unix_ms,
                        p.end_at_unix_ms, p.sort_text, p.resource_count,
                        p.media_bytes,
                        (SELECT count(*) FROM client_entity_heads h2
                         WHERE h2.space_id = p.space_id AND h2.entity_id = p.entity_id) > 1,
                        o.projection_json
                 FROM client_projections p
                 JOIN client_entity_heads h ON h.operation_id = p.operation_id
                 JOIN client_operations o ON o.operation_id = p.operation_id
                 WHERE p.space_id = ?1 AND p.entity_id = ?2
                   AND p.operation_id = ?3 AND p.schema_id = 'record'
                   AND p.tombstone = 0",
                params![
                    space_id.to_string(),
                    entity_id.to_string(),
                    operation_id.to_string()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let document = decode_record_projection(&row.8, space_id, entity_id, operation_id)?;
        Ok(Some(LocalRecordSummary {
            summary: LocalEntitySummary {
                operation_id,
                entity_id,
                schema: EntitySchema::Record,
                visibility: parse_visibility(&row.0)?,
                tombstone: row.1,
                start_at_unix_ms: row.2,
                end_at_unix_ms: row.3,
                sort_text: row.4,
                resource_count: nonnegative_u64(row.5)?,
                media_bytes: nonnegative_u64(row.6)?,
                conflicted: row.7,
            },
            document,
        }))
    }

    /// Rebuilds every entity head and client projection from immutable local
    /// operations. Delivery state is not touched.
    pub fn rebuild_derived_state(&self) -> Result<u64, ClientStoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operations = {
            let mut statement = transaction
                .prepare("SELECT projection_json FROM client_operations ORDER BY local_sequence")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|row| decode_operation(&row?))
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.execute("DELETE FROM client_projections", [])?;
        transaction.execute("DELETE FROM client_entity_visibility", [])?;
        transaction.execute("DELETE FROM client_entity_heads", [])?;
        transaction.execute("DELETE FROM client_operation_authorizations", [])?;
        transaction.execute("DELETE FROM client_operation_parents", [])?;
        for operation in &operations {
            insert_graph(&transaction, operation)?;
            insert_projection(&transaction, operation)?;
        }
        transaction.commit()?;
        u64::try_from(operations.len()).map_err(|_| corrupt("operation count overflow"))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, ClientStoreError> {
        self.connection
            .lock()
            .map_err(|_| ClientStoreError::LockPoisoned)
    }
}

fn commit_transaction(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
    stored_at_unix_ms: i64,
    source: CommitSource,
) -> Result<CommitResult, ClientStoreError> {
    operation
        .verify()
        .map_err(|error| ClientStoreError::InvalidOperation(error.to_string()))?;
    if stored_at_unix_ms < 0 {
        return Err(ClientStoreError::NegativeTimestamp);
    }
    let projection_json = serde_json::to_string(operation)
        .map_err(|error| ClientStoreError::InvalidOperation(error.to_string()))?;
    if let Some((sequence, existing)) = load_operation_row(transaction, operation.operation_id)? {
        if existing != *operation {
            return Err(ClientStoreError::OperationConflict(operation.operation_id));
        }
        apply_delivery_source(
            transaction,
            operation.operation_id,
            stored_at_unix_ms,
            source,
        )?;
        apply_resource_source(transaction, operation, stored_at_unix_ms, source)?;
        return Ok(CommitResult {
            local_sequence: sequence,
            operation_id: operation.operation_id,
            replayed: true,
            queued_peers: delivery_count(transaction, operation.operation_id)?,
        });
    }
    validate_references(transaction, operation)?;
    validate_topology(transaction, operation)?;
    transaction.execute(
        "INSERT INTO client_operations (
            operation_id, space_id, entity_id, schema_id, actor_id,
            occurred_at_unix_ms, stored_at_unix_ms, locally_authored, projection_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            operation.operation_id.to_string(),
            operation.space_id.to_string(),
            operation.entity_id.to_string(),
            operation.schema.as_str(),
            operation.actor_id.to_string(),
            operation.occurred_at_unix_ms,
            stored_at_unix_ms,
            i64::from(matches!(source, CommitSource::Local)),
            projection_json,
        ],
    )?;
    let local_sequence = positive_u64(transaction.last_insert_rowid())?;
    insert_graph(transaction, operation)?;
    insert_projection(transaction, operation)?;
    insert_operation_resources(transaction, operation, stored_at_unix_ms)?;
    apply_delivery_source(
        transaction,
        operation.operation_id,
        stored_at_unix_ms,
        source,
    )?;
    apply_resource_source(transaction, operation, stored_at_unix_ms, source)?;
    Ok(CommitResult {
        local_sequence,
        operation_id: operation.operation_id,
        replayed: false,
        queued_peers: delivery_count(transaction, operation.operation_id)?,
    })
}

fn installation_binding(
    node_id: NodeId,
    request: &TrustedSpaceBootstrapRequest,
) -> Result<ClientInstallationBinding, ClientStoreError> {
    let OperationBody::SpaceGenesis { controller } = request.genesis.body else {
        return Err(ClientStoreError::InvalidBootstrap(
            "genesis body has the wrong kind".into(),
        ));
    };
    let OperationBody::CapabilityGrant { ref grant } = request.initial_grant.body else {
        return Err(ClientStoreError::InvalidBootstrap(
            "initial grant body has the wrong kind".into(),
        ));
    };
    Ok(ClientInstallationBinding {
        node_id,
        space_id: request.genesis.space_id,
        controller_actor_id: controller,
        local_writer_actor_id: grant.subject,
        genesis_operation_id: request.genesis.operation_id,
        initial_grant_operation_id: request.initial_grant.operation_id,
        display_name: request.display_name.clone(),
        created_at_unix_ms: request.received_at_unix_ms,
    })
}

fn load_installation(connection: &Connection) -> Result<ClientInstallation, ClientStoreError> {
    type InstallationRow = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
    );
    let row: Option<InstallationRow> = connection
        .query_row(
            "SELECT phase, node_id, space_id, controller_actor_id,
                    local_writer_actor_id, genesis_operation_id,
                    initial_grant_operation_id, display_name, created_at_unix_ms
             FROM client_local_installation WHERE singleton = 1",
            [],
            |row| {
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
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(ClientInstallation::Unbound);
    };
    if row.0 == "initializing" {
        if row.1.is_some()
            || row.2.is_some()
            || row.3.is_some()
            || row.4.is_some()
            || row.5.is_some()
            || row.6.is_some()
            || row.7.is_some()
            || row.8.is_some()
        {
            return Err(corrupt(
                "initializing installation contains established fields",
            ));
        }
        return Ok(ClientInstallation::Initializing);
    }
    if row.0 != "established" {
        return Err(corrupt("unknown client installation phase"));
    }
    let required = |value: Option<String>, name: &'static str| {
        value.ok_or_else(|| corrupt(format!("established installation omitted {name}")))
    };
    let binding = ClientInstallationBinding {
        node_id: required(row.1, "node ID")?
            .parse()
            .map_err(|error| corrupt(format!("invalid installation node ID: {error}")))?,
        space_id: required(row.2, "space ID")?
            .parse()
            .map_err(|error| corrupt(format!("invalid installation space ID: {error}")))?,
        controller_actor_id: required(row.3, "controller actor ID")?
            .parse()
            .map_err(|error| corrupt(format!("invalid installation controller ID: {error}")))?,
        local_writer_actor_id: required(row.4, "local writer actor ID")?
            .parse()
            .map_err(|error| corrupt(format!("invalid installation writer ID: {error}")))?,
        genesis_operation_id: OperationId::parse(&required(row.5, "genesis operation ID")?)
            .map_err(|error| corrupt(format!("invalid installation genesis ID: {error}")))?,
        initial_grant_operation_id: OperationId::parse(&required(
            row.6,
            "initial grant operation ID",
        )?)
        .map_err(|error| corrupt(format!("invalid installation grant ID: {error}")))?,
        display_name: required(row.7, "display name")?,
        created_at_unix_ms: row
            .8
            .ok_or_else(|| corrupt("established installation omitted creation time"))?,
    };
    Ok(ClientInstallation::Established(Box::new(binding)))
}

fn operation_count(connection: &Connection) -> Result<u64, ClientStoreError> {
    let count = connection.query_row("SELECT count(*) FROM client_operations", [], |row| {
        row.get::<_, i64>(0)
    })?;
    nonnegative_u64(count)
}

fn operation_matches(
    connection: &Connection,
    expected: &OperationEnvelope,
) -> Result<bool, ClientStoreError> {
    Ok(load_operation_row(connection, expected.operation_id)?
        .is_some_and(|(_, operation)| operation == *expected))
}

fn secure_sqlite_files(path: &Path) -> Result<(), ClientStoreError> {
    set_private_permissions(path, false)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.try_exists()? {
            set_private_permissions(&sidecar, false)?;
        }
    }
    Ok(())
}

/// Resolves only the parent directory so `SQLITE_OPEN_NOFOLLOW` still checks
/// the final database component. This also accepts normal platform paths whose
/// ancestors (for example macOS `/var`) are symbolic links.
fn nofollow_database_path(path: &Path) -> Result<PathBuf, ClientStoreError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    set_private_permissions(parent, true)?;
    let parent = std::fs::canonicalize(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "client database path must name a file",
        )
    })?;
    Ok(parent.join(file_name))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) -> Result<(), std::io::Error> {
    Ok(())
}

fn configure(connection: &Connection, persistent: bool) -> Result<(), ClientStoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(Duration::from_secs(5))?;
    if persistent {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), ClientStoreError> {
    let mut version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > CLIENT_SCHEMA_VERSION {
        return Err(ClientStoreError::UnsupportedSchema {
            found: version,
            supported: CLIENT_SCHEMA_VERSION,
        });
    }
    while version < CLIENT_SCHEMA_VERSION {
        let expected = version + 1;
        let migration =
            MIGRATIONS
                .get(version as usize)
                .ok_or(ClientStoreError::MigrationVersionMismatch {
                    expected,
                    found: version,
                })?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration)?;
        let found: u32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if found != expected {
            return Err(ClientStoreError::MigrationVersionMismatch { expected, found });
        }
        transaction.commit()?;
        version = expected;
    }
    Ok(())
}

fn validate_peer(peer: &PeerConfig) -> Result<(), ClientStoreError> {
    if peer.added_at_unix_ms < 0 {
        return Err(ClientStoreError::NegativeTimestamp);
    }
    if peer.endpoint.is_empty() || peer.endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(ClientStoreError::InvalidPeerEndpoint);
    }
    if peer
        .peer_transport_credential
        .as_ref()
        .is_some_and(|value| {
            value.is_empty()
                || value.len() > 256
                || !value.is_ascii()
                || value.contains(char::is_whitespace)
        })
    {
        return Err(ClientStoreError::InvalidPeerEndpoint);
    }
    Ok(())
}

fn validate_resource_limit(limit: usize) -> Result<(), ClientStoreError> {
    if !(1..=MAX_RESOURCE_TRANSFER_BATCH).contains(&limit) {
        return Err(ClientStoreError::InvalidResourceTransferLimit);
    }
    Ok(())
}

fn insert_operation_resources(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
    discovered_at_unix_ms: i64,
) -> Result<(), ClientStoreError> {
    for (position, resource) in operation.body.resources().iter().enumerate() {
        let byte_length = i64::try_from(resource.byte_length)
            .map_err(|_| ClientStoreError::InvalidResourceProgress)?;
        transaction.execute(
            "INSERT OR IGNORE INTO client_resources (
                content_id, byte_length, media_type, role, original_name, discovered_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                resource.content_id.to_string(),
                byte_length,
                resource.media_type,
                resource.role,
                resource.original_name,
                discovered_at_unix_ms,
            ],
        )?;
        let existing_length: i64 = transaction.query_row(
            "SELECT byte_length FROM client_resources WHERE content_id = ?1",
            params![resource.content_id.to_string()],
            |row| row.get(0),
        )?;
        if existing_length != byte_length {
            return Err(ClientStoreError::ResourceDescriptorConflict);
        }
        transaction.execute(
            "INSERT INTO client_operation_resources (operation_id, position, content_id)
             VALUES (?1, ?2, ?3)",
            params![
                operation.operation_id.to_string(),
                limit_i64(position)?,
                resource.content_id.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn apply_resource_source(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
    at_unix_ms: i64,
    source: CommitSource,
) -> Result<(), ClientStoreError> {
    if operation.body.resources().is_empty() || source == CommitSource::Remote {
        return Ok(());
    }
    for resource in operation.body.resources() {
        match source {
            CommitSource::Local => {
                transaction.execute(
                    "UPDATE client_resources SET local_expected = 1 WHERE content_id = ?1",
                    params![resource.content_id.to_string()],
                )?;
                queue_resource_uploads(transaction, resource.content_id, at_unix_ms, None)?;
            }
            CommitSource::Peer(source_peer) => {
                let (available, byte_length): (bool, i64) = transaction.query_row(
                    "SELECT locally_available, byte_length FROM client_resources WHERE content_id = ?1",
                    params![resource.content_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let content_read_enabled = transaction.query_row(
                    "SELECT content_read_enabled FROM client_peers WHERE peer_id = ?1",
                    params![source_peer.to_string()],
                    |row| row.get::<_, bool>(0),
                )?;
                if content_read_enabled {
                    transaction.execute(
                        "INSERT OR IGNORE INTO client_resource_transfers (
                            peer_id, content_id, direction, state, next_attempt_at_unix_ms,
                            transferred_bytes, completed_at_unix_ms
                         ) VALUES (?1, ?2, 'download', ?3, ?4, ?5, ?6)",
                        params![
                            source_peer.to_string(),
                            resource.content_id.to_string(),
                            if available { "complete" } else { "pending" },
                            at_unix_ms,
                            if available { byte_length } else { 0 },
                            available.then_some(at_unix_ms),
                        ],
                    )?;
                }
                queue_resource_uploads(
                    transaction,
                    resource.content_id,
                    at_unix_ms,
                    Some(source_peer),
                )?;
            }
            CommitSource::Remote => {}
        }
    }
    Ok(())
}

fn queue_resource_uploads(
    transaction: &Transaction<'_>,
    content_id: ContentId,
    at_unix_ms: i64,
    excluded_peer: Option<NodeId>,
) -> Result<(), ClientStoreError> {
    transaction.execute(
        "INSERT OR IGNORE INTO client_resource_transfers (
            peer_id, content_id, direction, state, next_attempt_at_unix_ms
         ) SELECT p.peer_id, r.content_id, 'upload',
                  CASE r.locally_available WHEN 1 THEN 'pending' ELSE 'waiting_local' END,
                  ?2
           FROM client_peers p JOIN client_resources r ON r.content_id = ?1
          WHERE p.enabled = 1 AND p.push_enabled = 1
            AND (p.peer_transport_credential IS NULL OR EXISTS (
                SELECT 1 FROM client_operation_resources link
                JOIN client_operations operation USING(operation_id)
                JOIN client_peer_spaces space
                  ON space.peer_id=p.peer_id AND space.space_id=operation.space_id
                WHERE link.content_id=r.content_id
            ))
            AND (?3 IS NULL OR p.peer_id <> ?3)",
        params![
            content_id.to_string(),
            at_unix_ms,
            excluded_peer.map(|value| value.to_string()),
        ],
    )?;
    Ok(())
}

fn queue_known_resources_for_peer(
    transaction: &Transaction<'_>,
    peer_id: NodeId,
    fallback_at_unix_ms: i64,
) -> Result<(), ClientStoreError> {
    transaction.execute(
        "INSERT OR IGNORE INTO client_resource_transfers (
            peer_id, content_id, direction, state, next_attempt_at_unix_ms
         ) SELECT ?1, content_id, 'upload',
                  CASE locally_available WHEN 1 THEN 'pending' ELSE 'waiting_local' END,
                  max(discovered_at_unix_ms, ?2)
           FROM client_resources resource
          WHERE (SELECT peer_transport_credential FROM client_peers WHERE peer_id=?1) IS NULL
             OR EXISTS (
              SELECT 1 FROM client_operation_resources link
              JOIN client_operations operation USING(operation_id)
              JOIN client_peer_spaces space
                ON space.peer_id=?1 AND space.space_id=operation.space_id
              WHERE link.content_id=resource.content_id
          )",
        params![peer_id.to_string(), fallback_at_unix_ms],
    )?;
    Ok(())
}

fn queue_known_resources_for_peer_space(
    transaction: &Transaction<'_>,
    peer_id: NodeId,
    space_id: SpaceId,
    fallback_at_unix_ms: i64,
) -> Result<(), ClientStoreError> {
    transaction.execute(
        "INSERT OR IGNORE INTO client_resource_transfers (
            peer_id, content_id, direction, state, next_attempt_at_unix_ms
         ) SELECT ?1, resource.content_id, 'upload',
                  CASE resource.locally_available WHEN 1 THEN 'pending' ELSE 'waiting_local' END,
                  max(resource.discovered_at_unix_ms, ?3)
           FROM client_resources resource
          WHERE EXISTS (
              SELECT 1 FROM client_operation_resources link
              JOIN client_operations operation USING(operation_id)
              WHERE link.content_id=resource.content_id AND operation.space_id=?2
          )",
        params![
            peer_id.to_string(),
            space_id.to_string(),
            fallback_at_unix_ms,
        ],
    )?;
    Ok(())
}

fn load_resource_transfer(
    connection: &Connection,
    peer_id: &str,
    content_id: &str,
    direction: &str,
) -> Result<ResourceTransferItem, ClientStoreError> {
    let row = connection.query_row(
        "SELECT p.endpoint, p.enabled, p.push_enabled, p.content_read_enabled,
                p.peer_transport_credential, p.added_at_unix_ms,
                r.byte_length, r.media_type, r.role, r.original_name,
                t.attempt_count, t.remote_upload_url, t.transferred_bytes
         FROM client_resource_transfers t
         JOIN client_peers p USING(peer_id)
         JOIN client_resources r USING(content_id)
         WHERE t.peer_id = ?1 AND t.content_id = ?2 AND t.direction = ?3",
        params![peer_id, content_id, direction],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, i64>(12)?,
            ))
        },
    )?;
    Ok(ResourceTransferItem {
        peer: PeerConfig {
            peer_id: peer_id
                .parse()
                .map_err(|error| corrupt(format!("invalid peer ID: {error}")))?,
            endpoint: row.0,
            enabled: row.1,
            push_enabled: row.2,
            content_read_enabled: row.3,
            peer_transport_credential: row.4,
            added_at_unix_ms: row.5,
        },
        resource: ResourceRef {
            content_id: parse_content_id(content_id)?,
            byte_length: nonnegative_u64(row.6)?,
            media_type: row.7,
            role: row.8,
            original_name: row.9,
        },
        direction: match direction {
            "upload" => ResourceTransferDirection::Upload,
            "download" => ResourceTransferDirection::Download,
            _ => return Err(corrupt("invalid resource transfer direction")),
        },
        attempt_count: u32::try_from(row.10)
            .map_err(|_| corrupt("resource attempt count overflow"))?,
        remote_upload_url: row.11,
        transferred_bytes: nonnegative_u64(row.12)?,
    })
}

fn resource_descriptor(
    connection: &Connection,
    content_id: ContentId,
) -> Result<ContentDescriptor, ClientStoreError> {
    let byte_length: i64 = connection.query_row(
        "SELECT byte_length FROM client_resources WHERE content_id = ?1",
        params![content_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(ContentDescriptor {
        content_id,
        byte_length: nonnegative_u64(byte_length)?,
    })
}

fn parse_content_id(value: &str) -> Result<ContentId, ClientStoreError> {
    ContentId::parse(value).map_err(|error| corrupt(format!("invalid content ID: {error}")))
}

fn parse_peer_read_mode(
    mode: &str,
    session_id: Option<&str>,
    grant_operation_id: Option<&str>,
) -> Result<PeerReadMode, ClientStoreError> {
    match (mode, session_id, grant_operation_id) {
        ("supervisor_bearer", None, None) => Ok(PeerReadMode::SupervisorBearer),
        ("paired", Some(session), Some(grant)) => Ok(PeerReadMode::Paired {
            session_id: session
                .parse()
                .map_err(|error| corrupt(format!("invalid session ID: {error}")))?,
            grant_operation_id: grant
                .parse()
                .map_err(|error| corrupt(format!("invalid grant ID: {error}")))?,
        }),
        _ => Err(corrupt("invalid peer read mode")),
    }
}

fn apply_delivery_source(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    at_unix_ms: i64,
    source: CommitSource,
) -> Result<(), ClientStoreError> {
    if let CommitSource::Peer(peer_id) = source {
        let configured = transaction
            .query_row(
                "SELECT 1 FROM client_peers WHERE peer_id = ?1",
                params![peer_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !configured {
            return Err(ClientStoreError::UnknownPeer(peer_id));
        }
    }
    match source {
        CommitSource::Remote => return Ok(()),
        CommitSource::Local | CommitSource::Peer(_) => {
            transaction.execute(
                "INSERT OR IGNORE INTO client_deliveries (
                    peer_id, operation_id, state, next_attempt_at_unix_ms
                 ) SELECT peer_id, ?1, 'pending', ?2 FROM client_peers
                   WHERE enabled = 1 AND push_enabled = 1
                     AND (client_peers.peer_transport_credential IS NULL OR EXISTS (
                         SELECT 1 FROM client_peer_spaces space
                         JOIN client_operations operation
                           ON operation.operation_id=?1
                          AND operation.space_id=space.space_id
                         WHERE space.peer_id=client_peers.peer_id
                     ))
                     AND (?3 IS NULL OR peer_id <> ?3)",
                params![
                    operation_id.to_string(),
                    at_unix_ms,
                    match source {
                        CommitSource::Peer(peer_id) => Some(peer_id.to_string()),
                        _ => None,
                    },
                ],
            )?;
        }
    }
    if let CommitSource::Peer(peer_id) = source {
        let changed = transaction.execute(
            "INSERT INTO client_deliveries (
                peer_id, operation_id, state, next_attempt_at_unix_ms, acknowledged_at_unix_ms
             ) VALUES (?1, ?2, 'acknowledged', ?3, ?3)
             ON CONFLICT(peer_id, operation_id) DO UPDATE SET
                state = 'acknowledged', lease_id = NULL, lease_expires_at_unix_ms = NULL,
                acknowledged_at_unix_ms = excluded.acknowledged_at_unix_ms, last_error = NULL",
            params![peer_id.to_string(), operation_id.to_string(), at_unix_ms],
        )?;
        if changed != 1 {
            return Err(corrupt("source peer delivery state was not recorded"));
        }
    }
    Ok(())
}

fn validate_references(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for parent in &operation.causal_parents {
        if load_operation_row(transaction, *parent)?.is_none() {
            return Err(ClientStoreError::MissingParent(*parent));
        }
    }
    for authorization in &operation.authorization {
        if load_operation_row(transaction, *authorization)?.is_none() {
            return Err(ClientStoreError::MissingAuthorization(*authorization));
        }
    }
    Ok(())
}

fn validate_topology(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for parent in &operation.causal_parents {
        let (entity, schema): (String, String) = transaction.query_row(
            "SELECT entity_id, schema_id FROM client_operations WHERE operation_id = ?1",
            params![parent.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if entity != operation.entity_id.to_string() || schema != operation.schema.as_str() {
            return Err(ClientStoreError::ParentMismatch(*parent));
        }
    }
    let (history, heads): (i64, i64) = transaction.query_row(
        "SELECT
            (SELECT count(*) FROM client_operations WHERE space_id = ?1 AND entity_id = ?2),
            (SELECT count(*) FROM client_entity_heads WHERE space_id = ?1 AND entity_id = ?2)",
        params![
            operation.space_id.to_string(),
            operation.entity_id.to_string()
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if history > 0 && heads == 0 {
        return Err(corrupt("entity history has no current heads"));
    }
    if history > 0 && operation.causal_parents.is_empty() {
        return Err(ClientStoreError::EntityAlreadyExists);
    }
    if history == 0 && matches!(operation.body, OperationBody::Tombstone) {
        return Err(ClientStoreError::InitialTombstone);
    }
    let consumed = operation
        .causal_parents
        .iter()
        .try_fold(0_i64, |count, parent| {
            let present: i64 = transaction.query_row(
                "SELECT count(*) FROM client_entity_heads WHERE operation_id = ?1",
                params![parent.to_string()],
                |row| row.get(0),
            )?;
            Ok::<_, rusqlite::Error>(count + present)
        })?;
    if heads - consumed + 1 > i64::try_from(MAX_CAUSAL_PARENTS).unwrap_or(i64::MAX) {
        return Err(ClientStoreError::TooManyHeads);
    }
    Ok(())
}

fn insert_graph(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    for (position, parent) in operation.causal_parents.iter().enumerate() {
        transaction.execute(
            "INSERT INTO client_operation_parents (operation_id, parent_operation_id, position)
             VALUES (?1, ?2, ?3)",
            params![
                operation.operation_id.to_string(),
                parent.to_string(),
                limit_i64(position)?
            ],
        )?;
        transaction.execute(
            "DELETE FROM client_entity_heads WHERE operation_id = ?1",
            params![parent.to_string()],
        )?;
    }
    for (position, authorization) in operation.authorization.iter().enumerate() {
        transaction.execute(
            "INSERT INTO client_operation_authorizations (
                operation_id, authorization_operation_id, position
             ) VALUES (?1, ?2, ?3)",
            params![
                operation.operation_id.to_string(),
                authorization.to_string(),
                limit_i64(position)?
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO client_entity_heads (space_id, entity_id, schema_id, operation_id)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            operation.space_id.to_string(),
            operation.entity_id.to_string(),
            operation.schema.as_str(),
            operation.operation_id.to_string(),
        ],
    )?;
    Ok(())
}

fn insert_projection(
    transaction: &Transaction<'_>,
    operation: &OperationEnvelope,
) -> Result<(), ClientStoreError> {
    let (start, end, sort_text, preview_emoji, preview_text, preview_truncated) =
        match &operation.body {
            OperationBody::PutRecord {
                payload: ProtectedDocument::Public { document },
            } => {
                let (preview_text, preview_truncated) =
                    bounded_record_preview(document.text.as_deref());
                (
                    Some(document.start_at_unix_ms),
                    document.end_at_unix_ms,
                    None,
                    document.emoji.clone(),
                    preview_text,
                    preview_truncated,
                )
            }
            OperationBody::PutEvent {
                payload: ProtectedDocument::Public { document },
            } => (
                Some(document.start_at_unix_ms),
                document.end_at_unix_ms,
                Some(document.label.to_lowercase()),
                None,
                None,
                false,
            ),
            OperationBody::PutTag {
                payload: ProtectedDocument::Public { document },
            } => (
                None,
                None,
                Some(document.name.to_lowercase()),
                None,
                None,
                false,
            ),
            OperationBody::PutProfile { document } => {
                (None, None, Some(document.handle.clone()), None, None, false)
            }
            OperationBody::PutRecord {
                payload: ProtectedDocument::Private { .. },
            }
            | OperationBody::PutTag {
                payload: ProtectedDocument::Private { .. },
            }
            | OperationBody::PutEvent {
                payload: ProtectedDocument::Private { .. },
            }
            | OperationBody::Tombstone
                if is_client_schema(operation.schema) =>
            {
                (None, None, None, None, None, false)
            }
            _ => return Ok(()),
        };
    let visibility = if let Some(value) = operation.body.declared_visibility() {
        let value = visibility_key(value).to_owned();
        if operation.causal_parents.is_empty() {
            transaction.execute(
                "INSERT INTO client_entity_visibility (space_id, entity_id, schema_id, visibility)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    operation.space_id.to_string(),
                    operation.entity_id.to_string(),
                    operation.schema.as_str(),
                    value
                ],
            )?;
        } else {
            let existing: String = transaction.query_row(
                "SELECT visibility FROM client_entity_visibility WHERE space_id = ?1 AND entity_id = ?2",
                params![operation.space_id.to_string(), operation.entity_id.to_string()],
                |row| row.get(0),
            )?;
            if existing != value {
                return Err(ClientStoreError::InvalidOperation(
                    "entity visibility is immutable".into(),
                ));
            }
        }
        value
    } else {
        transaction.query_row(
            "SELECT visibility FROM client_entity_visibility WHERE space_id = ?1 AND entity_id = ?2",
            params![operation.space_id.to_string(), operation.entity_id.to_string()],
            |row| row.get::<_, String>(0),
        )?
    };
    let resources = operation.body.resources();
    let resource_count =
        i64::try_from(resources.len()).map_err(|_| corrupt("resource count overflow"))?;
    let media_bytes = resources.iter().try_fold(0_i64, |total, resource| {
        let bytes = i64::try_from(resource.byte_length)
            .map_err(|_| corrupt("media byte count overflow"))?;
        total
            .checked_add(bytes)
            .ok_or_else(|| corrupt("media byte total overflow"))
    })?;
    transaction.execute(
        "INSERT INTO client_projections (
            operation_id, space_id, entity_id, schema_id, visibility, tombstone,
            start_at_unix_ms, end_at_unix_ms, sort_text, resource_count, media_bytes,
            preview_emoji, preview_text, preview_truncated
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            operation.operation_id.to_string(),
            operation.space_id.to_string(),
            operation.entity_id.to_string(),
            operation.schema.as_str(),
            visibility,
            i64::from(matches!(operation.body, OperationBody::Tombstone)),
            start,
            end,
            sort_text,
            resource_count,
            media_bytes,
            preview_emoji,
            preview_text,
            preview_truncated,
        ],
    )?;
    Ok(())
}

fn bounded_record_preview(text: Option<&str>) -> (Option<String>, bool) {
    let Some(text) = text else {
        return (None, false);
    };
    match text
        .char_indices()
        .nth(MAX_RECORD_PREVIEW_TEXT_CHARS)
        .map(|(index, _)| index)
    {
        Some(cutoff) => (Some(text[..cutoff].to_owned()), true),
        None => (Some(text.to_owned()), false),
    }
}

fn load_operation_row(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<(u64, OperationEnvelope)>, ClientStoreError> {
    connection
        .query_row(
            "SELECT local_sequence, projection_json FROM client_operations WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(sequence, json)| Ok((positive_u64(sequence)?, decode_operation(&json)?)))
        .transpose()
}

fn decode_record_projection(
    json: &str,
    space_id: SpaceId,
    entity_id: EntityId,
    operation_id: OperationId,
) -> Result<Option<RecordDocument>, ClientStoreError> {
    let operation = decode_operation(json)?;
    if operation.operation_id != operation_id
        || operation.entity_id != entity_id
        || operation.space_id != space_id
        || operation.schema != EntitySchema::Record
    {
        return Err(corrupt("record projection does not match its operation"));
    }
    match operation.body {
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public { document },
        } => Ok(Some(document)),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Private { .. },
        } => Ok(None),
        _ => Err(corrupt("record projection has a non-record body")),
    }
}

fn decode_operation(json: &str) -> Result<OperationEnvelope, ClientStoreError> {
    let operation: OperationEnvelope = serde_json::from_str(json)
        .map_err(|error| corrupt(format!("invalid stored operation JSON: {error}")))?;
    operation
        .verify()
        .map_err(|error| corrupt(format!("stored operation failed verification: {error}")))?;
    Ok(operation)
}

fn delivery_count(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<u64, ClientStoreError> {
    let value = connection.query_row(
        "SELECT count(*) FROM client_deliveries WHERE operation_id = ?1",
        params![operation_id.to_string()],
        |row| row.get::<_, i64>(0),
    )?;
    nonnegative_u64(value)
}

const fn is_client_schema(schema: EntitySchema) -> bool {
    matches!(
        schema,
        EntitySchema::Record | EntitySchema::Event | EntitySchema::Tag | EntitySchema::Profile
    )
}

const fn visibility_key(value: Visibility) -> &'static str {
    match value {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

fn parse_visibility(value: &str) -> Result<Visibility, ClientStoreError> {
    match value {
        "public" => Ok(Visibility::Public),
        "private" => Ok(Visibility::Private),
        _ => Err(corrupt("invalid stored visibility")),
    }
}

fn positive_u64(value: i64) -> Result<u64, ClientStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| corrupt("expected positive SQLite integer"))
}

fn nonnegative_u64(value: i64) -> Result<u64, ClientStoreError> {
    u64::try_from(value).map_err(|_| corrupt("expected nonnegative SQLite integer"))
}

fn limit_i64(value: usize) -> Result<i64, ClientStoreError> {
    i64::try_from(value).map_err(|_| corrupt("integer exceeds SQLite range"))
}

fn corrupt(detail: impl Into<String>) -> ClientStoreError {
    ClientStoreError::Corrupt(detail.into())
}

#[cfg(test)]
mod tests;
