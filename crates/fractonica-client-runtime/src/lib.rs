#![forbid(unsafe_code)]
//! Native application lifecycle for local-first Fractonica clients.
//!
//! This crate owns keys, local operations, content, and background sync. UI
//! adapters receive semantic methods and small status values, never secrets or
//! raw storage handles.

use std::{
    collections::BTreeMap,
    error::Error,
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fractonica_application::{
    SpaceDescriptor, StoredOperation, TrustedSpaceBootstrapRequest,
    validate_trusted_space_bootstrap,
};
use fractonica_client::{
    ActorKeyCustody, AuthoringContext, KeyCustodyError, ObservedEntity, OperationAuthor,
    OperationDraft, SystemAuthoringRuntime,
};
use fractonica_client_content::{ClientContentError, ClientContentStore};
use fractonica_client_sqlite::{
    ActiveWorkspace, ClientInstallation, ClientInstallationBinding, ClientSqliteStore,
    ClientStoreError, CommitResult, LocalEntitySummary, LocalRecordPreview, LocalRecordSummary,
    PeerConfig, PeerReadMode, PeerSpaceConfig, SyncTarget,
};
use fractonica_content::{ContentId, ContentValidationError, ResourceRef};
use fractonica_data_model::{
    ActorId, EntityId, EntitySchema, EventDocument, NodeId, OperationBody, OperationEnvelope,
    OperationId, ProfileDocument, ProtectedDocument, RecordDocument, SpaceId, TagDocument,
};
use fractonica_keystore::{FileKeyStore, FileKeyStoreError, IdentityBundle, KeyStore};
use fractonica_pairing::{
    InvitationId, JoinerClaim, PairingAcceptance, PairingInvitation, PairingReceipt,
};
use fractonica_peer::{PeerReadChangesFields, PeerReadChangesProof, PeerSessionId};
use fractonica_space_bootstrap::build_trusted_space_bootstrap;
use fractonica_sync::{
    NodeHttpTransport, PeerProofCustody, SyncConfig, SyncError, SyncStatus, SyncTransport,
    SyncWorker, TransportError,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use thiserror::Error;
use tokio::{sync::watch, task::JoinHandle};

const CLIENT_DATABASE_FILE: &str = "client.sqlite3";
const CLIENT_CONTENT_DIRECTORY: &str = "content";
pub const RECORD_MEDIA_ROLE: &str = "record.media";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrePairRecordPolicy {
    Merge,
    Discard,
}

/// Public, verified half of a pending pairing. Transport credentials and
/// signing material remain inside the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingClaim {
    pub invitation_id: String,
    pub responder_node_id: String,
    pub space_id: String,
    pub endpoint: String,
    pub confirmation_octal: String,
    pub grant_operation_id: String,
    pub local_record_count: u64,
}

#[derive(Clone)]
struct PendingPairing {
    claim: PairingClaim,
    invitation_id: InvitationId,
    responder_node_id: NodeId,
    space_id: SpaceId,
    endpoint: String,
    grant_operation_id: OperationId,
    peer_transport_credential: String,
    /// Exact signed acceptance bytes. Retries must replay this message rather
    /// than generate a fresh nonce after the responder may already have
    /// completed the one-shot invitation.
    acceptance: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SupervisedNodeConfig {
    pub client_data_dir: PathBuf,
    pub node_data_dir: PathBuf,
    pub endpoint: String,
    pub bearer_token: String,
    pub sync: SyncConfig,
}

#[derive(Clone, Debug)]
pub struct StandaloneClientConfig {
    pub client_data_dir: PathBuf,
    pub display_name: String,
}

/// State of the protected identity independently from the client database.
/// Corrupt or temporarily unavailable platform storage is reported as an
/// adapter error, never as `Missing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandaloneIdentityState {
    /// No identity material has been persisted.
    Missing,
    /// The adapter has recoverable partial state, but `load_existing` cannot
    /// yet return a complete bundle. `create_or_resume` must finish it.
    Initializing,
    /// A complete bundle is loadable. Platform adapters must report this even
    /// when they retain a separate outer marker that still needs finalizing.
    Established,
}

/// Native secure-storage work required after the database lifecycle marker is
/// durable. `identity_present` passed to [`ClientRuntime::prepare_standalone`]
/// means a complete, loadable bundle rather than a partial platform write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandaloneIdentityAction {
    CreateOrResume,
    OpenExisting,
}

/// Secure-storage port required by standalone clients.
///
/// Mobile adapters keep the seed bundle in Keychain or behind Android
/// Keystore protection. Only native/Rust code implements this port; JavaScript
/// never receives an [`IdentityBundle`].
pub trait StandaloneIdentityStore: Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    fn state(&self) -> Result<StandaloneIdentityState, Self::Error>;
    fn create_or_resume(&self) -> Result<IdentityBundle, Self::Error>;
    fn load_existing(&self) -> Result<IdentityBundle, Self::Error>;
}

impl StandaloneIdentityStore for FileKeyStore {
    type Error = FileKeyStoreError;

    fn state(&self) -> Result<StandaloneIdentityState, Self::Error> {
        match fs::symlink_metadata(self.identity_dir()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(StandaloneIdentityState::Missing)
            }
            Err(source) => Err(FileKeyStoreError::Io {
                action: "inspect standalone identity directory",
                path: self.identity_dir().to_owned(),
                source,
            }),
            Ok(_) => match FileKeyStore::load_existing(self) {
                Ok(_) => Ok(StandaloneIdentityState::Established),
                Err(FileKeyStoreError::IdentityNotEstablished(_)) => {
                    Ok(StandaloneIdentityState::Initializing)
                }
                Err(error) => Err(error),
            },
        }
    }

    fn create_or_resume(&self) -> Result<IdentityBundle, Self::Error> {
        KeyStore::load_or_create(self)
    }

    fn load_existing(&self) -> Result<IdentityBundle, Self::Error> {
        FileKeyStore::load_existing(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientRuntimeStatus {
    pub node_id: NodeId,
    pub actor_id: ActorId,
    pub space_id: SpaceId,
    pub sync: SyncStatus,
}

#[derive(Clone)]
struct EstablishedIdentityCustody {
    identity: Arc<IdentityBundle>,
}

impl ActorKeyCustody for EstablishedIdentityCustody {
    fn actor_id(&self) -> ActorId {
        self.identity.local_writer_actor_id()
    }

    fn sign_operation(&self, draft: &OperationDraft) -> Result<OperationEnvelope, KeyCustodyError> {
        OperationEnvelope::sign(
            draft.space_id,
            draft.entity_id,
            draft.schema,
            draft.causal_parents.clone(),
            draft.authorization.clone(),
            draft.occurred_at_unix_ms,
            draft.nonce,
            draft.body.clone(),
            self.identity.local_writer_key(),
        )
        .map_err(KeyCustodyError::from)
    }
}

impl PeerProofCustody for EstablishedIdentityCustody {
    fn sign_read(
        &self,
        fields: PeerReadChangesFields,
    ) -> Result<PeerReadChangesProof, TransportError> {
        PeerReadChangesProof::sign(
            fields,
            self.identity.node_transport_key(),
            self.identity.local_writer_key(),
        )
        .map_err(|error| TransportError::permanent(error.to_string()))
    }
}

type NativeAuthor = OperationAuthor<EstablishedIdentityCustody, SystemAuthoringRuntime>;

pub struct ClientRuntime {
    store: ClientSqliteStore,
    content: ClientContentStore,
    author: Mutex<Arc<NativeAuthor>>,
    custody: EstablishedIdentityCustody,
    node_id: NodeId,
    actor_id: ActorId,
    local_space_id: SpaceId,
    pending_pairings: Mutex<BTreeMap<String, PendingPairing>>,
    sync: RuntimeSync,
}

enum RuntimeSync {
    /// Standalone clients have no transport worker until a peer is paired.
    Static(Box<SyncStatus>),
    Worker {
        status: watch::Receiver<SyncStatus>,
        shutdown: watch::Sender<bool>,
        task: Mutex<Option<JoinHandle<()>>>,
    },
}

impl ClientRuntime {
    /// Persists and validates the database half of standalone initialization
    /// before native code creates or opens protected keys.
    pub async fn prepare_standalone(
        config: StandaloneClientConfig,
        identity_present: bool,
    ) -> Result<StandaloneIdentityAction, ClientRuntimeError> {
        blocking(move || prepare_standalone_blocking(&config, identity_present)).await
    }

    /// Establishes or reopens a self-owned client without contacting a node.
    ///
    /// The database enters its durable initializing phase before protected key
    /// creation. Both signed trust anchors and their public installation
    /// binding are then committed in one SQLite transaction. Record creation
    /// becomes available only after every stored identifier has been checked
    /// against the protected identity.
    pub async fn bootstrap_standalone<S>(
        config: StandaloneClientConfig,
        identities: Arc<S>,
    ) -> Result<Self, ClientRuntimeError>
    where
        S: StandaloneIdentityStore,
    {
        let (mut client, custody) =
            blocking(move || bootstrap_standalone_blocking(config, identities)).await?;
        client.start_sync_worker(custody, BTreeMap::new(), SyncConfig::default())?;
        Ok(client)
    }

    pub async fn bootstrap_supervised(
        config: SupervisedNodeConfig,
    ) -> Result<Self, ClientRuntimeError> {
        prepare_private_directory(&config.client_data_dir)?;
        let endpoint = validate_supervised_endpoint(&config.endpoint)?;
        let identity = Arc::new(
            FileKeyStore::new(config.node_data_dir.join("identity"))
                .load_existing()
                .map_err(|error| ClientRuntimeError::Identity(error.to_string()))?,
        );
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(http_error)?;
        let node: BootstrapNodeResponse =
            get_json(&client, &endpoint, "api/node", &config.bearer_token).await?;
        let (node_id, space) = validate_node_contract(&node, &identity)?;
        let genesis: StoredOperation = get_json(
            &client,
            &endpoint,
            &format!(
                "api/spaces/{}/operations/{}",
                space.space_id, space.genesis_operation_id
            ),
            &config.bearer_token,
        )
        .await?;
        let initial_grant: StoredOperation = get_json(
            &client,
            &endpoint,
            &format!(
                "api/spaces/{}/operations/{}",
                space.space_id, space.initial_grant_operation_id
            ),
            &config.bearer_token,
        )
        .await?;
        validate_bootstrap_anchors(&identity, &space, &genesis, &initial_grant)?;

        let store = ClientSqliteStore::open(config.client_data_dir.join(CLIENT_DATABASE_FILE))?;
        store.commit_remote(&genesis.operation, genesis.received_at_unix_ms)?;
        store.commit_remote(&initial_grant.operation, initial_grant.received_at_unix_ms)?;
        let now = unix_time_millis()?;
        store.upsert_peer(&PeerConfig {
            peer_id: node_id,
            endpoint: endpoint_origin(&endpoint),
            enabled: true,
            push_enabled: true,
            content_read_enabled: true,
            peer_transport_credential: None,
            added_at_unix_ms: now,
        })?;
        store.configure_peer_space(&PeerSpaceConfig {
            peer_id: node_id,
            space_id: space.space_id,
            read_mode: PeerReadMode::SupervisorBearer,
            start_after: 0,
            next_pull_at_unix_ms: now,
        })?;
        let active = match store.active_workspace()? {
            Some(active) => active,
            None => {
                let active = ActiveWorkspace {
                    space_id: space.space_id,
                    authorization_operation_id: space.initial_grant_operation_id,
                    peer_id: Some(node_id),
                    activated_at_unix_ms: now,
                };
                store.set_active_workspace(active)?;
                active
            }
        };
        if store
            .operation(active.authorization_operation_id)?
            .is_none()
        {
            return Err(ClientRuntimeError::MissingInstallationAnchor(
                active.authorization_operation_id,
            ));
        }

        let content =
            ClientContentStore::open(config.client_data_dir.join(CLIENT_CONTENT_DIRECTORY))?;
        let custody = EstablishedIdentityCustody {
            identity: Arc::clone(&identity),
        };
        let author = Arc::new(OperationAuthor::new(
            AuthoringContext::new(active.space_id, vec![active.authorization_operation_id])?,
            custody.clone(),
            SystemAuthoringRuntime,
        ));
        let mut tokens = BTreeMap::new();
        tokens.insert(node_id, config.bearer_token);
        let transport = NodeHttpTransport::new(custody.clone(), tokens)?;
        let (worker, sync_status) =
            SyncWorker::new(store.clone(), content.clone(), transport, config.sync)?;
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let sync_task = tokio::spawn(worker.run(shutdown_receiver));

        Ok(Self {
            store,
            content,
            author: Mutex::new(author),
            custody,
            node_id,
            actor_id: identity.local_writer_actor_id(),
            local_space_id: space.space_id,
            pending_pairings: Mutex::new(BTreeMap::new()),
            sync: RuntimeSync::Worker {
                status: sync_status,
                shutdown,
                task: Mutex::new(Some(sync_task)),
            },
        })
    }

    #[must_use]
    pub fn status(&self) -> ClientRuntimeStatus {
        let space_id = self
            .author
            .lock()
            .map(|author| author.context().space_id)
            .unwrap_or(self.local_space_id);
        ClientRuntimeStatus {
            node_id: self.node_id,
            actor_id: self.actor_id,
            space_id,
            sync: match &self.sync {
                RuntimeSync::Static(status) => status.as_ref().clone(),
                RuntimeSync::Worker { status, .. } => status.borrow().clone(),
            },
        }
    }

    #[must_use]
    pub const fn content_store(&self) -> &ClientContentStore {
        &self.content
    }

    /// Imports a native attachment into the immutable client content store.
    ///
    /// File access, hashing, and copying run on Tokio's blocking pool. The
    /// returned reference is validated against the wire protocol and always
    /// carries the canonical record-media role.
    pub async fn import_attachment(
        &self,
        path: PathBuf,
        media_type: String,
        original_name: Option<String>,
    ) -> Result<ResourceRef, ClientRuntimeError> {
        let content = self.content.clone();
        blocking(move || {
            let mut resource = ResourceRef {
                content_id: ContentId::new([0_u8; 32]),
                byte_length: 0,
                media_type,
                role: RECORD_MEDIA_ROLE.to_owned(),
                original_name,
            };
            resource.validate()?;

            let blob = content.import_file(path)?;
            resource.content_id = blob.descriptor.content_id;
            resource.byte_length = blob.descriptor.byte_length;
            resource.validate()?;
            Ok(resource)
        })
        .await
    }

    pub async fn create_record(
        &self,
        payload: ProtectedDocument<RecordDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let author = self.active_author()?;
        self.commit_authored(move || author.create_record(payload))
            .await
    }

    pub async fn update_record(
        &self,
        entity_id: EntityId,
        payload: ProtectedDocument<RecordDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        self.update_authored(entity_id, EntitySchema::Record, move |author, observed| {
            author.update_record(observed, payload)
        })
        .await
    }

    pub async fn create_event(
        &self,
        payload: ProtectedDocument<EventDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let author = self.active_author()?;
        self.commit_authored(move || author.create_event(payload))
            .await
    }

    pub async fn update_event(
        &self,
        entity_id: EntityId,
        payload: ProtectedDocument<EventDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        self.update_authored(entity_id, EntitySchema::Event, move |author, observed| {
            author.update_event(observed, payload)
        })
        .await
    }

    pub async fn create_tag(
        &self,
        payload: ProtectedDocument<TagDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let author = self.active_author()?;
        self.commit_authored(move || author.create_tag(payload))
            .await
    }

    pub async fn update_tag(
        &self,
        entity_id: EntityId,
        payload: ProtectedDocument<TagDocument>,
    ) -> Result<CommitResult, ClientRuntimeError> {
        self.update_authored(entity_id, EntitySchema::Tag, move |author, observed| {
            author.update_tag(observed, payload)
        })
        .await
    }

    pub async fn put_profile(
        &self,
        document: ProfileDocument,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let store = self.store.clone();
        let author = self.active_author()?;
        let actor_id = self.actor_id;
        let space_id = author.context().space_id;
        blocking(move || {
            let entity_id = fractonica_data_model::profile_entity_id(actor_id);
            let observed = observed_entity(&store, space_id, entity_id, EntitySchema::Profile)?;
            let operation = author.put_profile(observed.as_ref(), document)?;
            Ok(store.commit_local(&operation, operation.occurred_at_unix_ms)?)
        })
        .await
    }

    pub async fn delete(
        &self,
        entity_id: EntityId,
        schema: EntitySchema,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let store = self.store.clone();
        let author = self.active_author()?;
        let space_id = author.context().space_id;
        blocking(move || {
            let observed = observed_entity(&store, space_id, entity_id, schema)?
                .ok_or(ClientRuntimeError::EntityNotFound(entity_id))?;
            let operation = author.delete(&observed)?;
            Ok(store.commit_local(&operation, operation.occurred_at_unix_ms)?)
        })
        .await
    }

    pub async fn list(
        &self,
        schema: EntitySchema,
        limit: usize,
    ) -> Result<Vec<LocalEntitySummary>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.active_space_id()?;
        blocking(move || Ok(store.list_entities(space_id, schema, limit)?)).await
    }

    pub async fn list_records(
        &self,
        limit: usize,
    ) -> Result<Vec<LocalRecordSummary>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.active_space_id()?;
        blocking(move || Ok(store.list_records(space_id, limit)?)).await
    }

    pub async fn list_record_previews(
        &self,
        limit: usize,
    ) -> Result<Vec<LocalRecordPreview>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.active_space_id()?;
        blocking(move || Ok(store.list_record_previews(space_id, limit)?)).await
    }

    pub async fn record(
        &self,
        entity_id: EntityId,
        operation_id: OperationId,
    ) -> Result<Option<LocalRecordSummary>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.active_space_id()?;
        blocking(move || Ok(store.record(space_id, entity_id, operation_id)?)).await
    }

    /// Number of current records in the installation's original standalone
    /// space. This stays stable after pairing and is used to make the first
    /// workspace transition an explicit user decision.
    pub async fn pre_pair_record_count(&self) -> Result<u64, ClientRuntimeError> {
        if self.active_space_id()? != self.local_space_id {
            return Ok(0);
        }
        let store = self.store.clone();
        let space_id = self.local_space_id;
        blocking(move || Ok(store.record_import_count(space_id)?)).await
    }

    /// Claims a one-shot local-network invitation using the runtime's
    /// protected node and actor keys. The verified transcript remains pending
    /// until the user compares all ten octal digits and explicitly accepts it.
    pub async fn claim_pairing_invitation(
        &self,
        qr: String,
    ) -> Result<PairingClaim, ClientRuntimeError> {
        const MAX_PAIRING_QR_BYTES: usize = 8 * 1_024;
        if qr.is_empty() || qr.len() > MAX_PAIRING_QR_BYTES {
            return Err(ClientRuntimeError::InvalidPairingInvitation);
        }
        let now = unix_time_millis()?;
        let invitation = PairingInvitation::decode(&qr, now)
            .map_err(|_| ClientRuntimeError::InvalidPairingInvitation)?;
        let invitation_id = invitation.descriptor().invitation_id.to_string();
        if let Some(existing) = self
            .pending_pairings
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)?
            .get(&invitation_id)
            .cloned()
        {
            return Ok(existing.claim);
        }

        let mut pending =
            claim_pairing(invitation, now, Arc::clone(&self.custody.identity)).await?;
        pending.claim.local_record_count = self.pre_pair_record_count().await?;
        let claim = pending.claim.clone();
        self.pending_pairings
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)?
            .insert(invitation_id, pending);
        Ok(claim)
    }

    /// Completes a pending pairing after human transcript verification and
    /// persists the remote node as a bidirectional operation/media peer.
    pub async fn accept_pairing_invitation(
        &self,
        invitation_id: String,
        record_policy: PrePairRecordPolicy,
    ) -> Result<PairingClaim, ClientRuntimeError> {
        let pending = self
            .pending_pairings
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)?
            .get(&invitation_id)
            .cloned()
            .ok_or(ClientRuntimeError::PairingNotPending)?;
        accept_pairing(self, &pending, record_policy).await?;
        self.pending_pairings
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)?
            .remove(&invitation_id);
        Ok(pending.claim)
    }

    /// Persists a completed pairing as a bidirectional operation and media
    /// peer. The credential is Noise-delivered and scoped by the node to the
    /// completed pairing capability.
    pub async fn configure_paired_peer(
        &self,
        peer_id: NodeId,
        endpoint: String,
        space_id: SpaceId,
        session_id: PeerSessionId,
        grant_operation_id: OperationId,
        peer_transport_credential: String,
        record_policy: PrePairRecordPolicy,
    ) -> Result<(), ClientRuntimeError> {
        let endpoint = validate_paired_endpoint(&endpoint)?;
        let store = self.store.clone();
        let now = unix_time_millis()?;
        let endpoint = endpoint_origin(&endpoint);
        let peer = PeerConfig {
            peer_id,
            endpoint: endpoint.clone(),
            enabled: true,
            push_enabled: true,
            content_read_enabled: true,
            peer_transport_credential: Some(peer_transport_credential),
            added_at_unix_ms: now,
        };
        // `commit_from_peer` intentionally refuses operations attributed to
        // an unknown source. Register a dormant source record before the
        // bootstrap pull, but do not enable synchronization or persist the
        // Noise-delivered credential until the grant and import validate.
        // A failed first pairing may leave this harmless disabled row so that
        // already verified bootstrap operations retain a valid provenance.
        if store.peer(peer_id)?.is_none() {
            store.upsert_peer(&PeerConfig {
                peer_id,
                endpoint: endpoint.clone(),
                enabled: false,
                push_enabled: false,
                content_read_enabled: true,
                peer_transport_credential: None,
                added_at_unix_ms: now,
            })?;
        }
        // Pull from sequence zero before switching the authoring namespace.
        // This guarantees the remote genesis and exact admitted grant are
        // durable locally; a paired device never authors against an unseen
        // authority chain.
        let transport = NodeHttpTransport::new(self.custody.clone(), BTreeMap::new())?;
        let mut target = SyncTarget {
            peer_id,
            endpoint,
            space_id,
            read_mode: PeerReadMode::Paired {
                session_id,
                grant_operation_id,
            },
            after: 0,
            pull_failure_count: 0,
        };
        let mut admitted_grant = false;
        for _ in 0..1_024 {
            let page = transport
                .pull(
                    &target,
                    100,
                    unix_time_millis()?,
                    std::time::Duration::from_secs(10),
                )
                .await?;
            let next_after = page.next_after;
            let has_more = page.has_more;
            let operations = page.operations;
            let store_for_commit = store.clone();
            blocking(move || {
                for operation in operations {
                    store_for_commit.commit_from_peer(
                        &operation,
                        operation.occurred_at_unix_ms,
                        peer_id,
                    )?;
                }
                Ok(())
            })
            .await?;
            admitted_grant = store.operation(grant_operation_id)?.is_some();
            if admitted_grant || !has_more {
                break;
            }
            target.after = next_after;
        }
        if !admitted_grant {
            return Err(ClientRuntimeError::PairingBootstrap(
                "the paired node did not return the admitted capability grant",
            ));
        }
        let author = Arc::new(OperationAuthor::new(
            AuthoringContext::new(space_id, vec![grant_operation_id])?,
            self.custody.clone(),
            SystemAuthoringRuntime,
        ));
        if record_policy == PrePairRecordPolicy::Merge && self.local_space_id != space_id {
            let mut after_local_sequence = 0;
            loop {
                let source_store = store.clone();
                let source_space_id = self.local_space_id;
                let batch = blocking(move || {
                    Ok(source_store.record_import_batch(
                        source_space_id,
                        after_local_sequence,
                        100,
                    )?)
                })
                .await?;
                if batch.is_empty() {
                    break;
                }
                for record in &batch {
                    if let Some(existing) = store.entity(space_id, record.entity_id)? {
                        let already_imported = existing.heads.len() == 1
                            && matches!(
                                &existing.heads[0].body,
                                OperationBody::PutRecord { payload } if payload == &record.payload
                            );
                        if already_imported {
                            continue;
                        }
                        return Err(ClientRuntimeError::PairingImportCollision(record.entity_id));
                    }
                    let operation =
                        author.import_record(record.entity_id, record.payload.clone())?;
                    store.commit_local(&operation, operation.occurred_at_unix_ms)?;
                }
                after_local_sequence = batch
                    .last()
                    .map(|record| record.local_sequence)
                    .unwrap_or(after_local_sequence);
            }
        }
        // Only publish the new peer session after its grant and any requested
        // local import have succeeded. A failed re-pair therefore leaves the
        // previous peer configuration untouched instead of exposing a
        // half-configured credential/session to the background sync worker.
        let peer_for_store = peer.clone();
        blocking({
            let store = store.clone();
            move || {
                store.upsert_peer(&peer_for_store)?;
                store.configure_peer_space(&PeerSpaceConfig {
                    peer_id,
                    space_id,
                    read_mode: PeerReadMode::Paired {
                        session_id,
                        grant_operation_id,
                    },
                    start_after: 0,
                    next_pull_at_unix_ms: now,
                })?;
                Ok(())
            }
        })
        .await?;
        store.set_active_workspace(ActiveWorkspace {
            space_id,
            authorization_operation_id: grant_operation_id,
            peer_id: Some(peer_id),
            activated_at_unix_ms: unix_time_millis()?,
        })?;
        *self
            .author
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)? = author;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), ClientRuntimeError> {
        self.request_shutdown();
        let task = match &self.sync {
            RuntimeSync::Static(_) => None,
            RuntimeSync::Worker { task, .. } => task
                .lock()
                .map_err(|_| ClientRuntimeError::LifecycleLock)?
                .take(),
        };
        if let Some(task) = task {
            task.await
                .map_err(|error| ClientRuntimeError::Join(error.to_string()))?;
        }
        Ok(())
    }

    pub fn request_shutdown(&self) {
        if let RuntimeSync::Worker { shutdown, .. } = &self.sync {
            let _ = shutdown.send(true);
        }
    }

    async fn commit_authored(
        &self,
        author_operation: impl FnOnce() -> Result<OperationEnvelope, fractonica_client::ClientError>
        + Send
        + 'static,
    ) -> Result<CommitResult, ClientRuntimeError> {
        let store = self.store.clone();
        blocking(move || {
            let operation = author_operation()?;
            Ok(store.commit_local(&operation, operation.occurred_at_unix_ms)?)
        })
        .await
    }

    async fn update_authored<F>(
        &self,
        entity_id: EntityId,
        schema: EntitySchema,
        update: F,
    ) -> Result<CommitResult, ClientRuntimeError>
    where
        F: FnOnce(
                &NativeAuthor,
                &ObservedEntity,
            ) -> Result<OperationEnvelope, fractonica_client::ClientError>
            + Send
            + 'static,
    {
        let store = self.store.clone();
        let author = self.active_author()?;
        let space_id = author.context().space_id;
        blocking(move || {
            let observed = observed_entity(&store, space_id, entity_id, schema)?
                .ok_or(ClientRuntimeError::EntityNotFound(entity_id))?;
            let operation = update(&author, &observed)?;
            Ok(store.commit_local(&operation, operation.occurred_at_unix_ms)?)
        })
        .await
    }

    fn active_author(&self) -> Result<Arc<NativeAuthor>, ClientRuntimeError> {
        self.author
            .lock()
            .map(|author| Arc::clone(&author))
            .map_err(|_| ClientRuntimeError::LifecycleLock)
    }

    fn active_space_id(&self) -> Result<SpaceId, ClientRuntimeError> {
        Ok(self.active_author()?.context().space_id)
    }

    fn start_sync_worker(
        &mut self,
        custody: EstablishedIdentityCustody,
        bearer_tokens: BTreeMap<NodeId, String>,
        config: SyncConfig,
    ) -> Result<(), ClientRuntimeError> {
        let transport = NodeHttpTransport::new(custody, bearer_tokens)?;
        let (worker, status) =
            SyncWorker::new(self.store.clone(), self.content.clone(), transport, config)?;
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(worker.run(shutdown_receiver));
        self.sync = RuntimeSync::Worker {
            status,
            shutdown,
            task: Mutex::new(Some(task)),
        };
        Ok(())
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        if let RuntimeSync::Worker { shutdown, .. } = &self.sync {
            let _ = shutdown.send(true);
        }
    }
}

fn bootstrap_standalone_blocking<S: StandaloneIdentityStore>(
    config: StandaloneClientConfig,
    identities: Arc<S>,
) -> Result<(ClientRuntime, EstablishedIdentityCustody), ClientRuntimeError> {
    let identity_state = identities
        .state()
        .map_err(|error| ClientRuntimeError::Identity(error.to_string()))?;
    let identity_present = identity_state == StandaloneIdentityState::Established;
    let action = prepare_standalone_blocking(&config, identity_present)?;
    let identity = match action {
        StandaloneIdentityAction::CreateOrResume => identities.create_or_resume(),
        StandaloneIdentityAction::OpenExisting => identities.load_existing(),
    }
    .map_err(|error| ClientRuntimeError::Identity(error.to_string()))?;
    let database_path = config.client_data_dir.join(CLIENT_DATABASE_FILE);
    let store = ClientSqliteStore::open(&database_path)?;
    let binding = match store.installation()? {
        ClientInstallation::Unbound => {
            return Err(ClientRuntimeError::StandaloneRecovery(
                "standalone database preparation did not persist its initializing marker",
            ));
        }
        ClientInstallation::Initializing => {
            establish_standalone(&store, &identity, &config.display_name)?
        }
        ClientInstallation::Established(binding) => {
            validate_standalone_binding(&store, &identity, &binding)?;
            *binding
        }
    };
    validate_standalone_binding(&store, &identity, &binding)?;

    let content = ClientContentStore::open(config.client_data_dir.join(CLIENT_CONTENT_DIRECTORY))?;
    let identity = Arc::new(identity);
    let custody = EstablishedIdentityCustody {
        identity: Arc::clone(&identity),
    };
    let now = unix_time_millis()?;
    let active = match store.active_workspace()? {
        Some(active) => active,
        None => {
            let active = ActiveWorkspace {
                space_id: binding.space_id,
                authorization_operation_id: binding.initial_grant_operation_id,
                peer_id: None,
                activated_at_unix_ms: now,
            };
            store.set_active_workspace(active)?;
            active
        }
    };
    if store
        .operation(active.authorization_operation_id)?
        .is_none()
    {
        return Err(ClientRuntimeError::MissingInstallationAnchor(
            active.authorization_operation_id,
        ));
    }
    let author = Arc::new(OperationAuthor::new(
        AuthoringContext::new(active.space_id, vec![active.authorization_operation_id])?,
        custody.clone(),
        SystemAuthoringRuntime,
    ));
    let sync = SyncStatus {
        counts: Some(store.sync_counts(now)?),
        ..SyncStatus::default()
    };
    Ok((
        ClientRuntime {
            store,
            content,
            author: Mutex::new(author),
            custody: custody.clone(),
            node_id: binding.node_id,
            actor_id: binding.local_writer_actor_id,
            local_space_id: binding.space_id,
            pending_pairings: Mutex::new(BTreeMap::new()),
            sync: RuntimeSync::Static(Box::new(sync)),
        },
        custody,
    ))
}

fn prepare_standalone_blocking(
    config: &StandaloneClientConfig,
    identity_present: bool,
) -> Result<StandaloneIdentityAction, ClientRuntimeError> {
    prepare_private_directory(&config.client_data_dir)?;
    let database_path = config.client_data_dir.join(CLIENT_DATABASE_FILE);
    let database_preexisting = inspect_client_database(&database_path)?;
    if !database_preexisting && identity_present {
        return Err(ClientRuntimeError::StandaloneRecovery(
            "protected identity exists without its client database",
        ));
    }
    let store = ClientSqliteStore::open(database_path)?;
    match store.installation()? {
        ClientInstallation::Unbound if identity_present => {
            Err(ClientRuntimeError::StandaloneRecovery(
                "an unbound client database cannot adopt an existing identity",
            ))
        }
        ClientInstallation::Unbound => {
            store.begin_local_installation()?;
            Ok(StandaloneIdentityAction::CreateOrResume)
        }
        ClientInstallation::Initializing if identity_present => {
            Ok(StandaloneIdentityAction::OpenExisting)
        }
        ClientInstallation::Initializing => Ok(StandaloneIdentityAction::CreateOrResume),
        ClientInstallation::Established(_) if identity_present => {
            Ok(StandaloneIdentityAction::OpenExisting)
        }
        ClientInstallation::Established(_) => Err(ClientRuntimeError::StandaloneRecovery(
            "established client database has no established protected identity",
        )),
    }
}

fn establish_standalone(
    store: &ClientSqliteStore,
    identity: &IdentityBundle,
    display_name: &str,
) -> Result<ClientInstallationBinding, ClientRuntimeError> {
    let bootstrap = build_trusted_space_bootstrap(identity, display_name, unix_time_millis()?)?;
    Ok(store
        .establish_local_space(identity.node_id(), &bootstrap)?
        .binding)
}

fn validate_standalone_binding(
    store: &ClientSqliteStore,
    identity: &IdentityBundle,
    binding: &ClientInstallationBinding,
) -> Result<(), ClientRuntimeError> {
    if binding.node_id != identity.node_id()
        || binding.space_id != identity.space_id()
        || binding.controller_actor_id != identity.space_controller_actor_id()
        || binding.local_writer_actor_id != identity.local_writer_actor_id()
    {
        return Err(ClientRuntimeError::StandaloneRecovery(
            "protected identity does not match the established client binding",
        ));
    }
    let genesis = store.operation(binding.genesis_operation_id)?.ok_or(
        ClientRuntimeError::MissingInstallationAnchor(binding.genesis_operation_id),
    )?;
    let initial_grant = store.operation(binding.initial_grant_operation_id)?.ok_or(
        ClientRuntimeError::MissingInstallationAnchor(binding.initial_grant_operation_id),
    )?;
    let bootstrap = TrustedSpaceBootstrapRequest {
        display_name: binding.display_name.clone(),
        genesis,
        initial_grant,
        received_at_unix_ms: binding.created_at_unix_ms,
    };
    validate_trusted_space_bootstrap(&bootstrap)
        .map_err(|error| ClientRuntimeError::InvalidInstallationAnchor(error.to_string()))?;
    let expected = installation_binding_from_request(identity.node_id(), &bootstrap)?;
    if &expected != binding {
        return Err(ClientRuntimeError::StandaloneRecovery(
            "stored trust anchors do not match the established client binding",
        ));
    }
    Ok(())
}

fn installation_binding_from_request(
    node_id: NodeId,
    request: &TrustedSpaceBootstrapRequest,
) -> Result<ClientInstallationBinding, ClientRuntimeError> {
    let OperationBody::SpaceGenesis { controller } = &request.genesis.body else {
        return Err(ClientRuntimeError::InvalidInstallationAnchor(
            "genesis body has the wrong kind".into(),
        ));
    };
    let OperationBody::CapabilityGrant { grant } = &request.initial_grant.body else {
        return Err(ClientRuntimeError::InvalidInstallationAnchor(
            "initial grant body has the wrong kind".into(),
        ));
    };
    Ok(ClientInstallationBinding {
        node_id,
        space_id: request.genesis.space_id,
        controller_actor_id: *controller,
        local_writer_actor_id: grant.subject,
        genesis_operation_id: request.genesis.operation_id,
        initial_grant_operation_id: request.initial_grant.operation_id,
        display_name: request.display_name.clone(),
        created_at_unix_ms: request.received_at_unix_ms,
    })
}

fn inspect_client_database(path: &Path) -> Result<bool, ClientRuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(ClientRuntimeError::StandaloneRecovery(
            "client database path is not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ClientRuntimeError::Io(error)),
    }
}

fn observed_entity(
    store: &ClientSqliteStore,
    space_id: SpaceId,
    entity_id: EntityId,
    schema: EntitySchema,
) -> Result<Option<ObservedEntity>, ClientRuntimeError> {
    let Some(entity) = store.entity(space_id, entity_id)? else {
        return Ok(None);
    };
    if entity.schema != schema {
        return Err(ClientRuntimeError::SchemaMismatch {
            expected: schema,
            found: entity.schema,
        });
    }
    Ok(Some(ObservedEntity::new(
        space_id,
        entity_id,
        schema,
        entity
            .heads
            .iter()
            .map(|operation| operation.operation_id)
            .collect(),
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapNodeResponse {
    node_id: Option<NodeId>,
    spaces: Option<Vec<SpaceDescriptor>>,
    profile: String,
}

fn validate_node_contract(
    node: &BootstrapNodeResponse,
    identity: &IdentityBundle,
) -> Result<(NodeId, SpaceDescriptor), ClientRuntimeError> {
    if node.profile != "node" {
        return Err(contract(
            "supervised client runtime requires a node profile",
        ));
    }
    let node_id = node
        .node_id
        .ok_or_else(|| contract("node omitted its identity"))?;
    if node_id != identity.node_id() {
        return Err(contract(
            "node identity does not match protected installation keys",
        ));
    }
    let matches = node
        .spaces
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|space| space.space_id == identity.space_id())
        .cloned()
        .collect::<Vec<_>>();
    let [space] = matches.as_slice() else {
        return Err(contract(
            "node must expose exactly one descriptor for its protected default space",
        ));
    };
    if space.local_writer_actor_id != identity.local_writer_actor_id()
        || space.controller_actor_id != identity.space_controller_actor_id()
    {
        return Err(contract(
            "space descriptor does not match protected writer/controller keys",
        ));
    }
    Ok((node_id, space.clone()))
}

fn validate_bootstrap_anchors(
    identity: &IdentityBundle,
    space: &SpaceDescriptor,
    genesis: &StoredOperation,
    grant: &StoredOperation,
) -> Result<(), ClientRuntimeError> {
    genesis
        .operation
        .verify()
        .map_err(|error| contract(error.to_string()))?;
    grant
        .operation
        .verify()
        .map_err(|error| contract(error.to_string()))?;
    let genesis_matches = genesis.operation.operation_id == space.genesis_operation_id
        && genesis.operation.space_id == space.space_id
        && genesis.operation.actor_id == identity.space_controller_actor_id()
        && matches!(
            genesis.operation.body,
            OperationBody::SpaceGenesis { controller }
                if controller == identity.space_controller_actor_id()
        );
    let grant_matches = grant.operation.operation_id == space.initial_grant_operation_id
        && grant.operation.space_id == space.space_id
        && grant.operation.actor_id == identity.space_controller_actor_id()
        && grant.operation.authorization.as_slice() == [space.genesis_operation_id]
        && matches!(
            &grant.operation.body,
            OperationBody::CapabilityGrant { grant }
                if grant.subject == identity.local_writer_actor_id()
        );
    if !genesis_matches || !grant_matches {
        return Err(contract(
            "downloaded bootstrap operations do not match the advertised trust anchors",
        ));
    }
    Ok(())
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    endpoint: &Url,
    path: &str,
    bearer_token: &str,
) -> Result<T, ClientRuntimeError> {
    let url = endpoint
        .join(path)
        .map_err(|error| contract(format!("invalid node route: {error}")))?;
    let response = client
        .get(url)
        .bearer_auth(bearer_token)
        .send()
        .await
        .map_err(http_error)?;
    if !response.status().is_success() {
        return Err(ClientRuntimeError::Http(format!(
            "supervised node returned HTTP {}",
            response.status()
        )));
    }
    response.json().await.map_err(http_error)
}

fn validate_supervised_endpoint(value: &str) -> Result<Url, ClientRuntimeError> {
    let url = Url::parse(value).map_err(|error| contract(format!("invalid endpoint: {error}")))?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(contract(
            "supervised endpoint must be a plain HTTP loopback origin",
        ));
    }
    Ok(url)
}

fn validate_paired_endpoint(value: &str) -> Result<Url, ClientRuntimeError> {
    let url = Url::parse(value).map_err(|error| contract(format!("invalid endpoint: {error}")))?;
    let local_network = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|address| match address {
                IpAddr::V4(address) => {
                    address.is_loopback() || address.is_private() || address.is_link_local()
                }
                IpAddr::V6(address) => {
                    address.is_loopback()
                        || address.is_unique_local()
                        || address.is_unicast_link_local()
                }
            })
    });
    if url.scheme() != "http"
        || !local_network
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(contract(
            "paired endpoint must be a plain HTTP local-network origin",
        ));
    }
    Ok(url)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingHandshakeResponse {
    response_frame_base64url: String,
    receipt_frame_base64url: String,
    session: PairingSessionResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairingSessionResponse {
    invitation_id: String,
    space_id: String,
    state: String,
    expires_at_unix_ms: i64,
    joiner_node_id: Option<String>,
    subject_actor_id: Option<String>,
    confirmation_octal: Option<String>,
    grant_operation_id: Option<String>,
}

async fn claim_pairing(
    invitation: PairingInvitation,
    now: i64,
    identity: Arc<IdentityBundle>,
) -> Result<PendingPairing, ClientRuntimeError> {
    let descriptor = invitation.descriptor();
    let endpoints = descriptor
        .endpoint_hints
        .iter()
        .filter_map(|hint| validate_paired_endpoint(hint).ok())
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return Err(ClientRuntimeError::InvalidPairingInvitation);
    }

    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| ClientRuntimeError::RandomSourceUnavailable)?;
    let claim = JoinerClaim::sign(
        descriptor,
        identity.node_transport_key(),
        identity.local_writer_key(),
        nonce,
    );
    let mut handshake = invitation
        .start_initiator(now)
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let first_frame = handshake
        .write_message(
            &claim
                .canonical_bytes()
                .map_err(|_| ClientRuntimeError::PairingFailed)?,
        )
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let request = serde_json::json!({
        "invitationId": descriptor.invitation_id.to_string(),
        "frameBase64url": URL_SAFE_NO_PAD.encode(&first_frame),
    });

    // iOS can suspend the original request while presenting its local-network
    // permission sheet. The responder durably replays the exact Noise response
    // for this exact frame, so retrying here is safe even if the first response
    // was lost after the invitation had already been claimed.
    let mut response = None;
    for attempt in 0..5_u32 {
        let mut requests = tokio::task::JoinSet::new();
        for endpoint in &endpoints {
            let endpoint = endpoint.clone();
            let url = endpoint
                .join("api/pairing/handshake")
                .map_err(|_| ClientRuntimeError::InvalidPairingInvitation)?;
            let client = client.clone();
            let request = request.clone();
            requests.spawn(async move {
                let result = client.post(url).json(&request).send().await;
                (endpoint, result)
            });
        }
        while let Some(result) = requests.join_next().await {
            if let Ok((endpoint, result)) = result {
                match result {
                    Ok(value) if value.status().is_success() => {
                        requests.abort_all();
                        response = Some((endpoint, value));
                        break;
                    }
                    Ok(value) => eprintln!(
                        "Fractonica pairing endpoint {endpoint} rejected the handshake with HTTP {}",
                        value.status()
                    ),
                    Err(error) => eprintln!(
                        "Fractonica pairing endpoint {endpoint} was unreachable: {error}"
                    ),
                }
            }
        }
        if response.is_some() {
            break;
        }
        if attempt < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(
                500_u64.saturating_mul(u64::from(attempt + 1)),
            ))
            .await;
        }
    }
    let (endpoint, response) = response.ok_or(ClientRuntimeError::PairingFailed)?;
    let response: PairingHandshakeResponse = response
        .json()
        .await
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let response_frame = URL_SAFE_NO_PAD
        .decode(response.response_frame_base64url)
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let receipt_frame = URL_SAFE_NO_PAD
        .decode(response.receipt_frame_base64url)
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    if !handshake
        .read_message(&response_frame)
        .map_err(|_| ClientRuntimeError::PairingFailed)?
        .is_empty()
    {
        return Err(ClientRuntimeError::PairingFailed);
    }
    let mut transport = handshake
        .finish()
        .map_err(|_| ClientRuntimeError::PairingFailed)?;
    let receipt = PairingReceipt::from_canonical_bytes(
        &transport
            .read_message(&receipt_frame)
            .map_err(|_| ClientRuntimeError::PairingFailed)?,
    )
    .map_err(|_| ClientRuntimeError::PairingFailed)?;
    receipt
        .verify_for(descriptor, &claim, transport.handshake_hash())
        .map_err(|_| ClientRuntimeError::PairingFailed)?;

    let session = response.session;
    let confirmation = transport.confirmation_octal().to_owned();
    let expected_joiner_node_id = identity.node_id().to_string();
    let expected_subject_actor_id = identity.local_writer_actor_id().to_string();
    let grant_operation_id = session
        .grant_operation_id
        .ok_or(ClientRuntimeError::PairingFailed)?;
    if session.invitation_id != descriptor.invitation_id.to_string()
        || session.space_id != descriptor.space_id.to_string()
        || session.state != "claimed"
        || session.expires_at_unix_ms != descriptor.expires_at_unix_ms
        || session.joiner_node_id.as_deref() != Some(expected_joiner_node_id.as_str())
        || session.subject_actor_id.as_deref() != Some(expected_subject_actor_id.as_str())
        || session.confirmation_octal.as_deref() != Some(confirmation.as_str())
        || OperationId::parse(&grant_operation_id).is_err()
    {
        return Err(ClientRuntimeError::PairingFailed);
    }

    let endpoint = endpoint_origin(&endpoint);
    let public = PairingClaim {
        invitation_id: descriptor.invitation_id.to_string(),
        responder_node_id: descriptor.responder_node_id.to_string(),
        space_id: descriptor.space_id.to_string(),
        endpoint: endpoint.clone(),
        confirmation_octal: confirmation,
        grant_operation_id: grant_operation_id.clone(),
        local_record_count: 0,
    };
    let mut acceptance_nonce = [0_u8; 32];
    getrandom::fill(&mut acceptance_nonce)
        .map_err(|_| ClientRuntimeError::RandomSourceUnavailable)?;
    let parsed_grant_operation_id =
        OperationId::parse(&grant_operation_id).map_err(|_| ClientRuntimeError::PairingFailed)?;
    let acceptance = PairingAcceptance::sign(
        descriptor.invitation_id,
        claim.digest(),
        *transport.handshake_hash(),
        descriptor.responder_node_id,
        descriptor.space_id,
        parsed_grant_operation_id,
        identity.node_transport_key(),
        identity.local_writer_key(),
        acceptance_nonce,
    )
    .canonical_bytes()
    .map_err(|_| ClientRuntimeError::PairingFailed)?;
    Ok(PendingPairing {
        claim: public,
        invitation_id: descriptor.invitation_id,
        responder_node_id: descriptor.responder_node_id,
        space_id: descriptor.space_id,
        endpoint,
        grant_operation_id: parsed_grant_operation_id,
        peer_transport_credential: format!(
            "{}.{}",
            descriptor.invitation_id,
            URL_SAFE_NO_PAD.encode(receipt.peer_access_token())
        ),
        acceptance,
    })
}

async fn accept_pairing(
    runtime: &ClientRuntime,
    pending: &PendingPairing,
    record_policy: PrePairRecordPolicy,
) -> Result<(), ClientRuntimeError> {
    let identity = &runtime.custody.identity;
    let endpoint = Url::parse(&pending.endpoint).map_err(|error| {
        ClientRuntimeError::PairingCompletion(format!("invalid responder endpoint: {error}"))
    })?;
    let url = endpoint
        .join(&format!(
            "api/pairing/invitations/{}/accept",
            pending.invitation_id
        ))
        .map_err(|error| {
            ClientRuntimeError::PairingCompletion(format!("invalid acceptance route: {error}"))
        })?;
    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| {
            ClientRuntimeError::PairingCompletion(format!("HTTP client setup failed: {error}"))
        })?;
    let request = serde_json::json!({
        "acceptanceBase64url": URL_SAFE_NO_PAD.encode(&pending.acceptance),
    });
    let mut response = None;
    let mut last_failure = "responder did not return a successful acceptance".to_owned();
    for attempt in 0..5_u32 {
        match client.post(url.clone()).json(&request).send().await {
            Ok(value) if value.status().is_success() => {
                response = Some(value);
                break;
            }
            // A responder may have completed the invitation even when its
            // response was lost. Retrying the exact signed acceptance is
            // idempotent; the completed session is returned on replay.
            Ok(value) if attempt < 4 => {
                last_failure = format!("responder returned HTTP {}", value.status());
                tokio::time::sleep(std::time::Duration::from_millis(
                    400_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Err(error) if attempt < 4 => {
                last_failure = format!("responder was unreachable: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(
                    400_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Ok(value) => {
                last_failure = format!("responder returned HTTP {}", value.status());
                break;
            }
            Err(error) => {
                last_failure = format!("responder was unreachable: {error}");
                break;
            }
        }
    }
    let response = response.ok_or(ClientRuntimeError::PairingCompletion(last_failure))?;
    eprintln!(
        "Fractonica pairing acceptance acknowledged by responder {}; validating completed session",
        pending.endpoint
    );
    let session: PairingSessionResponse = response
        .json()
        .await
        .map_err(|error| {
            ClientRuntimeError::PairingCompletion(format!(
                "responder returned an invalid completed session: {error}"
            ))
        })?;
    if session.invitation_id != pending.claim.invitation_id
        || session.space_id != pending.claim.space_id
        || session.state != "completed"
        || session.joiner_node_id.as_deref() != Some(identity.node_id().to_string().as_str())
        || session.subject_actor_id.as_deref()
            != Some(identity.local_writer_actor_id().to_string().as_str())
        || session.confirmation_octal.as_deref() != Some(pending.claim.confirmation_octal.as_str())
        || session.grant_operation_id.as_deref() != Some(pending.claim.grant_operation_id.as_str())
    {
        return Err(ClientRuntimeError::PairingCompletion(
            "completed session did not match the authenticated claim".to_owned(),
        ));
    }
    let session_id: PeerSessionId = pending
        .claim
        .invitation_id
        .parse()
        .map_err(|error| {
            ClientRuntimeError::PairingCompletion(format!(
                "completed session identifier is invalid: {error}"
            ))
        })?;
    eprintln!(
        "Fractonica pairing session validated; bootstrapping admitted workspace from {}",
        pending.endpoint
    );
    let result = runtime
        .configure_paired_peer(
            pending.responder_node_id,
            pending.endpoint.clone(),
            pending.space_id,
            session_id,
            pending.grant_operation_id,
            pending.peer_transport_credential.clone(),
            record_policy,
        )
        .await;
    if let Err(error) = &result {
        eprintln!(
            "Fractonica pairing workspace bootstrap failed for {}: {error}",
            pending.endpoint
        );
    }
    result
}

fn endpoint_origin(endpoint: &Url) -> String {
    let mut origin = endpoint.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    origin.to_string().trim_end_matches('/').to_owned()
}

fn unix_time_millis() -> Result<i64, ClientRuntimeError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClientRuntimeError::Clock)?
        .as_millis();
    i64::try_from(value).map_err(|_| ClientRuntimeError::Clock)
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ClientRuntimeError> + Send + 'static,
) -> Result<T, ClientRuntimeError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| ClientRuntimeError::Join(error.to_string()))?
}

fn prepare_private_directory(path: &Path) -> Result<(), ClientRuntimeError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ClientRuntimeError::UnsafeClientDataDirectory(
                "path is a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ClientRuntimeError::UnsafeClientDataDirectory(
                "path is not a directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ClientRuntimeError::UnsafeClientDataDirectory(
                    "created path was replaced by a symbolic link or non-directory",
                ));
            }
        }
        Err(error) => return Err(ClientRuntimeError::Io(error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn http_error(error: reqwest::Error) -> ClientRuntimeError {
    ClientRuntimeError::Http(error.to_string())
}

fn contract(detail: impl Into<String>) -> ClientRuntimeError {
    ClientRuntimeError::NodeContract(detail.into())
}

#[derive(Debug, Error)]
pub enum ClientRuntimeError {
    #[error("failed to prepare client storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("client data directory is unsafe: {0}")]
    UnsafeClientDataDirectory(&'static str),
    #[error("protected identity is unavailable: {0}")]
    Identity(String),
    #[error("standalone client requires explicit recovery: {0}")]
    StandaloneRecovery(&'static str),
    #[error("standalone space bootstrap failed: {0}")]
    Bootstrap(#[from] fractonica_space_bootstrap::BootstrapBuildError),
    #[error("standalone installation anchor {0} is missing")]
    MissingInstallationAnchor(OperationId),
    #[error("standalone installation anchor is invalid: {0}")]
    InvalidInstallationAnchor(String),
    #[error("supervised node request failed: {0}")]
    Http(String),
    #[error("supervised node contract is invalid: {0}")]
    NodeContract(String),
    #[error("client store failed: {0}")]
    Store(#[from] ClientStoreError),
    #[error("client content store failed: {0}")]
    Content(#[from] ClientContentError),
    #[error("attachment reference is invalid: {0}")]
    ResourceValidation(#[from] ContentValidationError),
    #[error("client authoring failed: {0}")]
    Authoring(#[from] fractonica_client::ClientError),
    #[error("synchronization setup failed: {0}")]
    Sync(#[from] SyncError),
    #[error("transport setup failed: {0}")]
    Transport(#[from] TransportError),
    #[error("entity {0} is not available locally")]
    EntityNotFound(EntityId),
    #[error("entity schema mismatch: expected {expected:?}, found {found:?}")]
    SchemaMismatch {
        expected: EntitySchema,
        found: EntitySchema,
    },
    #[error("system clock is unavailable")]
    Clock,
    #[error("background task failed: {0}")]
    Join(String),
    #[error("client lifecycle lock was poisoned")]
    LifecycleLock,
    #[error("paired workspace bootstrap failed: {0}")]
    PairingBootstrap(&'static str),
    #[error("local record {0} already exists in the paired workspace")]
    PairingImportCollision(EntityId),
    #[error("pairing invitation is invalid or unsafe for local-network transport")]
    InvalidPairingInvitation,
    #[error("pairing ceremony failed")]
    PairingFailed,
    #[error("pairing completion failed: {0}")]
    PairingCompletion(String),
    #[error("pairing invitation is not pending human confirmation")]
    PairingNotPending,
    #[error("secure random source is unavailable")]
    RandomSourceUnavailable,
}

#[cfg(test)]
mod tests;
