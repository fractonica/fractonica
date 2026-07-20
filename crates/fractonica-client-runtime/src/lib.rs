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
    ClientInstallation, ClientInstallationBinding, ClientSqliteStore, ClientStoreError,
    CommitResult, LocalEntitySummary, LocalRecordPreview, LocalRecordSummary, PeerConfig,
    PeerReadMode, PeerSpaceConfig,
};
use fractonica_content::{ContentId, ContentValidationError, ResourceRef};
use fractonica_data_model::{
    ActorId, EntityId, EntitySchema, EventDocument, NodeId, OperationBody, OperationEnvelope,
    OperationId, ProfileDocument, ProtectedDocument, RecordDocument, SpaceId, TagDocument,
};
use fractonica_keystore::{FileKeyStore, FileKeyStoreError, IdentityBundle, KeyStore};
use fractonica_peer::{PeerReadChangesFields, PeerReadChangesProof};
use fractonica_space_bootstrap::build_trusted_space_bootstrap;
use fractonica_sync::{
    NodeHttpTransport, PeerProofCustody, SyncConfig, SyncError, SyncStatus, SyncWorker,
    TransportError,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use thiserror::Error;
use tokio::{sync::watch, task::JoinHandle};

const CLIENT_DATABASE_FILE: &str = "client.sqlite3";
const CLIENT_CONTENT_DIRECTORY: &str = "content";
pub const RECORD_MEDIA_ROLE: &str = "record.media";

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
    author: Arc<NativeAuthor>,
    node_id: NodeId,
    actor_id: ActorId,
    space_id: SpaceId,
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
        blocking(move || bootstrap_standalone_blocking(config, identities)).await
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
            added_at_unix_ms: now,
        })?;
        store.configure_peer_space(&PeerSpaceConfig {
            peer_id: node_id,
            space_id: space.space_id,
            read_mode: PeerReadMode::SupervisorBearer,
            start_after: 0,
            next_pull_at_unix_ms: now,
        })?;

        let content =
            ClientContentStore::open(config.client_data_dir.join(CLIENT_CONTENT_DIRECTORY))?;
        let custody = EstablishedIdentityCustody {
            identity: Arc::clone(&identity),
        };
        let author = Arc::new(OperationAuthor::new(
            AuthoringContext::new(space.space_id, vec![space.initial_grant_operation_id])?,
            custody.clone(),
            SystemAuthoringRuntime,
        ));
        let mut tokens = BTreeMap::new();
        tokens.insert(node_id, config.bearer_token);
        let transport = NodeHttpTransport::new(custody, tokens)?;
        let (worker, sync_status) =
            SyncWorker::new(store.clone(), content.clone(), transport, config.sync)?;
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let sync_task = tokio::spawn(worker.run(shutdown_receiver));

        Ok(Self {
            store,
            content,
            author,
            node_id,
            actor_id: identity.local_writer_actor_id(),
            space_id: space.space_id,
            sync: RuntimeSync::Worker {
                status: sync_status,
                shutdown,
                task: Mutex::new(Some(sync_task)),
            },
        })
    }

    #[must_use]
    pub fn status(&self) -> ClientRuntimeStatus {
        ClientRuntimeStatus {
            node_id: self.node_id,
            actor_id: self.actor_id,
            space_id: self.space_id,
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
        let author = Arc::clone(&self.author);
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
        let author = Arc::clone(&self.author);
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
        let author = Arc::clone(&self.author);
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
        let author = Arc::clone(&self.author);
        let actor_id = self.actor_id;
        let space_id = self.space_id;
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
        let author = Arc::clone(&self.author);
        let space_id = self.space_id;
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
        let space_id = self.space_id;
        blocking(move || Ok(store.list_entities(space_id, schema, limit)?)).await
    }

    pub async fn list_records(
        &self,
        limit: usize,
    ) -> Result<Vec<LocalRecordSummary>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.space_id;
        blocking(move || Ok(store.list_records(space_id, limit)?)).await
    }

    pub async fn list_record_previews(
        &self,
        limit: usize,
    ) -> Result<Vec<LocalRecordPreview>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.space_id;
        blocking(move || Ok(store.list_record_previews(space_id, limit)?)).await
    }

    pub async fn record(
        &self,
        entity_id: EntityId,
        operation_id: OperationId,
    ) -> Result<Option<LocalRecordSummary>, ClientRuntimeError> {
        let store = self.store.clone();
        let space_id = self.space_id;
        blocking(move || Ok(store.record(space_id, entity_id, operation_id)?)).await
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
        let author = Arc::clone(&self.author);
        let space_id = self.space_id;
        blocking(move || {
            let observed = observed_entity(&store, space_id, entity_id, schema)?
                .ok_or(ClientRuntimeError::EntityNotFound(entity_id))?;
            let operation = update(&author, &observed)?;
            Ok(store.commit_local(&operation, operation.occurred_at_unix_ms)?)
        })
        .await
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
) -> Result<ClientRuntime, ClientRuntimeError> {
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
    let author = Arc::new(OperationAuthor::new(
        AuthoringContext::new(binding.space_id, vec![binding.initial_grant_operation_id])?,
        custody,
        SystemAuthoringRuntime,
    ));
    let now = unix_time_millis()?;
    let sync = SyncStatus {
        counts: Some(store.sync_counts(now)?),
        ..SyncStatus::default()
    };
    Ok(ClientRuntime {
        store,
        content,
        author,
        node_id: binding.node_id,
        actor_id: binding.local_writer_actor_id,
        space_id: binding.space_id,
        sync: RuntimeSync::Static(Box::new(sync)),
    })
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
}

#[cfg(test)]
mod tests;
