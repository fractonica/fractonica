#![forbid(unsafe_code)]
//! Native application lifecycle for local-first Fractonica clients.
//!
//! This crate owns keys, local operations, content, and background sync. UI
//! adapters receive semantic methods and small status values, never secrets or
//! raw storage handles.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use fractonica_application::{SpaceDescriptor, StoredOperation};
use fractonica_client::{
    ActorKeyCustody, AuthoringContext, KeyCustodyError, ObservedEntity, OperationAuthor,
    OperationDraft, SystemAuthoringRuntime,
};
use fractonica_client_content::{ClientContentError, ClientContentStore};
use fractonica_client_sqlite::{
    ClientSqliteStore, ClientStoreError, CommitResult, LocalEntitySummary, PeerConfig,
    PeerReadMode, PeerSpaceConfig,
};
use fractonica_data_model::{
    ActorId, EntityId, EntitySchema, EventDocument, NodeId, OperationBody, OperationEnvelope,
    ProfileDocument, ProtectedDocument, RecordDocument, SpaceId, TagDocument,
};
use fractonica_keystore::{FileKeyStore, IdentityBundle};
use fractonica_peer::{PeerReadChangesFields, PeerReadChangesProof};
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

#[derive(Clone, Debug)]
pub struct SupervisedNodeConfig {
    pub client_data_dir: PathBuf,
    pub node_data_dir: PathBuf,
    pub endpoint: String,
    pub bearer_token: String,
    pub sync: SyncConfig,
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
    sync_status: watch::Receiver<SyncStatus>,
    shutdown: watch::Sender<bool>,
    sync_task: Mutex<Option<JoinHandle<()>>>,
}

impl ClientRuntime {
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
            sync_status,
            shutdown,
            sync_task: Mutex::new(Some(sync_task)),
        })
    }

    #[must_use]
    pub fn status(&self) -> ClientRuntimeStatus {
        ClientRuntimeStatus {
            node_id: self.node_id,
            actor_id: self.actor_id,
            space_id: self.space_id,
            sync: self.sync_status.borrow().clone(),
        }
    }

    #[must_use]
    pub const fn content_store(&self) -> &ClientContentStore {
        &self.content
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

    pub async fn shutdown(&self) -> Result<(), ClientRuntimeError> {
        self.request_shutdown();
        let task = self
            .sync_task
            .lock()
            .map_err(|_| ClientRuntimeError::LifecycleLock)?
            .take();
        if let Some(task) = task {
            task.await
                .map_err(|error| ClientRuntimeError::Join(error.to_string()))?;
        }
        Ok(())
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
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
        let _ = self.shutdown.send(true);
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
    if node.profile != "full" {
        return Err(contract("supervised client runtime requires a full node"));
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
    std::fs::create_dir_all(path)?;
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
    #[error("protected identity is unavailable: {0}")]
    Identity(String),
    #[error("supervised node request failed: {0}")]
    Http(String),
    #[error("supervised node contract is invalid: {0}")]
    NodeContract(String),
    #[error("client store failed: {0}")]
    Store(#[from] ClientStoreError),
    #[error("client content store failed: {0}")]
    Content(#[from] ClientContentError),
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
