#![forbid(unsafe_code)]
//! Narrow native boundary for Fractonica's iOS and Android clients.
//!
//! Platform wrappers own secure storage and app-private directory discovery.
//! React Native receives only bounded semantic DTOs from this crate. Identity
//! material is generated, versioned, decoded, and validated exclusively here;
//! Keychain and Android Keystore adapters persist it as an opaque byte string.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use fractonica_application::SpaceDescriptor;
use fractonica_client_runtime::{
    ClientRuntime, ClientRuntimeError, PairingClaim, PrePairRecordPolicy, StandaloneClientConfig,
    StandaloneIdentityAction, StandaloneIdentityState, StandaloneIdentityStore,
};
use fractonica_client_sqlite::ClientStoreError;
use fractonica_data_model::{EntityId, OperationId, ProtectedDocument, RecordDocument, Visibility};
use fractonica_keystore::IdentityBundle;
use fractonica_trust::{SigningKey, SpaceId};
use tokio::runtime::Runtime;
use zeroize::{Zeroize, Zeroizing};

pub const MOBILE_BRIDGE_API_VERSION: u32 = 1;
const IDENTITY_MAGIC: &[u8; 8] = b"FRIDMAT1";
const ROLE_BYTES: usize = 32;
const IDENTITY_PAYLOAD_BYTES: usize = ROLE_BYTES * 4;
const IDENTITY_MATERIAL_BYTES: usize = IDENTITY_MAGIC.len() + IDENTITY_PAYLOAD_BYTES;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_RECORD_JSON_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_RECORD_PAGE_SIZE: u32 = 200;
/// Per-field UTF-8 budgets for the feed DTO. These are deliberately much
/// smaller than the canonical record limits because list calls are previews,
/// not document transfer APIs.
const MAX_RECORD_PREVIEW_EMOJI_BYTES: usize = 128;
const MAX_RECORD_PREVIEW_TEXT_BYTES: usize = 768;
const MAX_RECORD_PREVIEW_SORT_TEXT_BYTES: usize = 512;
const MAX_RECORD_PREVIEW_ITEM_BYTES: usize = 2 * 1_024;
const MAX_RECORD_PREVIEW_PAGE_BYTES: usize = 64 * 1_024;
const RECORD_PREVIEW_FIXED_BUDGET_BYTES: usize = 256;
const MAX_RECORD_DETAIL_JSON_BYTES: usize = 2 * 1_024 * 1_024;
const RESET_LOCAL_INSTALLATION_CONFIRMATION: &str = "RESET_LOCAL_INSTALLATION";

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileBridgeStatus {
    pub api_version: u32,
    pub implementation: String,
    pub rust_core_linked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileIdentityAction {
    CreateOrResume,
    OpenExisting,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileClientStatus {
    pub phase: String,
    pub node_id: Option<String>,
    pub actor_id: Option<String>,
    pub space_id: Option<String>,
    pub sync_running: bool,
    pub cycle: u64,
    pub pending_operations: u64,
    pub rejected_operations: u64,
    pub waiting_uploads: u64,
    pub pending_uploads: u64,
    pub pending_downloads: u64,
    pub rejected_resources: u64,
    pub synchronized_bytes: u64,
    pub total_bytes: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileWorkspace {
    pub space_id: String,
    pub display_name: String,
    pub genesis_operation_id: String,
    pub initial_grant_operation_id: String,
    pub controller_actor_id: String,
    pub local_writer_actor_id: String,
    pub created_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileRecordPreview {
    pub operation_id: String,
    pub entity_id: String,
    pub schema: String,
    pub visibility: String,
    pub conflicted: bool,
    pub tombstone: bool,
    pub start_at_unix_ms: Option<i64>,
    pub end_at_unix_ms: Option<i64>,
    pub sort_text: Option<String>,
    pub resource_count: u64,
    pub media_bytes: u64,
    /// Bounded public display fields only. Metadata, references, resource
    /// descriptors, and encrypted private content never cross list calls.
    pub emoji: Option<String>,
    pub text_preview: Option<String>,
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileRecordDetail {
    pub operation_id: String,
    pub entity_id: String,
    pub schema: String,
    pub visibility: String,
    pub conflicted: bool,
    pub tombstone: bool,
    pub start_at_unix_ms: Option<i64>,
    pub end_at_unix_ms: Option<i64>,
    pub sort_text: Option<String>,
    pub resource_count: u64,
    pub media_bytes: u64,
    /// Exact public `RecordDocument` JSON, bounded and kept opaque by native
    /// wrappers so metadata integers are never rounded through NSNumber or
    /// JavaScript Number. Private encrypted envelopes never cross this API.
    pub document_json: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileCommitResult {
    pub local_sequence: u64,
    pub operation_id: String,
    pub replayed: bool,
    pub queued_peers: u64,
}

/// Verified result of the joiner's Noise handshake. The planned grant id is
/// not authority by itself: the desktop node must still admit that operation
/// after the user compares and confirms all ten octal digits.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobilePairingClaim {
    pub invitation_id: String,
    pub responder_node_id: String,
    pub space_id: String,
    pub endpoint: String,
    pub confirmation_octal: String,
    pub grant_operation_id: String,
    pub local_record_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobilePrePairRecordPolicy {
    Merge,
    Discard,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileClientError {
    #[error("Protected identity material is invalid.")]
    InvalidIdentity,
    #[error("The native client configuration is invalid.")]
    InvalidConfiguration,
    #[error("The record request is invalid.")]
    InvalidRecord,
    #[error("The native client has already been opened.")]
    AlreadyOpened,
    #[error("The local installation requires explicit recovery.")]
    RecoveryRequired,
    #[error("The native client could not be initialized.")]
    InitializationFailed,
    #[error("Secure random identity material could not be generated.")]
    RandomSourceUnavailable,
    #[error("The local client operation failed.")]
    OperationFailed,
    #[error("The pairing invitation is invalid or is not safe for this transport.")]
    InvalidPairingInvitation,
    #[error("The pairing handshake failed.")]
    PairingFailed,
    #[error("No invitation endpoint was reachable on the local network.")]
    PairingTransportUnavailable,
}

#[uniffi::export]
pub fn mobile_core_bridge_status() -> MobileBridgeStatus {
    MobileBridgeStatus {
        api_version: MOBILE_BRIDGE_API_VERSION,
        implementation: "fractonica-rust-uniffi".to_owned(),
        rust_core_linked: true,
    }
}

/// Creates one versioned, opaque identity value for native protected storage.
///
/// The three signing roles and the space identifier are generated separately,
/// then validated for role separation and a non-zero space before any bytes
/// are returned to the platform adapter.
#[uniffi::export]
pub fn generate_identity_material() -> Result<Vec<u8>, MobileClientError> {
    for _ in 0..16 {
        let mut payload = Zeroizing::new([0_u8; IDENTITY_PAYLOAD_BYTES]);
        getrandom::fill(payload.as_mut_slice())
            .map_err(|_| MobileClientError::RandomSourceUnavailable)?;
        if decode_payload(&payload).is_ok() {
            let mut encoded = Vec::with_capacity(IDENTITY_MATERIAL_BYTES);
            encoded.extend_from_slice(IDENTITY_MAGIC);
            encoded.extend_from_slice(payload.as_slice());
            return Ok(encoded);
        }
    }
    Err(MobileClientError::RandomSourceUnavailable)
}

/// Prepared standalone bootstrap. The storage path is supplied only by the
/// platform module and is never returned to JavaScript.
#[derive(uniffi::Object)]
pub struct MobileClientBootstrap {
    executor: Arc<Runtime>,
    config: StandaloneClientConfig,
    opened: Mutex<bool>,
}

#[uniffi::export]
impl MobileClientBootstrap {
    #[uniffi::constructor]
    pub fn new(storage_dir: String) -> Result<Arc<Self>, MobileClientError> {
        let path = PathBuf::from(storage_dir);
        if !path.is_absolute() {
            return Err(MobileClientError::InvalidConfiguration);
        }
        let executor = Runtime::new().map_err(|_| MobileClientError::InitializationFailed)?;
        Ok(Arc::new(Self {
            executor: Arc::new(executor),
            config: StandaloneClientConfig {
                client_data_dir: path,
            },
            opened: Mutex::new(false),
        }))
    }

    pub fn prepare(
        &self,
        identity_present: bool,
    ) -> Result<MobileIdentityAction, MobileClientError> {
        let action = self
            .executor
            .block_on(ClientRuntime::prepare_standalone(
                self.config.clone(),
                identity_present,
            ))
            .map_err(map_initialization_error)?;
        Ok(match action {
            StandaloneIdentityAction::CreateOrResume => MobileIdentityAction::CreateOrResume,
            StandaloneIdentityAction::OpenExisting => MobileIdentityAction::OpenExisting,
        })
    }

    pub fn open(
        &self,
        identity_material: Vec<u8>,
    ) -> Result<Arc<MobileClientCore>, MobileClientError> {
        let identity_material = Zeroizing::new(identity_material);
        let identity = Arc::new(OpaqueIdentity::decode(&identity_material)?);

        let mut opened = self
            .opened
            .lock()
            .map_err(|_| MobileClientError::InitializationFailed)?;
        if *opened {
            return Err(MobileClientError::AlreadyOpened);
        }

        let client = self
            .executor
            .block_on(ClientRuntime::bootstrap_standalone(
                self.config.clone(),
                Arc::clone(&identity),
            ))
            .map_err(map_initialization_error)?;
        *opened = true;
        Ok(Arc::new(MobileClientCore {
            client: Arc::new(client),
            executor: Arc::clone(&self.executor),
            shutdown: Mutex::new(false),
        }))
    }

    /// Deletes this client's app-private database and content only after the
    /// native adapter supplies the explicit destructive confirmation token.
    /// Protected identity removal remains platform-owned and must happen
    /// after this method succeeds, so a crash can never silently replace an
    /// identity while its old database is still present.
    pub fn reset_local_installation(&self, confirmation: String) -> Result<(), MobileClientError> {
        if confirmation != RESET_LOCAL_INSTALLATION_CONFIRMATION {
            return Err(MobileClientError::InvalidConfiguration);
        }
        let opened = self
            .opened
            .lock()
            .map_err(|_| MobileClientError::OperationFailed)?;
        if *opened {
            return Err(MobileClientError::AlreadyOpened);
        }
        reset_client_data_directory(&self.config.client_data_dir)
    }
}

#[derive(uniffi::Object)]
pub struct MobileClientCore {
    // Keep the client before its executor so it is dropped first.
    client: Arc<ClientRuntime>,
    executor: Arc<Runtime>,
    shutdown: Mutex<bool>,
}

#[uniffi::export]
impl MobileClientCore {
    pub fn status(&self) -> MobileClientStatus {
        let status = self.client.status();
        let counts = status.sync.counts.unwrap_or_default();
        MobileClientStatus {
            phase: "ready".to_owned(),
            node_id: Some(status.node_id.to_string()),
            actor_id: Some(status.actor_id.to_string()),
            space_id: status.space_id.map(|space_id| space_id.to_string()),
            sync_running: status.sync.running,
            cycle: status.sync.cycle,
            pending_operations: counts
                .pending_deliveries
                .saturating_add(counts.leased_deliveries),
            rejected_operations: counts.rejected_deliveries,
            waiting_uploads: counts.resources.waiting_uploads,
            pending_uploads: counts
                .resources
                .pending_uploads
                .saturating_add(counts.resources.leased_transfers),
            pending_downloads: counts.resources.pending_downloads,
            rejected_resources: counts.resources.rejected_transfers,
            synchronized_bytes: counts.resources.transferred_bytes,
            total_bytes: counts.resources.total_bytes,
            last_error: status
                .sync
                .last_error
                .map(|_| "Synchronization failed.".to_owned()),
        }
    }

    pub fn list_workspaces(&self) -> Result<Vec<MobileWorkspace>, MobileClientError> {
        self.client
            .workspaces()
            .map(|workspaces| workspaces.into_iter().map(mobile_workspace).collect())
            .map_err(|_| MobileClientError::OperationFailed)
    }

    pub fn create_workspace(
        &self,
        display_name: String,
    ) -> Result<MobileWorkspace, MobileClientError> {
        if display_name.trim().is_empty() || display_name.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(MobileClientError::InvalidConfiguration);
        }
        self.executor
            .block_on(self.client.create_workspace(display_name))
            .map(mobile_workspace)
            .map_err(|_| MobileClientError::OperationFailed)
    }

    pub fn activate_workspace(&self, space_id: String) -> Result<(), MobileClientError> {
        let space_id = space_id
            .parse()
            .map_err(|_| MobileClientError::InvalidConfiguration)?;
        self.executor
            .block_on(self.client.activate_workspace(space_id))
            .map_err(|_| MobileClientError::OperationFailed)
    }

    pub fn delete_workspace(&self, space_id: String) -> Result<(), MobileClientError> {
        let space_id = space_id
            .parse()
            .map_err(|_| MobileClientError::InvalidConfiguration)?;
        self.executor
            .block_on(self.client.delete_workspace(space_id))
            .map_err(|_| MobileClientError::OperationFailed)
    }

    pub fn list_records(&self, limit: u32) -> Result<Vec<MobileRecordPreview>, MobileClientError> {
        if !(1..=MAX_RECORD_PAGE_SIZE).contains(&limit) {
            return Err(MobileClientError::InvalidRecord);
        }
        let records = self
            .executor
            .block_on(self.client.list_record_previews(limit as usize))
            .map_err(|_| MobileClientError::OperationFailed)?;
        let previews = records
            .into_iter()
            .map(|record| {
                let summary = record.summary;
                validate_preview_field(record.emoji.as_deref(), MAX_RECORD_PREVIEW_EMOJI_BYTES)?;
                validate_preview_field(
                    record.text_preview.as_deref(),
                    MAX_RECORD_PREVIEW_TEXT_BYTES,
                )?;
                validate_preview_field(
                    summary.sort_text.as_deref(),
                    MAX_RECORD_PREVIEW_SORT_TEXT_BYTES,
                )?;
                let preview = MobileRecordPreview {
                    operation_id: summary.operation_id.to_string(),
                    entity_id: summary.entity_id.to_string(),
                    schema: summary.schema.as_str().to_owned(),
                    visibility: visibility_name(summary.visibility).to_owned(),
                    conflicted: summary.conflicted,
                    tombstone: summary.tombstone,
                    start_at_unix_ms: summary.start_at_unix_ms,
                    end_at_unix_ms: summary.end_at_unix_ms,
                    sort_text: summary.sort_text,
                    resource_count: summary.resource_count,
                    media_bytes: summary.media_bytes,
                    emoji: record.emoji,
                    text_preview: record.text_preview,
                    preview_truncated: record.preview_truncated,
                };
                if record_preview_budget_bytes(&preview) > MAX_RECORD_PREVIEW_ITEM_BYTES {
                    return Err(MobileClientError::OperationFailed);
                }
                Ok(preview)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(take_record_preview_page(previews))
    }

    /// Reads one exact live record head. Both identifiers are required so a
    /// stale or mismatched list item fails closed instead of opening another
    /// entity's operation. The full public document remains an opaque JSON
    /// string across native/JavaScript boundaries.
    pub fn get_record(
        &self,
        operation_id: String,
        entity_id: String,
    ) -> Result<Option<MobileRecordDetail>, MobileClientError> {
        let operation_id =
            OperationId::parse(&operation_id).map_err(|_| MobileClientError::InvalidRecord)?;
        let entity_id =
            EntityId::parse(&entity_id).map_err(|_| MobileClientError::InvalidRecord)?;
        let Some(record) = self
            .executor
            .block_on(self.client.record(entity_id, operation_id))
            .map_err(|_| MobileClientError::OperationFailed)?
        else {
            return Ok(None);
        };
        let summary = record.summary;
        let document_json = record
            .document
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| MobileClientError::OperationFailed)?;
        if document_json
            .as_ref()
            .is_some_and(|json| json.len() > MAX_RECORD_DETAIL_JSON_BYTES)
        {
            return Err(MobileClientError::OperationFailed);
        }
        Ok(Some(MobileRecordDetail {
            operation_id: summary.operation_id.to_string(),
            entity_id: summary.entity_id.to_string(),
            schema: summary.schema.as_str().to_owned(),
            visibility: visibility_name(summary.visibility).to_owned(),
            conflicted: summary.conflicted,
            tombstone: summary.tombstone,
            start_at_unix_ms: summary.start_at_unix_ms,
            end_at_unix_ms: summary.end_at_unix_ms,
            sort_text: summary.sort_text,
            resource_count: summary.resource_count,
            media_bytes: summary.media_bytes,
            document_json,
        }))
    }

    pub fn create_public_record(
        &self,
        payload_json: String,
    ) -> Result<MobileCommitResult, MobileClientError> {
        if payload_json.len() > MAX_RECORD_JSON_BYTES {
            return Err(MobileClientError::InvalidRecord);
        }
        let payload: ProtectedDocument<RecordDocument> =
            serde_json::from_str(&payload_json).map_err(|_| MobileClientError::InvalidRecord)?;
        let document = match &payload {
            ProtectedDocument::Public { document } => document,
            ProtectedDocument::Private { .. } => return Err(MobileClientError::InvalidRecord),
        };
        document
            .validate()
            .map_err(|_| MobileClientError::InvalidRecord)?;
        let result = self
            .executor
            .block_on(self.client.create_record(payload))
            .map_err(|_| MobileClientError::OperationFailed)?;
        Ok(MobileCommitResult {
            local_sequence: result.local_sequence,
            operation_id: result.operation_id.to_string(),
            replayed: result.replayed,
            queued_peers: result.queued_peers,
        })
    }

    /// Claims a short-lived local-network invitation using the protected device
    /// identity. The raw QR secret is used only for this call and is neither
    /// logged nor persisted. Endpoint hints are restricted to loopback or
    /// private/link-local addresses; the transport credential is returned only
    /// inside the encrypted Noise receipt.
    pub fn claim_pairing_invitation(
        &self,
        qr: String,
    ) -> Result<MobilePairingClaim, MobileClientError> {
        let claim = self
            .executor
            .block_on(self.client.claim_pairing_invitation(qr))
            .map_err(map_pairing_error)?;
        Ok(mobile_pairing_claim(claim))
    }

    /// Admits a claimed pairing only after the user has compared the complete
    /// ten-octal transcript. The acceptance is dual-signed below JavaScript;
    /// after the node returns the completed grant, the peer is persisted as
    /// bidirectional operation/media peer and the background worker discovers
    /// it without exposing transport credentials to JavaScript.
    pub fn accept_pairing_invitation(
        &self,
        invitation_id: String,
        record_policy: MobilePrePairRecordPolicy,
    ) -> Result<MobilePairingClaim, MobileClientError> {
        let claim = self
            .executor
            .block_on(self.client.accept_pairing_invitation(
                invitation_id,
                match record_policy {
                    MobilePrePairRecordPolicy::Merge => PrePairRecordPolicy::Merge,
                    MobilePrePairRecordPolicy::Discard => PrePairRecordPolicy::Discard,
                },
            ))
            .map_err(map_pairing_error)?;
        Ok(mobile_pairing_claim(claim))
    }

    pub fn shutdown(&self) -> Result<(), MobileClientError> {
        let mut shutdown = self
            .shutdown
            .lock()
            .map_err(|_| MobileClientError::OperationFailed)?;
        if *shutdown {
            return Ok(());
        }
        self.executor
            .block_on(self.client.shutdown())
            .map_err(|_| MobileClientError::OperationFailed)?;
        *shutdown = true;
        Ok(())
    }
}

fn mobile_pairing_claim(value: PairingClaim) -> MobilePairingClaim {
    MobilePairingClaim {
        invitation_id: value.invitation_id,
        responder_node_id: value.responder_node_id,
        space_id: value.space_id,
        endpoint: value.endpoint,
        confirmation_octal: value.confirmation_octal,
        grant_operation_id: value.grant_operation_id,
        local_record_count: value.local_record_count,
    }
}

fn map_pairing_error(error: ClientRuntimeError) -> MobileClientError {
    match error {
        ClientRuntimeError::InvalidPairingInvitation => MobileClientError::InvalidPairingInvitation,
        ClientRuntimeError::RandomSourceUnavailable => MobileClientError::RandomSourceUnavailable,
        ClientRuntimeError::PairingTransportUnavailable(_) => {
            MobileClientError::PairingTransportUnavailable
        }
        _ => MobileClientError::PairingFailed,
    }
}

impl Drop for MobileClientCore {
    fn drop(&mut self) {
        self.client.request_shutdown();
    }
}

struct OpaqueIdentity {
    payload: Zeroizing<[u8; IDENTITY_PAYLOAD_BYTES]>,
}

impl OpaqueIdentity {
    fn decode(material: &[u8]) -> Result<Self, MobileClientError> {
        if material.len() != IDENTITY_MATERIAL_BYTES
            || &material[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC
        {
            return Err(MobileClientError::InvalidIdentity);
        }
        let mut payload = Zeroizing::new([0_u8; IDENTITY_PAYLOAD_BYTES]);
        payload.copy_from_slice(&material[IDENTITY_MAGIC.len()..]);
        decode_payload(&payload)?;
        Ok(Self { payload })
    }

    fn bundle(&self) -> Result<IdentityBundle, OpaqueIdentityError> {
        decode_payload(&self.payload).map_err(|_| OpaqueIdentityError)
    }
}

impl fmt::Debug for OpaqueIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueIdentity([REDACTED])")
    }
}

#[derive(Debug)]
struct OpaqueIdentityError;

impl fmt::Display for OpaqueIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protected identity is invalid")
    }
}

impl Error for OpaqueIdentityError {}

impl StandaloneIdentityStore for OpaqueIdentity {
    type Error = OpaqueIdentityError;

    fn state(&self) -> Result<StandaloneIdentityState, Self::Error> {
        Ok(StandaloneIdentityState::Established)
    }

    fn create_or_resume(&self) -> Result<IdentityBundle, Self::Error> {
        self.bundle()
    }

    fn load_existing(&self) -> Result<IdentityBundle, Self::Error> {
        self.bundle()
    }
}

fn validate_preview_field(value: Option<&str>, maximum: usize) -> Result<(), MobileClientError> {
    if value.is_some_and(|value| value.len() > maximum) {
        return Err(MobileClientError::OperationFailed);
    }
    Ok(())
}

/// Conservative semantic wire budget. The fixed allowance is larger than the
/// UniFFI tags, lengths, booleans, and integer fields for this record, so a
/// page admitted here is also below the raw UniFFI payload ceiling.
fn record_preview_budget_bytes(record: &MobileRecordPreview) -> usize {
    RECORD_PREVIEW_FIXED_BUDGET_BYTES
        .saturating_add(record.operation_id.len())
        .saturating_add(record.entity_id.len())
        .saturating_add(record.schema.len())
        .saturating_add(record.visibility.len())
        .saturating_add(record.sort_text.as_ref().map_or(0, String::len))
        .saturating_add(record.emoji.as_ref().map_or(0, String::len))
        .saturating_add(record.text_preview.as_ref().map_or(0, String::len))
}

fn take_record_preview_page(records: Vec<MobileRecordPreview>) -> Vec<MobileRecordPreview> {
    let mut used = 4_usize; // UniFFI sequence length prefix.
    records
        .into_iter()
        .take_while(|record| {
            let next = record_preview_budget_bytes(record);
            let Some(total) = used.checked_add(next) else {
                return false;
            };
            if total > MAX_RECORD_PREVIEW_PAGE_BYTES {
                return false;
            }
            used = total;
            true
        })
        .collect()
}

fn decode_payload(
    payload: &[u8; IDENTITY_PAYLOAD_BYTES],
) -> Result<IdentityBundle, MobileClientError> {
    let mut node = Zeroizing::new([0_u8; ROLE_BYTES]);
    let mut controller = Zeroizing::new([0_u8; ROLE_BYTES]);
    let mut writer = Zeroizing::new([0_u8; ROLE_BYTES]);
    node.copy_from_slice(&payload[0..ROLE_BYTES]);
    controller.copy_from_slice(&payload[ROLE_BYTES..ROLE_BYTES * 2]);
    writer.copy_from_slice(&payload[ROLE_BYTES * 2..ROLE_BYTES * 3]);
    let mut space = [0_u8; ROLE_BYTES];
    space.copy_from_slice(&payload[ROLE_BYTES * 3..]);
    let bundle = IdentityBundle::from_keys(
        SigningKey::from_seed(*node),
        SigningKey::from_seed(*controller),
        SigningKey::from_seed(*writer),
        SpaceId::from_bytes(space),
    )
    .map_err(|_| MobileClientError::InvalidIdentity);
    space.zeroize();
    bundle
}

const fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

fn mobile_workspace(workspace: SpaceDescriptor) -> MobileWorkspace {
    MobileWorkspace {
        space_id: workspace.space_id.to_string(),
        display_name: workspace.display_name,
        genesis_operation_id: workspace.genesis_operation_id.to_string(),
        initial_grant_operation_id: workspace.initial_grant_operation_id.to_string(),
        controller_actor_id: workspace.controller_actor_id.to_string(),
        local_writer_actor_id: workspace.local_writer_actor_id.to_string(),
        created_at_unix_ms: workspace.created_at_unix_ms,
    }
}

fn reset_client_data_directory(path: &Path) -> Result<(), MobileClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(MobileClientError::OperationFailed),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(MobileClientError::RecoveryRequired);
    }
    fs::remove_dir_all(path).map_err(|_| MobileClientError::OperationFailed)
}

fn map_initialization_error(error: ClientRuntimeError) -> MobileClientError {
    match error {
        ClientRuntimeError::StandaloneRecovery(_)
        | ClientRuntimeError::MissingInstallationAnchor(_) => MobileClientError::RecoveryRequired,
        ClientRuntimeError::Store(
            ClientStoreError::Corrupt(_)
            | ClientStoreError::InvalidBootstrap(_)
            | ClientStoreError::InstallationConflict,
        ) => MobileClientError::RecoveryRequired,
        _ => MobileClientError::InitializationFailed,
    }
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn handshake_is_explicitly_versioned() {
        assert_eq!(
            mobile_core_bridge_status(),
            MobileBridgeStatus {
                api_version: 1,
                implementation: "fractonica-rust-uniffi".to_owned(),
                rust_core_linked: true,
            }
        );
    }

    #[test]
    fn unreachable_pairing_transport_keeps_its_specific_mobile_error() {
        assert!(matches!(
            map_pairing_error(ClientRuntimeError::PairingTransportUnavailable(
                "http://192.168.1.20:49152: request timed out".to_owned(),
            )),
            MobileClientError::PairingTransportUnavailable
        ));
    }

    #[test]
    fn generated_identity_round_trips_but_malformed_values_fail_closed() {
        let material = generate_identity_material().expect("identity");
        let identity = OpaqueIdentity::decode(&material).expect("decode");
        identity.bundle().expect("bundle");
        assert!(matches!(
            OpaqueIdentity::decode(b"not-an-identity"),
            Err(MobileClientError::InvalidIdentity)
        ));
    }

    #[test]
    fn explicit_mobile_workspace_reopens_with_its_records() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("client");
        let bootstrap =
            MobileClientBootstrap::new(path.to_string_lossy().into_owned()).expect("bootstrap");
        assert_eq!(
            bootstrap.prepare(false).expect("prepare"),
            MobileIdentityAction::CreateOrResume
        );
        let material = generate_identity_material().expect("identity");
        let client = bootstrap.open(material.clone()).expect("open");
        assert!(client.list_workspaces().expect("workspaces").is_empty());
        let workspace = client
            .create_workspace("Personal space".to_owned())
            .expect("workspace");
        assert_eq!(
            client.status().space_id.as_deref(),
            Some(workspace.space_id.as_str())
        );
        let result = client
            .create_public_record(
                r#"{"visibility":"public","document":{"startAtUnixMs":1,"text":"hello","metadata":{},"resources":[],"references":[]}}"#
                    .to_owned(),
            )
            .expect("create");
        assert!(!result.operation_id.is_empty());
        let records = client.list_records(10).expect("list");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].text_preview.as_deref(), Some("hello"));
        let detail = client
            .get_record(
                records[0].operation_id.clone(),
                records[0].entity_id.clone(),
            )
            .expect("get record")
            .expect("detail");
        assert!(
            detail
                .document_json
                .as_deref()
                .is_some_and(|json| json.contains("hello"))
        );
        client.shutdown().expect("shutdown");
        drop(client);
        drop(bootstrap);

        let reopened =
            MobileClientBootstrap::new(path.to_string_lossy().into_owned()).expect("bootstrap");
        assert_eq!(
            reopened.prepare(true).expect("prepare"),
            MobileIdentityAction::OpenExisting
        );
        let client = reopened.open(material).expect("reopen");
        assert_eq!(client.list_records(10).expect("list").len(), 1);
        client.shutdown().expect("shutdown");
    }

    #[test]
    fn record_preview_page_has_per_field_and_total_wire_budgets() {
        let record = MobileRecordPreview {
            operation_id: format!("sha-256:{}", "a".repeat(64)),
            entity_id: "31000000-0000-4000-8000-000000000001".to_owned(),
            schema: "record".to_owned(),
            visibility: "public".to_owned(),
            conflicted: false,
            tombstone: false,
            start_at_unix_ms: Some(1),
            end_at_unix_ms: None,
            sort_text: None,
            resource_count: 0,
            media_bytes: 0,
            emoji: Some("🌀".repeat(32)),
            text_preview: Some("🌀".repeat(192)),
            preview_truncated: true,
        };
        assert_eq!(
            record.emoji.as_deref().unwrap().len(),
            MAX_RECORD_PREVIEW_EMOJI_BYTES
        );
        assert_eq!(
            record.text_preview.as_deref().unwrap().len(),
            MAX_RECORD_PREVIEW_TEXT_BYTES
        );
        assert!(record_preview_budget_bytes(&record) <= MAX_RECORD_PREVIEW_ITEM_BYTES);

        let page = take_record_preview_page(vec![record; MAX_RECORD_PAGE_SIZE as usize]);
        assert!(!page.is_empty());
        assert!(page.len() < MAX_RECORD_PAGE_SIZE as usize);
        let total = page.iter().fold(4_usize, |sum, record| {
            sum + record_preview_budget_bytes(record)
        });
        assert!(total <= MAX_RECORD_PREVIEW_PAGE_BYTES);
    }

    #[test]
    fn local_reset_is_explicit_and_cannot_run_while_open() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("client");
        let material = generate_identity_material().expect("identity");
        let bootstrap =
            MobileClientBootstrap::new(path.to_string_lossy().into_owned()).expect("bootstrap");
        bootstrap.prepare(false).expect("prepare");

        assert!(matches!(
            bootstrap.reset_local_installation("wrong".to_owned()),
            Err(MobileClientError::InvalidConfiguration)
        ));
        assert!(path.exists());

        let client = bootstrap.open(material.clone()).expect("open");
        assert!(matches!(
            bootstrap.reset_local_installation(RESET_LOCAL_INSTALLATION_CONFIRMATION.to_owned()),
            Err(MobileClientError::AlreadyOpened)
        ));
        client.shutdown().expect("shutdown");
        drop(client);
        drop(bootstrap);

        let recovery = MobileClientBootstrap::new(path.to_string_lossy().into_owned())
            .expect("recovery bootstrap");
        recovery
            .reset_local_installation(RESET_LOCAL_INSTALLATION_CONFIRMATION.to_owned())
            .expect("reset");
        assert!(!path.exists());
        assert_eq!(
            recovery
                .prepare(true)
                .expect("existing identity may bind fresh storage"),
            MobileIdentityAction::OpenExisting
        );
        assert_eq!(
            recovery.prepare(false).expect("fresh preparation"),
            MobileIdentityAction::CreateOrResume
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_reset_never_follows_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target");
        fs::write(target.join("keep"), b"untouched").expect("marker");
        let linked_path = directory.path().join("client");
        symlink(&target, &linked_path).expect("symlink");
        let recovery = MobileClientBootstrap::new(linked_path.to_string_lossy().into_owned())
            .expect("recovery bootstrap");

        assert!(matches!(
            recovery.reset_local_installation(RESET_LOCAL_INSTALLATION_CONFIRMATION.to_owned()),
            Err(MobileClientError::RecoveryRequired)
        ));
        assert_eq!(fs::read(target.join("keep")).expect("marker"), b"untouched");
    }
}
