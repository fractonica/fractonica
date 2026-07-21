#![forbid(unsafe_code)]
//! Narrow native boundary for Fractonica's iOS and Android clients.
//!
//! Platform wrappers own secure storage and app-private directory discovery.
//! React Native receives only bounded semantic DTOs from this crate. Identity
//! material is generated, versioned, decoded, and validated exclusively here;
//! Keychain and Android Keystore adapters persist it as an opaque byte string.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fractonica_client_runtime::{
    ClientRuntime, ClientRuntimeError, StandaloneClientConfig, StandaloneIdentityAction,
    StandaloneIdentityState, StandaloneIdentityStore,
};
use fractonica_client_sqlite::ClientStoreError;
use fractonica_data_model::{
    EntityId, NodeId, OperationId, ProtectedDocument, RecordDocument, Visibility,
};
use fractonica_keystore::IdentityBundle;
use fractonica_pairing::{
    InvitationId, JoinerClaim, PairingAcceptance, PairingInvitation, PairingReceipt,
};
use fractonica_peer::PeerSessionId;
use fractonica_trust::{SigningKey, SpaceId};
use reqwest::{Client, Url};
use serde::Deserialize;
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
const MAX_PAIRING_QR_BYTES: usize = 8 * 1_024;

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
    pub fn new(storage_dir: String, display_name: String) -> Result<Arc<Self>, MobileClientError> {
        let path = PathBuf::from(storage_dir);
        if !path.is_absolute()
            || display_name.trim().is_empty()
            || display_name.len() > MAX_DISPLAY_NAME_BYTES
        {
            return Err(MobileClientError::InvalidConfiguration);
        }
        let executor = Runtime::new().map_err(|_| MobileClientError::InitializationFailed)?;
        Ok(Arc::new(Self {
            executor: Arc::new(executor),
            config: StandaloneClientConfig {
                client_data_dir: path,
                display_name,
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
            identity,
            executor: Arc::clone(&self.executor),
            pending_pairings: Mutex::new(BTreeMap::new()),
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
    identity: Arc<OpaqueIdentity>,
    executor: Arc<Runtime>,
    pending_pairings: Mutex<BTreeMap<String, PendingPairing>>,
    shutdown: Mutex<bool>,
}

#[derive(Clone)]
struct PendingPairing {
    claim: MobilePairingClaim,
    invitation_id: InvitationId,
    responder_node_id: NodeId,
    space_id: SpaceId,
    endpoint: String,
    claim_digest: [u8; 32],
    handshake_hash: [u8; 32],
    grant_operation_id: OperationId,
    peer_transport_credential: String,
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
            space_id: Some(status.space_id.to_string()),
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
        if qr.is_empty() || qr.len() > MAX_PAIRING_QR_BYTES {
            return Err(MobileClientError::InvalidPairingInvitation);
        }
        let now = unix_time_millis().ok_or(MobileClientError::PairingFailed)?;
        let invitation = PairingInvitation::decode(&qr, now)
            .map_err(|_| MobileClientError::InvalidPairingInvitation)?;
        let invitation_id = invitation.descriptor().invitation_id.to_string();
        if let Some(existing) = self
            .pending_pairings
            .lock()
            .map_err(|_| MobileClientError::PairingFailed)?
            .get(&invitation_id)
            .cloned()
        {
            return Ok(existing.claim);
        }
        let identity = self
            .identity
            .bundle()
            .map_err(|_| MobileClientError::InvalidIdentity)?;
        let verified = self
            .executor
            .block_on(claim_pairing(invitation, now, identity))?;
        let claim = verified.claim.clone();
        self.pending_pairings
            .lock()
            .map_err(|_| MobileClientError::PairingFailed)?
            .insert(claim.invitation_id.clone(), verified);
        Ok(claim)
    }

    /// Admits a claimed pairing only after the user has compared the complete
    /// ten-octal transcript. The acceptance is dual-signed below JavaScript;
    /// after the node returns the completed grant, the peer is persisted as
    /// bidirectional operation/media peer and the background worker discovers
    /// it without exposing transport credentials to JavaScript.
    pub fn accept_pairing_invitation(
        &self,
        invitation_id: String,
    ) -> Result<MobilePairingClaim, MobileClientError> {
        let pending = self
            .pending_pairings
            .lock()
            .map_err(|_| MobileClientError::PairingFailed)?
            .get(&invitation_id)
            .cloned()
            .ok_or(MobileClientError::PairingFailed)?;
        let identity = self
            .identity
            .bundle()
            .map_err(|_| MobileClientError::InvalidIdentity)?;
        self.executor.block_on(accept_pairing(
            &pending,
            &identity,
            Arc::clone(&self.client),
        ))?;
        self.pending_pairings
            .lock()
            .map_err(|_| MobileClientError::PairingFailed)?
            .remove(&invitation_id);
        Ok(pending.claim)
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
    identity: IdentityBundle,
) -> Result<PendingPairing, MobileClientError> {
    let descriptor = invitation.descriptor();
    let endpoint = descriptor
        .endpoint_hints
        .iter()
        .find_map(|hint| safe_pairing_endpoint(hint).ok())
        .ok_or(MobileClientError::InvalidPairingInvitation)?;

    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| MobileClientError::RandomSourceUnavailable)?;
    let claim = JoinerClaim::sign(
        descriptor,
        identity.node_transport_key(),
        identity.local_writer_key(),
        nonce,
    );
    let mut handshake = invitation
        .start_initiator(now)
        .map_err(|_| MobileClientError::PairingFailed)?;
    let first_frame = handshake
        .write_message(
            &claim
                .canonical_bytes()
                .map_err(|_| MobileClientError::PairingFailed)?,
        )
        .map_err(|_| MobileClientError::PairingFailed)?;
    let url = endpoint
        .join("api/pairing/handshake")
        .map_err(|_| MobileClientError::InvalidPairingInvitation)?;
    let response = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| MobileClientError::PairingFailed)?
        .post(url)
        .json(&serde_json::json!({
            "invitationId": descriptor.invitation_id.to_string(),
            "frameBase64url": URL_SAFE_NO_PAD.encode(first_frame),
        }))
        .send()
        .await
        .map_err(|_| MobileClientError::PairingFailed)?;
    if !response.status().is_success() {
        return Err(MobileClientError::PairingFailed);
    }
    let response: PairingHandshakeResponse = response
        .json()
        .await
        .map_err(|_| MobileClientError::PairingFailed)?;
    let response_frame = URL_SAFE_NO_PAD
        .decode(response.response_frame_base64url)
        .map_err(|_| MobileClientError::PairingFailed)?;
    let receipt_frame = URL_SAFE_NO_PAD
        .decode(response.receipt_frame_base64url)
        .map_err(|_| MobileClientError::PairingFailed)?;
    if !handshake
        .read_message(&response_frame)
        .map_err(|_| MobileClientError::PairingFailed)?
        .is_empty()
    {
        return Err(MobileClientError::PairingFailed);
    }
    let mut transport = handshake
        .finish()
        .map_err(|_| MobileClientError::PairingFailed)?;
    let receipt = PairingReceipt::from_canonical_bytes(
        &transport
            .read_message(&receipt_frame)
            .map_err(|_| MobileClientError::PairingFailed)?,
    )
    .map_err(|_| MobileClientError::PairingFailed)?;
    receipt
        .verify_for(descriptor, &claim, transport.handshake_hash())
        .map_err(|_| MobileClientError::PairingFailed)?;

    let session = response.session;
    let confirmation = transport.confirmation_octal().to_owned();
    let expected_joiner_node_id = identity.node_id().to_string();
    let expected_subject_actor_id = identity.local_writer_actor_id().to_string();
    let grant_operation_id = session
        .grant_operation_id
        .ok_or(MobileClientError::PairingFailed)?;
    if session.invitation_id != descriptor.invitation_id.to_string()
        || session.space_id != descriptor.space_id.to_string()
        || session.state != "claimed"
        || session.expires_at_unix_ms != descriptor.expires_at_unix_ms
        || session.joiner_node_id.as_deref() != Some(expected_joiner_node_id.as_str())
        || session.subject_actor_id.as_deref() != Some(expected_subject_actor_id.as_str())
        || session.confirmation_octal.as_deref() != Some(confirmation.as_str())
        || OperationId::parse(&grant_operation_id).is_err()
    {
        return Err(MobileClientError::PairingFailed);
    }

    let public = MobilePairingClaim {
        invitation_id: descriptor.invitation_id.to_string(),
        responder_node_id: descriptor.responder_node_id.to_string(),
        space_id: descriptor.space_id.to_string(),
        endpoint: endpoint_origin(&endpoint),
        confirmation_octal: confirmation,
        grant_operation_id: grant_operation_id.clone(),
    };
    Ok(PendingPairing {
        claim: public,
        invitation_id: descriptor.invitation_id,
        responder_node_id: descriptor.responder_node_id,
        space_id: descriptor.space_id,
        endpoint: endpoint_origin(&endpoint),
        claim_digest: claim.digest(),
        handshake_hash: *transport.handshake_hash(),
        grant_operation_id: OperationId::parse(&grant_operation_id)
            .map_err(|_| MobileClientError::PairingFailed)?,
        peer_transport_credential: format!(
            "{}.{}",
            descriptor.invitation_id,
            URL_SAFE_NO_PAD.encode(receipt.peer_access_token())
        ),
    })
}

async fn accept_pairing(
    pending: &PendingPairing,
    identity: &IdentityBundle,
    client_runtime: Arc<ClientRuntime>,
) -> Result<(), MobileClientError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| MobileClientError::RandomSourceUnavailable)?;
    let acceptance = PairingAcceptance::sign(
        pending.invitation_id,
        pending.claim_digest,
        pending.handshake_hash,
        pending.responder_node_id,
        pending.space_id,
        pending.grant_operation_id,
        identity.node_transport_key(),
        identity.local_writer_key(),
        nonce,
    );
    let endpoint = Url::parse(&pending.endpoint).map_err(|_| MobileClientError::PairingFailed)?;
    let url = endpoint
        .join(&format!(
            "api/pairing/invitations/{}/accept",
            pending.invitation_id
        ))
        .map_err(|_| MobileClientError::PairingFailed)?;
    let response = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| MobileClientError::PairingFailed)?
        .post(url)
        .json(&serde_json::json!({
            "acceptanceBase64url": URL_SAFE_NO_PAD.encode(
                acceptance
                    .canonical_bytes()
                    .map_err(|_| MobileClientError::PairingFailed)?,
            ),
        }))
        .send()
        .await
        .map_err(|_| MobileClientError::PairingFailed)?;
    if !response.status().is_success() {
        return Err(MobileClientError::PairingFailed);
    }
    let session: PairingSessionResponse = response
        .json()
        .await
        .map_err(|_| MobileClientError::PairingFailed)?;
    if session.invitation_id != pending.claim.invitation_id
        || session.space_id != pending.claim.space_id
        || session.state != "completed"
        || session.joiner_node_id.as_deref() != Some(identity.node_id().to_string().as_str())
        || session.subject_actor_id.as_deref()
            != Some(identity.local_writer_actor_id().to_string().as_str())
        || session.confirmation_octal.as_deref() != Some(pending.claim.confirmation_octal.as_str())
        || session.grant_operation_id.as_deref() != Some(pending.claim.grant_operation_id.as_str())
    {
        return Err(MobileClientError::PairingFailed);
    }
    let session_id: PeerSessionId = pending
        .claim
        .invitation_id
        .parse()
        .map_err(|_| MobileClientError::PairingFailed)?;
    client_runtime
        .configure_paired_peer(
            pending.responder_node_id,
            pending.endpoint.clone(),
            pending.space_id,
            session_id,
            pending.grant_operation_id,
            pending.peer_transport_credential.clone(),
        )
        .await
        .map_err(|_| MobileClientError::PairingFailed)
}

fn safe_pairing_endpoint(value: &str) -> Result<Url, MobileClientError> {
    let mut url = Url::parse(value).map_err(|_| MobileClientError::InvalidPairingInvitation)?;
    let host_is_local = url.host_str().is_some_and(is_local_network_host);
    if url.scheme() != "http"
        || !host_is_local
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(MobileClientError::InvalidPairingInvitation);
    }
    url.set_path("/");
    Ok(url)
}

fn is_local_network_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| match address {
            std::net::IpAddr::V4(address) => {
                address.is_loopback() || address.is_private() || address.is_link_local()
            }
            std::net::IpAddr::V6(address) => {
                address.is_loopback()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
            }
        })
}

fn endpoint_origin(url: &Url) -> String {
    let mut value = url.clone();
    value.set_path("");
    value.to_string().trim_end_matches('/').to_owned()
}

fn unix_time_millis() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
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
        | ClientRuntimeError::MissingInstallationAnchor(_)
        | ClientRuntimeError::InvalidInstallationAnchor(_) => MobileClientError::RecoveryRequired,
        ClientRuntimeError::Store(
            ClientStoreError::UnsupportedSchema { .. }
            | ClientStoreError::MigrationVersionMismatch { .. }
            | ClientStoreError::Corrupt(_)
            | ClientStoreError::InvalidBootstrap(_)
            | ClientStoreError::UntrackedInstallationOperations
            | ClientStoreError::InstallationNotInitializing
            | ClientStoreError::InstallationConflict,
        ) => MobileClientError::RecoveryRequired,
        _ => MobileClientError::InitializationFailed,
    }
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use fractonica_data_model::CapabilityAction;
    use fractonica_pairing::{
        CapabilityGrantTemplate, InvitationParameters, IssuedInvitation, PairingReceipt,
    };
    use serde::Deserialize;
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
    fn pairing_transport_accepts_only_plain_http_local_network_origins() {
        assert_eq!(
            safe_pairing_endpoint("http://127.0.0.1:8787/path")
                .expect("loopback")
                .as_str(),
            "http://127.0.0.1:8787/"
        );
        assert!(safe_pairing_endpoint("http://localhost:8787").is_ok());
        assert!(safe_pairing_endpoint("http://192.168.1.20:8787").is_ok());
        assert!(safe_pairing_endpoint("https://127.0.0.1:8787").is_err());
        assert!(safe_pairing_endpoint("http://8.8.8.8:8787").is_err());
        assert!(safe_pairing_endpoint("http://user@127.0.0.1:8787").is_err());
        assert!(safe_pairing_endpoint("http://127.0.0.1:8787?secret=x").is_err());
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestHandshakeRequest {
        invitation_id: String,
        frame_base64url: String,
    }

    struct TestResponder {
        issued: IssuedInvitation,
        responder_key: SigningKey,
        grant_operation_id: OperationId,
    }

    async fn test_pairing_handshake(
        State(state): State<Arc<Mutex<Option<TestResponder>>>>,
        Json(request): Json<TestHandshakeRequest>,
    ) -> Json<serde_json::Value> {
        let fixture = state.lock().expect("fixture lock").take().expect("one use");
        let descriptor = fixture.issued.invitation.descriptor();
        assert_eq!(request.invitation_id, descriptor.invitation_id.to_string());
        let first = URL_SAFE_NO_PAD
            .decode(request.frame_base64url)
            .expect("first frame");
        let mut responder = fixture.issued.secret.start_responder().expect("responder");
        let claim =
            JoinerClaim::from_canonical_bytes(&responder.read_message(&first).expect("read claim"))
                .expect("claim");
        claim.verify_for(descriptor).expect("claim proof");
        let response_frame = responder.write_message(&[]).expect("response");
        let mut transport = responder.finish().expect("transport");
        let receipt = PairingReceipt::sign(
            descriptor,
            &claim,
            *transport.handshake_hash(),
            [21; 32],
            &fixture.responder_key,
        );
        let receipt_frame = transport
            .write_message(&receipt.canonical_bytes().expect("receipt"))
            .expect("receipt frame");
        Json(serde_json::json!({
            "responseFrameBase64url": URL_SAFE_NO_PAD.encode(response_frame),
            "receiptFrameBase64url": URL_SAFE_NO_PAD.encode(receipt_frame),
            "session": {
                "invitationId": descriptor.invitation_id.to_string(),
                "spaceId": descriptor.space_id.to_string(),
                "state": "claimed",
                "expiresAtUnixMs": descriptor.expires_at_unix_ms,
                "joinerNodeId": claim.joiner_node_id.to_string(),
                "subjectActorId": claim.subject_actor_id.to_string(),
                "confirmationOctal": transport.confirmation_octal(),
                "grantOperationId": fixture.grant_operation_id.to_string(),
            }
        }))
    }

    #[test]
    fn mobile_joiner_verifies_a_real_noise_receipt_and_confirmation() {
        let executor = Runtime::new().expect("runtime");
        executor.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("address"));
            let now = unix_time_millis().expect("clock");
            let responder_key = SigningKey::from_seed([11; 32]);
            let issued = PairingInvitation::issue(
                &responder_key,
                InvitationParameters {
                    space_id: SpaceId::from_bytes([12; 32]),
                    genesis_operation_id: OperationId::from_bytes([13; 32]),
                    now_unix_ms: now,
                    expires_at_unix_ms: now + 60_000,
                    endpoint_hints: vec![endpoint.clone()],
                    capability: CapabilityGrantTemplate {
                        actions: vec![CapabilityAction::ReadSpace],
                        schemas: vec![],
                        visibilities: vec![],
                        content_roles: vec![],
                        max_resource_byte_length: None,
                        not_before_unix_ms: None,
                        expires_at_unix_ms: None,
                        delegation_depth: 0,
                        label: "mobile test".to_owned(),
                    },
                },
            )
            .expect("invitation");
            let qr = issued.invitation.to_qr_string().expect("qr");
            let state = Arc::new(Mutex::new(Some(TestResponder {
                issued,
                responder_key,
                grant_operation_id: OperationId::from_bytes([14; 32]),
            })));
            let server = tokio::spawn(
                axum::serve(
                    listener,
                    Router::new()
                        .route("/api/pairing/handshake", post(test_pairing_handshake))
                        .with_state(state),
                )
                .into_future(),
            );
            let identity = IdentityBundle::from_keys(
                SigningKey::from_seed([21; 32]),
                SigningKey::from_seed([22; 32]),
                SigningKey::from_seed([23; 32]),
                SpaceId::from_bytes([24; 32]),
            )
            .expect("identity");
            let invitation = PairingInvitation::decode(&qr, now).expect("decode invitation");
            let result = claim_pairing(invitation, now, identity)
                .await
                .expect("verified claim");
            assert_eq!(result.endpoint, endpoint);
            assert_eq!(result.claim.confirmation_octal.len(), 10);
            assert_eq!(result.grant_operation_id, OperationId::from_bytes([14; 32]));
            server.abort();
        });
    }

    #[test]
    fn established_database_reopens_while_native_lifecycle_marker_lags() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("client");
        let bootstrap = MobileClientBootstrap::new(
            path.to_string_lossy().into_owned(),
            "Personal space".to_owned(),
        )
        .expect("bootstrap");
        assert_eq!(
            bootstrap.prepare(false).expect("prepare"),
            MobileIdentityAction::CreateOrResume
        );
        let material = generate_identity_material().expect("identity");
        let client = bootstrap.open(material.clone()).expect("open");
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

        // Platform storage is deliberately treated as present even if its
        // outer lifecycle byte still says `initializing`. This models a crash
        // after Rust committed the installation but before native storage was
        // marked established.
        let reopened = MobileClientBootstrap::new(
            path.to_string_lossy().into_owned(),
            "Personal space".to_owned(),
        )
        .expect("bootstrap");
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
        let bootstrap = MobileClientBootstrap::new(
            path.to_string_lossy().into_owned(),
            "Personal space".to_owned(),
        )
        .expect("bootstrap");
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

        let recovery = MobileClientBootstrap::new(
            path.to_string_lossy().into_owned(),
            "Personal space".to_owned(),
        )
        .expect("recovery bootstrap");
        recovery
            .reset_local_installation(RESET_LOCAL_INSTALLATION_CONFIRMATION.to_owned())
            .expect("reset");
        assert!(!path.exists());
        assert!(matches!(
            recovery.prepare(true),
            Err(MobileClientError::RecoveryRequired)
        ));
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
        let recovery = MobileClientBootstrap::new(
            linked_path.to_string_lossy().into_owned(),
            "Personal space".to_owned(),
        )
        .expect("recovery bootstrap");

        assert!(matches!(
            recovery.reset_local_installation(RESET_LOCAL_INSTALLATION_CONFIRMATION.to_owned()),
            Err(MobileClientError::RecoveryRequired)
        ));
        assert_eq!(fs::read(target.join("keep")).expect("marker"), b"untouched");
    }
}
