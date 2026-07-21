use std::{collections::BTreeMap, time::Duration};

use fractonica_content::{ResourceRef, hash_bytes};
use fractonica_data_model::{OperationNonce, RecordDocument, SigningKey};
use fractonica_keystore::IdentityBundle;
use fractonica_space_bootstrap::build_trusted_space_bootstrap;

use super::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn space() -> SpaceId {
    SpaceId::from_bytes([1; 32])
}

fn entity(byte: u8) -> EntityId {
    EntityId::new(Uuid::from_bytes([byte; 16]))
}

fn genesis(signing_key: &SigningKey) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        entity(1),
        EntitySchema::SpaceGenesis,
        Vec::new(),
        Vec::new(),
        1,
        OperationNonce::from_bytes([1; 16]),
        OperationBody::SpaceGenesis {
            controller: signing_key.actor_id(),
        },
        signing_key,
    )
    .unwrap()
}

fn record(
    signing_key: &SigningKey,
    entity_id: EntityId,
    parents: Vec<OperationId>,
    authorization: OperationId,
    nonce: u8,
    start: i64,
    text: &str,
) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        entity_id,
        EntitySchema::Record,
        parents,
        vec![authorization],
        10 + i64::from(nonce),
        OperationNonce::from_bytes([nonce; 16]),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public {
                document: RecordDocument {
                    start_at_unix_ms: start,
                    end_at_unix_ms: None,
                    emoji: Some("🌀".into()),
                    text: Some(text.into()),
                    metadata: BTreeMap::new(),
                    resources: Vec::new(),
                    references: Vec::new(),
                },
            },
        },
        signing_key,
    )
    .unwrap()
}

fn record_with_resource(
    signing_key: &SigningKey,
    entity_id: EntityId,
    authorization: OperationId,
    nonce: u8,
    resource: ResourceRef,
) -> OperationEnvelope {
    OperationEnvelope::sign(
        space(),
        entity_id,
        EntitySchema::Record,
        Vec::new(),
        vec![authorization],
        10 + i64::from(nonce),
        OperationNonce::from_bytes([nonce; 16]),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public {
                document: RecordDocument {
                    start_at_unix_ms: 100,
                    end_at_unix_ms: None,
                    emoji: Some("📎".into()),
                    text: Some("resource".into()),
                    metadata: BTreeMap::new(),
                    resources: vec![resource],
                    references: Vec::new(),
                },
            },
        },
        signing_key,
    )
    .unwrap()
}

fn seeded_store() -> (ClientSqliteStore, SigningKey, OperationEnvelope) {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(7);
    let genesis = genesis(&signing_key);
    store.commit_remote(&genesis, 1).unwrap();
    (store, signing_key, genesis)
}

fn standalone_identity(seed: u8) -> IdentityBundle {
    IdentityBundle::from_keys(
        key(seed),
        key(seed + 1),
        key(seed + 2),
        SpaceId::from_bytes([seed + 3; 32]),
    )
    .unwrap()
}

#[test]
fn local_commit_is_atomic_replayable_and_materialized_before_delivery() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(9).node_id(),
        endpoint: "https://node.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    let operation = record(
        &signing_key,
        entity(2),
        Vec::new(),
        genesis.operation_id,
        2,
        100,
        "offline first",
    );

    let committed = store.commit_local(&operation, 3).unwrap();
    assert!(!committed.replayed);
    assert_eq!(committed.queued_peers, 1);
    let local = store.entity(space(), operation.entity_id).unwrap().unwrap();
    assert_eq!(local.heads, vec![operation.clone()]);
    let summaries = store
        .list_entities(space(), EntitySchema::Record, 20)
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].start_at_unix_ms, Some(100));
    let records = store.list_records(space(), 20).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].summary.entity_id, operation.entity_id);
    assert_eq!(
        records[0]
            .document
            .as_ref()
            .and_then(|document| document.text.as_deref()),
        Some("offline first")
    );
    let previews = store.list_record_previews(space(), 20).unwrap();
    assert_eq!(previews[0].emoji.as_deref(), Some("🌀"));
    assert_eq!(previews[0].text_preview.as_deref(), Some("offline first"));
    assert!(!previews[0].preview_truncated);
    let detail = store
        .record(space(), operation.entity_id, operation.operation_id)
        .unwrap()
        .expect("record detail");
    assert_eq!(
        detail
            .document
            .as_ref()
            .and_then(|document| document.text.as_deref()),
        Some("offline first")
    );
    assert!(store.commit_local(&operation, 4).unwrap().replayed);
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().pending, 1);
}

#[test]
fn disabled_provisional_peer_can_supply_bootstrap_operations_without_syncing() {
    let (store, signing_key, genesis) = seeded_store();
    let peer_id = key(19).node_id();
    let operation = record(
        &signing_key,
        entity(19),
        Vec::new(),
        genesis.operation_id,
        19,
        190,
        "bootstrap",
    );
    assert!(matches!(
        store.commit_from_peer(&operation, 20, peer_id),
        Err(ClientStoreError::UnknownPeer(found)) if found == peer_id
    ));

    let provisional = PeerConfig {
        peer_id,
        endpoint: "http://192.168.0.24:56523".into(),
        enabled: false,
        push_enabled: false,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 20,
    };
    store.upsert_peer(&provisional).unwrap();
    assert_eq!(store.peer(peer_id).unwrap(), Some(provisional));
    store.commit_from_peer(&operation, 20, peer_id).unwrap();
    assert!(store.enabled_peers(10).unwrap().is_empty());
}

#[test]
fn record_feed_projection_is_bounded_and_detail_requires_the_exact_live_head() {
    let (store, signing_key, genesis) = seeded_store();
    let long_text = "🌀".repeat(MAX_RECORD_PREVIEW_TEXT_CHARS + 1);
    let operation = record(
        &signing_key,
        entity(21),
        Vec::new(),
        genesis.operation_id,
        21,
        100,
        &long_text,
    );
    store.commit_local(&operation, 3).unwrap();

    assert_eq!(store.record_import_count(space()).unwrap(), 1);
    let import = store.record_import_batch(space(), 0, 100).unwrap();
    assert_eq!(import.len(), 1);
    assert_eq!(import[0].entity_id, operation.entity_id);
    assert_eq!(
        import[0].payload,
        match operation.body.clone() {
            OperationBody::PutRecord { payload } => payload,
            _ => unreachable!(),
        }
    );
    assert!(
        store
            .record_import_batch(space(), import[0].local_sequence, 100)
            .unwrap()
            .is_empty()
    );

    let previews = store.list_record_previews(space(), 20).unwrap();
    assert_eq!(previews.len(), 1);
    let preview = &previews[0];
    assert_eq!(
        preview.text_preview.as_deref().unwrap().chars().count(),
        MAX_RECORD_PREVIEW_TEXT_CHARS
    );
    assert_eq!(preview.text_preview.as_deref().unwrap().len(), 768);
    assert!(preview.preview_truncated);

    let detail = store
        .record(space(), operation.entity_id, operation.operation_id)
        .unwrap()
        .expect("exact detail");
    assert_eq!(
        detail.document.and_then(|document| document.text),
        Some(long_text)
    );
    assert!(
        store
            .record(space(), entity(22), operation.operation_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn local_resource_waits_for_verification_then_resumes_durable_upload_progress() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(31).node_id(),
        endpoint: "https://media.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    let bytes = b"abcdefgh";
    let resource = ResourceRef {
        content_id: hash_bytes(bytes),
        byte_length: bytes.len() as u64,
        media_type: "application/octet-stream".into(),
        role: "attachment".into(),
        original_name: Some("fixture.bin".into()),
    };
    let operation = record_with_resource(
        &signing_key,
        entity(31),
        genesis.operation_id,
        31,
        resource.clone(),
    );
    store.commit_local(&operation, 3).unwrap();

    assert_eq!(
        store.resource_scan_candidates(10).unwrap(),
        vec![resource.descriptor()]
    );
    assert_eq!(store.sync_counts(3).unwrap().resources.waiting_uploads, 1);
    assert!(
        store
            .lease_due_resources(
                3,
                Duration::from_secs(1),
                10,
                ResourceTransferLeaseId::new(),
            )
            .unwrap()
            .is_empty()
    );

    store.mark_resource_local(resource.descriptor(), 4).unwrap();
    let first_lease = ResourceTransferLeaseId::new();
    let first = store
        .lease_due_resources(4, Duration::from_secs(1), 10, first_lease)
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].direction, ResourceTransferDirection::Upload);
    store
        .record_resource_progress(
            peer.peer_id,
            resource.content_id,
            ResourceTransferDirection::Upload,
            first_lease,
            4,
            Some("https://media.example/api/uploads/resume"),
        )
        .unwrap();
    store
        .retry_resource_transfer(
            peer.peer_id,
            resource.content_id,
            ResourceTransferDirection::Upload,
            first_lease,
            5,
            "next chunk",
        )
        .unwrap();

    let second_lease = ResourceTransferLeaseId::new();
    let resumed = store
        .lease_due_resources(5, Duration::from_secs(1), 10, second_lease)
        .unwrap();
    assert_eq!(resumed[0].transferred_bytes, 4);
    assert_eq!(
        resumed[0].remote_upload_url.as_deref(),
        Some("https://media.example/api/uploads/resume")
    );
    store
        .complete_resource_transfer(
            peer.peer_id,
            resource.content_id,
            ResourceTransferDirection::Upload,
            second_lease,
            6,
        )
        .unwrap();
    let counts = store.sync_counts(6).unwrap().resources;
    assert_eq!(counts.completed_transfers, 1);
    assert_eq!(counts.transferred_bytes, bytes.len() as u64);
}

#[test]
fn completed_peer_download_unlocks_fanout_without_duplicate_source_upload() {
    let (store, signing_key, genesis) = seeded_store();
    let source = PeerConfig {
        peer_id: key(32).node_id(),
        endpoint: "https://source.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    let destination = PeerConfig {
        peer_id: key(33).node_id(),
        endpoint: "https://destination.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&source).unwrap();
    store.upsert_peer(&destination).unwrap();
    let bytes = b"peer resource";
    let resource = ResourceRef {
        content_id: hash_bytes(bytes),
        byte_length: bytes.len() as u64,
        media_type: "image/jpeg".into(),
        role: "photo".into(),
        original_name: Some("photo.jpg".into()),
    };
    let operation = record_with_resource(
        &signing_key,
        entity(32),
        genesis.operation_id,
        32,
        resource.clone(),
    );
    store
        .commit_from_peer(&operation, 3, source.peer_id)
        .unwrap();
    let counts = store.sync_counts(3).unwrap().resources;
    assert_eq!(counts.pending_downloads, 1);
    assert_eq!(counts.waiting_uploads, 1);

    let lease = ResourceTransferLeaseId::new();
    let transfers = store
        .lease_due_resources(3, Duration::from_secs(1), 10, lease)
        .unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].peer.peer_id, source.peer_id);
    assert_eq!(transfers[0].direction, ResourceTransferDirection::Download);
    store
        .complete_resource_transfer(
            source.peer_id,
            resource.content_id,
            ResourceTransferDirection::Download,
            lease,
            4,
        )
        .unwrap();

    let counts = store.sync_counts(4).unwrap().resources;
    assert_eq!(counts.pending_downloads, 0);
    assert_eq!(counts.pending_uploads, 1);
    assert_eq!(counts.waiting_uploads, 0);
    let upload = store
        .lease_due_resources(
            4,
            Duration::from_secs(1),
            10,
            ResourceTransferLeaseId::new(),
        )
        .unwrap();
    assert_eq!(upload.len(), 1);
    assert_eq!(upload[0].peer.peer_id, destination.peer_id);
    assert_eq!(upload[0].direction, ResourceTransferDirection::Upload);
}

#[test]
fn three_node_chain_forwards_complete_trust_history_and_converges() {
    let relay = ClientSqliteStore::open_in_memory().unwrap();
    let identity = standalone_identity(90);
    let bootstrap = build_trusted_space_bootstrap(&identity, "Shared space", 100).unwrap();
    let upstream = PeerConfig {
        peer_id: key(94).node_id(),
        endpoint: "https://upstream.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 101,
    };
    let downstream = PeerConfig {
        peer_id: key(95).node_id(),
        endpoint: "https://downstream.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 101,
    };
    relay.upsert_peer(&upstream).unwrap();
    relay.upsert_peer(&downstream).unwrap();
    relay
        .commit_from_peer(&bootstrap.genesis, 102, upstream.peer_id)
        .unwrap();
    relay
        .commit_from_peer(&bootstrap.initial_grant, 103, upstream.peer_id)
        .unwrap();
    let record = OperationEnvelope::sign(
        identity.space_id(),
        entity(96),
        EntitySchema::Record,
        Vec::new(),
        vec![bootstrap.initial_grant.operation_id],
        104,
        OperationNonce::from_bytes([96; 16]),
        OperationBody::PutRecord {
            payload: ProtectedDocument::Public {
                document: RecordDocument {
                    start_at_unix_ms: 104,
                    end_at_unix_ms: None,
                    emoji: None,
                    text: Some("transitive".into()),
                    metadata: BTreeMap::new(),
                    resources: Vec::new(),
                    references: Vec::new(),
                },
            },
        },
        identity.local_writer_key(),
    )
    .unwrap();
    relay
        .commit_from_peer(&record, 104, upstream.peer_id)
        .unwrap();

    assert_eq!(
        relay.outbox_counts(upstream.peer_id).unwrap().acknowledged,
        3
    );
    let forwarded = relay
        .lease_due(
            downstream.peer_id,
            104,
            Duration::from_secs(1),
            10,
            DeliveryLeaseId::new(),
        )
        .unwrap();
    assert_eq!(
        forwarded
            .iter()
            .map(|item| item.operation.operation_id)
            .collect::<Vec<_>>(),
        vec![
            bootstrap.genesis.operation_id,
            bootstrap.initial_grant.operation_id,
            record.operation_id,
        ]
    );

    let leaf = ClientSqliteStore::open_in_memory().unwrap();
    let relay_peer = PeerConfig {
        peer_id: key(97).node_id(),
        endpoint: "https://relay.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 105,
    };
    leaf.upsert_peer(&relay_peer).unwrap();
    for item in forwarded {
        leaf.commit_from_peer(&item.operation, 105, relay_peer.peer_id)
            .unwrap();
    }
    assert_eq!(
        leaf.entity(identity.space_id(), record.entity_id)
            .unwrap()
            .unwrap()
            .heads,
        vec![record]
    );
    assert_eq!(
        leaf.outbox_counts(relay_peer.peer_id).unwrap().acknowledged,
        3
    );
}

#[test]
fn concurrent_heads_are_preserved_then_explicitly_merged() {
    let (store, signing_key, genesis) = seeded_store();
    let root = record(
        &signing_key,
        entity(3),
        Vec::new(),
        genesis.operation_id,
        3,
        100,
        "root",
    );
    store.commit_local(&root, 2).unwrap();
    let left = record(
        &signing_key,
        root.entity_id,
        vec![root.operation_id],
        genesis.operation_id,
        4,
        101,
        "left",
    );
    let right = record(
        &signing_key,
        root.entity_id,
        vec![root.operation_id],
        genesis.operation_id,
        5,
        102,
        "right",
    );
    store.commit_remote(&left, 3).unwrap();
    store.commit_remote(&right, 4).unwrap();
    let conflicted = store.entity(space(), root.entity_id).unwrap().unwrap();
    assert_eq!(conflicted.heads.len(), 2);
    assert!(
        store
            .list_entities(space(), EntitySchema::Record, 20)
            .unwrap()
            .iter()
            .all(|item| item.conflicted)
    );

    let merged = record(
        &signing_key,
        root.entity_id,
        vec![left.operation_id, right.operation_id],
        genesis.operation_id,
        6,
        103,
        "merged",
    );
    store.commit_local(&merged, 5).unwrap();
    let resolved = store.entity(space(), root.entity_id).unwrap().unwrap();
    assert_eq!(resolved.heads, vec![merged]);
}

#[test]
fn expired_delivery_lease_recovers_and_stale_worker_cannot_acknowledge() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(8).node_id(),
        endpoint: "http://127.0.0.1:8789".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    let operation = record(
        &signing_key,
        entity(4),
        Vec::new(),
        genesis.operation_id,
        7,
        100,
        "queued",
    );
    store.commit_local(&operation, 3).unwrap();

    let first = DeliveryLeaseId::new();
    let leased = store
        .lease_due(peer.peer_id, 10, Duration::from_millis(5), 10, first)
        .unwrap();
    assert_eq!(leased[0].attempt_count, 1);
    assert!(
        store
            .lease_due(
                peer.peer_id,
                14,
                Duration::from_millis(5),
                10,
                DeliveryLeaseId::new()
            )
            .unwrap()
            .is_empty()
    );

    let second = DeliveryLeaseId::new();
    let recovered = store
        .lease_due(peer.peer_id, 15, Duration::from_millis(5), 10, second)
        .unwrap();
    assert_eq!(recovered[0].attempt_count, 2);
    assert!(matches!(
        store.acknowledge(peer.peer_id, operation.operation_id, first, 16),
        Err(ClientStoreError::LeaseMismatch)
    ));
    store
        .acknowledge(peer.peer_id, operation.operation_id, second, 16)
        .unwrap();
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().acknowledged, 1);
}

#[test]
fn retry_backoff_and_terminal_rejection_are_durable() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(14).node_id(),
        endpoint: "https://retry.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    let operation = record(
        &signing_key,
        entity(14),
        Vec::new(),
        genesis.operation_id,
        14,
        100,
        "retry",
    );
    store.commit_local(&operation, 3).unwrap();
    let first = DeliveryLeaseId::new();
    let leased = store
        .lease_due(peer.peer_id, 3, Duration::from_secs(1), 10, first)
        .unwrap();
    assert_eq!(leased.len(), 1);
    store
        .retry(peer.peer_id, operation.operation_id, first, 50, "offline")
        .unwrap();
    assert!(
        store
            .lease_due(
                peer.peer_id,
                49,
                Duration::from_secs(1),
                10,
                DeliveryLeaseId::new()
            )
            .unwrap()
            .is_empty()
    );
    let second = DeliveryLeaseId::new();
    let retried = store
        .lease_due(peer.peer_id, 50, Duration::from_secs(1), 10, second)
        .unwrap();
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].operation.operation_id, operation.operation_id);
    assert_eq!(retried[0].attempt_count, 2);
    store
        .reject(
            peer.peer_id,
            operation.operation_id,
            second,
            51,
            "capability revoked",
        )
        .unwrap();
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().rejected, 1);
}

#[test]
fn missing_dependencies_roll_back_without_partial_history() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    let signing_key = key(7);
    let missing = OperationId::from_bytes([0xaa; 32]);
    let operation = record(
        &signing_key,
        entity(5),
        Vec::new(),
        missing,
        8,
        100,
        "must fail",
    );
    assert!(matches!(
        store.commit_local(&operation, 1),
        Err(ClientStoreError::MissingAuthorization(id)) if id == missing
    ));
    assert!(
        store
            .entity(space(), operation.entity_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_peer_added_later_receives_all_history_and_peer_ingest_forwards_elsewhere() {
    let (store, signing_key, genesis) = seeded_store();
    let local = record(
        &signing_key,
        entity(6),
        Vec::new(),
        genesis.operation_id,
        9,
        100,
        "local",
    );
    let remote = record(
        &signing_key,
        entity(7),
        Vec::new(),
        genesis.operation_id,
        10,
        101,
        "remote",
    );
    store.commit_local(&local, 2).unwrap();
    store.commit_remote(&remote, 3).unwrap();
    let peer = PeerConfig {
        peer_id: key(10).node_id(),
        endpoint: "https://later.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 4,
    };
    store.upsert_peer(&peer).unwrap();
    let lease = store
        .lease_due(
            peer.peer_id,
            4,
            Duration::from_secs(1),
            10,
            DeliveryLeaseId::new(),
        )
        .unwrap();
    assert_eq!(lease.len(), 2);
    assert!(
        lease
            .iter()
            .any(|item| item.operation.operation_id == local.operation_id)
    );
    assert!(
        lease
            .iter()
            .any(|item| item.operation.operation_id == remote.operation_id)
    );

    let second = PeerConfig {
        peer_id: key(12).node_id(),
        endpoint: "https://second.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 5,
    };
    store.upsert_peer(&second).unwrap();
    let forwarded = record(
        &signing_key,
        entity(9),
        Vec::new(),
        genesis.operation_id,
        12,
        102,
        "forwarded",
    );
    store.commit_from_peer(&forwarded, 6, peer.peer_id).unwrap();
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().acknowledged, 1);
    let to_second = store
        .lease_due(
            second.peer_id,
            6,
            Duration::from_secs(1),
            10,
            DeliveryLeaseId::new(),
        )
        .unwrap();
    assert!(
        to_second
            .iter()
            .any(|item| item.operation.operation_id == forwarded.operation_id)
    );
}

#[test]
fn file_store_survives_reopen_with_heads_and_outbox_intact() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.sqlite3");
    let signing_key = key(7);
    let genesis = genesis(&signing_key);
    let operation = record(
        &signing_key,
        entity(8),
        Vec::new(),
        genesis.operation_id,
        11,
        100,
        "durable",
    );
    let peer = PeerConfig {
        peer_id: key(11).node_id(),
        endpoint: "https://durable.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 1,
    };
    {
        let store = ClientSqliteStore::open(&path).unwrap();
        store.commit_remote(&genesis, 1).unwrap();
        store.upsert_peer(&peer).unwrap();
        store.commit_local(&operation, 2).unwrap();
    }
    let reopened = ClientSqliteStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .entity(space(), operation.entity_id)
            .unwrap()
            .unwrap()
            .heads,
        vec![operation]
    );
    assert_eq!(reopened.outbox_counts(peer.peer_id).unwrap().pending, 1);
    drop(reopened);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn projections_and_heads_rebuild_without_touching_delivery_state() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(13).node_id(),
        endpoint: "https://rebuild.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    let operation = record(
        &signing_key,
        entity(10),
        Vec::new(),
        genesis.operation_id,
        13,
        333,
        "rebuild",
    );
    store.commit_local(&operation, 3).unwrap();
    assert_eq!(store.rebuild_derived_state().unwrap(), 2);
    assert_eq!(
        store
            .entity(space(), operation.entity_id)
            .unwrap()
            .unwrap()
            .heads,
        vec![operation]
    );
    assert_eq!(
        store
            .list_entities(space(), EntitySchema::Record, 10)
            .unwrap()[0]
            .start_at_unix_ms,
        Some(333)
    );
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().pending, 1);
}

#[test]
fn peer_space_cursor_and_failure_state_use_compare_and_swap() {
    let (store, _signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(15).node_id(),
        endpoint: "https://cursor.example".into(),
        enabled: true,
        push_enabled: true,
        content_read_enabled: true,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    store
        .configure_peer_space(&PeerSpaceConfig {
            peer_id: peer.peer_id,
            space_id: space(),
            read_mode: PeerReadMode::Paired {
                session_id: PeerSessionId::from_bytes([5; 16]),
                grant_operation_id: genesis.operation_id,
            },
            start_after: 0,
            next_pull_at_unix_ms: 10,
        })
        .unwrap();
    assert_eq!(store.due_sync_targets(9, 10).unwrap().len(), 0);
    assert_eq!(store.due_sync_targets(10, 10).unwrap()[0].after, 0);
    store
        .advance_pull_cursor(peer.peer_id, space(), 0, 7, 10, 20)
        .unwrap();
    assert!(matches!(
        store.record_pull_failure(peer.peer_id, space(), 0, 30, "stale"),
        Err(ClientStoreError::PullCursorMismatch)
    ));
    let target = store.due_sync_targets(20, 10).unwrap().remove(0);
    assert_eq!(target.after, 7);
    store
        .record_pull_failure(peer.peer_id, space(), 7, 40, "offline")
        .unwrap();
    assert_eq!(store.due_sync_targets(39, 10).unwrap().len(), 0);
    let failed = store.due_sync_targets(40, 10).unwrap().remove(0);
    assert_eq!(failed.pull_failure_count, 1);
}

#[test]
fn paired_read_only_peer_never_queues_local_operations_or_media_uploads() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(18).node_id(),
        endpoint: "http://127.0.0.1:8789".into(),
        enabled: true,
        push_enabled: false,
        content_read_enabled: false,
        peer_transport_credential: None,
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    store
        .configure_peer_space(&PeerSpaceConfig {
            peer_id: peer.peer_id,
            space_id: space(),
            read_mode: PeerReadMode::Paired {
                session_id: PeerSessionId::from_bytes([18; 16]),
                grant_operation_id: genesis.operation_id,
            },
            start_after: 0,
            next_pull_at_unix_ms: 2,
        })
        .unwrap();
    let operation = record(
        &signing_key,
        entity(18),
        Vec::new(),
        genesis.operation_id,
        18,
        180,
        "local only",
    );
    let result = store.commit_local(&operation, 3).unwrap();
    assert_eq!(result.queued_peers, 0);
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().pending, 0);
    assert_eq!(store.sync_counts(3).unwrap().resources.pending_uploads, 0);
    let targets = store.due_sync_targets(3, 10).unwrap();
    assert_eq!(targets.len(), 1);
    assert!(matches!(targets[0].read_mode, PeerReadMode::Paired { .. }));
}

#[test]
fn standalone_establishment_is_atomic_replayable_and_pins_exact_anchors() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    assert_eq!(store.installation().unwrap(), ClientInstallation::Unbound);
    assert_eq!(
        store.begin_local_installation().unwrap(),
        ClientInstallation::Initializing
    );
    let identity = standalone_identity(40);
    let bootstrap = build_trusted_space_bootstrap(&identity, "Personal space", 100).unwrap();

    let established = store
        .establish_local_space(identity.node_id(), &bootstrap)
        .unwrap();
    assert!(!established.replayed);
    assert_eq!(established.binding.node_id, identity.node_id());
    assert_eq!(established.binding.space_id, identity.space_id());
    assert_eq!(
        established.binding.controller_actor_id,
        identity.space_controller_actor_id()
    );
    assert_eq!(
        established.binding.local_writer_actor_id,
        identity.local_writer_actor_id()
    );
    assert_eq!(
        store
            .operation(bootstrap.genesis.operation_id)
            .unwrap()
            .unwrap(),
        bootstrap.genesis
    );
    assert_eq!(
        store
            .operation(bootstrap.initial_grant.operation_id)
            .unwrap()
            .unwrap(),
        bootstrap.initial_grant
    );
    assert_eq!(operation_count(&store.lock().unwrap()).unwrap(), 2);

    let replay = store
        .establish_local_space(identity.node_id(), &bootstrap)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.binding, established.binding);
}

#[test]
fn standalone_establishment_rejects_an_exact_preexisting_anchor() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    store.begin_local_installation().unwrap();
    let identity = standalone_identity(50);
    let bootstrap = build_trusted_space_bootstrap(&identity, "Personal space", 200).unwrap();
    store.commit_remote(&bootstrap.genesis, 200).unwrap();

    assert!(matches!(
        store.establish_local_space(identity.node_id(), &bootstrap),
        Err(ClientStoreError::UntrackedInstallationOperations)
    ));
    assert_eq!(
        store.installation().unwrap(),
        ClientInstallation::Initializing
    );
    assert!(
        store
            .operation(bootstrap.initial_grant.operation_id)
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn persistent_store_rejects_a_symbolic_link_database_path() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let real_path = directory.path().join("real.sqlite3");
    drop(ClientSqliteStore::open(&real_path).unwrap());
    let linked_path = directory.path().join("linked.sqlite3");
    symlink(&real_path, &linked_path).unwrap();

    assert!(matches!(
        ClientSqliteStore::open(&linked_path),
        Err(ClientStoreError::Sqlite(_))
    ));
}

#[test]
fn standalone_establishment_rejects_untracked_operations() {
    let store = ClientSqliteStore::open_in_memory().unwrap();
    store.begin_local_installation().unwrap();
    let expected_identity = standalone_identity(70);
    let expected =
        build_trusted_space_bootstrap(&expected_identity, "Personal space", 300).unwrap();
    let unrelated_identity = standalone_identity(80);
    let unrelated = build_trusted_space_bootstrap(&unrelated_identity, "Other space", 301).unwrap();
    store.commit_remote(&unrelated.genesis, 301).unwrap();

    assert!(matches!(
        store.establish_local_space(expected_identity.node_id(), &expected),
        Err(ClientStoreError::UntrackedInstallationOperations)
    ));
    assert_eq!(
        store.installation().unwrap(),
        ClientInstallation::Initializing
    );
    assert!(
        store
            .operation(expected.genesis.operation_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn ordered_migrations_upgrade_a_version_one_client_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.sqlite3");
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(MIGRATIONS[0]).unwrap();
        assert_eq!(
            connection
                .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            1
        );
    }

    let store = ClientSqliteStore::open(&path).unwrap();
    assert_eq!(store.installation().unwrap(), ClientInstallation::Unbound);
    let connection = store.lock().unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        CLIENT_SCHEMA_VERSION
    );
}
