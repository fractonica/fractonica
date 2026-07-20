use std::{collections::BTreeMap, time::Duration};

use fractonica_content::{ResourceRef, hash_bytes};
use fractonica_data_model::{OperationNonce, RecordDocument, SigningKey};

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

#[test]
fn local_commit_is_atomic_replayable_and_materialized_before_delivery() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(9).node_id(),
        endpoint: "https://node.example".into(),
        enabled: true,
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
    assert!(store.commit_local(&operation, 4).unwrap().replayed);
    assert_eq!(store.outbox_counts(peer.peer_id).unwrap().pending, 1);
}

#[test]
fn local_resource_waits_for_verification_then_resumes_durable_upload_progress() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(31).node_id(),
        endpoint: "https://media.example".into(),
        enabled: true,
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
        added_at_unix_ms: 2,
    };
    let destination = PeerConfig {
        peer_id: key(33).node_id(),
        endpoint: "https://destination.example".into(),
        enabled: true,
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
}

#[test]
fn projections_and_heads_rebuild_without_touching_delivery_state() {
    let (store, signing_key, genesis) = seeded_store();
    let peer = PeerConfig {
        peer_id: key(13).node_id(),
        endpoint: "https://rebuild.example".into(),
        enabled: true,
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
        added_at_unix_ms: 2,
    };
    store.upsert_peer(&peer).unwrap();
    store
        .configure_peer_space(&PeerSpaceConfig {
            peer_id: peer.peer_id,
            space_id: space(),
            session_id: PeerSessionId::from_bytes([5; 16]),
            grant_operation_id: genesis.operation_id,
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
