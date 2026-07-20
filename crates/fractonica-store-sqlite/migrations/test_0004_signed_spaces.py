#!/usr/bin/env python3
"""Apply migrations 0001-0004 and probe protocol-v2 SQLite invariants."""

from __future__ import annotations

import sqlite3
from pathlib import Path


MIGRATIONS = Path(__file__).resolve().parent
ACTOR = "actor:ed25519:" + "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
WRITER = "actor:ed25519:" + "44" * 32
OTHER_ACTOR = "actor:ed25519:" + "55" * 32
ENTITY_A = "018f3e7a-5b6c-7d8e-9fab-102030405060"
ENTITY_B = "018f3e7a-5b6c-7d8e-9fab-102030405061"
ENTITY_GENESIS_A = "018f3e7a-5b6c-7d8e-9fab-102030405062"
ENTITY_GENESIS_B = "018f3e7a-5b6c-7d8e-9fab-102030405063"
ENTITY_GRANT = "018f3e7a-5b6c-7d8e-9fab-102030405064"
ENTITY_REVOCATION = "018f3e7a-5b6c-7d8e-9fab-102030405065"
ENTITY_CROSS_REVOCATION = "018f3e7a-5b6c-7d8e-9fab-102030405066"
ENTITY_INITIAL_GRANT_A = "018f3e7a-5b6c-7d8e-9fab-102030405067"
ENTITY_INITIAL_GRANT_B = "018f3e7a-5b6c-7d8e-9fab-102030405068"
ENTITY_MISMATCH_GENESIS = "018f3e7a-5b6c-7d8e-9fab-102030405069"
ENTITY_MISMATCH_GRANT = "018f3e7a-5b6c-7d8e-9fab-10203040506a"


def space(byte: int) -> str:
    return "space:" + f"{byte:02x}" * 32


def operation(byte: int) -> str:
    return "sha-256:" + f"{byte:02x}" * 32


def apply(connection: sqlite3.Connection, version: int) -> None:
    path = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
    sql = path.read_text(encoding="utf-8")
    try:
        connection.executescript(f"BEGIN IMMEDIATE;\n{sql}\nCOMMIT;")
    except Exception:
        connection.rollback()
        raise


def insert_space(
    connection: sqlite3.Connection,
    *,
    space_id: str,
    genesis_id: str,
    initial_grant_id: str,
    display_name: str | None = None,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        INSERT INTO spaces (
            space_id, genesis_operation_id, controller_actor_id,
            initial_grant_operation_id, local_writer_actor_id,
            display_name, created_at_unix_ms
        ) VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        (
            space_id,
            genesis_id,
            ACTOR,
            initial_grant_id,
            WRITER,
            display_name or f"test {space_id[-2:]}",
        ),
    )
    insert_operation(
        connection,
        space_id=space_id,
        operation_id=genesis_id,
        entity_id=ENTITY_GENESIS_A if space_id == space(1) else ENTITY_GENESIS_B,
        schema_id="space.genesis.v1",
    )
    insert_operation(
        connection,
        space_id=space_id,
        operation_id=initial_grant_id,
        entity_id=(
            ENTITY_INITIAL_GRANT_A if space_id == space(1) else ENTITY_INITIAL_GRANT_B
        ),
        schema_id="capability.grant.v1",
    )
    connection.execute(
        "INSERT INTO operation_authorization_refs VALUES (?, ?, ?, 0)",
        (space_id, initial_grant_id, genesis_id),
    )
    connection.execute(
        """
        INSERT INTO capability_grants (
            space_id, grant_operation_id, issuer_actor_id, subject_actor_id,
            delegation_depth, label
        ) VALUES (?, ?, ?, ?, 0, 'initial local writer')
        """,
        (space_id, initial_grant_id, ACTOR, WRITER),
    )
    connection.execute(
        "INSERT INTO capability_grant_actions VALUES (?, ?, 0, 'appendOperation')",
        (space_id, initial_grant_id),
    )
    connection.execute(
        "INSERT INTO capability_grant_schema_scopes VALUES (?, ?, 0, 'record.v1')",
        (space_id, initial_grant_id),
    )
    connection.executemany(
        "INSERT INTO capability_grant_record_visibilities VALUES (?, ?, ?, ?)",
        (
            (space_id, initial_grant_id, 0, "public"),
            (space_id, initial_grant_id, 1, "private"),
        ),
    )
    connection.commit()


def insert_operation(
    connection: sqlite3.Connection,
    *,
    space_id: str,
    operation_id: str,
    entity_id: str,
    schema_id: str = "record.v1",
) -> None:
    connection.execute(
        """
        INSERT INTO operations (
            operation_id, protocol_version, space_id, entity_id, schema_id,
            actor_id, occurred_at_unix_ms, received_at_unix_ms, nonce,
            canonical_payload, cose_sign1, projection_json
        ) VALUES (?, 2, ?, ?, ?, ?, 2, 3, ?, ?, ?, '{}')
        """,
        (
            operation_id,
            space_id,
            entity_id,
            schema_id,
            ACTOR,
            bytes.fromhex(operation_id[8:40]),
            b"\x8b",
            b"\xd2" + b"\x00" * 79,
        ),
    )


def expect_integrity_error(
    connection: sqlite3.Connection,
    name: str,
    sql: str,
    parameters: tuple[object, ...],
) -> None:
    connection.execute("SAVEPOINT negative_probe")
    try:
        connection.execute(sql, parameters)
    except sqlite3.IntegrityError:
        connection.execute("ROLLBACK TO negative_probe")
        connection.execute("RELEASE negative_probe")
        return
    connection.execute("ROLLBACK TO negative_probe")
    connection.execute("RELEASE negative_probe")
    raise AssertionError(f"negative probe unexpectedly succeeded: {name}")


def test_empty_upgrade_and_constraints() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    for version in range(1, 4):
        apply(connection, version)

    connection.execute(
        "INSERT INTO node_installation VALUES (1, 'installation-test', 1)"
    )
    connection.execute(
        "INSERT INTO blobs VALUES (?, 4, 1)", (operation(240),)
    )
    connection.execute(
        """
        INSERT INTO upload_sessions (
            upload_id, upload_length, upload_offset, state,
            created_at_unix_ms, expires_at_unix_ms
        ) VALUES ('upload-test', 4, 0, 'active', 1, 2)
        """
    )
    connection.commit()
    apply(connection, 4)

    assert connection.execute("PRAGMA user_version").fetchone() == (4,)
    assert connection.execute("SELECT count(*) FROM node_installation").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM blobs").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM upload_sessions").fetchone() == (1,)
    assert connection.execute(
        "SELECT singleton, high_water_unix_ms FROM node_admission_clock"
    ).fetchone() == (1, 0)
    expect_integrity_error(
        connection,
        "negative admission clock",
        "UPDATE node_admission_clock SET high_water_unix_ms = -1 WHERE singleton = 1",
        (),
    )
    expect_integrity_error(
        connection,
        "second admission clock singleton",
        "INSERT INTO node_admission_clock VALUES (2, 0)",
        (),
    )

    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        INSERT INTO spaces (
            space_id, genesis_operation_id, controller_actor_id,
            initial_grant_operation_id, local_writer_actor_id,
            display_name, created_at_unix_ms
        ) VALUES (?, ?, ?, ?, ?, 'incomplete', 1)
        """,
        (space(9), operation(9), ACTOR, operation(19), WRITER),
    )
    try:
        connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
    else:
        raise AssertionError("space committed without its deferred genesis operation")

    mismatch_space = space(8)
    mismatch_genesis = operation(28)
    mismatch_grant = operation(29)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        """
        INSERT INTO spaces (
            space_id, genesis_operation_id, controller_actor_id,
            initial_grant_operation_id, local_writer_actor_id,
            display_name, created_at_unix_ms
        ) VALUES (?, ?, ?, ?, ?, 'subject mismatch', 1)
        """,
        (mismatch_space, mismatch_genesis, ACTOR, mismatch_grant, WRITER),
    )
    insert_operation(
        connection,
        space_id=mismatch_space,
        operation_id=mismatch_genesis,
        entity_id=ENTITY_MISMATCH_GENESIS,
        schema_id="space.genesis.v1",
    )
    insert_operation(
        connection,
        space_id=mismatch_space,
        operation_id=mismatch_grant,
        entity_id=ENTITY_MISMATCH_GRANT,
        schema_id="capability.grant.v1",
    )
    connection.execute(
        """
        INSERT INTO capability_grants (
            space_id, grant_operation_id, issuer_actor_id, subject_actor_id,
            delegation_depth, label
        ) VALUES (?, ?, ?, ?, 0, 'wrong subject')
        """,
        (mismatch_space, mismatch_grant, ACTOR, OTHER_ACTOR),
    )
    try:
        connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
    else:
        raise AssertionError("initial grant subject mismatch committed")

    space_one, space_two = space(1), space(2)
    genesis_one, genesis_two = operation(1), operation(2)
    insert_space(
        connection,
        space_id=space_one,
        genesis_id=genesis_one,
        initial_grant_id=operation(11),
        display_name="🌒" * 128,
    )
    insert_space(
        connection,
        space_id=space_two,
        genesis_id=genesis_two,
        initial_grant_id=operation(12),
    )

    parent_one, child_one = operation(3), operation(4)
    cross_space_parent = operation(5)
    other_entity_parent = operation(6)
    for operation_id, selected_space, entity_id in (
        (parent_one, space_one, ENTITY_A),
        (child_one, space_one, ENTITY_A),
        (cross_space_parent, space_two, ENTITY_A),
        (other_entity_parent, space_one, ENTITY_B),
    ):
        insert_operation(
            connection,
            space_id=selected_space,
            operation_id=operation_id,
            entity_id=entity_id,
        )
    connection.commit()

    connection.execute(
        "INSERT INTO record_entity_visibility VALUES (?, ?, 'record.v1', ?, 'public')",
        (space_one, ENTITY_A, parent_one),
    )
    expect_integrity_error(
        connection,
        "ambiguous record visibility",
        "INSERT INTO record_entity_visibility VALUES (?, ?, 'record.v1', ?, 'private')",
        (space_one, ENTITY_A, child_one),
    )
    expect_integrity_error(
        connection,
        "cross-entity visibility origin",
        "INSERT INTO record_entity_visibility VALUES (?, ?, 'record.v1', ?, 'public')",
        (space_one, ENTITY_A, other_entity_parent),
    )

    connection.execute(
        "INSERT INTO operation_parents VALUES (?, ?, 'record.v1', ?, ?, 0)",
        (space_one, ENTITY_A, child_one, parent_one),
    )
    expect_integrity_error(
        connection,
        "cross-space parent",
        "INSERT INTO operation_parents VALUES (?, ?, 'record.v1', ?, ?, 1)",
        (space_one, ENTITY_A, child_one, cross_space_parent),
    )
    expect_integrity_error(
        connection,
        "cross-entity parent",
        "INSERT INTO operation_parents VALUES (?, ?, 'record.v1', ?, ?, 1)",
        (space_one, ENTITY_A, child_one, other_entity_parent),
    )
    expect_integrity_error(
        connection,
        "cross-space authorization",
        "INSERT INTO operation_authorization_refs VALUES (?, ?, ?, 0)",
        (space_one, child_one, genesis_two),
    )
    expect_integrity_error(
        connection,
        "cross-space entity head",
        "INSERT INTO entity_heads VALUES (?, ?, 'record.v1', ?)",
        (space_one, ENTITY_A, cross_space_parent),
    )
    expect_integrity_error(
        connection,
        "cross-space resource",
        """
        INSERT INTO operation_resources (
            space_id, operation_id, position, content_id,
            byte_length, media_type, role
        ) VALUES (?, ?, 0, ?, 4, 'text/plain', 'attachment')
        """,
        (space_one, cross_space_parent, operation(240)),
    )
    expect_integrity_error(
        connection,
        "genesis authorization",
        "INSERT INTO operation_authorization_refs VALUES (?, ?, ?, 0)",
        (space_one, genesis_one, child_one),
    )

    grant_id = operation(7)
    insert_operation(
        connection,
        space_id=space_two,
        operation_id=grant_id,
        entity_id=ENTITY_GRANT,
        schema_id="capability.grant.v1",
    )
    connection.execute(
        """
        INSERT INTO capability_grants (
            space_id, grant_operation_id, issuer_actor_id, subject_actor_id,
            delegation_depth, max_resource_byte_length, label
        ) VALUES (?, ?, ?, ?, 0, 1024, 'test grant')
        """,
        (space_two, grant_id, ACTOR, ACTOR),
    )
    connection.execute(
        "INSERT INTO operation_authorization_refs VALUES (?, ?, ?, 0)",
        (space_two, grant_id, genesis_two),
    )
    connection.executemany(
        "INSERT INTO capability_grant_actions VALUES (?, ?, ?, ?)",
        (
            (space_two, grant_id, 0, "appendOperation"),
            (space_two, grant_id, 1, "writeContent"),
        ),
    )
    connection.execute(
        "INSERT INTO capability_grant_schema_scopes VALUES (?, ?, 0, 'record.v1')",
        (space_two, grant_id),
    )
    connection.execute(
        "INSERT INTO capability_grant_record_visibilities VALUES (?, ?, 0, 'public')",
        (space_two, grant_id),
    )
    connection.execute(
        "INSERT INTO capability_grant_content_roles VALUES (?, ?, 0, 'attachment')",
        (space_two, grant_id),
    )
    expect_integrity_error(
        connection,
        "unknown capability action",
        "INSERT INTO capability_grant_actions VALUES (?, ?, 2, 'admin')",
        (space_two, grant_id),
    )
    expect_integrity_error(
        connection,
        "delegation depth above model limit",
        """
        UPDATE capability_grants
        SET delegation_depth = 17
        WHERE space_id = ? AND grant_operation_id = ?
        """,
        (space_two, grant_id),
    )
    expect_integrity_error(
        connection,
        "cross-space grant projection",
        """
        INSERT INTO capability_grants (
            space_id, grant_operation_id, issuer_actor_id, subject_actor_id,
            delegation_depth, label
        ) VALUES (?, ?, ?, ?, 0, 'wrong space')
        """,
        (space_one, grant_id, ACTOR, ACTOR),
    )

    revocation_id = operation(8)
    insert_operation(
        connection,
        space_id=space_two,
        operation_id=revocation_id,
        entity_id=ENTITY_REVOCATION,
        schema_id="capability.revoke.v1",
    )
    connection.execute(
        "INSERT INTO operation_authorization_refs VALUES (?, ?, ?, 0)",
        (space_two, revocation_id, grant_id),
    )
    connection.execute(
        """
        INSERT INTO capability_grant_revocations (
            space_id, revocation_operation_id, revoker_actor_id,
            grant_operation_id, reason, detail
        ) VALUES (?, ?, ?, ?, 'keyCompromised', 'test detail')
        """,
        (space_two, revocation_id, ACTOR, grant_id),
    )
    expect_integrity_error(
        connection,
        "unknown revocation reason",
        """
        UPDATE capability_grant_revocations
        SET reason = 'unknown'
        WHERE space_id = ? AND revocation_operation_id = ?
        """,
        (space_two, revocation_id),
    )

    cross_revocation_id = operation(10)
    insert_operation(
        connection,
        space_id=space_one,
        operation_id=cross_revocation_id,
        entity_id=ENTITY_CROSS_REVOCATION,
        schema_id="capability.revoke.v1",
    )
    expect_integrity_error(
        connection,
        "cross-space grant revocation",
        """
        INSERT INTO capability_grant_revocations (
            space_id, revocation_operation_id, revoker_actor_id,
            grant_operation_id, reason
        ) VALUES (?, ?, ?, ?, 'administrative')
        """,
        (space_one, cross_revocation_id, ACTOR, grant_id),
    )
    connection.commit()

    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_nonempty_legacy_upgrade_is_rejected() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    for version in range(1, 4):
        apply(connection, version)
    connection.execute(
        """
        INSERT INTO operations (
            operation_id, protocol_version, entity_id, schema_id, actor_id,
            kind, occurred_at_unix_ms, received_at_unix_ms, payload
        ) VALUES (?, 1, ?, 'record.v1', ?, 'tombstone', 1, 1, X'7B7D')
        """,
        (
            "00000000-0000-0000-0000-000000000001",
            ENTITY_A,
            "00000000-0000-0000-0000-000000000002",
        ),
    )
    connection.commit()
    try:
        apply(connection, 4)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("v4 accepted a nonempty unsigned operation log")
    assert connection.execute("PRAGMA user_version").fetchone() == (3,)
    assert connection.execute("SELECT count(*) FROM operations").fetchone() == (1,)


if __name__ == "__main__":
    test_empty_upgrade_and_constraints()
    test_nonempty_legacy_upgrade_is_rejected()
    print("migration 0004 signed-space checks passed")
