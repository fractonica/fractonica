-- Protocol v2 is a clean replacement for the unsigned UUID operation log.
-- The Rust migration boundary verifies this condition before executing SQL;
-- this guard prevents accidental destructive application by another caller.
CREATE TEMP TABLE _fractonica_v4_empty_legacy_guard (
    operation_count INTEGER NOT NULL CHECK (operation_count = 0)
) STRICT;

INSERT INTO _fractonica_v4_empty_legacy_guard (operation_count)
SELECT count(*) FROM operations;

DROP TABLE operation_resources;
DROP TABLE idempotency_receipts;
DROP TABLE entity_heads;
DROP TABLE operation_parents;
DROP TABLE operations;
DROP TABLE _fractonica_v4_empty_legacy_guard;

-- Capability windows use this durable nondecreasing node clock, never a raw
-- wall-clock sample alone. Admission advances it in an independent committed
-- transaction before authorization, including for requests later denied.
CREATE TABLE node_admission_clock (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    high_water_unix_ms INTEGER NOT NULL CHECK (high_water_unix_ms >= 0)
) STRICT;

INSERT INTO node_admission_clock (singleton, high_water_unix_ms) VALUES (1, 0);

-- A space row is inserted before its genesis operation and controller-issued
-- initial local-writer grant in the same transaction. Deferred reverse foreign
-- keys are checked at COMMIT after both operation/projection rows exist. The
-- immediate operations -> spaces key prevents operations for an unknown space.
CREATE TABLE spaces (
    space_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(space_id) = 70
        AND substr(space_id, 1, 6) = 'space:'
        AND substr(space_id, 7) NOT GLOB '*[^0-9a-f]*'
        AND substr(space_id, 7) <> printf('%064d', 0)
    ),
    genesis_operation_id TEXT NOT NULL UNIQUE CHECK (
        length(genesis_operation_id) = 72
        AND substr(genesis_operation_id, 1, 8) = 'sha-256:'
        AND substr(genesis_operation_id, 9) NOT GLOB '*[^0-9a-f]*'
    ),
    controller_actor_id TEXT NOT NULL CHECK (
        length(controller_actor_id) = 78
        AND substr(controller_actor_id, 1, 14) = 'actor:ed25519:'
        AND substr(controller_actor_id, 15) NOT GLOB '*[^0-9a-f]*'
    ),
    initial_grant_operation_id TEXT NOT NULL UNIQUE CHECK (
        length(initial_grant_operation_id) = 72
        AND substr(initial_grant_operation_id, 1, 8) = 'sha-256:'
        AND substr(initial_grant_operation_id, 9) NOT GLOB '*[^0-9a-f]*'
    ),
    local_writer_actor_id TEXT NOT NULL CHECK (
        length(local_writer_actor_id) = 78
        AND substr(local_writer_actor_id, 1, 14) = 'actor:ed25519:'
        AND substr(local_writer_actor_id, 15) NOT GLOB '*[^0-9a-f]*'
    ),
    display_name TEXT NOT NULL CHECK (
        -- At most 128 Unicode scalars in the application. Rust enforces the
        -- scalar/control rules; SQL permits their 4-byte UTF-8 upper bound.
        length(CAST(display_name AS BLOB)) BETWEEN 1 AND 512
        AND instr(display_name, char(0)) = 0
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    FOREIGN KEY (space_id, genesis_operation_id, controller_actor_id)
        REFERENCES operations(space_id, operation_id, actor_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        space_id,
        initial_grant_operation_id,
        controller_actor_id,
        local_writer_actor_id
    ) REFERENCES capability_grants(
        space_id,
        grant_operation_id,
        issuer_actor_id,
        subject_actor_id
    ) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (initial_grant_operation_id <> genesis_operation_id),
    CHECK (local_writer_actor_id <> controller_actor_id)
) STRICT;

CREATE TABLE operations (
    local_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE CHECK (
        length(operation_id) = 72
        AND substr(operation_id, 1, 8) = 'sha-256:'
        AND substr(operation_id, 9) NOT GLOB '*[^0-9a-f]*'
    ),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = 2),
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL CHECK (
        length(entity_id) = 36
        AND substr(entity_id, 9, 1) = '-'
        AND substr(entity_id, 14, 1) = '-'
        AND substr(entity_id, 19, 1) = '-'
        AND substr(entity_id, 24, 1) = '-'
        AND length(replace(entity_id, '-', '')) = 32
        AND replace(entity_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND entity_id <> '00000000-0000-0000-0000-000000000000'
    ),
    schema_id TEXT NOT NULL CHECK (schema_id IN (
        'event.v1',
        'profile.v1',
        'record.v1',
        'record.v2',
        'space.genesis.v1',
        'capability.grant.v1',
        'capability.revoke.v1',
        'tag.v1'
    )),
    actor_id TEXT NOT NULL CHECK (
        length(actor_id) = 78
        AND substr(actor_id, 1, 14) = 'actor:ed25519:'
        AND substr(actor_id, 15) NOT GLOB '*[^0-9a-f]*'
    ),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 16),
    canonical_payload BLOB NOT NULL CHECK (
        length(canonical_payload) BETWEEN 1 AND 2097152
        AND hex(substr(canonical_payload, 1, 1)) = '8B'
    ),
    cose_sign1 BLOB NOT NULL CHECK (
        length(cose_sign1) BETWEEN 80 AND 2097408
        AND hex(substr(cose_sign1, 1, 1)) = 'D2'
    ),
    projection_json TEXT NOT NULL CHECK (
        length(CAST(projection_json AS BLOB)) BETWEEN 2 AND 8388608
        AND json_valid(projection_json)
        AND json_type(projection_json) = 'object'
    ),
    UNIQUE (space_id, operation_id),
    UNIQUE (space_id, operation_id, actor_id),
    UNIQUE (space_id, operation_id, actor_id, schema_id),
    UNIQUE (space_id, entity_id, schema_id, operation_id),
    FOREIGN KEY (space_id)
        REFERENCES spaces(space_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX operations_space_changes_idx
    ON operations (space_id, local_sequence);

CREATE INDEX operations_entity_history_idx
    ON operations (space_id, entity_id, schema_id, local_sequence);

CREATE INDEX operations_actor_history_idx
    ON operations (space_id, actor_id, local_sequence);

-- One entity UUID denotes one schema history inside a space. Cross-schema
-- evolution requires an explicit new protocol rule rather than an accidental
-- second initial branch.
CREATE TRIGGER operations_one_schema_per_entity
BEFORE INSERT ON operations
WHEN EXISTS (
    SELECT 1
    FROM operations AS existing
    WHERE existing.space_id = NEW.space_id
      AND existing.entity_id = NEW.entity_id
      AND existing.schema_id <> NEW.schema_id
)
BEGIN
    SELECT RAISE(ABORT, 'entity schema mismatch');
END;

-- A space.genesis.v1 operation must be the exact locally selected trust
-- anchor, and the selected anchor must use that schema and controller actor.
CREATE TRIGGER operations_validate_genesis
BEFORE INSERT ON operations
WHEN
    NEW.schema_id = 'space.genesis.v1'
    OR EXISTS (
        SELECT 1 FROM spaces
        WHERE spaces.space_id = NEW.space_id
          AND spaces.genesis_operation_id = NEW.operation_id
    )
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM spaces
        WHERE spaces.space_id = NEW.space_id
          AND spaces.genesis_operation_id = NEW.operation_id
          AND spaces.controller_actor_id = NEW.actor_id
          AND NEW.schema_id = 'space.genesis.v1'
    ) THEN RAISE(ABORT, 'invalid space genesis projection') END;
END;

CREATE TABLE operation_parents (
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    parent_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 63),
    PRIMARY KEY (space_id, operation_id, parent_operation_id),
    UNIQUE (space_id, operation_id, position),
    FOREIGN KEY (space_id, entity_id, schema_id, operation_id)
        REFERENCES operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (space_id, entity_id, schema_id, parent_operation_id)
        REFERENCES operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE RESTRICT,
    CHECK (operation_id <> parent_operation_id)
) STRICT;

CREATE INDEX operation_parents_parent_idx
    ON operation_parents (space_id, parent_operation_id, operation_id);

CREATE TRIGGER operation_parents_forbid_genesis
BEFORE INSERT ON operation_parents
WHEN EXISTS (
    SELECT 1 FROM spaces
    WHERE spaces.space_id = NEW.space_id
      AND spaces.genesis_operation_id = NEW.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'space genesis cannot have causal parents');
END;

-- Authorization may name a capability.grant.v1 operation or the selected
-- space genesis root. Referencing operations rather than only the grant
-- projection permits that bootstrap while still enforcing same-space identity.
CREATE TABLE operation_authorization_refs (
    space_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    authorization_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 63),
    PRIMARY KEY (space_id, operation_id, authorization_operation_id),
    UNIQUE (space_id, operation_id, position),
    FOREIGN KEY (space_id, operation_id)
        REFERENCES operations(space_id, operation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (space_id, authorization_operation_id)
        REFERENCES operations(space_id, operation_id)
        ON DELETE RESTRICT,
    CHECK (operation_id <> authorization_operation_id)
) STRICT;

CREATE INDEX operation_authorization_refs_authority_idx
    ON operation_authorization_refs (
        space_id,
        authorization_operation_id,
        operation_id
    );

CREATE TRIGGER operation_authorization_refs_forbid_genesis
BEFORE INSERT ON operation_authorization_refs
WHEN EXISTS (
    SELECT 1 FROM spaces
    WHERE spaces.space_id = NEW.space_id
      AND spaces.genesis_operation_id = NEW.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'space genesis cannot have authorization references');
END;

CREATE TABLE entity_heads (
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY (space_id, entity_id, schema_id, operation_id),
    UNIQUE (space_id, operation_id),
    FOREIGN KEY (space_id, entity_id, schema_id, operation_id)
        REFERENCES operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX entity_heads_entity_idx
    ON entity_heads (space_id, entity_id, schema_id, operation_id);

-- Immutable visibility is materialized once for each client entity. Revisions
-- and tombstones authorize against this row, rather than only their new body,
-- so a narrow capability cannot cross or erase another visibility domain.
CREATE TABLE client_entity_visibility (
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL CHECK (schema_id IN (
        'event.v1', 'profile.v1', 'record.v1', 'record.v2', 'tag.v1'
    )),
    origin_operation_id TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    PRIMARY KEY (space_id, entity_id),
    UNIQUE (space_id, origin_operation_id),
    FOREIGN KEY (space_id, entity_id, schema_id, origin_operation_id)
        REFERENCES operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX client_entity_visibility_lookup_idx
    ON client_entity_visibility (space_id, visibility, entity_id);

-- Resource references remain valid when bytes are absent locally, so this
-- table intentionally has no foreign key to blobs.
CREATE TABLE operation_resources (
    space_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 63),
    content_id TEXT NOT NULL CHECK (
        length(content_id) = 72
        AND substr(content_id, 1, 8) = 'sha-256:'
        AND substr(content_id, 9) NOT GLOB '*[^0-9a-f]*'
    ),
    byte_length INTEGER NOT NULL CHECK (
        byte_length BETWEEN 0 AND 1099511627776
    ),
    media_type TEXT NOT NULL CHECK (
        length(CAST(media_type AS BLOB)) BETWEEN 3 AND 127
        AND instr(media_type, '/') > 1
        AND instr(media_type, char(0)) = 0
    ),
    role TEXT NOT NULL CHECK (
        length(CAST(role AS BLOB)) BETWEEN 1 AND 64
        AND role NOT GLOB '*[^a-z0-9._-]*'
    ),
    original_name TEXT CHECK (
        original_name IS NULL
        OR (
            length(CAST(original_name AS BLOB)) BETWEEN 1 AND 255
            AND instr(original_name, char(0)) = 0
            AND instr(original_name, '/') = 0
            AND instr(original_name, char(92)) = 0
        )
    ),
    PRIMARY KEY (space_id, operation_id, position),
    UNIQUE (space_id, operation_id, content_id),
    FOREIGN KEY (space_id, operation_id)
        REFERENCES operations(space_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX operation_resources_content_idx
    ON operation_resources (content_id, space_id, operation_id);

-- These are verified projections of capability.grant.v1 bodies. The operation
-- payload remains authoritative. NULL bound columns mean the grant supplies no
-- authority for that dimension; they never mean unlimited authority.
CREATE TABLE capability_grants (
    space_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    issuer_actor_id TEXT NOT NULL,
    grant_schema_id TEXT NOT NULL DEFAULT 'capability.grant.v1' CHECK (
        grant_schema_id = 'capability.grant.v1'
    ),
    subject_actor_id TEXT NOT NULL CHECK (
        length(subject_actor_id) = 78
        AND substr(subject_actor_id, 1, 14) = 'actor:ed25519:'
        AND substr(subject_actor_id, 15) NOT GLOB '*[^0-9a-f]*'
    ),
    delegation_depth INTEGER NOT NULL CHECK (delegation_depth BETWEEN 0 AND 16),
    not_before_unix_ms INTEGER CHECK (
        not_before_unix_ms IS NULL OR not_before_unix_ms >= 0
    ),
    expires_at_unix_ms INTEGER CHECK (
        expires_at_unix_ms IS NULL OR expires_at_unix_ms >= 0
    ),
    max_resource_byte_length INTEGER CHECK (
        max_resource_byte_length IS NULL
        OR max_resource_byte_length BETWEEN 0 AND 1099511627776
    ),
    label TEXT NOT NULL CHECK (
        -- At most 128 Unicode scalars in the model. Four UTF-8 bytes per
        -- scalar is the conservative SQL bound; Rust enforces scalar count
        -- and rejects every control character.
        length(CAST(label AS BLOB)) BETWEEN 1 AND 512
        AND instr(label, char(0)) = 0
    ),
    PRIMARY KEY (space_id, grant_operation_id),
    UNIQUE (
        space_id,
        grant_operation_id,
        issuer_actor_id,
        subject_actor_id
    ),
    FOREIGN KEY (
        space_id,
        grant_operation_id,
        issuer_actor_id,
        grant_schema_id
    ) REFERENCES operations(space_id, operation_id, actor_id, schema_id)
        ON DELETE RESTRICT,
    CHECK (
        expires_at_unix_ms IS NULL
        OR not_before_unix_ms IS NULL
        OR expires_at_unix_ms > not_before_unix_ms
    )
) STRICT;

CREATE INDEX capability_grants_subject_idx
    ON capability_grants (space_id, subject_actor_id, grant_operation_id);

CREATE INDEX capability_grants_issuer_idx
    ON capability_grants (space_id, issuer_actor_id, grant_operation_id);

-- This closed action registry mirrors CapabilityAction. Adding an action is a
-- data-model and schema migration, never a wildcard or prefix interpretation.
CREATE TABLE capability_grant_actions (
    space_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 4),
    action TEXT NOT NULL CHECK (action IN (
        'appendOperation',
        'issueCapability',
        'revokeCapability',
        'readSpace',
        'writeContent'
    )),
    PRIMARY KEY (space_id, grant_operation_id, action),
    UNIQUE (space_id, grant_operation_id, position),
    FOREIGN KEY (space_id, grant_operation_id)
        REFERENCES capability_grants(space_id, grant_operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX capability_grant_actions_lookup_idx
    ON capability_grant_actions (space_id, action, grant_operation_id);

CREATE TABLE capability_grant_schema_scopes (
    space_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 31),
    schema_id TEXT NOT NULL CHECK (schema_id IN (
        'event.v1',
        'profile.v1',
        'record.v1',
        'record.v2',
        'space.genesis.v1',
        'capability.grant.v1',
        'capability.revoke.v1',
        'tag.v1'
    )),
    PRIMARY KEY (space_id, grant_operation_id, schema_id),
    UNIQUE (space_id, grant_operation_id, position),
    FOREIGN KEY (space_id, grant_operation_id)
        REFERENCES capability_grants(space_id, grant_operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX capability_grant_schema_scopes_lookup_idx
    ON capability_grant_schema_scopes (space_id, schema_id, grant_operation_id);

CREATE TABLE capability_grant_visibilities (
    space_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 1),
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    PRIMARY KEY (space_id, grant_operation_id, visibility),
    UNIQUE (space_id, grant_operation_id, position),
    FOREIGN KEY (space_id, grant_operation_id)
        REFERENCES capability_grants(space_id, grant_operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE capability_grant_content_roles (
    space_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 63),
    role TEXT NOT NULL CHECK (
        length(CAST(role AS BLOB)) BETWEEN 1 AND 64
        AND role NOT GLOB '*[^a-z0-9._-]*'
        AND instr(role, '*') = 0
    ),
    PRIMARY KEY (space_id, grant_operation_id, role),
    UNIQUE (space_id, grant_operation_id, position),
    FOREIGN KEY (space_id, grant_operation_id)
        REFERENCES capability_grants(space_id, grant_operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX capability_grant_content_roles_lookup_idx
    ON capability_grant_content_roles (space_id, role, grant_operation_id);

CREATE TABLE capability_grant_revocations (
    space_id TEXT NOT NULL,
    revocation_operation_id TEXT NOT NULL,
    revoker_actor_id TEXT NOT NULL,
    revocation_schema_id TEXT NOT NULL DEFAULT 'capability.revoke.v1' CHECK (
        revocation_schema_id = 'capability.revoke.v1'
    ),
    grant_operation_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN (
        'keyCompromised',
        'deviceLost',
        'keyRotated',
        'scopeChanged',
        'administrative'
    )),
    detail TEXT CHECK (
        detail IS NULL
        OR (
            -- At most 512 Unicode scalars in the model; Rust remains
            -- authoritative for scalar count and control-character rejection.
            length(CAST(detail AS BLOB)) BETWEEN 1 AND 2048
            AND instr(detail, char(0)) = 0
        )
    ),
    PRIMARY KEY (space_id, revocation_operation_id),
    FOREIGN KEY (
        space_id,
        revocation_operation_id,
        revoker_actor_id,
        revocation_schema_id
    ) REFERENCES operations(space_id, operation_id, actor_id, schema_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (space_id, grant_operation_id)
        REFERENCES capability_grants(space_id, grant_operation_id)
        ON DELETE RESTRICT,
    CHECK (revocation_operation_id <> grant_operation_id)
) STRICT;

CREATE INDEX capability_grant_revocations_target_idx
    ON capability_grant_revocations (
        space_id,
        grant_operation_id,
        revocation_operation_id
    );

CREATE INDEX capability_grant_revocations_actor_idx
    ON capability_grant_revocations (
        space_id,
        revoker_actor_id,
        revocation_operation_id
    );

PRAGMA user_version = 4;
