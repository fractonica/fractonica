# Operation log

Fractonica's first storage kernel is an append-only causal operation log. A
node stores immutable operations, assigns each one a local sequence cursor, and
derives the current heads of each entity. It does not use arrival time as a
conflict resolver and it does not physically delete history.

The canonical HTTP contract is
[`contracts/openapi/v1.yaml`](../contracts/openapi/v1.yaml). These routes are
available only from the stateful `node` profile. The stateless `saros` profile
returns `503` because it deliberately opens no storage.

## Operation envelope

Clients submit `POST /api/v1/operations` with a required `Idempotency-Key`
header and this strict envelope:

- `protocolVersion`: currently exactly `1`;
- `operationId`: canonical client-generated UUID;
- `entityId`: canonical UUID of the affected entity;
- `schema`: currently exactly `record.v1`;
- `causalParents`: zero through 64 unique operation UUIDs;
- `occurredAtUnixMs`: nonnegative client-declared event time;
- `body`: either `put` with a document or `tombstone`.

The request never contains `actorId`. The node resolves it from the trusted
local application context and includes that UUID in the stored operation. In
this first loopback-only slice the actor is the persistent installation ID; it
is not yet a paired or cryptographic identity. A client therefore cannot
attribute an operation to another actor by changing JSON.

`record.v1` documents require `startAtUnixMs` and `visibility`. They may include
`endAtUnixMs`, `emoji`, `text`, and a JSON `metadata` object. When an end time is
present, it must not precede the start time. Visibility is either `public` or
`private`.

## Idempotent append

An accepted append returns `201` and the stored operation. Retrying the same
canonical request with the same actor-scoped `Idempotency-Key` returns `200`
and the original stored operation, including its original `localSequence`.

Reusing an idempotency key for different content returns `409`. Malformed JSON
or a domain-invalid document returns `422`. A causal reference that cannot be
admitted to the log also returns `409`.

The stored shape is:

```json
{
  "localSequence": 1,
  "operation": {
    "protocolVersion": 1,
    "operationId": "b7e117dd-d840-493b-9da6-6cbcd24d056e",
    "entityId": "89891765-c47f-4422-8e0f-d254940490d1",
    "actorId": "ea1f84d1-ed2a-4bda-8773-687108fecb5d",
    "schema": "record.v1",
    "causalParents": [],
    "occurredAtUnixMs": 1784390400000,
    "body": {
      "kind": "put",
      "document": {
        "startAtUnixMs": 1784390400000,
        "visibility": "private",
        "emoji": "🌀",
        "metadata": {}
      }
    }
  }
}
```

## Causal heads and merging

An operation with no parents starts an entity history. Every causal parent must
already exist, belong to the same canonical entity and schema, and differ from
the new operation ID.

When an operation is accepted, the named parents stop being heads and the new
operation becomes a head. Existing heads that were not named remain current.
This is how the node retains concurrent edits without inventing a winner from
network arrival order.

`GET /api/v1/entities/{entityId}` returns every current head as a full stored
operation. `conflicted` is true when more than one head remains. A merge is a
`put` whose `causalParents` includes every current head observed by the merging
actor; after it is accepted, that put is the sole head unless another concurrent
branch arrived.

A tombstone is a durable operation, not a SQL delete. It remains in history and
can remain an entity head. Replication, compaction, and backup must preserve it.
Any later operation that intentionally follows a tombstone names it as a causal
parent.

## Change cursor

`GET /api/v1/operations?after=0&limit=100` returns stored operations in ascending
`localSequence` order together with `nextAfter` and `hasMore`. `after` is an
exclusive cursor and `limit` is capped at 200.

`localSequence` is assigned by one node solely for incremental reads. It is not
an operation ID, event timestamp, causal clock, replication identity, or global
ordering primitive. A cursor from one node has no meaning on another node.

## Identifier rule

Canonical operation and entity identifiers are UUIDs throughout storage,
causality, and replication. A short human-facing identifier may be introduced
as an alias, but it never replaces the canonical UUID and must not appear in a
causal parent list.
