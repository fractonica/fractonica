# Client core and local-first write path

Fractonica clients author data locally. A node is a durable peer and relay,
not the authority that decides whether a user's record exists.

## Boundaries

The first client stack has four deliberately separate layers:

| Layer | Owns | Must not own |
| --- | --- | --- |
| UI | drafts, navigation, rendering, progress | private keys, canonical signing, synchronous network saves |
| Native client core | document validation, actor identity boundary, canonical signed operations | HTTP policy, UI state |
| Local store and outbox | durable operations, entity heads, projections, retry state | rewriting signed envelopes |
| Node transport | projection reads, immutable operation delivery, later resource transfer | deciding whether local creation succeeded |

Rust's `fractonica-client` implements the native authoring boundary.
`fractonica-client-sqlite` atomically persists immutable operations, current
heads, disposable projections, configured peers, and their delivery state.
The TypeScript `@fractonica/client` package implements strict node reads and
delivery of already-signed operations. `fractonica-sync` consumes the durable
outbox and paired change cursors on a supervised native async task.

## Create, edit, and delete

Creation receives a new UUIDv7 entity ID, current Unix milliseconds, and a
random 128-bit operation nonce. The native key boundary signs the complete
draft, and the client verifies that the returned envelope is both valid and an
exact projection of the requested draft.

Editing and deletion name every current operation head observed by the local
store. A tombstone is another immutable operation; missing remote state is not
a deletion signal. If two clients edit offline, both heads remain visible
until a later operation explicitly merges them.

Profiles use the deterministic actor-bound entity ID defined by the data
model, so separate devices do not invent different profile entities for the
same actor.

## Durable write sequence

For create, edit, and delete, a native client must perform this sequence:

1. read the local entity heads and applicable capability references;
2. create and sign the operation through `OperationAuthor`;
3. atomically store the operation, advance local heads/projections, and add an
   outbox delivery item;
4. report local success to the UI;
5. let a background worker deliver the unchanged envelope and resources;
6. mark each peer delivery acknowledged without removing local history.

Steps 2-3 must not wait for a node request. Retrying an operation is safe
because its digest-derived operation ID is the idempotency key. An admission
failure is durable synchronization state requiring inspection; it is not a
reason to delete or roll back local data.

## Platform use

- Desktop: the Tauri Rust process owns actor custody, the local store, and the
  outbox. The React webview invokes narrow commands and uses the TypeScript
  package for typed projection data only where appropriate.
- iOS: a Swift bridge invokes the same Rust semantics or matches the published
  conformance vectors, with actor keys held behind Keychain-backed custody.
- Headless agents: `SoftwareActorKey` may be used with an explicitly provisioned
  capability and protected service storage.
- Embedded helpers: constrained devices may author a smaller supported
  operation subset or hand observations to a paired hub; they do not need the
  TypeScript transport.

## Implemented persistence layer

The client SQLite adapter provides:

- an independent fresh schema, separate from node installation storage;
- atomic verified local commits and idempotent replay;
- preserved concurrent heads and explicit merge advancement;
- rebuildable entity heads and application projections;
- backfill when a new peer is configured;
- forwarding of operations learned from one peer to other enabled peers;
- bounded expiring delivery leases with acknowledgement, retry, and terminal
  rejection states.

Its methods are synchronous and bounded. Tauri and iOS bridges must execute
them on native blocking pools and return small results to the UI.

## Synchronization worker

The native worker runs bounded push and pull cycles. Pushes retain exact signed
bytes and use expiring outbox leases. Retryable failures receive capped
exponential backoff; permanent admission failures remain visible as rejected
delivery state. Pulls use fresh dual-signed paired-read proofs and compare-and-
swap cursors. A cursor advances only after every operation in its page has
been verified and committed, so a crash replays an idempotent page rather than
losing data.

SQLite calls run on Tokio's blocking pool. The supervisor exposes a compact
watch snapshot containing cycle counters and aggregate queue state and accepts
explicit cancellation. HTTP and proof custody are injected boundaries, which
keeps deterministic tests independent of networking and lets desktop/iOS
provide reviewed native key custody.

The content layer now includes a private crash-safe local blob store and
bounded HTTP primitives for availability, tus creation/resume/checksummed
chunks, and resumable range downloads. Operation convergence still does not
wait for media availability. Durable automatic resource discovery and transfer
queueing is not wired into the supervisor yet.

The current peer route is still loopback-only and unauthenticated transport is
not safe to expose on a LAN. Encrypted session transport and platform command
wiring remain subsequent phases.
