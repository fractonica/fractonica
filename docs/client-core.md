# Client core and local-first write path

Fractonica clients author data locally. A node is a durable peer and relay,
not the authority that decides whether a user's record exists.

## Boundaries

The first client stack has four deliberately separate layers:

| Layer | Owns | Must not own |
| --- | --- | --- |
| UI | drafts, navigation, rendering, progress | private keys, canonical signing, synchronous network saves |
| Native client core | document validation, actor identity boundary, canonical signed operations | HTTP policy, UI state |
| Local store and outbox | durable operations, entity heads, projections, operation/resource retry state | rewriting signed envelopes, storing blob bytes |
| Node transport | projection reads, immutable operation delivery, bounded resource transfer | deciding whether local creation succeeded |

Rust's `fractonica-client` implements the native authoring boundary.
`fractonica-client-sqlite` atomically persists immutable operations, current
heads, disposable projections, configured peers, and their delivery state.
`fractonica-client-runtime` composes key custody, authoring, SQLite, private
content, transport, and the synchronization worker into one application-owned
lifecycle. The TypeScript `@fractonica/client` package remains useful for
strict node administration and projection reads; it is not the desktop local
write boundary.

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

- Desktop: the Tauri Rust process owns `ClientRuntime`. The React webview
  invokes narrow commands and receives small serializable results; it does not
  receive keys, database handles, storage paths, or synchronization controls.
- Mobile: React Native calls a standalone Expo native module whose Swift and
  Kotlin adapters invoke the same Rust semantics. Keys remain behind
  platform-backed native custody and never enter JavaScript.
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
  rejection states;
- immutable operation-to-resource indexes and independent per-peer transfer
  queues;
- durable tus upload URLs, byte progress, expiring resource leases, and
  aggregate content progress.

Its methods are synchronous and bounded. Tauri and iOS bridges must execute
them on native blocking pools and return small results to the UI.

## Synchronization worker

The native worker runs bounded push and pull cycles. Pushes retain exact signed
bytes and use expiring outbox leases. Retryable failures receive capped
exponential backoff; permanent admission failures remain visible as rejected
delivery state. A cursor advances only after every operation in its page has
been verified and committed, so a crash replays an idempotent page rather than
losing data.

Peer-space configuration makes the read trust mode explicit:

- `supervisor_bearer` is only for the desktop-owned node on a numeric loopback
  HTTP origin. The bearer token is delivered out of band by the Tauri
  supervisor and authorizes the ordinary incremental changes route.
- `paired` uses the pairing session, capability grant, and a fresh dual-signed
  read proof. This is the mode for an independently paired peer.

The two modes share cursor and verification semantics but are not silently
interchangeable.

SQLite calls run on Tokio's blocking pool. The supervisor exposes a compact
watch snapshot containing cycle counters and aggregate queue state and accepts
explicit cancellation. HTTP and proof custody are injected boundaries, which
keeps deterministic tests independent of networking and lets desktop/iOS
provide reviewed native key custody.

The content layer includes a private crash-safe local blob store and bounded
HTTP primitives for availability, tus creation/resume/checksummed chunks, and
resumable range downloads. The supervisor now discovers resources from every
committed operation, reconciles locally authored blobs, and advances durable
per-peer upload/download queues one bounded chunk at a time. A completed
download is verified before it unlocks fan-out to other peers. Operation
convergence still does not wait for media availability.

The status snapshot reports waiting, pending, leased, completed, and rejected
resource work plus aggregate synchronized and total bytes. Platform UIs can
render progress without scanning operations or touching the filesystem.

## Desktop runtime bootstrap

The bundled node owns the installation's initial controller, writer, genesis,
and initial writer grant. `ClientRuntime::bootstrap_supervised` loads the same
protected identity, fetches the advertised signed anchors through the private
supervisor channel, verifies that every identity and operation ID agrees, and
commits those anchors into the independent client store. Only then does it
enable background pull and delivery. This prevents the desktop client from
creating a parallel identity or trusting metadata that disagrees with its
protected keys.

Local create, update, delete, bounded list, status, and shutdown operations are
wired through Tauri. The React Records workspace now consumes that boundary:
it reads client SQLite rather than node projections, returns from saves at the
local commit boundary, preserves resources and references on edits, and treats
private payloads as opaque. Client SQLite and its WAL/SHM files are private on
Unix.

Attachment selection also stays behind the native boundary. The picker returns
its selected paths only to Rust; the client hashes and copies regular files on
the blocking pool, atomically publishes their immutable bytes in the private
content store, and returns only validated `record.media` references to React.
Cancelling is a no-op, equal bytes deduplicate, and removing a draft reference
does not delete historical content.

Private-record key management/decryption and richer feed pagination remain
future client-facing layers. Paired-device lifecycle management is exposed by
the node: completed sessions retain authenticated last-seen activity and a
controller-signed administrative revocation disables their grant without
deleting the audit trail.

Pairing accepts explicit private/link-local endpoint hints. The QR secret opens
a Noise session; its encrypted receipt carries a random transport credential
whose digest alone is stored by the node. Each use is rechecked against the
completed pairing and current grant. The current data plane is plain HTTP and
therefore restricted to a trusted private network; a confidential persistent
peer channel remains a subsequent hardening phase.

The Noise joiner ceremony is implemented once in `fractonica-client-runtime`.
Mobile UniFFI and desktop Tauri expose only verified claim summaries and the
explicit merge/keep-separate decision. The first HTTP request is retried with
the identical Noise frame because the responder can durably replay its exact
opaque response after an iOS local-network permission transition. Desktop
bootstrap preserves an already admitted paired workspace across restarts.
