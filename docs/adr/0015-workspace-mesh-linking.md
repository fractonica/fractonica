# ADR 0015: Symmetric workspace mesh linking

- Status: Accepted; implementation in progress
- Date: 2026-07-23
- Supersedes: The pairing-session topology assumptions in ADR 0011 and ADR
  0012. Their Noise transcript, human confirmation, dual key possession, and
  replay-protection requirements remain in force.

## Context

Pairing v1 models the invitation responder as the workspace authority and
binds peer transport to one completed pairing row. That produces a directed
hub-and-spoke topology: a device that joined a workspace can replicate data,
but cannot introduce another device unless the original responder remains
available. Peer addresses and credentials do not converge across the network.

This contradicts the product's persistence goal. A personal vault must remain
available when any one desktop, phone, or original invitation issuer is
offline. Linking is therefore membership in a workspace-scoped device network,
not one node granting temporary access to another node.

## Decision

### Workspace is the root boundary

A workspace is a separate vault and the root of all trust, records, content,
membership, peer-directory state, and routing policy. Every link action names
one explicit `SpaceId`. The application selects a workspace before rendering
records, links, online state, or network controls; there is no installation-
global peer graph.

Two different `SpaceId` values are never silently combined. Linking a device
that does not yet contain the selected workspace joins that workspace. If the
device also contains records in another workspace, the UI offers an explicit
record import into the selected destination. Combining two established vaults
requires a separate, explicit merge operation that selects or creates the
destination root and preserves provenance.

An installation may have zero or more workspaces. Creating a workspace makes
a fresh trust root and canonical first member grant. Deleting a workspace is
an explicitly confirmed local destructive action: it removes that workspace's
local operation log, materialized records, content no longer referenced by
another local workspace, peer graph, routing state, and active selection. It
does not send a remote deletion request and cannot erase another member's
replica. Deleting the active or last workspace returns the application to the
root workspace chooser, where a new local or linked workspace can be created.

### Link is symmetric network membership

An invitation is only a short-lived rendezvous and human-confirmed key
exchange. It does not make the responder the permanent parent of the joiner.
After completion, both nodes have the same relationship: members of the named
workspace with one direct peer edge. It must not matter which member displayed
the invitation.

The default personal-device membership grant includes bounded authority to:

- append the supported workspace record schemas;
- read the workspace;
- transfer supported content;
- publish the member's own node announcement; and
- link another member with no broader authority than the issuer possesses.

General capability delegation remains strictly attenuating. Workspace linking
uses a distinct `linkWorkspace` authority: it may reproduce only a same-or-
narrower workspace-member grant and cannot create controller, revocation, or
arbitrary administrative authority. This authority is renewable rather than
depth-decreasing, so network growth does not fail after an arbitrary chain
length. It remains bounded by the capability graph visit limit and by exact
scope intersection.

Storage is created directly in this workspace form.

### Signed workspace peer directory

Each member publishes a workspace-scoped node announcement containing:

- `SpaceId`, `NodeId`, and the actor that holds membership;
- one or more bounded endpoint hints;
- a monotonically increasing announcement epoch;
- an expiry time; and
- a node-key signature binding the announcement to the `NodeId`, in addition
  to the enclosing actor-signed operation.

A node may announce only itself. Endpoint hints are routing data, not trust.
Expired announcements remain auditable history but are not dialed. A node can
set `discoverable=false`, which prevents its address from being returned in
directory exchanges while preserving its membership and outbound sync.

On link completion, peers exchange their admitted directory inventories and
durable operation/content inventory summaries. The new member learns every
currently discoverable address it does not already know. Directory operations
replicate like other immutable operations, so later changes also converge.
Pairwise session secrets are never forwarded.

### Membership-authenticated transport

Peer requests are authorized by fresh dual-signed node/actor proofs plus an
active workspace-member capability chain. Direct transport no longer requires
the receiver to possess the caller's original pairing-session row. Pairing
session IDs remain valid transcript/audit identifiers but are not graph
membership or the only transport authorization mechanism.

Every operation is relayed unchanged. A receiver admits it once by immutable
`OperationId`, then may advertise or deliver that same operation to every
eligible peer except the immediate source. Relays never re-sign an operation
or mark it locally authored.

Mesh cycles are allowed and desirable. Duplicate suppression, durable delivery
state, and anti-entropy inventories prevent feedback loops. The implementation
must not reject a direct link merely because an indirect path already exists.

### Local routing policy and unlinking

Discoverability and propagation controls are node-local, workspace-scoped
routing policy. For each workspace a node stores:

- whether its own endpoint is discoverable;
- whether newly discovered peers may be dialed automatically;
- an allow/deny policy for which member nodes may send operations or content;
  and
- whether a direct edge is enabled.

These controls do not rewrite signed workspace history and cannot grant
authority. A restrictive policy may reduce availability, so the UI must show
that consequence.

`unlink` is an authenticated bilateral edge-removal request. Each receiver
disables the direct edge to the other node and acknowledges the request. It
does not revoke either workspace member and does not erase replicated data;
the nodes may still communicate through other allowed paths. If one side is
offline, the request remains durable and the local edge is disabled
immediately.

Removing a device from the vault is a separate administrative revocation. It
revokes membership authority and consequently blocks future transport and
operation admission according to the distributed revocation rules. The UI
must never label edge unlinking as device revocation or data deletion.

### Reliability requirements

Correctness is anti-entropy convergence, not notification delivery. For every
workspace:

1. local commits are durable before network activity;
2. all admitted operations and referenced content are eligible for unchanged
   relay to every allowed member;
3. every member retains the signed peer directory, not only its inviter;
4. losing any single non-unique member does not disconnect a graph that still
   has an alternate physical path;
5. reconnecting members repair missed operations and content from inventory;
6. workspace graphs, routing policy, cursors, and active selection never leak
   into another workspace; and
7. visible record state never becomes empty merely because a link ceremony
   selected a different workspace root.

## Implementation sequence

1. add `linkWorkspace` and canonical member-grant authorization;
2. allow one node installation to host multiple explicitly trusted spaces;
3. adopt a joined workspace into the local sidecar after confirmation;
4. add signed node-announcement operations and per-workspace routing tables;
5. add membership-authenticated push, pull, and content requests;
6. exchange directory and anti-entropy summaries during link completion;
7. expose workspace selection, discoverability, propagation, unlink, and
   revoke as distinct UI actions; and
8. remove session-bound invitation authority once mesh tests pass on every
   platform.

No intermediate release may claim symmetric linking while invitation creation
still depends on a different node's controller or while a successful link can
switch the visible workspace without an explicit destination choice.

## Consequences

- Any online full member can introduce a new personal device to its workspace.
- Invitations are direction-neutral; availability no longer depends on the
  original inviter.
- Cyclic meshes improve resilience without duplicating records.
- Users can keep unrelated local or shared vaults with entirely separate node
  networks on one installation.
- Endpoint privacy is controllable without conflating invisibility, unlinking,
  and cryptographic revocation.
- The peer proof, directory, sidecar storage, and UI contracts form one
  coordinated workspace model.
