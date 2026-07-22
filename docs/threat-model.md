# Trust-kernel threat model

- Status: Normative for the signed operation protocol
- Date: 2026-07-18

This document defines the security boundary for Fractonica's cryptographic
trust kernel. It applies to signed operations, actor and node keys, spaces,
capability admission, and the future QR pairing flow. It does not authorize
LAN or Internet exposure. The terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** have their meanings from
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html).

## Security goals

The trust kernel is intended to provide:

- **authorship:** an operation attributed to an actor was signed by the private
  key corresponding to that `ActorId`;
- **integrity:** any change to a signed operation changes its `OperationId` or
  invalidates its signature;
- **causal integrity:** every declared parent identifies the exact immutable
  parent operation bytes the author claims to have observed;
- **scoped authority:** possession of an actor key alone does not grant that
  actor permission to mutate every space;
- **offline verification:** signature and identifier verification does not
  require the originating node or a central account service;
- **explicit bootstrap:** a new peer gains trust only through a bounded pairing
  ceremony and an explicit capability grant; and
- **local-first availability:** an unavailable resource blob never makes an
  otherwise valid signed operation disappear.

Signatures do not establish that a statement is true, that the signer is a
particular legal person, or that a device was uncompromised. They prove only
possession of a signing key and integrity of the signed bytes.

## Identities and trust anchors

Fractonica uses four identities with deliberately different lifecycles:

| Identity | Meaning | Security role |
| --- | --- | --- |
| `InstallationId` | One local database lifecycle | Diagnostics only. It MUST NOT authorize, sign, or be treated as a peer identity. |
| `NodeId` | One node transport endpoint, derived from its Ed25519 public key | Pins a node during pairing and future authenticated transport. It MUST NOT be reused as an actor key. |
| `SpaceId` | A random 256-bit authorization and replication namespace | Scopes operations and grants. It conveys no authority by itself. |
| `ActorId` | An author, derived directly from its Ed25519 public key | Verifies operation authorship and is the subject or issuer of capabilities. |

An actor may represent a person-controlled device, an automation agent, a
sensor, or a node performing an explicitly granted system action. A user
profile is application data, not a root security identity. Multiple actors may
control one profile through grants without sharing private keys.

The initial controller recorded when a space is created is its first local
trust anchor. Every later authority MUST be derived from a verifiable grant
chain rooted at a controller trusted for that space. Importing an operation,
knowing a `SpaceId`, discovering a network endpoint, or possessing content
bytes MUST NOT create authority.

## Assets

Protected assets include:

- actor and node private keys;
- capability-grant and revocation state;
- signed operation bytes and their causal relationships;
- private structured payloads and private resource plaintext;
- the local database, content store, pairing invitations, and recovery data;
- availability and liveness of a node under bounded hostile input.

Public operation payloads and public resource bytes are intentionally
distributable. Their integrity and authorship remain protected even when their
confidentiality does not.

## Adversary model

Receivers MUST assume an attacker can:

- submit arbitrary, truncated, duplicated, reordered, or non-canonical input;
- know valid actor, node, space, entity, operation, and content identifiers;
- replay an authentic operation or pairing request;
- omit ancestors, revocations, branches, or resources from a partial graph;
- create many keys, entities, uploads, and network connections;
- observe packet timing, sizes, cleartext routing fields, and public content;
- copy encrypted blobs and compare stable ciphertext digests;
- operate a malicious peer or helper and lie about its clock or current heads;
- steal a QR image before it expires; and
- obtain a device and inspect ordinary storage if the platform is physically
  compromised.

The attacker is assumed unable to break SHA-256 or Ed25519, extract secrets
from a correctly operating hardware-backed keystore, or compromise the
operating system account that owns a running node. A process already executing
with that account's full privileges is outside the isolation provided by this
protocol and may read local plaintext or invoke authorized local interfaces.

## Required invariants and mitigations

### Forgery, mutation, and replay

Every authoritative operation MUST use the deterministic CBOR and
COSE Sign1 representation defined by
[ADR 0009](adr/0009-signed-operation-trust-kernel.md). A receiver MUST derive
the verification key from the asserted `ActorId`, verify the Ed25519 signature,
recompute the SHA-256 `OperationId`, validate all bounds, and reject a
non-canonical representation before admission.

Replaying the same signed operation is idempotent because its operation digest
is unchanged. A valid signature with a different nonce is a distinct operation
and is still subject to causal and capability validation. Transport request
IDs and HTTP idempotency keys are local delivery aids; they are not authority.

### Causal omission and equivocation

A parent digest proves which exact parent bytes were named; it does not prove
that the author knew every branch. A node MUST retain concurrent heads rather
than infer a winner from arrival time. Missing parents cause quarantine or
rejection, never an invented placeholder. A peer can withhold a branch or
revocation until graph synchronization detects the omission. This phase makes
no global-completeness or total-order guarantee.

### Unauthorized actors

A correct signature proves authorship but not permission. Before applying an
operation to a space, the node MUST evaluate the referenced capability chain
and the node's accepted revocations according to
[ADR 0010](adr/0010-space-capabilities-and-pairing.md). Grants are bound to an
`ActorId`; they are not bearer tokens. An API session may select an actor but
MUST NOT let a server silently sign as that actor unless the server explicitly
owns that actor key and has a matching grant.

### Clocks

`occurredAtUnixMs` is a signed assertion by the actor, not a trusted timestamp.
It MUST NOT override causality, prove that an action happened before
revocation, or establish invitation freshness. Invitation expiration and local
admission deadlines use the receiving node's clock. For capability windows the
node persists a nondecreasing high-water value before evaluation and uses the
maximum of that value and the current sample, including when the request is
later denied. This prevents local clock rollback from reopening an already
closed window; distributed time attestation is not provided.

### Resource and parser attacks

Content IDs protect immutable bytes, not the safety or meaning of those bytes.
Nodes MUST enforce encoded-size, nesting, collection, upload, decompression,
and concurrency bounds before expensive work. Media decoders, model loaders,
and metadata extractors remain untrusted helpers and MUST receive bounded
inputs. A missing or malicious resource MUST NOT rewrite the signed operation
that references it.

### Pairing interception and replay

A QR invitation is a short-lived bootstrap secret, not a permanent credential.
It MUST bind the expected `NodeId`, an unpredictable single-use secret, the
intended space, expiration, and requested capability summary. The pairing
protocol MUST authenticate the node key, bind its complete transcript to the
invitation, require explicit user confirmation of the peer and grant, and
consume the invitation atomically. Endpoint discovery and physical proximity
alone MUST NOT establish trust.

ADR 0011 fixes the authenticated key exchange as bounded
`Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s` messages with a signed transcript
receipt and complete two-glyph confirmation. Desktop pairing now explicitly
advertises one private/link-local endpoint and the encrypted receipt carries a
random grant-scoped transport credential. This is a trusted-private-network
milestone, not authorization for public exposure: the subsequent data plane is
plain HTTP and does not protect traffic from a local passive observer.

## Private payloads and observable metadata

`private` is not synonymous with anonymous. Signing and content addressing do
not encrypt data. When an application encrypts a private operation body, a
node or traffic observer may still learn:

- `SpaceId`, `ActorId`, `EntityId`, schema, parent and grant digests;
- claimed occurrence time, operation order at each node, and update frequency;
- ciphertext and envelope lengths, resource count, and transfer timing;
- stable content digests, equality, and availability; and
- media type, role, and original-name labels if the application leaves them in
  the clear.

Private resources SHOULD be encrypted before content hashing with fresh,
authenticated randomized encryption so equal plaintext does not normally
produce equal ciphertext. Privacy-sensitive schemas SHOULD use generic media
types, omit original names, and consider padding or chunking policies. Those
measures reduce correlation; they do not hide the graph topology or network
traffic. A future payload-encryption ADR MUST specify key distribution,
algorithm suites, associated data, padding, and recovery. Until then,
`visibility: private` is an access-policy label, not a protocol-level
confidentiality guarantee.

## Key lifecycle and recovery

- Keys MUST be generated from a cryptographically secure platform random
  source. Actor, node, invitation, session, and content-encryption key material
  MUST be domain-separated and MUST NOT be reused across roles.
- Private key material MUST never appear in logs, URLs, QR invitations,
  operation bodies, crash reports, or public backups. Desktop releases SHOULD
  use the operating-system keystore; headless and embedded profiles require a
  documented protected-secret backend before non-loopback operation.
- The current raw Unix `FileKeyStore` verifies effective-user ownership, exact
  modes, single-link files, and no-follow opens, but it does not prove that a
  macOS or network filesystem has no extended ACL. It is a single-user local
  bootstrap backend, not the production macOS secret-store boundary.
- Windows identity seeds and pairing secrets are encrypted before publication
  with current-user DPAPI and domain-specific optional entropy.
- An `ActorId` or `NodeId` cannot retain its identity after key replacement,
  because the identity contains the public key. Rotation creates a new ID.
  Actor continuity is expressed by granting the new actor and revoking the old
  one. Node rotation requires re-pairing.
- Revocation does not make historical signatures invalid and MUST NOT rewrite
  old operation IDs. A node rejects new admissions under a revocation once it
  has accepted that revocation. Cross-node treatment of operations concurrent
  with a revocation is deferred to the replication protocol.
- Each space SHOULD provision a second independently protected controller or
  recovery actor before external use. If all controller keys are lost, the
  existing graph remains verifiable and readable, but no implementation may
  invent a replacement controller or use a vendor backdoor.
- Any future private-key export MUST be an explicitly requested, authenticated,
  encrypted recovery format with separate review. Pairing MUST issue a new key
  and grant rather than copy an existing actor or node private key.

## Deliberate non-goals for this phase

This phase does not provide:

- non-loopback listening, TLS deployment, LAN discovery, NAT traversal, or
  Internet exposure;
- peer replication, graph-completeness proofs, global ordering, or consensus;
- confidentiality or traffic-shape privacy for the authenticated peer-read
  primitive;
- non-loopback pairing transport, discovery, or transport resumption;
- anonymous communication or concealment of graph and traffic metadata;
- payload-encryption, shared-space key distribution, or encrypted recovery;
- automatic trust in imported legacy signatures, API keys, usernames, or
  installation identifiers; or
- protection after operating-system compromise, malicious firmware, coerced
  key use, or cryptographic algorithm failure.

Any implementation that crosses one of these boundaries requires a new ADR,
versioned contract, abuse bounds, conformance fixtures, and an update to this
threat model before the restriction is relaxed.
