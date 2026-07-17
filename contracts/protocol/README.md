# Fractonica device protocol principles

This contract is licensed under Apache-2.0; see [the contract license](../LICENSE).

This document sets constraints for the future device protocol without choosing
a transport, serialization format, or cryptographic algorithm. A concrete,
versioned schema and conformance fixtures are required before implementation.

## Versioned envelopes

Every device message is carried in an envelope whose schema identifies its
protocol version. A schema is expected to define, at minimum, a message
identity, sender or device identity, message kind, time or ordering context,
payload encoding, bounded payload, and any correlation or causation context
needed by that message kind. These are semantic requirements, not a prescribed
wire layout.

An implementation must reject unsupported versions and malformed envelopes
predictably. It must never reinterpret an unknown version as the current one.
Compatibility rules, required fields, optional-field behavior, and transition
procedures belong to each published protocol version.

## Bounds and resource safety

Each version specifies hard limits before release, including total encoded
size, payload size, nesting depth, string and collection lengths, decompressed
size where applicable, and work that validation may perform. A receiver checks
framing and declared lengths before allocating large buffers and applies time
and concurrency limits to processing.

Limits are part of the contract and shared by Rust and C++ implementations.
Accepted and rejected boundary cases are checked in as conformance fixtures.

## Validation and helper behavior

Network and helper messages are untrusted. The node validates an envelope and
its message-specific payload before changing durable state. Failures use
bounded, versioned error information and must not echo secrets or arbitrary
untrusted payloads.

Retry, duplicate-delivery, correlation, and ordering semantics are defined per
message kind. Helpers may not infer authority from the presence of a syntactic
identifier; authorization remains a node decision.

## Security decision deferred

Fractonica has not selected signature, hashing, encryption, key-derivation,
canonicalization, pairing, or key-rotation algorithms. Those choices require a
threat model, an ADR, test vectors, and an explicit definition of the exact
bytes covered by integrity protection. Implementations must not introduce a
private algorithm or treat transport encryption alone as message authority.

Envelope metadata should be minimized because routing and timing information
may remain observable even when a future payload is protected.
