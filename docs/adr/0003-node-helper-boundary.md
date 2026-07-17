# ADR 0003: Node and helper process boundary

- Status: Accepted
- Date: 2026-07-17

## Context

Operating-system and device integrations may be unstable, privileged, or use
different runtimes. A failure in one integration must not bypass node policy or
corrupt durable state.

## Decision

The node is the sole owner of durable state, identity and key access, policy
enforcement, network listeners, and helper lifecycle. Helpers are separately
launched adapters with explicit, versioned request and response envelopes.

Every helper call has bounded payloads, execution time, memory expectations,
and result size. Helpers receive the minimum capability required for a job.
They may not access the node's SQLite database or long-lived secrets, traverse
arbitrary filesystem paths, bind public ports, or make policy decisions.

The node validates helper output before committing it. Calls define whether
they are retryable and, when retries are allowed, carry an operation identity
so duplicate delivery can be handled safely. Crashes, timeouts, malformed
responses, and unsupported versions become structured failures rather than
implicit fallbacks.

The transport and cryptographic protection for this boundary remain open until
their deployment threat model is documented.

## Consequences

- A helper compromise has a constrained blast radius.
- Helpers can be restarted, upgraded, and tested independently.
- Boundary validation and process supervision add implementation work.
- New helper capabilities require explicit node policy and contract review.
