# ADR 0014: React Native mobile client boundary

- Status: Accepted
- Date: 2026-07-20
- Scope: New Fractonica mobile clients for iOS and Android.

## Context

Fractonica is building its mobile client from a clean domain model rather than
porting the Exeligmos SwiftUI application. Maintaining independent SwiftUI and
Android UI implementations would duplicate navigation, drafts, validation
adapters, temporal presentation, and glyph composition while still requiring a
shared native data engine.

The existing Rust client crates already define the intended local durability
boundary, but `ClientRuntime` currently bootstraps only by adopting a supervised
desktop node. A mobile application must eventually initialize, author, and read
records without a server or a running JavaScript engine.

## Decision

The mobile application uses React Native with Expo development builds and the
React Native New Architecture. Expo Go is not a supported Fractonica runtime
because it cannot contain the custom native Rust client.

The layers remain deliberately separate:

| Layer | Owns | Must not own |
| --- | --- | --- |
| React Native | screens, navigation, drafts, rendering, transient progress | private keys, SQLite, canonical signing, replication decisions |
| Expo native module | lifecycle, platform storage adapters, bounded DTO conversion | product state or a second persistence model |
| Rust mobile facade | stable mobile API, validation, error codes, runtime ownership | React component state |
| Rust client runtime | signed operations, local SQLite, content, synchronization | UI policy |

The Expo module is a standalone workspace package so its Swift, Kotlin, native
artifacts, and conformance tests have an independent lifecycle. The Rust facade
will use pinned UniFFI generation. JavaScript receives only bounded semantic
DTOs; it never receives secret key material, database handles, native paths,
raw signed envelopes, or bulk attachment bytes. Timeline reads use preview
DTOs under both row-count and total-byte budgets. Exact record lookup requires
the immutable operation ID plus entity ID; its bounded public document JSON
remains opaque across native/JavaScript so canonical integer metadata cannot be
silently rounded.

Every mobile operation is asynchronous at the JavaScript boundary. Creation
returns only after the signed operation and projection are durable locally and
never waits for networking. Rust owns its Tokio lifecycle; native wrappers must
not create a temporary runtime for each method call.

The canonical data-only glyph geometry is shared through
`@fractonica/glyph-core`. Mobile rendering has a dedicated React Native SVG
adapter and does not reinterpret octal digit order or stroke rules.

## First vertical slice

The first production slice is deliberately narrow:

1. boot a development build on iOS and Android;
2. prove the standalone Expo native module is linked;
3. initialize the native client without a server;
4. list a bounded local record page;
5. create one public record and return at the local commit boundary;
6. force-quit, restart, and prove identity, anchors, and record persistence.

Attachments, pairing, background synchronization, private-record key
distribution, events, and tags follow after this slice is reliable.

## Native identity and storage requirements

The mobile key adapter must distinguish missing identity from existing
identity. iOS stores device-only seed material in Keychain. Android stores an
encrypted seed bundle outside backup storage, protected by a non-exportable
Android Keystore wrapping key. Secrets may enter native/Rust process memory but
never JavaScript.

Database and key recovery states must agree. An existing identity with a
missing installation database, or an established database with missing or
mismatched identity, fails closed into an explicit recovery state. It must not
silently generate replacement trust anchors.

## Offline space ownership

A fresh phone creates and owns a real personal space before any desktop hub or
network peer exists. Records authored there remain in that space permanently.
Pairing may add delivery peers, admit further trusted spaces, or grant another
device authority, but it must never re-sign, rewrite, or migrate the phone's
existing operation history into a hub-owned space.

If two independently initialized devices are paired later, both established
spaces remain valid. A future product flow may let the user choose a default
space and may present records from several spaces as one timeline, but that is
a projection concern rather than an identity migration. This follows directly
from the local-first promise: offline work is canonical data, not a temporary
JavaScript queue waiting for a server to assign its final identity.

## Consequences

- iOS and Android share one product UI and typed adapter layer.
- The desktop Control Center remains Tauri and React; it is not replaced by
  React Native.
- Platform code remains necessary for secure storage, lifecycle scheduling,
  native file selection, and packaging the Rust library.
- Expo development builds are required whenever native dependencies change.
- A browser or Expo Go preview may render presentation components but cannot be
  treated as proof of native-client behavior.
