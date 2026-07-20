# Fractonica Mobile

The new iOS and Android client is an Expo SDK 57 / React Native 0.86 application. It uses Expo Router and is intended to run as a development build because durable Fractonica storage, signing, and synchronization belong to a custom Rust-backed native module.

## Boundary

React Native owns presentation, navigation, and short-lived editor state. The native client owns identity, the local operation log, content-addressed media, projections, and background synchronization. The JavaScript layer does not persist a shadow record database and never fabricates synchronization results.

`@fractonica/mobile-native` supplies the autolinked, versioned `FractonicaClient` module. Its `bridgeStatus()` handshake verifies the generated UniFFI bindings and Rust client are linked. The functional module boundary exposes these initial client methods:

- `clientStatus()`
- `clientListRecords({ limit })`
- `clientGetRecord({ operationId, entityId })`
- `clientCreateRecord({ payload })`
- `clientResetLocalInstallation({ confirmation })`

Every response is strictly decoded before it reaches UI state. Optional fields must be omitted, not serialized as `null`, and unknown fields are rejected.

The records screen polls `clientStatus()` while the linked runtime is starting and does not query the projection until it reports `ready`. It then requests up to 100 record previews. Native also stops the page at a 64 KiB wire budget, so list payloads cannot grow with large documents. Feed previews contain only bounded emoji/text display fields; metadata, references, resource descriptors, and private payloads stay below the list boundary. A composer draft is cleared only after `clientCreateRecord()` returns a validated local commit. Validation and native failures remain visible in the composer without discarding the draft.

Exact record lookup requires both operation and entity ID and has a 2 MiB
document ceiling. Public document JSON stays opaque across the bridge so exact
metadata integers are not rounded through platform or JavaScript numbers.
Outgoing drafts reject unsafe integers and canonical container limits before
native serialization.

If a development build does not contain that module, the app deliberately renders a native-core-unavailable state. It does not substitute fixtures or call a server.

Identity/database mismatches render a separate recovery state. The app does
not replace protected keys during startup: it requires a destructive user
confirmation, resets both the local data store and the protected identity, and
only then bootstraps a fresh installation.

Glyphs are rendered by `@fractonica/glyph-react-native`, which consumes the shared canonical MSB-first geometry rather than duplicating mobile stroke rules.

## Local development

Install workspace dependencies, then create native projects and launch a development build:

```sh
pnpm install
rustup target add aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios
pnpm mobile:native:ios
pnpm --filter @fractonica/mobile run prebuild
pnpm mobile:ios
```

For Android, install the Rust targets that match Expo's default ABIs, run
`pnpm mobile:native:android` before prebuild, and finish with
`pnpm mobile:android`:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

The top-level iOS and Android commands rebuild the respective Rust artifacts
on subsequent runs. After the development build is installed, start Metro
with:

```sh
pnpm --filter @fractonica/mobile run start
```

Expo Go is not a supported runtime for Fractonica Mobile because it cannot include the custom native client.

## Validation

```sh
pnpm --filter @fractonica/mobile run check
pnpm --filter @fractonica/mobile run doctor
```
