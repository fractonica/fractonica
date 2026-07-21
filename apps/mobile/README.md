# Fractonica Mobile

The new iOS and Android client is an Expo SDK 57 / React Native 0.86 application. It uses Expo Router and is intended to run as a development build because durable Fractonica storage, signing, and synchronization belong to a custom Rust-backed native module.

## Boundary

React Native owns presentation, navigation, and short-lived editor state. The native client owns identity, the local operation log, content-addressed media, projections, and background synchronization. The JavaScript layer does not persist a shadow record database and never fabricates synchronization results.

`@fractonica/mobile-native` supplies the autolinked, versioned `FractonicaClient` module. Its `bridgeStatus()` handshake verifies the generated UniFFI bindings and Rust client are linked. The functional module boundary exposes these initial client methods:

- `clientStatus()`
- `clientListRecords({ limit })`
- `clientGetRecord({ operationId, entityId })`
- `clientCreateRecord({ payload })`
- `clientClaimPairingInvitation({ qr })`
- `clientAcceptPairingInvitation({ invitationId })`
- `clientResetLocalInstallation({ confirmation })`

Every response is strictly decoded before it reaches UI state. Optional fields must be omitted, not serialized as `null`, and unknown fields are rejected.

The records screen polls `clientStatus()` while the linked runtime is starting and does not query the projection until it reports `ready`. It then requests up to 100 record previews. Native also stops the page at a 64 KiB wire budget, so list payloads cannot grow with large documents. Feed previews contain only bounded emoji/text display fields; metadata, references, resource descriptors, and private payloads stay below the list boundary. A composer draft is cleared only after `clientCreateRecord()` returns a validated local commit. Validation and native failures remain visible in the composer without discarding the draft.

Exact record lookup requires both operation and entity ID and has a 2 MiB
document ceiling. Public document JSON stays opaque across the bridge so exact
metadata integers are not rounded through platform or JavaScript numbers.
Outgoing drafts reject unsafe integers and canonical container limits before
native serialization.

If a development build does not contain that module, the app deliberately renders a native-core-unavailable state. It does not substitute fixtures or call a server.

The desktop QR opens `fractonica://pair?invitation=...`. Expo Router takes the
app directly to the pairing surface, which validates the bounded canonical
`fractonica-pairing:v1:` invitation and automatically performs the Noise
initiator exchange below JavaScript with the device's protected node and actor
keys. It verifies the responder-signed transcript receipt and displays the
complete confirmation as two five-digit MSB-first glyphs and a two-row octal
digit grid. If that sequence matches the desktop, the user presses Pair. Rust
then signs an acceptance with both protected keys; only a valid acceptance can
activate the already-prepared capability grant.

Completed peers are persisted below JavaScript. Before switching workspaces,
the native runtime pulls and verifies the desktop space genesis and the exact
pairing-issued grant. It then authors new records into that shared space and
the background worker pushes and pulls signed operations plus resumable media.
The desktop QR carries an explicit private-LAN endpoint, so a physical phone on
the same network can complete the exchange. Automatic discovery and a
confidential persistent peer channel are later transport hardening; this
milestone should be tested only on a trusted private network.

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

For the desktop-pairing test, start the desktop first with `pnpm desktop:dev`,
then install/run this development build on the iPhone. Both devices must be on
the same private network and macOS must allow incoming connections for the
Fractonica development binary.

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

The Expo configuration disables Xcode user-script sandboxing for the app
project. React Native's release bundle phase resolves JavaScript through Node
across the pnpm workspace and writes into Xcode's build-products directory;
those paths are dynamic and cannot be completely declared as build-phase
inputs and outputs. Run `prebuild` again after regenerating the iOS project so
the setting is reapplied automatically.

## Validation

```sh
pnpm --filter @fractonica/mobile run check
pnpm --filter @fractonica/mobile run doctor
```
