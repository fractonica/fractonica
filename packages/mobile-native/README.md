# `@fractonica/mobile-native`

Standalone Expo module boundary for the Fractonica mobile client. It links the
Rust client through pinned UniFFI 0.32.0 bindings and exposes versioned,
bounded operations for bridge/client status, record previews, exact record
lookup, durable public-record creation, and explicit local-installation
recovery. It also exposes the bounded loopback pairing claim: Rust validates
the invitation, signs with protected keys, completes Noise, verifies the
responder receipt, and returns only public ceremony fields and the two-glyph
confirmation value. The separate acceptance method keeps the pending
transcript below JavaScript, creates a fresh dual-signed acceptance with the
protected node and actor keys, verifies the completed responder session, and
persists a pull-only paired peer for the background worker.

The module must never expose private keys, SQLite handles, native storage
paths, raw signed envelopes, or bulk attachment bytes to JavaScript.

Record listing is a feed projection, not document transfer: every preview has
bounded emoji/text fields and the whole page has a 64 KiB semantic wire budget,
so a response may contain fewer rows than its count limit. Exact detail lookup
requires both the immutable operation ID and entity ID and returns at most a
2 MiB public document JSON string. That string remains opaque across Swift,
Kotlin, and JavaScript so canonical metadata integers are never silently
rounded through platform number types.

The consuming Expo application loads the native module. This package keeps the
versioned bridge contract free of an additional Expo JavaScript installation,
which prevents duplicate native dependency graphs in a pnpm monorepo.

## Native build

From the repository root:

```sh
rustup target add aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
pnpm mobile:native:ios
pnpm mobile:native:android
```

The iOS command creates an iPhone plus universal Apple-silicon/Intel simulator
XCFramework, with an iOS 16.4 deployment floor, consumed by the podspec. The
Android command uses the installed Android NDK directly and creates JNI
libraries for Expo's four default ABIs: arm64-v8a, armeabi-v7a, x86, and
x86_64. It defaults to Expo's NDK `27.1.12297006`; an intentional toolchain
change can be tested with `FRACTONICA_ANDROID_NDK_VERSION` or an exact
`FRACTONICA_ANDROID_NDK_ROOT`. Run the relevant command before `expo prebuild`
or whenever the Rust facade changes. Generated Swift and Kotlin source is
checked in; compiled libraries are local build products.

The native lifecycle is deliberately crash-resumable: SQLite enters its
initializing phase before protected material is created. A complete protected
identity counts as present even while its outer Keychain/Keystore lifecycle
marker says `initializing`. Rust opens or validates the installation first;
only then does native storage transition that marker to `established`. A crash
between those last two writes therefore resumes the same identity rather than
generating replacement trust anchors.

Recovery is deliberately destructive and never automatic. JavaScript must
send the exact reset confirmation after showing a user confirmation dialog;
Rust removes the local database and content before the native adapter removes
Keychain/Keystore identity state. If either step is interrupted, the next boot
returns to the recovery screen instead of replacing keys silently.
