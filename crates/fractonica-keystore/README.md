# Fractonica keystore boundary

`fractonica-keystore` owns persistent local identity bootstrap without making
the rest of the node depend on raw files. Its `KeyStore` port can later be
implemented by macOS Keychain, Windows Credential Manager, Linux Secret
Service, TPMs, or secure elements.

The initial `FileKeyStore` stores four exact 32-byte values under a private
identity directory:

- `node-transport.ed25519`: node transport/pairing Ed25519 seed;
- `space-controller.ed25519`: space controller actor Ed25519 seed;
- `local-writer.ed25519`: ordinary local writer actor Ed25519 seed;
- `space.id`: non-secret, random 256-bit authorization-space identity.

On Unix the directory must be owned by the effective user with mode `0700`.
Every file must be owned by the effective user, have exactly one hard link, and
use mode `0600`. Symlinks, non-regular files, malformed lengths, missing files
from a completed identity, and identity collisions are rejected rather than
repaired.

On Windows, `FileKeyStore` protects every private seed with current-user DPAPI
and role-specific entropy before filesystem publication. Pairing invitation
secrets use the same current-user protection boundary. Unix owner and
mode checks do not prove that a macOS or network filesystem has no extended
ACL, so this raw adapter is currently limited to controlled single-user local
filesystems. Production macOS desktop releases require a reviewed Keychain
adapter.

Bootstrap is serialized by an advisory lock. A durable start marker permits a
crashed first bootstrap to fill only missing files while preserving every
valid file already published. The complete manifest is written only after all
roles validate. Once complete, a missing role is an error and is never silently
regenerated. Each value is written and synced to a private temporary file,
published without replacement using an atomic hard link, and followed by
directory synchronization.

For a full node, the identity directory is only one part of the installation.
Before SQLite bootstrap, `installation.pending.json` durably records the exact
signed genesis and initial grant; `installation.json` retains that material
after completion. Back up and restore the stopped node's `fractonica.db`,
complete `identity/`, and `installation.json` as one trust-critical unit, plus
`content/` whenever it contains media not available elsewhere. The installation
state is public binding data, not a secret, but restoring it without the exact
database and identity it pins fails closed. Likewise, an established
installation with a missing identity or database is rejected; the node never
generates replacement controller keys or silently creates a new trust anchor.

Never copy individual seed files into logs, issue reports, command-line
arguments, or configuration files.
