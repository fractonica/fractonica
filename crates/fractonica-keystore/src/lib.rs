#![forbid(unsafe_code)]
//! Platform boundary for persistent Fractonica node and actor identities.
//!
//! Consumers depend on [`KeyStore`], not on a filesystem layout. The initial
//! [`FileKeyStore`] adapter supports headless and desktop bootstrap. Platform
//! adapters can later store the same three roles in Keychain, Credential
//! Manager, Secret Service, a TPM, or a secure element without changing the
//! caller-facing identity bundle.

use std::{error::Error, fmt};

use fractonica_trust::{ActorId, NodeId, SigningKey, SpaceId};
use thiserror::Error;

mod filesystem;
mod pairing;

pub use filesystem::{FileKeyStore, FileKeyStoreError};
pub use pairing::{FilePairingSecretVault, PairingSecretVaultError};

/// One secret identity role in a Fractonica node installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRole {
    /// Authenticates node transport and pairing endpoints.
    NodeTransport,
    /// Controls bootstrap capabilities for one space.
    SpaceController,
    /// Authors ordinary operations created by this installation.
    LocalWriter,
}

impl fmt::Display for KeyRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NodeTransport => "node transport",
            Self::SpaceController => "space controller",
            Self::LocalWriter => "local writer",
        })
    }
}

/// Replaceable persistent-key backend used by node bootstrap.
pub trait KeyStore: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    /// Loads an established identity or durably creates it once.
    fn load_or_create(&self) -> Result<IdentityBundle, Self::Error>;
}

/// Three distinct signing roles and their local authorization space.
///
/// This type deliberately has no serialization implementation and exposes no
/// seed bytes. Its debug representation contains only public identifiers.
pub struct IdentityBundle {
    node_transport: SigningKey,
    space_controller: SigningKey,
    local_writer: SigningKey,
    space_id: SpaceId,
}

impl IdentityBundle {
    /// Validates and assembles identities loaded by any key-store backend.
    pub fn from_keys(
        node_transport: SigningKey,
        space_controller: SigningKey,
        local_writer: SigningKey,
        space_id: SpaceId,
    ) -> Result<Self, IdentityError> {
        let public_keys = [
            (
                KeyRole::NodeTransport,
                *node_transport.public_key().as_bytes(),
            ),
            (
                KeyRole::SpaceController,
                *space_controller.public_key().as_bytes(),
            ),
            (KeyRole::LocalWriter, *local_writer.public_key().as_bytes()),
        ];
        for left in 0..public_keys.len() {
            for right in (left + 1)..public_keys.len() {
                if public_keys[left].1 == public_keys[right].1 {
                    return Err(IdentityError::KeyCollision {
                        first: public_keys[left].0,
                        second: public_keys[right].0,
                    });
                }
            }
        }
        if space_id.as_bytes() == &[0; 32] {
            return Err(IdentityError::ZeroSpaceId);
        }
        Ok(Self {
            node_transport,
            space_controller,
            local_writer,
            space_id,
        })
    }

    #[must_use]
    pub const fn node_transport_key(&self) -> &SigningKey {
        &self.node_transport
    }

    #[must_use]
    pub const fn space_controller_key(&self) -> &SigningKey {
        &self.space_controller
    }

    #[must_use]
    pub const fn local_writer_key(&self) -> &SigningKey {
        &self.local_writer
    }

    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_transport.node_id()
    }

    #[must_use]
    pub fn space_controller_actor_id(&self) -> ActorId {
        self.space_controller.actor_id()
    }

    #[must_use]
    pub fn local_writer_actor_id(&self) -> ActorId {
        self.local_writer.actor_id()
    }

    #[must_use]
    pub const fn space_id(&self) -> SpaceId {
        self.space_id
    }
}

impl fmt::Debug for IdentityBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityBundle")
            .field("node_id", &self.node_id())
            .field(
                "space_controller_actor_id",
                &self.space_controller_actor_id(),
            )
            .field("local_writer_actor_id", &self.local_writer_actor_id())
            .field("space_id", &self.space_id)
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("{first} and {second} identities resolve to the same Ed25519 public key")]
    KeyCollision { first: KeyRole, second: KeyRole },
    #[error("space identity cannot be all zeroes")]
    ZeroSpaceId,
}
