//! Pure domain values shared by Fractonica adapters.
//!
//! This crate deliberately has no database, network, filesystem, or async
//! runtime dependencies.

use core::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies one installed node database.
///
/// This is intentionally not a cryptographic node identity. Pairing will add a
/// public-key-derived identity without overloading installation lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InstallationId(Uuid);

impl InstallationId {
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for InstallationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Metadata that must survive every restart of the same node database.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallationMetadata {
    pub installation_id: InstallationId,
    pub created_at_unix_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_id_round_trips() {
        let original = InstallationId::new(Uuid::now_v7());
        let parsed = InstallationId::parse(&original.to_string()).expect("valid UUID");

        assert_eq!(parsed, original);
    }
}
