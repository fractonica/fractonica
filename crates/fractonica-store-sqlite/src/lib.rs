//! SQLite persistence for embedded and headless Fractonica nodes.

use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fractonica_core::{InstallationId, InstallationMetadata};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreReadiness {
    pub schema_version: u32,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to prepare the node data directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("node database uses schema {found}, but this binary supports up to {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("stored installation ID is invalid: {0}")]
    InvalidInstallationId(#[from] uuid::Error),

    #[error("node database lock was poisoned")]
    LockPoisoned,

    #[error("system clock is earlier than the Unix epoch")]
    ClockBeforeUnixEpoch,
}

#[derive(Clone)]
pub struct SqliteStore {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            prepare_private_directory(parent)?;
        }
        prepare_private_file(&path)?;

        let mut connection = Connection::open(&path)?;
        configure_connection(&connection, true)?;
        migrate(&mut connection)?;
        ensure_installation(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(path),
        })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let mut connection = Connection::open_in_memory()?;
        configure_connection(&connection, false)?;
        migrate(&mut connection)?;
        ensure_installation(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(PathBuf::from(":memory:")),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn readiness(&self) -> Result<StoreReadiness, StoreError> {
        self.with_connection(|connection| {
            connection.query_row("SELECT 1", [], |_| Ok(()))?;
            let schema_version = schema_version(connection)?;
            Ok(StoreReadiness { schema_version })
        })
    }

    pub fn installation(&self) -> Result<InstallationMetadata, StoreError> {
        self.with_connection(|connection| {
            let (installation_id, created_at_unix_ms): (String, i64) = connection.query_row(
                "SELECT installation_id, created_at_unix_ms
                 FROM node_installation
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;

            Ok(InstallationMetadata {
                installation_id: InstallationId::parse(&installation_id)?,
                created_at_unix_ms,
            })
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        operation(&connection)
    }
}

fn configure_connection(connection: &Connection, persistent: bool) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(Duration::from_secs(5))?;
    if persistent {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn prepare_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a private data directory", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn prepare_private_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular database file", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?;
        }
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn schema_version(connection: &Connection) -> Result<u32, StoreError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StoreError::from)
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let current = schema_version(connection)?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    if current == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE node_installation (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                installation_id TEXT NOT NULL UNIQUE,
                created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0)
            ) STRICT;
            PRAGMA user_version = 1;",
        )?;
        transaction.commit()?;
    }

    Ok(())
}

fn ensure_installation(connection: &Connection) -> Result<(), StoreError> {
    let existing: Option<i64> = connection
        .query_row(
            "SELECT singleton FROM node_installation WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    if existing.is_none() {
        let created_at_unix_ms: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::ClockBeforeUnixEpoch)?
            .as_millis()
            .try_into()
            .map_err(|_| StoreError::ClockBeforeUnixEpoch)?;

        connection.execute(
            "INSERT INTO node_installation
                (singleton, installation_id, created_at_unix_ms)
             VALUES (1, ?1, ?2)",
            params![Uuid::now_v7().to_string(), created_at_unix_ms],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_ready_database() {
        let store = SqliteStore::open_in_memory().expect("open database");

        assert_eq!(
            store.readiness().expect("database ready"),
            StoreReadiness {
                schema_version: SCHEMA_VERSION,
            }
        );
        assert!(store.installation().is_ok());
    }

    #[test]
    fn installation_identity_survives_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fractonica.db");

        let first_id = {
            let store = SqliteStore::open(&path).expect("first open");
            store.installation().expect("installation").installation_id
        };

        let reopened = SqliteStore::open(&path).expect("second open");
        let second_id = reopened
            .installation()
            .expect("installation")
            .installation_id;

        assert_eq!(first_id, second_id);
    }

    #[test]
    fn refuses_a_database_from_a_newer_binary() {
        let mut connection = Connection::open_in_memory().expect("database");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("set schema");

        assert!(matches!(
            migrate(&mut connection),
            Err(StoreError::UnsupportedSchema { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persistent_state_is_private_and_fully_synchronous() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let data_directory = directory.path().join("node");
        let path = data_directory.join("fractonica.db");
        let store = SqliteStore::open(&path).expect("open database");

        assert_eq!(
            fs::metadata(&data_directory)
                .expect("data directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).expect("database").permissions().mode() & 0o777,
            0o600
        );
        store
            .with_connection(|connection| {
                let synchronous: u8 =
                    connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
                assert_eq!(synchronous, 2);
                Ok(())
            })
            .expect("synchronous mode");
    }
}
