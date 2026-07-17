//! Process-level safeguards for the Fractonica node executable.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use fs4::TryLockError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeStartupError {
    #[error("refusing to expose the unauthenticated bootstrap API on non-loopback address {0}")]
    NonLoopbackBind(SocketAddr),

    #[error("could not determine a platform data directory")]
    MissingDataDirectory,

    #[error("failed to prepare node data directory: {0}")]
    Io(#[from] io::Error),

    #[error("another Fractonica node is already using {0}")]
    AlreadyRunning(PathBuf),

    #[error("failed to acquire node process lock: {0}")]
    Lock(String),
}

pub fn validate_bind(address: SocketAddr) -> Result<SocketAddr, NodeStartupError> {
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(NodeStartupError::NonLoopbackBind(address))
    }
}

pub fn default_data_dir() -> Result<PathBuf, NodeStartupError> {
    ProjectDirs::from("com", "Fractonica", "Fractonica")
        .map(|directories| directories.data_local_dir().join("node"))
        .ok_or(NodeStartupError::MissingDataDirectory)
}

pub struct NodeProcessLock {
    #[allow(dead_code)]
    file: File,
    path: PathBuf,
}

pub struct NodeReadyFile {
    path: PathBuf,
}

impl NodeReadyFile {
    pub fn publish(path: &Path, address: SocketAddr) -> Result<Self, NodeStartupError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            prepare_private_directory(parent)?;
        }
        if matches!(fs::symlink_metadata(path), Ok(metadata) if metadata.file_type().is_symlink()) {
            return Err(NodeStartupError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} must not be a symbolic link", path.display()),
            )));
        }

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        writeln!(file, "http://{address}")?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for NodeReadyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl NodeProcessLock {
    pub fn acquire(data_dir: &Path) -> Result<Self, NodeStartupError> {
        prepare_private_directory(data_dir)?;
        let path = data_dir.join("node.lock");
        if matches!(fs::symlink_metadata(&path), Ok(metadata) if metadata.file_type().is_symlink())
        {
            return Err(NodeStartupError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} must not be a symbolic link", path.display()),
            )));
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { file, path }),
            Err(TryLockError::WouldBlock) => Err(NodeStartupError::AlreadyRunning(path)),
            Err(error) => Err(NodeStartupError::Lock(error.to_string())),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_loopback_binding() {
        let address = "127.0.0.1:8789".parse().expect("address");
        assert_eq!(validate_bind(address).expect("loopback"), address);
    }

    #[test]
    fn rejects_public_binding_until_auth_exists() {
        let address = "0.0.0.0:8789".parse().expect("address");
        assert!(matches!(
            validate_bind(address),
            Err(NodeStartupError::NonLoopbackBind(_))
        ));
    }

    #[test]
    fn process_lock_prevents_two_nodes_using_one_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = NodeProcessLock::acquire(directory.path()).expect("first lock");
        let second = NodeProcessLock::acquire(directory.path());

        assert!(matches!(second, Err(NodeStartupError::AlreadyRunning(_))));
        drop(first);
        assert!(NodeProcessLock::acquire(directory.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn process_state_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary directory");
        let directory = root.path().join("node");
        let process_lock = NodeProcessLock::acquire(&directory).expect("lock");

        assert_eq!(
            fs::metadata(&directory)
                .expect("data directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(process_lock.path())
                .expect("lock file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn ready_file_publishes_the_bound_endpoint_and_cleans_up() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("bootstrap").join("node.ready");
        let address = "127.0.0.1:43123".parse().expect("address");

        let ready = NodeReadyFile::publish(&path, address).expect("ready file");
        assert_eq!(
            fs::read_to_string(ready.path()).expect("read ready file"),
            "http://127.0.0.1:43123\n"
        );
        drop(ready);
        assert!(!path.exists());
    }
}
