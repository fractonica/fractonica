//! Process-level safeguards for the Fractonica node executable.

pub mod bootstrap;
pub mod durable_pairing;
pub mod installation;

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
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(NodeStartupError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} must be a regular lock file", path.display()),
                )));
            }
            Ok(metadata) => validate_private_file(&path, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(NodeStartupError::Io(error)),
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;

        validate_private_file(&path, &file.metadata()?)?;

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
        Ok(metadata) => validate_private_directory(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            validate_private_directory(path, &fs::symlink_metadata(path)?)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        validate_owner(path, metadata)?;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o700 {
            return Err(private_state_error(
                path,
                format!("mode is {mode:#o}, expected 0o700"),
            ));
        }
    }
    Ok(())
}

fn validate_private_file(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        validate_owner(path, metadata)?;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o600 {
            return Err(private_state_error(
                path,
                format!("mode is {mode:#o}, expected 0o600"),
            ));
        }
        if metadata.nlink() != 1 {
            return Err(private_state_error(
                path,
                format!("has {} hard links, expected exactly one", metadata.nlink()),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let expected = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected {
        return Err(private_state_error(
            path,
            format!("owner is uid {}, expected uid {expected}", metadata.uid()),
        ));
    }
    Ok(())
}

fn private_state_error(path: &Path, detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} is not private node state: {detail}", path.display()),
    )
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
        let data_dir = directory.path().join("node");
        let first = NodeProcessLock::acquire(&data_dir).expect("first lock");
        let second = NodeProcessLock::acquire(&data_dir);

        assert!(matches!(second, Err(NodeStartupError::AlreadyRunning(_))));
        drop(first);
        assert!(NodeProcessLock::acquire(&data_dir).is_ok());
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

    #[cfg(unix)]
    #[test]
    fn existing_process_state_is_rejected_not_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary directory");
        let data_dir = root.path().join("node");
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            NodeProcessLock::acquire(&data_dir),
            Err(NodeStartupError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(
            fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );

        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = NodeProcessLock::acquire(&data_dir).unwrap();
        let lock_path = lock.path().to_owned();
        drop(lock);
        fs::hard_link(&lock_path, root.path().join("lock-copy")).unwrap();
        assert!(matches!(
            NodeProcessLock::acquire(&data_dir),
            Err(NodeStartupError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
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
