//! One verified descriptor for a local kernel lock. Each owner keeps its own
//! waiting, error, handoff and explicit-unlock policy.
use super::*;
use std::{fs::TryLockError, io};

#[derive(Debug)]
pub(crate) struct LockFile {
    file: File,
    path: PathBuf,
    identity: (u64, u64),
}
impl LockFile {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Self::open_with(path, true)
    }
    pub(crate) fn existing(path: &Path) -> io::Result<Self> {
        Self::open_with(path, false)
    }
    fn open_with(path: &Path, create: bool) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
            .open(path)?;
        let metadata = file.metadata()?;
        require_owned(&metadata).map_err(io::Error::other)?;
        let lock = Self {
            identity: (metadata.dev(), metadata.ino()),
            file,
            path: path.to_owned(),
        };
        lock.validate()?;
        Ok(lock)
    }
    pub(crate) fn validate(&self) -> io::Result<()> {
        let opened = self.file.metadata()?;
        let current = fs::symlink_metadata(&self.path)?;
        require_owned(&opened).map_err(io::Error::other)?;
        require_owned(&current).map_err(io::Error::other)?;
        if self.identity != (opened.dev(), opened.ino())
            || self.identity != (current.dev(), current.ino())
        {
            return Err(io::Error::other("lock file changed outside its owner"));
        }
        Ok(())
    }
    pub(crate) fn try_lock(&self) -> Result<(), TryLockError> {
        self.validate().map_err(TryLockError::Error)?;
        self.file.try_lock()?;
        if let Err(error) = self.validate() {
            let _ = self.file.unlock();
            return Err(TryLockError::Error(error));
        }
        Ok(())
    }
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
    // Physical worker slots deliberately transfer the open description to a
    // supervisor. Closing the daemon must not explicitly unlock that lease.
    pub(crate) fn into_file(self) -> File {
        self.file
    }
}

#[cfg(test)]
mod tests;
