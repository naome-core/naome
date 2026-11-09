//! Reclaim only candidate caches whose owning job is durably acknowledged.
//! Canonical provider records and published proof input remain with their owners.
use super::*;

pub(crate) fn retire_candidate(directory: &Path, job: u64) -> Result<bool, crate::Error> {
    let root = directory.join(".program-work");
    let root = match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == nix::unistd::geteuid().as_raw() =>
        {
            fs::canonicalize(root)?
        }
        Ok(_) => return Err(crate::InputFault::CandidateDirectoryInvalid.into()),
    };
    let path = root.join(format!("candidate-{job}.sqlite3"));
    let lock_path = path.with_extension("proof-work.lock");
    let metadata = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return retire_orphan_lock(&lock_path);
        }
        Err(error) => return Err(error.into()),
        Ok(_) => crate::storage::owned_file(&path)?,
    };
    let identity = (metadata.dev(), metadata.ino());
    let lock = crate::storage::LockFile::existing(&lock_path)?;
    let lock_identity = lock.file().metadata()?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(&path)?;
    let opened = file.metadata()?;
    if (opened.dev(), opened.ino()) != identity {
        return Err(crate::InputFault::CandidateChanged.into());
    }
    let mut header = [0; 100];
    file.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0"
        || header[68..72] != (naome_checker::program::APPLICATION_ID as u32).to_be_bytes()
    {
        return Err(crate::InputFault::CandidateFormat.into());
    }
    let connection = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(candidate_sql)?;
    crate::storage::sqlite_common(&connection, 4096).map_err(candidate_sql)?;
    naome_checker::program::verify_database(&connection)?;
    let (busy, _, _): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(candidate_sql)?;
    connection
        .close()
        .map_err(|(_, error)| candidate_sql(error))?;
    if busy != 0 {
        return Ok(false);
    }
    let current = crate::storage::owned_file(&path)?;
    let current_lock = crate::storage::owned_file(&lock_path)?;
    if (current.dev(), current.ino()) != identity
        || (current_lock.dev(), current_lock.ino()) != (lock_identity.dev(), lock_identity.ino())
    {
        return Err(crate::InputFault::CandidateChanged.into());
    }
    fs::remove_file(&path)?;
    fs::remove_file(lock_path)?;
    File::open(root).and_then(|file| file.sync_all())?;
    Ok(true)
}

// A crash can occur after unlinking the disposable database but before its
// empty lock leaf. The caller has already checked the durable job acknowledgement.
fn retire_orphan_lock(path: &Path) -> Result<bool, crate::Error> {
    let lock = match crate::storage::LockFile::existing(path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let opened = lock.file().metadata()?;
    let current = crate::storage::owned_file(path)?;
    if opened.len() != 0 || (opened.dev(), opened.ino()) != (current.dev(), current.ino()) {
        return Err(crate::InputFault::CandidateLockChanged.into());
    }
    fs::remove_file(path)?;
    File::open(path.parent().expect("candidate lock directory"))
        .and_then(|file| file.sync_all())?;
    Ok(true)
}

fn candidate_sql(error: rusqlite::Error) -> crate::Error {
    let (reason, sqlite_code) = crate::error::sqlite_fault(&error);
    crate::Error::ProgramSql {
        reason,
        sqlite_code,
    }
}
