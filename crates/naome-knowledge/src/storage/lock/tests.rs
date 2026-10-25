use super::*;
use crate::checkpoint::tests::Directory;

#[test]
fn competing_owners_and_inherited_descriptors_keep_one_kernel_lease() {
    let directory = Directory::new();
    let path = directory.0.join("lease.lock");
    let first = LockFile::open(&path).unwrap();
    first.try_lock().unwrap();
    let second = LockFile::existing(&path).unwrap();
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));
    let inherited = first.file().try_clone().unwrap();
    drop(first);
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));
    drop(inherited);
    second.try_lock().unwrap();
}

#[test]
fn nonregular_shared_and_replaced_leaves_cannot_establish_ownership() {
    let directory = Directory::new();
    let target = directory.0.join("target");
    let path = directory.0.join("lease.lock");
    assert_eq!(
        LockFile::existing(&path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!path.exists());
    fs::write(&target, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(LockFile::open(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(LockFile::open(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(LockFile::open(&path).is_err());
    fs::remove_dir(&path).unwrap();
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(LockFile::open(&path).is_err());
    fs::remove_file(&path).unwrap();
    let stale = LockFile::open(&path).unwrap();
    fs::rename(&path, directory.0.join("retired.lock")).unwrap();
    let current = LockFile::open(&path).unwrap();
    assert!(stale.try_lock().is_err());
    current.try_lock().unwrap();
    assert_eq!(fs::read(target).unwrap(), b"unchanged");
}
