use super::*;
use crate::checkpoint::tests::Directory;

#[test]
fn node_state_is_private_without_modifying_parent_permissions_and_aliases_keep_one_owner() {
    let parent = std::env::temp_dir().join(format!(
        "naome-private-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&parent).unwrap();
    let before = fs::metadata(&parent).unwrap().permissions().mode();
    let directory = parent.join("node");
    private_directory(&directory).unwrap();
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::metadata(&parent).unwrap().permissions().mode(), before);
    let alias = parent.join("alias");
    std::os::unix::fs::symlink(&directory, &alias).unwrap();
    private_directory(&alias).unwrap();
    assert_eq!(
        fs::canonicalize(&alias).unwrap(),
        fs::canonicalize(&directory).unwrap()
    );
    let file = parent.join("file");
    fs::write(&file, b"unchanged").unwrap();
    assert!(private_directory(&file).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"unchanged");
    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn owned_reads_preserve_missing_empty_and_exact_byte_bounds() {
    let directory = Directory::new();
    let path = directory.0.join("input");
    assert_eq!(read_owned(&path, 3).unwrap(), None);
    fs::write(&path, b"").unwrap();
    assert_eq!(read_owned(&path, 0).unwrap(), Some(Vec::new()));
    fs::write(&path, b"abc").unwrap();
    assert_eq!(read_owned(&path, 3).unwrap(), Some(b"abc".to_vec()));
    assert!(read_owned(&path, 2).is_err());
}

#[test]
fn owned_reads_reject_directories_symbolic_links_and_shared_inodes() {
    let directory = Directory::new();
    let path = directory.0.join("input");
    let alias = directory.0.join("alias");
    assert!(read_owned(&directory.0, 32).is_err());
    fs::write(&path, b"abc").unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(read_owned(&alias, 32).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_owned(&path, 32).is_err());
    assert!(read_owned(&alias, 32).is_err());
}

#[test]
fn configuration_snapshot_survives_atomic_replacement_without_relaxing_store_ownership() {
    let directory = Directory::new();
    let path = directory.0.join("profile");
    write_marker(&path, b"old").unwrap();
    let snapshot = File::open(&path).unwrap();
    let strict = File::open(&path).unwrap();
    let incoming = directory.0.join("incoming");
    write_marker(&incoming, b"new").unwrap();
    fs::rename(incoming, &path).unwrap();

    assert_eq!(snapshot.metadata().unwrap().nlink(), 0);
    assert!(read_descriptor(strict, 3, InputLinks::One).is_err());
    assert_eq!(
        read_descriptor(snapshot, 3, InputLinks::Snapshot).unwrap(),
        b"old"
    );
    assert_eq!(
        read_owned_snapshot(&path, 3).unwrap(),
        Some(b"new".to_vec())
    );
    assert!(read_owned_snapshot(&path, 2).is_err());
    assert!(owned_file(&path).is_ok());
    let alias = directory.0.join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_owned_snapshot(&path, 3).is_err());
    assert!(read_owned_snapshot(&alias, 3).is_err());
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(read_owned_snapshot(&alias, 3).is_err());
    assert!(read_owned_snapshot(&directory.0, 3).is_err());
}
