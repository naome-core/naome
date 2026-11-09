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
    let error = read_owned(&path, 2).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::OwnedInputCapacity)
    );
}

#[test]
fn owned_reads_reject_directories_symbolic_links_and_shared_inodes() {
    let directory = Directory::new();
    let path = directory.0.join("input");
    let alias = directory.0.join("alias");
    let error = read_owned(&directory.0, 32).unwrap_err();
    assert_eq!(error.code(), u32::from(crate::InputFault::OwnedFileType));
    fs::write(&path, b"abc").unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(read_owned(&alias, 32).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    for linked in [&path, &alias] {
        let error = read_owned(linked, 32).unwrap_err();
        assert_eq!(error.code(), u32::from(crate::InputFault::OwnedFileLinks));
    }
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

#[test]
fn owned_file_validation_reports_type_links_and_missing_metadata() {
    let directory = Directory::new();
    let missing = directory.0.join("missing");
    let error = owned_file(&missing).unwrap_err();
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(
        value["code"],
        u32::from(crate::outcome::OperationCode::StorageIo)
    );
    assert_eq!(
        value["operation"],
        u32::from(crate::StorageIoOperation::InspectOwnedFile)
    );
    assert_eq!(value["kind"], u32::from(crate::IoFaultKind::NotFound));
    assert_eq!(value["os_code"], nix::errno::Errno::ENOENT as i32);
    let error = owned_file(&directory.0).unwrap_err();
    assert_eq!(error.code(), u32::from(crate::InputFault::OwnedFileType));
    assert!(error.storage().fatal());
    let path = directory.0.join("owned");
    fs::write(&path, b"kept").unwrap();
    let alias = directory.0.join("alias");
    fs::hard_link(&path, &alias).unwrap();
    let error = owned_file(&path).unwrap_err();
    assert_eq!(error.code(), u32::from(crate::InputFault::OwnedFileLinks));
    assert!(error.storage().fatal());
    assert_eq!(fs::read(&path).unwrap(), b"kept");
}

#[test]
fn research_directory_rejects_an_alias_without_touching_its_target() {
    let directory = Directory::new();
    let target = directory.0.join("target");
    fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, directory.0.join("research")).unwrap();
    assert_eq!(
        research_directory(&directory.0).unwrap_err(),
        crate::Error::from(crate::InputFault::ResearchDirectoryInvalid)
    );
    assert!(target.is_dir());
}
