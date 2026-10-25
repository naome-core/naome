use super::*;

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
