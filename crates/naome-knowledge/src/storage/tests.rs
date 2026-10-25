use super::*;
use crate::checkpoint::tests::Directory;

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
