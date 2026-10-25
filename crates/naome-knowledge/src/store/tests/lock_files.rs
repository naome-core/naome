use super::*;

#[test]
fn canonical_catalog_rejects_symbolic_or_shared_lock_leaves_before_ownership() {
    for shared in [false, true] {
        let directory = Directory::new();
        let target = directory.0.join("unrelated-file");
        let lock = directory.0.join("knowledge.lock");
        fs::write(&target, b"unchanged").unwrap();
        if shared {
            fs::hard_link(&target, &lock).unwrap();
        } else {
            std::os::unix::fs::symlink(&target, &lock).unwrap();
        }
        assert!(Store::open(&directory.0).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        assert!(!directory.0.join(DATABASE_FILE).exists());
    }
}
