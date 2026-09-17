use super::*;
use std::{
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nr-files-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn private_outputs_are_bounded_idempotent_and_never_overwritten() {
    let dir = Directory::new();
    assert_eq!(fs::metadata(&dir.0).unwrap().mode() & 0o777, 0o700);
    assert!(directory(&dir.0).is_err());
    let path = dir.0.join("secret");
    create(&path, b"retained original", true).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(read(&path, 17, true).unwrap(), b"retained original");
    assert!(read(&path, 16, true).is_err());
    assert!(create(&path, b"replacement", true).is_err());
    create_or_match(&path, b"retained original", true).unwrap();
    assert!(create_or_match(&path, b"different content", true).is_err());
    assert_eq!(read(&path, 17, true).unwrap(), b"retained original");
    assert_eq!(
        fs::read_dir(&dir.0).unwrap().count(),
        1,
        "failed creates clean their staging files"
    );
}

#[test]
fn private_reads_and_replacements_reject_symlinks_or_public_modes() {
    let dir = Directory::new();
    let original = dir.0.join("original");
    create(&original, b"keep", true).unwrap();
    let link = dir.0.join("link");
    symlink(&original, &link).unwrap();
    assert!(read(&link, 4, true).is_err());
    assert!(create_or_match(&link, b"keep", true).is_err());
    assert!(replace_private(&link, b"overwrite").is_err());
    assert_eq!(read(&original, 4, true).unwrap(), b"keep");
    assert!(read(&dir.0, 4096, false).is_err());
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read(&original, 4, true).is_err());
    assert!(replace_private(&original, b"overwrite").is_err());
    assert_eq!(read(&original, 4, false).unwrap(), b"keep");
}

#[test]
fn private_replacement_preserves_permissions_and_existing_target_on_rejection() {
    let dir = Directory::new();
    let path = dir.0.join("profile");
    assert!(replace_private(&path, b"missing target").is_err());
    create(&path, b"old profile", true).unwrap();
    replace_private(&path, b"new operator profile").unwrap();
    assert_eq!(read(&path, 16384, true).unwrap(), b"new operator profile");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn generated_keys_require_exact_role_shape_and_private_permissions() {
    let dir = Directory::new();
    let path = dir.0.join("account.key");
    let original = write_key(&path, 1).unwrap();
    assert_eq!(
        key(&path, 1).unwrap().verifying_key(),
        original.verifying_key()
    );
    assert!(key(&path, 2).is_err());
    assert!(write_key(&path, 1).is_err());
    assert_eq!(
        key(&path, 1).unwrap().verifying_key(),
        original.verifying_key()
    );
    let malformed = dir.0.join("malformed.key");
    create(&malformed, b"NRKEY001\x01", true).unwrap();
    assert!(key(&malformed, 1).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(key(&path, 1).is_err());
    assert!(unhex::<32>("01").is_err());
    assert!(unhex::<1>("gg").is_err());
    assert_eq!(unhex::<3>(&hex(&[0, 17, 255])).unwrap(), [0, 17, 255]);
}
