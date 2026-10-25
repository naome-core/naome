use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(std::path::PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-wallet-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        crate::storage::private_directory(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn initialized_wallet_survives_reopen_and_proves_the_same_address() {
    let directory = Directory::new();
    let identity = initialize(&directory.0).unwrap();
    let original = fs::read(directory.0.join(KEY)).unwrap();
    assert_eq!(initialize(&directory.0).unwrap(), identity);
    assert_eq!(fs::read(directory.0.join(KEY)).unwrap(), original);
    assert_eq!(
        fs::metadata(directory.0.join(KEY))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let challenge = OwnershipChallenge::new("storage-contract-verifier".into()).unwrap();
    prove(&directory.0, challenge.clone())
        .unwrap()
        .verify(identity.address, &challenge)
        .unwrap();
    assert_eq!(fs::read(directory.0.join(KEY)).unwrap(), original);
}

#[test]
fn interrupted_first_initialization_recovers_the_original_key_at_each_commit_boundary() {
    for step in 1..=3 {
        let directory = Directory::new();
        assert!(
            initialize_at(&directory.0, |at| {
                if at == step {
                    Err("injected initialization interruption".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let key = read_key(&directory.0, KEY)
            .unwrap()
            .or_else(|| read_key(&directory.0, PENDING_KEY).unwrap())
            .unwrap();
        let expected = key.address();
        assert_eq!(initialize(&directory.0).unwrap().address, expected);
        assert_eq!(initialize(&directory.0).unwrap().address, expected);
    }
}

#[test]
fn lost_changed_corrupt_or_exposed_private_keys_fail_without_replacement() {
    let directory = Directory::new();
    let expected = initialize(&directory.0).unwrap();
    let original = fs::read(directory.0.join(KEY)).unwrap();
    let receipt = fs::read(directory.0.join(IDENTITY)).unwrap();
    fs::remove_file(directory.0.join(KEY)).unwrap();
    assert!(initialize(&directory.0).unwrap_err().contains("missing"));
    assert!(!directory.0.join(KEY).exists());
    assert_eq!(identity(&directory.0).unwrap(), Some(expected));
    for bytes in [b"corrupt".to_vec(), {
        let other = Directory::new();
        initialize(&other.0).unwrap();
        fs::read(other.0.join(KEY)).unwrap()
    }] {
        fs::write(directory.0.join(KEY), &bytes).unwrap();
        fs::set_permissions(directory.0.join(KEY), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(initialize(&directory.0).is_err());
        assert_eq!(fs::read(directory.0.join(KEY)).unwrap(), bytes);
        assert_eq!(fs::read(directory.0.join(IDENTITY)).unwrap(), receipt);
    }
    fs::write(directory.0.join(KEY), original).unwrap();
    fs::set_permissions(directory.0.join(KEY), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(initialize(&directory.0).unwrap_err().contains("owner-only"));
    fs::set_permissions(directory.0.join(KEY), fs::Permissions::from_mode(0o600)).unwrap();
    initialize(&directory.0).unwrap();
}

#[test]
fn private_key_reads_reject_symbolic_and_hard_links() {
    let directory = Directory::new();
    initialize(&directory.0).unwrap();
    let saved = directory.0.join("saved.key");
    fs::rename(directory.0.join(KEY), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, directory.0.join(KEY)).unwrap();
    assert!(initialize(&directory.0).is_err());
    fs::remove_file(directory.0.join(KEY)).unwrap();
    fs::hard_link(&saved, directory.0.join(KEY)).unwrap();
    assert!(initialize(&directory.0).is_err());
    fs::remove_file(&saved).unwrap();
    initialize(&directory.0).unwrap();
}
