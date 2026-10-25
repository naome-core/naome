use super::super::tests::Directory;
use super::*;

#[test]
fn boundaries_exact_text_clear_and_isolation() {
    let a = Directory::new();
    let b = Directory::new();
    assert_eq!(load(&a.0).unwrap(), "");
    for text in [
        "  math\n\tλ  ".into(),
        "x".repeat(1024),
        "🦀".repeat(256),
        "\u{0001}".repeat(1024),
        "".into(),
    ] {
        assert_eq!(update(&a.0, &text).unwrap(), text);
        assert_eq!(load(&a.0).unwrap(), text);
        assert_eq!(load(&b.0).unwrap(), "");
    }
    update(&a.0, "previous").unwrap();
    for text in ["x".repeat(1025), format!("{}x", "🦀".repeat(256))] {
        assert!(update(&a.0, &text).is_err());
        assert_eq!(load(&a.0).unwrap(), "previous");
    }
}

#[test]
fn failures_and_interrupted_replacement_recover_previous_value() {
    for cut in 0..=2 {
        let directory = Directory::new();
        update(&directory.0, "previous").unwrap();
        assert!(
            update_at(
                &directory.0,
                "next",
                |at| if at == cut {
                    Err("injected failure".into())
                } else {
                    Ok(())
                },
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(load(&directory.0).unwrap(), "previous");
        let pending: Pending = read(&directory.0, PENDING).unwrap().unwrap();
        assert_eq!(pending.previous.interest, "previous");
    }
    for cut in 0..=2 {
        let directory = Directory::new();
        update(&directory.0, "previous").unwrap();
        let interrupted = std::panic::catch_unwind(|| {
            let _ = update_at(
                &directory.0,
                "next",
                |at| {
                    assert_ne!(at, cut, "simulated process loss");
                    Ok(())
                },
                || Ok(()),
            );
        });
        assert!(interrupted.is_err());
        fs::write(directory.0.join(INCOMING), b"incomplete").unwrap();
        assert_eq!(
            load(&directory.0).unwrap(),
            if cut == 2 { "next" } else { "previous" }
        );
        assert!(!directory.0.join(INCOMING).exists());
    }
}

#[test]
fn failed_final_sync_and_failed_rollback_retain_old_bytes_and_report_uncertainty() {
    let directory = Directory::new();
    update(&directory.0, "previous").unwrap();
    let failure = update_at(
        &directory.0,
        "next",
        |at| {
            if at == 2 {
                Err("injected final sync failure".into())
            } else {
                Ok(())
            }
        },
        || Err("injected recovery filesystem failure".into()),
    )
    .unwrap_err();
    assert!(failure.recovery_required);
    assert!(failure.message.contains("recovery required"));
    let pending: Pending = read(&directory.0, PENDING).unwrap().unwrap();
    assert_eq!(pending.previous.interest, "previous");
    // Revoke an unconfirmed receipt using the retained old snapshot. The old
    // value can be recovered after storage access becomes available again.
    replace(&directory.0, COMMIT, &pending.previous.receipt().unwrap()).unwrap();
    assert_eq!(load(&directory.0).unwrap(), "previous");
}

#[test]
fn missing_or_inconsistent_established_commit_receipts_fail_closed() {
    let directory = Directory::new();
    update(&directory.0, "first").unwrap();
    update(&directory.0, "second").unwrap();
    let receipt = fs::read(directory.0.join(COMMIT)).unwrap();
    fs::remove_file(directory.0.join(COMMIT)).unwrap();
    assert!(
        load(&directory.0)
            .unwrap_err()
            .contains("commit receipt is missing")
    );
    fs::write(directory.0.join(COMMIT), &receipt).unwrap();
    let original = fs::read(directory.0.join(CONFIG)).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["interest"] = serde_json::json!("changed");
    fs::write(
        directory.0.join(CONFIG),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(
        load(&directory.0)
            .unwrap_err()
            .contains("configuration mismatch")
    );
    assert_eq!(fs::read(directory.0.join(COMMIT)).unwrap(), receipt);
}

#[test]
fn owned_profile_read_does_not_require_the_parent_directory_uid() {
    let directory = Directory::new();
    update(&directory.0, "owned profile").unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let parent = directory
        .0
        .ancestors()
        .skip(1)
        .find(|path| path.metadata().is_ok_and(|metadata| metadata.uid() != uid))
        .unwrap_or_else(|| directory.0.parent().unwrap());
    let owned = directory.0.join(CONFIG);
    let relative = owned.strip_prefix(parent).unwrap().to_str().unwrap();
    let profile: Configuration = read(parent, relative).unwrap().unwrap();
    assert_eq!(profile.interest, "owned profile");
    assert_eq!(owned.metadata().unwrap().uid(), uid);
    // Nonroot supported-platform runs find a genuinely foreign-owned
    // ancestor, with no writes or privilege changes outside the owned leaf.
    if uid != 0 {
        assert_ne!(parent.metadata().unwrap().uid(), uid);
    }
}

#[test]
fn malformed_versions_and_file_aliases_fail_closed() {
    let directory = Directory::new();
    let foreign = Directory::new();
    let path = directory.0.join(CONFIG);
    for input in [
        b"{}".as_slice(),
        br#"{"version":2,"revision":0,"interest":"x"}"#,
        br#"{"version":1,"revision":0,"interest":"x","extra":true}"#,
    ] {
        fs::write(&path, input).unwrap();
        assert!(load(&directory.0).is_err());
    }
    fs::remove_file(&path).unwrap();
    update(&foreign.0, "foreign").unwrap();
    std::os::unix::fs::symlink(foreign.0.join(CONFIG), &path).unwrap();
    assert!(update(&directory.0, "next").is_err());
    assert_eq!(load(&foreign.0).unwrap(), "foreign");
}
