use super::*;

#[test]
fn interrupted_or_paused_finalization_reopens_unchecked_and_reproduces_the_manifest() {
    const CASE: &str = "proof_work::tests::lifecycle::interrupted_or_paused_finalization_reopens_unchecked_and_reproduces_the_manifest";
    if std::env::var_os("NAOME_FINALIZATION_RECOVERY_CASE").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_FINALIZATION_RECOVERY_CASE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut expected = None;
    for interrupted_after in [0, 1, 4, 7, 12] {
        let directory = Directory::new();
        let mut work = Work::open(&directory.path()).unwrap();
        identity(&mut work);
        finish(&mut work);
        let mut quantum = budget();
        quantum.batch_steps = 1;
        for _ in 0..interrupted_after {
            work.prepare_export(&quantum).unwrap();
        }
        let mut paused = quantum.clone();
        paused.paused = Some("resource reduction".into());
        paused.batch_steps = 0;
        assert!(!work.prepare_export(&paused).unwrap());
        drop(work);
        let mut work = Work::open(&directory.path()).unwrap();
        assert_eq!(work.status().unwrap().checked_commands, 0);
        assert!(!work.status().unwrap().fully_checked);
        finish(&mut work);
        while !work.prepare_export(&quantum).unwrap() {}
        let checked = work.into_checked().unwrap();
        let manifest = checked.proof().unwrap().manifest().clone();
        match &expected {
            Some(expected) => assert_eq!(&manifest, expected),
            None => expected = Some(manifest),
        }
    }
}

#[test]
fn candidate_retirement_preserves_replacement_foreign_files_and_live_custody() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let path = directory.0.join(".program-work/candidate-1.sqlite3");
    let work = Work::open(&path).unwrap();
    assert!(!retire_candidate(&directory.0, 1).unwrap());
    assert!(path.exists());
    drop(work);
    let foreign = directory.0.join("foreign.sqlite3");
    let connection = Connection::open(&foreign).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('retain');",
        )
        .unwrap();
    drop(connection);
    let expected = fs::read(&foreign).unwrap();
    fs::rename(&foreign, &path).unwrap();
    assert!(retire_candidate(&directory.0, 1).is_err());
    assert_eq!(fs::read(&path).unwrap(), expected);
    fs::rename(&path, &foreign).unwrap();
    symlink(&foreign, &path).unwrap();
    assert!(retire_candidate(&directory.0, 1).is_err());
    assert_eq!(fs::read(&foreign).unwrap(), expected);
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
}

#[test]
fn candidate_retirement_preserves_owned_files_with_a_damaged_current_schema() {
    for change in [
        "ALTER TABLE input ADD COLUMN unexpected INTEGER",
        "CREATE TRIGGER unexpected AFTER INSERT ON input BEGIN DELETE FROM result; END",
    ] {
        let directory = Directory::new();
        let path = directory.0.join(".program-work/candidate-1.sqlite3");
        let mut work = Work::open(&path).unwrap();
        identity(&mut work);
        drop(work);
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(change).unwrap();
        drop(connection);
        let expected = fs::read(&path).unwrap();
        assert!(retire_candidate(&directory.0, 1).is_err());
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert!(path.with_extension("proof-work.lock").exists());
    }
}
