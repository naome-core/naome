use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Directory(pub(crate) PathBuf);
impl Directory {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Linux getrusage preserves pre-exec statistics from the launcher. VmHWM is
// scoped to the current memory image, so parallel parent tests cannot inflate
// the isolated history comparison. Missing measurements fail the test.
#[cfg(any(target_os = "linux", feature = "system-tests"))]
pub(crate) fn image_peak_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let mut fields = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .expect("current-image RSS high-water mark")
            .split_whitespace();
        let kib: u64 = fields.next().unwrap().parse().unwrap();
        assert_eq!(fields.next(), Some("kB"));
        assert_eq!(fields.next(), None);
        kib.checked_mul(1024).unwrap()
    }
    #[cfg(not(target_os = "linux"))]
    {
        u64::try_from(
            nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF)
                .unwrap()
                .max_rss(),
        )
        .unwrap()
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rss_measurement_does_not_inherit_the_launchers_memory() {
    const TEST: &str = "checkpoint::tests::rss_measurement_does_not_inherit_the_launchers_memory";
    if std::env::var_os("NAOME_RSS_IMAGE_PROBE").is_some() {
        let image = image_peak_rss_bytes();
        let lifetime = u64::try_from(
            nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF)
                .unwrap()
                .max_rss(),
        )
        .unwrap()
        .checked_mul(1024)
        .unwrap();
        assert!(
            lifetime >= image + 32 * 1024 * 1024,
            "launcher RSS was not isolated: lifetime={lifetime}, image={image}"
        );
        println!(
            "RSS_IMAGE_METRICS {}",
            serde_json::json!({"lifetime_peak_bytes":lifetime,"image_peak_bytes":image})
        );
        return;
    }
    let mut memory = vec![0u8; 64 * 1024 * 1024];
    for page in memory.chunks_mut(4096) {
        page[0] = 1;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env("NAOME_RSS_IMAGE_PROBE", "1")
        .output()
        .unwrap();
    std::hint::black_box(&memory);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{stdout}");
}

#[test]
fn interrupted_updates_roll_back_every_row_and_the_header() {
    let directory = Directory::new();
    let path = directory.0.join("checkpoint.sqlite3");
    let mut checkpoint = Checkpoint::create(
        &path,
        "test",
        &1u64,
        vec![Update::put("record", "one", &1u64).unwrap()],
    )
    .unwrap();
    assert!(
        checkpoint
            .commit(
                &2u64,
                vec![
                    Update::put("record", "one", &2u64).unwrap(),
                    Update::put("", "invalid", &3u64).unwrap()
                ]
            )
            .is_err()
    );
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(1));
    drop(checkpoint);
    let external = Connection::open(&path).unwrap();
    external
        .execute_batch("BEGIN IMMEDIATE; DELETE FROM entries; UPDATE checkpoint SET header=X'32'")
        .unwrap();
    drop(external); // A terminated writer cannot publish a partial checkpoint.
    let checkpoint = Checkpoint::open(&path, "test").unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(1));
}

#[test]
fn initialization_resumes_only_empty_or_complete_owned_stages() {
    let directory = Directory::new();
    let path = directory.0.join("empty.sqlite3");
    fs::write(path.with_extension("initializing"), []).unwrap();
    let checkpoint = Checkpoint::create(&path, "test", &7u64, vec![]).unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 7);
    drop(checkpoint);
    let source = directory.0.join("source.sqlite3");
    drop(
        Checkpoint::create(
            &source,
            "test",
            &8u64,
            vec![Update::put("record", "one", &8u64).unwrap()],
        )
        .unwrap(),
    );
    let target = directory.0.join("target.sqlite3");
    fs::rename(source, target.with_extension("initializing")).unwrap();
    let checkpoint = Checkpoint::create(&target, "test", &9u64, vec![]).unwrap();
    assert_eq!(
        checkpoint.header::<u64>().unwrap(),
        8,
        "a committed checkpoint is never replaced with fresh state"
    );
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(8));
}

#[test]
fn row_binding_deletion_external_mutation_and_file_aliases_fail_closed() {
    for mode in 0..5 {
        let directory = Directory::new();
        let path = directory.0.join("checkpoint.sqlite3");
        let checkpoint = Checkpoint::create(
            &path,
            "test",
            &1u64,
            vec![
                Update::put("record", "one", &1u64).unwrap(),
                Update::put("record", "two", &2u64).unwrap(),
            ],
        )
        .unwrap();
        if mode == 4 {
            fs::hard_link(&path, directory.0.join("alias")).unwrap();
        } else {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(match mode {
                0 => "DELETE FROM entries WHERE key='one'",
                1 => "UPDATE entries SET payload=X'39' WHERE key='one'",
                2 => "UPDATE entries SET payload=(SELECT payload FROM entries WHERE key='two'), digest=(SELECT digest FROM entries WHERE key='two') WHERE key='one'",
                _ => "UPDATE checkpoint SET domain='other'",
            }).unwrap();
        }
        assert!(checkpoint.get::<u64>("record", "absent", 32).is_err());
        drop(checkpoint);
        assert!(Checkpoint::open(&path, "test").is_err());
    }
}

/// Equal-length sources bind different canonical closed targets, so the
/// lifetime screens exercise distinct obligations rather than whitespace aliases.
pub(crate) fn question_source(index: usize) -> String {
    use naome_foundation::{Formula, FreeVariable};
    let x = FreeVariable::new(0);
    let mut formula = Formula::equal(x, x);
    for bit in 0..12 {
        let atom = if index & (1 << bit) == 0 {
            Formula::equal(x, x)
        } else {
            Formula::member(x, x)
        };
        formula = Formula::implies(atom, formula);
    }
    crate::test_inputs::question(Formula::for_all(x, formula)).to_hex()
}

#[test]
fn row_read_limit_and_digest_failures_remain_distinct_and_fail_closed() {
    let directory = Directory::new();
    let path = directory.0.join("typed-row.sqlite3");
    let checkpoint = Checkpoint::create(
        &path,
        "test",
        &1u64,
        vec![Update::put("record", "one", &"retained payload").unwrap()],
    )
    .unwrap();
    let error = checkpoint.page("record", None, 0, 1024).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointPageBudget)
    );
    let error = checkpoint.page("record", None, 1, 64).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointPageMemoryLimit)
    );
    let error = checkpoint.page("record", None, 1, 2).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointRecordReadLimit)
    );
    let stored = serde_json::to_value(error.storage()).unwrap();
    assert_eq!(stored["fatal"], true);
    assert_eq!(
        stored["cause_code"],
        u32::from(crate::InputFault::CheckpointRecordReadLimit)
    );

    checkpoint
        .connection
        .execute(
            "UPDATE entries SET digest = zeroblob(32) WHERE kind = 'record' AND key = 'one'",
            [],
        )
        .unwrap();
    let error = checkpoint.page("record", None, 1, 1024).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointRecordDigest)
    );
    assert_eq!(
        serde_json::to_value(error.storage()).unwrap()["fatal"],
        true
    );
    let count: i64 = checkpoint
        .connection
        .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn external_checkpoint_change_and_replacement_keep_specific_fail_closed_causes() {
    let directory = Directory::new();
    let path = directory.0.join("owner.sqlite3");
    let checkpoint = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    let outside = Connection::open(&path).unwrap();
    outside
        .execute("UPDATE checkpoint SET header = X'32'", [])
        .unwrap();
    let error = checkpoint.page("record", None, 1, 1024).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointOutsideOwner)
    );
    let error = checkpoint.query(|_| Ok(())).unwrap_err();
    assert!(error.fatal());
    assert_eq!(
        serde_json::to_value(error).unwrap()["cause_code"],
        u32::from(crate::InputFault::CheckpointOutsideOwner)
    );
    drop(outside);
    drop(checkpoint);

    let path = directory.0.join("replaced.sqlite3");
    let checkpoint = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    fs::rename(&path, directory.0.join("old.sqlite3")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    let error = checkpoint.page("record", None, 1, 1024).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointFileReplaced)
    );
    assert!(checkpoint.query(|_| Ok(())).unwrap_err().fatal());
}

#[test]
fn uncertain_checkpoint_commit_requires_replay_before_any_read() {
    let directory = Directory::new();
    let path = directory.0.join("uncertain.sqlite3");
    let mut checkpoint = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    fail_after_commit();
    assert!(matches!(
        checkpoint.commit(&2u64, vec![]),
        Err(CommitError::Uncertain(_))
    ));
    let error = checkpoint.page("record", None, 1, 1024).unwrap_err();
    assert!(matches!(error, crate::Error::UncertainDurability(_)));
    assert!(error.fatal());
    drop(checkpoint);
    let recovered = Checkpoint::open(&path, "test").unwrap();
    assert_eq!(recovered.header::<u64>().unwrap(), 2);
}

#[test]
fn checkpoint_json_errors_keep_categories_positions_and_storage_fatality() {
    for (bytes, expected) in [
        (b"{!".as_slice(), crate::CheckpointJsonFault::Syntax),
        (b"{".as_slice(), crate::CheckpointJsonFault::Eof),
    ] {
        let error = decode::<serde_json::Value>(bytes).unwrap_err();
        assert!(
            matches!(error, crate::Error::CheckpointDecode { reason, line: 1, column: _, } if reason == expected)
        );
    }
    let error = decode::<u64>(b"\"wrong\"").unwrap_err();
    assert!(matches!(
        error,
        crate::Error::CheckpointDecode {
            reason: crate::CheckpointJsonFault::Data,
            ..
        }
    ));
    let error = decode::<serde_json::Value>(b" {\"value\":1}").unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointNoncanonical)
    );

    let directory = Directory::new();
    let path = directory.0.join("bad-json.sqlite3");
    let checkpoint = Checkpoint::create(
        &path,
        "test",
        &1u64,
        vec![Update::put("record", "one", &1u64).unwrap()],
    )
    .unwrap();
    let bytes = b"{!";
    checkpoint
        .connection
        .execute(
            "UPDATE entries SET payload = ?1, digest = ?2 WHERE kind = 'record' AND key = 'one'",
            params![
                bytes.as_slice(),
                digest("test", "record", "one", bytes).as_slice()
            ],
        )
        .unwrap();
    let error = checkpoint
        .get::<serde_json::Value>("record", "one", 1024)
        .unwrap_err();
    let value = serde_json::to_value(error.storage()).unwrap();
    assert_eq!(value["fatal"], true);
    assert_eq!(
        value["cause_code"],
        u32::from(crate::outcome::OperationCode::CheckpointDecode)
    );
    assert_eq!(
        value["reason"],
        u32::from(crate::CheckpointJsonFault::Syntax)
    );
    assert_eq!(value["line"], 1);
}

#[test]
fn checkpoint_header_domain_and_digest_failures_keep_specific_causes() {
    let directory = Directory::new();
    let path = directory.0.join("header.sqlite3");
    let checkpoint = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    checkpoint
        .connection
        .execute("UPDATE checkpoint SET domain = 'other'", [])
        .unwrap();
    let error = checkpoint.header::<u64>().unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointHeaderDomain)
    );
    let stored = serde_json::to_value(error.storage()).unwrap();
    assert_eq!(stored["fatal"], true);
    assert_eq!(
        stored["cause_code"],
        u32::from(crate::InputFault::CheckpointHeaderDomain)
    );
    checkpoint
        .connection
        .execute(
            "UPDATE checkpoint SET domain = 'test', digest = zeroblob(32)",
            [],
        )
        .unwrap();
    let error = checkpoint.header::<u64>().unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointHeaderDigest)
    );
    assert!(error.storage().fatal());
    checkpoint
        .connection
        .execute("DELETE FROM checkpoint", [])
        .unwrap();
    let error = checkpoint.header::<u64>().unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointHeaderCardinality)
    );
    assert!(error.storage().fatal());
}

#[test]
fn checkpoint_sql_read_failure_retains_native_code_and_fails_closed() {
    let directory = Directory::new();
    let path = directory.0.join("missing-table.sqlite3");
    let checkpoint = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    checkpoint
        .connection
        .execute("DROP TABLE entries", [])
        .unwrap();
    let error = checkpoint.page("record", None, 1, 1024).unwrap_err();
    let value = serde_json::to_value(error.storage()).unwrap();
    assert_eq!(value["fatal"], true);
    assert_eq!(
        value["cause_code"],
        u32::from(crate::outcome::OperationCode::CheckpointSql)
    );
    assert_eq!(
        value["reason"],
        u32::from(crate::CheckpointSqlFault::Engine)
    );
    assert_eq!(value["sqlite_code"], rusqlite::ffi::SQLITE_ERROR);
}

#[test]
fn checkpoint_direct_reads_and_kind_validation_retain_specific_failures() {
    let directory = Directory::new();
    let path = directory.0.join("direct.sqlite3");
    let checkpoint = Checkpoint::create(
        &path,
        "test",
        &1u64,
        vec![
            Update::put("record", "one", &"long payload").unwrap(),
            Update::put("unexpected", "two", &2u64).unwrap(),
        ],
    )
    .unwrap();
    let error = checkpoint.get_bytes("record", "one", 2).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointRecordReadLimit)
    );
    let error = checkpoint.require_kinds(&["record"]).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointUnexpectedKind)
    );
    assert!(error.storage().fatal());
}

#[test]
fn checkpoint_creation_reports_io_cause_without_creating_missing_parent() {
    let directory = Directory::new();
    let parent = directory.0.join("missing");
    let path = parent.join("checkpoint.sqlite3");
    let error = Checkpoint::create(&path, "test", &1u64, vec![])
        .err()
        .unwrap();
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(
        value["code"],
        u32::from(crate::outcome::OperationCode::StorageIo)
    );
    assert_eq!(
        value["operation"],
        u32::from(crate::StorageIoOperation::CreateStage)
    );
    assert_eq!(value["kind"], u32::from(crate::IoFaultKind::NotFound));
    assert_eq!(value["os_code"], nix::errno::Errno::ENOENT as i32);
    assert!(!parent.exists());
}

#[test]
fn oversized_initial_header_does_not_publish_and_stage_can_recover() {
    let directory = Directory::new();
    let path = directory.0.join("capacity.sqlite3");
    let oversized = "x".repeat(MAX_HEADER);
    let error = Checkpoint::create(&path, "test", &oversized, vec![])
        .err()
        .unwrap();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::CheckpointHeaderCapacity)
    );
    assert!(error.storage().fatal());
    assert!(!path.exists());
    let recovered = Checkpoint::create(&path, "test", &1u64, vec![]).unwrap();
    assert_eq!(recovered.header::<u64>().unwrap(), 1);
}
