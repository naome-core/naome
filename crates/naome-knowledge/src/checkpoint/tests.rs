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
    let mut formula = "eq(x,x)".to_owned();
    for bit in 0..12 {
        let atom = if index & (1 << bit) == 0 {
            "eq (x,x)"
        } else {
            "mem(x,x)"
        };
        formula = format!("imp({atom},{formula})");
    }
    format!("goal = all(x,{formula})")
}
