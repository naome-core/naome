use super::*;
use sha2::Digest;

#[test]
fn smaller_restart_keeps_original_results_and_rejects_corruption_before_retirement() {
    const TEST: &str = "jobs::service::tests::resource_calibration::smaller_restart_keeps_original_results_and_rejects_corruption_before_retirement";
    if let Some(directory) = std::env::var_os("NAOME_JOB_REOPEN_DIRECTORY") {
        let mut profile = crate::resources::ResourceProfile::default();
        profile.tuning.active_job_bytes = Some(4096);
        crate::resources::configure(profile).unwrap();
        let opened = Disk::open(Path::new(&directory), Settings::default(), 0);
        if std::env::var_os("NAOME_JOB_REOPEN_CORRUPT").is_some() {
            assert!(
                opened
                    .err()
                    .unwrap()
                    .contains("checkpoint or budget differs")
            );
            return;
        }
        let (disk, journal) = opened.unwrap();
        assert!(journal.records.is_empty());
        assert_eq!(journal.retired_jobs, 6);
        assert_eq!(journal.next_id, 7);
        assert_eq!(journal.total_reserved_units, 6);
        let mut records = Vec::new();
        let mut after = 0;
        loop {
            let page = disk
                .recovery_page(after, journal.next_id, &Default::default())
                .unwrap();
            records.extend(page.records);
            match page.next {
                Some(next) => {
                    assert!(next > after);
                    after = next;
                }
                None => break,
            }
        }
        assert_eq!(
            records.iter().map(|record| record.id).collect::<Vec<_>>(),
            (1..=6).collect::<Vec<_>>()
        );
        assert_eq!(
            crate::hex(&sha2::Sha256::digest(serde_json::to_vec(&records).unwrap())),
            std::env::var("NAOME_JOB_REOPEN_DIGEST").unwrap()
        );
        return;
    }
    let directory = Directory::new();
    let settings = Settings::default();
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    for cursor in 0..6 {
        let (reply, _receipt) = oneshot::channel();
        owner
            .submit(Input::find(cursor), Binding::new([0; 32], [0; 32]), reply)
            .unwrap();
        let id = owner.journal.next_id - 1;
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
        owner.reserve(id, 1).unwrap();
        let record = owner.journal.records.get_mut(&id).unwrap();
        record.checkpoint = 1;
        record.state = State::Complete;
        record.result = Some(Output::Question(crate::mocks::create_question(cursor)));
        owner.save().unwrap();
    }
    let expected = owner.journal.records.values().cloned().collect::<Vec<_>>();
    assert_eq!(expected.len(), 6);
    let digest = crate::hex(&sha2::Sha256::digest(
        serde_json::to_vec(&expected).unwrap(),
    ));
    drop(owner);
    let reopen = |corrupt| {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_JOB_REOPEN_DIRECTORY", &directory.0)
            .env("NAOME_JOB_REOPEN_DIGEST", &digest);
        if corrupt {
            child.env("NAOME_JOB_REOPEN_CORRUPT", "1");
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    reopen(false);
    reopen(false); // Persisted retirement must not double-count on another restart.
    let (mut disk, mut journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut corrupt = expected[0].clone();
    corrupt.checkpoint = corrupt.reserved_units + 1;
    journal.records.insert(corrupt.id, corrupt);
    journal.retired_jobs -= 1;
    disk.save(&mut journal).unwrap();
    drop(disk);
    reopen(true);
}
