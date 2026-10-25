use super::*;
mod allowance;
mod checkpoint;
mod lifecycle;
mod resource_calibration;
use std::time::Duration;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-job-unit-{}-{}-{}",
            std::process::id(),
            wall_ms().unwrap(),
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

fn fixture(units: u32) -> (Directory, Owner) {
    let directory = Directory::new();
    let mut settings = Settings::default();
    settings.solving.limits.work_units = units;
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    (
        directory,
        Owner::new(disk, journal, settings, Arc::default()),
    )
}

#[cfg(feature = "developer-tools")]
#[test]
fn streamed_candidate_groups_keep_original_reservations_and_survive_restart() {
    use naome_proof::program::Command;
    let directory = Directory::new();
    let mut settings = Settings::default();
    settings.solving.mock.program_units = 3;
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let group = vec![Command::Reflexivity { variable: 0 }];
    assert!(
        owner
            .disk
            .save_program_group(&owner.journal, 1, 2, group.clone())
            .is_err()
    );
    owner
        .disk
        .save_program_group(&owner.journal, 1, 1, group.clone())
        .unwrap();
    assert!(
        owner
            .disk
            .save_program_group(
                &owner.journal,
                1,
                1,
                vec![Command::Equal { left: 0, right: 0 }]
            )
            .is_err()
    );
    owner.journal.records.get_mut(&1).unwrap().checkpoint = 1;
    owner.save().unwrap();
    let original = owner.journal.records[&1].clone();
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(disk.program_group(1, 1).unwrap(), group);
    assert_eq!(journal.records[&1].checkpoint, 1);
    assert_eq!(journal.records[&1].reserved_units, original.reserved_units);
    assert_eq!(journal.records[&1].expires_ms, original.expires_ms);
    assert_eq!(journal.records[&1].state, State::Suspended);
}

#[test]
fn candidate_stream_backpressure_retries_the_same_reserved_unit_after_disk_pressure() {
    use naome_proof::program::Command;
    let (_directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let reserved = owner.journal.records[&1].reserved_units;
    let (reply, mut receipt) = oneshot::channel();
    owner.programs.insert(
        1,
        PendingProgram {
            unit: 1,
            records: vec![Command::Reflexivity { variable: 0 }],
            reply,
        },
    );
    crate::resources::with_disk_available(0, || owner.persist_programs().unwrap());
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(owner.programs.len(), 1);
    assert_eq!(owner.journal.records[&1].reserved_units, reserved);
    assert_eq!(owner.journal.records[&1].checkpoint, 0);
    owner.persist_programs().unwrap();
    assert!(receipt.try_recv().unwrap().is_ok());
    assert_eq!(owner.journal.records[&1].reserved_units, reserved);
    assert_eq!(
        owner.disk.program_group(1, 1).unwrap(),
        vec![Command::Reflexivity { variable: 0 }]
    );
    assert!(owner.programs.is_empty());
}
fn submit(owner: &mut Owner, epoch: u8) -> oneshot::Receiver<Completion> {
    let (reply, receipt) = oneshot::channel();
    owner
        .submit(
            Input::Solve {
                question: crate::mocks::create_question(0),
            },
            Binding::new([0; 32], [0; 32]).with_selection([epoch; 32]),
            reply,
        )
        .unwrap();
    receipt
}

#[test]
fn retries_and_selection_changes_share_the_original_obligation_allowance() {
    let (directory, mut owner) = fixture(2);
    let _first = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.checkpoint = 1;
    record.state = State::Failed;
    record.acknowledged = true;
    owner.save().unwrap();
    let original = owner.journal.records[&1].clone();
    let _second = submit(&mut owner, 2);
    let retry = owner.journal.records.get_mut(&2).unwrap();
    assert_eq!(retry.created_ms, original.created_ms);
    assert_eq!(retry.expires_ms, original.expires_ms);
    assert_eq!(retry.reserved_units, 1);
    retry.state = State::Running;
    owner.reserve(2, 1).unwrap();
    owner.journal.records.get_mut(&2).unwrap().checkpoint = 1;
    assert_eq!(owner.reserve(2, 2).unwrap(), Reservation::Exhausted);
    assert_eq!(
        owner
            .journal
            .accounts
            .values()
            .next()
            .unwrap()
            .reserved_units,
        2
    );
    assert_eq!(owner.journal.records[&2].state, State::Expired);
    let settings = owner.settings;
    drop(owner);
    let (_, recovered) = Disk::open(&directory.0, settings, 999).unwrap();
    assert_eq!(
        recovered.accounts.values().next().unwrap().reserved_units,
        2
    );
    assert_eq!(recovered.next_id, 3);
}

#[test]
fn overlapping_epochs_cannot_reserve_more_than_the_shared_work_budget() {
    let (_directory, mut owner) = fixture(2);
    let _first = submit(&mut owner, 1);
    let _second = submit(&mut owner, 2);
    for id in [1, 2] {
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    }
    owner.reserve(1, 1).unwrap();
    owner.journal.records.get_mut(&1).unwrap().checkpoint = 1;
    owner.reserve(2, 1).unwrap();
    owner.journal.records.get_mut(&2).unwrap().checkpoint = 1;
    assert_eq!(owner.reserve(1, 2).unwrap(), Reservation::Exhausted);
    assert_eq!(
        owner
            .journal
            .accounts
            .values()
            .next()
            .unwrap()
            .reserved_units,
        2
    );
}

#[tokio::test]
async fn reservation_events_keep_exhaustion_local_but_stop_on_persistence_failure() {
    for corrupt_storage in [false, true] {
        let (directory, mut owner) = fixture(1);
        let _receipt = submit(&mut owner, 1);
        owner.journal.records.get_mut(&1).unwrap().state = State::Running;
        assert_eq!(owner.reserve(1, 1).unwrap(), Reservation::Granted);
        owner.journal.records.get_mut(&1).unwrap().checkpoint = 1;
        let settings = owner.settings;
        if corrupt_storage {
            let external =
                rusqlite::Connection::open(directory.0.join("research/jobs.sqlite3")).unwrap();
            external
                .execute("UPDATE checkpoint SET entry_count=entry_count+1", [])
                .unwrap();
        }
        let (commands, receive) = mpsc::channel(2);
        let (halt, stopped) = oneshot::channel();
        let (events, progress) = mpsc::channel(2);
        let sender = events.clone();
        let task = tokio::spawn(owner.run(receive, stopped, events, progress));
        let (reply, outcome) = oneshot::channel();
        sender
            .send(process::Event::Reserve {
                id: 1,
                next: 2,
                reply,
            })
            .await
            .unwrap();
        let rejection = tokio::time::timeout(Duration::from_secs(2), outcome)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        if corrupt_storage {
            assert!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert!(commands.is_closed());
        } else {
            // This diagnostic deliberately differs from the former control
            // prefix. The normal outcome still leaves the real driver running.
            assert_eq!(rejection, "research work budget exhausted");
            let (reply, page) = oneshot::channel();
            commands
                .send(Command::Recover {
                    after: 0,
                    before: 2,
                    reply,
                })
                .await
                .unwrap();
            let page = tokio::time::timeout(Duration::from_secs(2), page)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(page.records.len(), 1);
            assert_eq!(page.records[0].state, State::Expired);
            assert_eq!(page.records[0].reserved_units, 1);
            assert!(!task.is_finished());
            halt.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let (_, recovered) = Disk::open(&directory.0, settings, 0).unwrap();
            assert_eq!(recovered.records[&1].state, State::Expired);
        }
    }
}

#[test]
fn identical_bindings_share_one_job_but_changed_epochs_do_not() {
    let (_directory, mut owner) = fixture(4);
    let _first = submit(&mut owner, 1);
    let _duplicate = submit(&mut owner, 1);
    assert_eq!(owner.journal.records.len(), 1);
    assert_eq!(owner.waiters[&1].len(), 2);
    let _changed = submit(&mut owner, 2);
    assert_eq!(owner.journal.records.len(), 2);
    assert_eq!(owner.journal.accounts.len(), 1);
}

#[test]
fn uncertain_running_recovery_is_held_even_after_its_original_horizon() {
    let directory = Directory::new();
    let mut settings = Settings::default();
    settings.solving.recovery = RecoveryPolicy::HoldInFlight;
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    let _receipt = submit(&mut owner, 1);
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Running;
    record.spent_ms = record.settings.limits.horizon_ms;
    owner.journal.accounts.values_mut().next().unwrap().spent_ms = record.spent_ms;
    owner.journal.total_spent_ms = record.spent_ms;
    owner.save().unwrap();
    drop(owner);
    let (_, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(journal.records[&1].state, State::InDoubt);
    assert!(!journal.records[&1].acknowledged);
}

#[test]
fn cleanup_uncertainty_overrides_cancelled_and_expired_states() {
    for previous in [State::Cancelled, State::Expired] {
        let (_directory, mut owner) = fixture(4);
        let _receipt = submit(&mut owner, 1);
        owner.journal.records.get_mut(&1).unwrap().state = previous;
        let error = owner
            .complete(
                1,
                process::Outcome {
                    state: State::InDoubt,
                    result: Err("unconfirmed cleanup".into()),
                },
            )
            .unwrap_err();
        assert!(error.contains("reconciliation"));
        assert_eq!(owner.journal.records[&1].state, State::InDoubt);
        assert!(!owner.journal.records[&1].acknowledged);
        assert!(owner.journal.records[&1].result.is_none());
    }
}

#[test]
fn late_completion_never_delivers_a_candidate_as_complete() {
    let (_directory, mut owner) = fixture(4);
    let mut receipt = submit(&mut owner, 1);
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Running;
    record.spent_ms = record.settings.limits.horizon_ms;
    owner.journal.accounts.values_mut().next().unwrap().spent_ms = record.spent_ms;
    owner.journal.total_spent_ms = record.spent_ms;
    owner
        .complete(
            1,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::NoCandidate),
            },
        )
        .unwrap();
    let completion = receipt.try_recv().unwrap();
    assert_eq!(completion.state, State::Expired);
    assert!(completion.result.is_err());
}

#[test]
fn abandoned_oldest_completion_survives_newer_terminal_history() {
    for state in [State::Cancelled, State::Expired] {
        let (directory, mut owner) = fixture(4);
        let receipt = submit(&mut owner, 1);
        owner.journal.records.get_mut(&1).unwrap().state = State::Running;
        owner.reserve(1, 1).unwrap();
        owner.journal.records.get_mut(&1).unwrap().state = state;
        let (cancel, _) = oneshot::channel();
        owner.running.insert(
            1,
            Running {
                cancel: Some(cancel),
                clock: Instant::now(),
            },
        );
        drop(receipt);
        // A slow cancelled provider may outlive many short finding jobs.
        for cursor in 0..=crate::resources::limits().terminal_job_page as u64 {
            let (reply, mut receipt) = oneshot::channel();
            owner
                .submit(
                    Input::Find { cursor },
                    Binding::new([0; 32], [0; 32]),
                    reply,
                )
                .unwrap();
            let id = owner.journal.next_id - 1;
            owner.journal.records.get_mut(&id).unwrap().state = State::Running;
            owner.reserve(id, 1).unwrap();
            owner.journal.records.get_mut(&id).unwrap().checkpoint = 1;
            owner
                .complete(
                    id,
                    process::Outcome {
                        state: State::Complete,
                        result: Ok(Output::Question(crate::mocks::create_question(cursor))),
                    },
                )
                .unwrap();
            assert_eq!(receipt.try_recv().unwrap().id, id);
            owner.journal.records.get_mut(&id).unwrap().acknowledged = true;
            owner.save().unwrap();
        }
        assert_eq!(
            owner.journal.records.len(),
            crate::resources::limits().terminal_job_page + 1
        );
        owner
            .complete(
                1,
                process::Outcome {
                    state: State::Cancelled,
                    result: Err("cancelled provider drained".into()),
                },
            )
            .unwrap();
        assert!(owner.running.is_empty());
        assert!(!owner.waiters.contains_key(&1));
        let saved = owner.disk.saved().unwrap();
        assert_eq!(
            saved["payload"]["records"]["1"]["state"],
            serde_json::to_value(state).unwrap()
        );
        assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], true);
        owner.save().unwrap();
        assert_eq!(
            owner.journal.records.len(),
            crate::resources::limits().terminal_job_page
        );
        assert!(!owner.journal.records.contains_key(&1));
        assert!(
            owner.journal.accounts.is_empty(),
            "completed budgets leave active residency"
        );
        let key = Input::Solve {
            question: crate::mocks::create_question(0),
        }
        .account_key();
        let account = owner.disk.account(&key).unwrap().unwrap();
        assert_eq!(account.reserved_units, 1);
        assert!(account.spent_ms > 0);
        let settings = owner.settings;
        drop(owner);
        let (disk, recovered) = Disk::open(&directory.0, settings, 0).unwrap();
        assert_eq!(
            recovered.records.len(),
            crate::resources::limits().terminal_job_page
        );
        assert!(recovered.accounts.is_empty());
        assert_eq!(disk.account(&key).unwrap().unwrap().reserved_units, 1);
    }
}

#[tokio::test]
async fn failed_clock_accounting_still_drains_all_owned_tasks() {
    let (_directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    let (cancel, _) = oneshot::channel();
    owner.running.insert(
        1,
        Running {
            cancel: Some(cancel),
            clock: Instant::now(),
        },
    );
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let copied = observed.clone();
    owner.tasks.push(Box::pin(async move {
        copied.store(true, Ordering::SeqCst);
        (
            1,
            process::Outcome {
                state: State::InDoubt,
                result: Err("uncertain".into()),
            },
        )
    }));
    owner.journal.observed_ms = wall_ms().unwrap() + 100_000;
    assert!(owner.stop_all().await.is_err());
    assert!(observed.load(Ordering::SeqCst));
    assert!(owner.tasks.is_empty() && owner.running.is_empty());
    assert_eq!(owner.journal.records[&1].state, State::InDoubt);
    let saved = owner.disk.saved().unwrap();
    assert_eq!(saved["payload"]["records"]["1"]["state"], "in_doubt");
    assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], false);
}

#[test]
fn delivered_cleanup_uncertainty_is_retained_before_clock_failure() {
    let (_directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.journal.observed_ms = wall_ms().unwrap() + 100_000;
    let error = owner
        .complete(
            1,
            process::Outcome {
                state: State::InDoubt,
                result: Err("unconfirmed provider group".into()),
            },
        )
        .unwrap_err();
    assert!(error.contains("reconciliation") && error.contains("clock rollback"));
    assert_eq!(owner.journal.records[&1].state, State::InDoubt);
    let saved = owner.disk.saved().unwrap();
    assert_eq!(saved["payload"]["records"]["1"]["state"], "in_doubt");
    assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], false);
}

#[test]
fn established_state_and_kernel_slot_identity_cannot_be_silently_replaced() {
    for missing in ["jobs.sqlite3", "slot-0.lock", "research"] {
        let (directory, owner) = fixture(4);
        let settings = owner.settings;
        drop(owner);
        let path = if missing == "research" {
            directory.0.join(missing)
        } else {
            directory.0.join("research").join(missing)
        };
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
        assert!(
            Disk::open(&directory.0, settings, 0).is_err(),
            "missing {missing} granted fresh state"
        );
    }
    let (directory, owner) = fixture(4);
    let settings = owner.settings;
    drop(owner);
    let path = directory.0.join("research/slot-0.lock");
    let replacement = directory.0.join("replacement");
    fs::write(&replacement, []).unwrap();
    fs::rename(replacement, path).unwrap();
    assert!(
        Disk::open(&directory.0, settings, 0)
            .err()
            .unwrap()
            .contains("slot identity")
    );
}

#[test]
fn corrupt_semantic_checkpoint_and_hardlink_are_rejected() {
    let (directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().checkpoint = 1;
    owner.disk.save(&mut owner.journal).unwrap();
    let settings = owner.settings;
    drop(owner);
    assert!(Disk::open(&directory.0, settings, 0).is_err());
    let (directory, owner) = fixture(4);
    let settings = owner.settings;
    drop(owner);
    fs::hard_link(
        directory.0.join("research/jobs.sqlite3"),
        directory.0.join("alias"),
    )
    .unwrap();
    assert!(Disk::open(&directory.0, settings, 0).is_err());
}

#[test]
fn bounded_kernel_slots_are_independent_and_never_reused_while_held() {
    let (_directory, owner) = fixture(4);
    let first = owner.disk.slot(0).unwrap().unwrap();
    assert!(owner.disk.slot(0).unwrap().is_none());
    let second = owner.disk.slot(1).unwrap().unwrap();
    let third = owner.disk.slot(1).unwrap().unwrap();
    assert!(owner.disk.slot(1).unwrap().is_none());
    drop(first);
    assert!(owner.disk.slot(0).unwrap().is_some());
    drop((second, third));
}

#[test]
fn dropping_service_joins_the_owner_even_without_explicit_shutdown() {
    let directory = Directory::new();
    let (service, client, _) =
        Service::open(&directory.0, Settings::default(), 0, Arc::default()).unwrap();
    drop(service);
    assert!(client.sender.is_closed());
}

#[tokio::test]
async fn clean_shutdown_charges_drain_time_and_rejects_late_success() {
    let (_directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Running;
    record.spent_ms = record.settings.limits.horizon_ms - 1;
    owner.journal.accounts.values_mut().next().unwrap().spent_ms = record.spent_ms;
    owner.journal.total_spent_ms = record.spent_ms;
    let (cancel, _) = oneshot::channel();
    owner.running.insert(
        1,
        Running {
            cancel: Some(cancel),
            clock: Instant::now(),
        },
    );
    owner.tasks.push(Box::pin(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        (
            1,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::NoCandidate),
            },
        )
    }));
    owner.stop_all().await.unwrap();
    assert_eq!(owner.journal.records[&1].state, State::Expired);
    assert!(owner.journal.records[&1].result.is_none());
    assert!(owner.journal.records[&1].spent_ms >= owner.settings.solving.limits.horizon_ms);
}

#[test]
fn result_reservations_apply_backpressure_before_work_and_leave_other_roles_available() {
    let (_directory, mut owner) = fixture(4);
    let mut receipts = Vec::new();
    let attempts = crate::resources::limits().active_job_bytes
        / output_reservation(&Input::Solve {
            question: crate::mocks::create_question(0),
        })
        + 1;
    for epoch in 1..=attempts {
        receipts.push(submit(&mut owner, u8::try_from(epoch).unwrap()));
    }
    assert!(
        owner.journal.records.len() < attempts,
        "large future results require capacity before execution"
    );
    assert!(receipts.iter_mut().any(|reply| {
        reply.try_recv().is_ok_and(|c| {
            c.id == 0
                && c.result
                    .is_err_and(|error| error.contains("result byte reservation"))
        })
    }));
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(
            Input::Find { cursor: 0 },
            Binding::new([0; 32], [0; 32]),
            reply,
        )
        .unwrap();
    assert!(
        owner
            .journal
            .records
            .values()
            .any(|r| matches!(r.input, Input::Find { .. }))
    );
    assert!(owner.compact_bytes(0).unwrap());
}

#[test]
fn cleanup_error_is_preserved_alongside_an_earlier_driver_failure() {
    let error = combine_outcomes(
        Err("driver clock failed".into()),
        Err("provider termination unconfirmed".into()),
    )
    .unwrap_err();
    assert!(error.contains("driver clock failed") && error.contains("termination unconfirmed"));
}

// Isolated processes make the RSS comparison independent of parallel unit tests.
// Each child reopens the same durable history; no provider or proof authority is
// simulated by this accounting test. Process supervision has separate tests.
#[cfg(feature = "system-tests")]
#[test]
fn thousands_of_obligations_keep_only_retained_accounts_across_process_restarts() {
    const TOTAL: usize = 4096;
    const INITIAL: usize = 256;
    const BATCH: usize = 1024;
    const TEST: &str = "jobs::service::tests::thousands_of_obligations_keep_only_retained_accounts_across_process_restarts";
    fn input(index: usize) -> Input {
        Input::Solve {
            question: crate::checkpoint::tests::question_source(index),
        }
    }
    fn settle(owner: &mut Owner, input: Input, retry: bool) {
        let before = owner.disk.account(&input.account_key()).unwrap();
        let (reply, mut receipt) = oneshot::channel();
        owner
            .submit(
                input.clone(),
                Binding::new([0; 32], [0; 32]).with_selection([u8::from(retry); 32]),
                reply,
            )
            .unwrap();
        let id = owner.journal.next_id - 1;
        if let Some(original) = &before {
            let record = &owner.journal.records[&id];
            assert_eq!(record.created_ms, original.created_ms);
            assert_eq!(record.expires_ms, original.expires_ms);
            assert_eq!(record.spent_ms, original.spent_ms);
            assert_eq!(record.reserved_units, original.reserved_units);
        }
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
        owner
            .clocks
            .insert(id, Instant::now() - Duration::from_millis(2));
        owner.reserve(id, 1).unwrap();
        assert!(owner.disk.last_write_stats().0 <= 4);
        assert!(owner.disk.last_write_stats().1 < 16 * 1024);
        owner.journal.records.get_mut(&id).unwrap().checkpoint = 1;
        owner
            .complete(
                id,
                process::Outcome {
                    state: State::Complete,
                    result: Ok(Output::NoCandidate),
                },
            )
            .unwrap();
        assert_eq!(receipt.try_recv().unwrap().state, State::Complete);
        owner.journal.records.get_mut(&id).unwrap().acknowledged = true;
        owner.save().unwrap();
        let retained = owner
            .journal
            .records
            .values()
            .filter(|r| !matches!(r.input, Input::Find { .. }))
            .map(|r| r.input.account_key())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            owner
                .journal
                .accounts
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            retained
        );
        assert!(owner.journal.records.len() <= crate::resources::limits().terminal_job_page);
        assert!(owner.journal.accounts.len() <= owner.journal.records.len());
        let account = owner.disk.account(&input.account_key()).unwrap().unwrap();
        assert_eq!(account.reserved_units, if retry { 2 } else { 1 });
        assert!(account.spent_ms >= before.map_or(2, |a| a.spent_ms + 2));
    }
    if let Some(directory) = std::env::var_os("NAOME_BUDGET_TEST_DIRECTORY") {
        let directory = PathBuf::from(directory);
        let phase: usize = std::env::var("NAOME_BUDGET_TEST_PHASE")
            .unwrap()
            .parse()
            .unwrap();
        let mut settings = Settings::default();
        settings.solving.limits.work_units = 2;
        let (disk, state) = Disk::open(&directory, settings, 0).unwrap();
        let mut owner = Owner::new(disk, state, settings, Arc::default());
        assert!(owner.journal.accounts.len() <= owner.journal.records.len());
        // Archived history is exhausted, and rejected lookups never become resident.
        let active = owner.journal.accounts.len();
        for index in 0..INITIAL {
            let (reply, mut receipt) = oneshot::channel();
            owner
                .submit(input(index), Binding::new([1; 32], [2; 32]), reply)
                .unwrap();
            assert_eq!(receipt.try_recv().unwrap().state, State::Expired);
            assert_eq!(owner.journal.accounts.len(), active);
            assert_eq!(
                owner
                    .disk
                    .account(&input(index).account_key())
                    .unwrap()
                    .unwrap()
                    .reserved_units,
                2
            );
        }
        // Re-submit old native rows after a real process restart. Their original
        // time horizon, spent time and reserved units all survive eviction.
        if phase > 0 {
            let index = if phase == 1 {
                INITIAL
            } else {
                (phase - 1) * BATCH
            };
            settle(&mut owner, input(index), true);
            for old in [INITIAL, BATCH, 2 * BATCH].into_iter().take(phase) {
                let (reply, mut receipt) = oneshot::channel();
                owner
                    .submit(input(old), Binding::new([3; 32], [4; 32]), reply)
                    .unwrap();
                assert_eq!(receipt.try_recv().unwrap().state, State::Expired);
                assert_eq!(
                    owner
                        .disk
                        .account(&input(old).account_key())
                        .unwrap()
                        .unwrap()
                        .reserved_units,
                    2
                );
            }
        }
        let started = Instant::now();
        let mut max_bytes = 0;
        for index in (phase * BATCH).max(INITIAL)..(phase + 1) * BATCH {
            settle(&mut owner, input(index), false);
            max_bytes = max_bytes.max(owner.journal.encoded_active_len().unwrap());
        }
        assert_eq!(owner.disk.account_count(), (phase + 1) * BATCH);
        assert!(
            max_bytes < 256 * 1024,
            "active accounting bytes: {max_bytes}"
        );
        let peak = crate::checkpoint::tests::image_peak_rss_bytes();
        assert!(peak < 128 * 1024 * 1024, "isolated peak RSS: {peak}");
        println!(
            "BUDGET_HISTORY_METRICS {}",
            serde_json::json!({"phase":phase,"history":owner.disk.account_count(),"active_accounts":owner.journal.accounts.len(),"retained_jobs":owner.journal.records.len(),"max_active_bytes":max_bytes,"peak_rss_bytes":peak,"work_seconds":started.elapsed().as_secs_f64()})
        );
        return;
    }
    let (directory, mut owner) = fixture(2);
    let settings = owner.settings;
    for index in 0..INITIAL {
        owner.journal.accounts.insert(
            input(index).account_key(),
            Account {
                settings: settings.solving,
                created_ms: owner.journal.observed_ms,
                expires_ms: owner.journal.observed_ms + settings.solving.limits.horizon_ms,
                spent_ms: 2,
                reserved_units: 2,
                held: None,
            },
        );
    }
    owner.journal.retired_jobs = INITIAL as u64;
    owner.journal.next_id = owner.journal.retired_jobs + 1;
    owner.journal.total_spent_ms = (2 * INITIAL) as u64;
    owner.journal.total_reserved_units = (2 * INITIAL) as u64;
    owner.save().unwrap();
    drop(owner);
    let mut first_peak = None;
    for phase in 0..TOTAL / BATCH {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_BUDGET_TEST_DIRECTORY", &directory.0)
            .env("NAOME_BUDGET_TEST_PHASE", phase.to_string())
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "phase {phase}: {}\n{stdout}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix("BUDGET_HISTORY_METRICS "))
            .unwrap();
        println!("BUDGET_HISTORY_METRICS {line}");
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let peak = value["peak_rss_bytes"].as_u64().unwrap();
        let first = *first_peak.get_or_insert(peak);
        assert!(
            peak <= first + 16 * 1024 * 1024,
            "RSS grows with archived accounts: {line}"
        );
    }
    let (disk, state) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(disk.account_count(), TOTAL);
    assert_eq!(state.accounts.len(), state.records.len());
    drop(disk);
    fs::remove_file(directory.0.join("research/jobs.sqlite3")).unwrap();
    assert!(
        Disk::open(&directory.0, settings, 0).is_err(),
        "initialization receipt forbids resetting old allowances"
    );
}

#[test]
fn archived_unacknowledged_results_recover_in_fifo_pages_without_blocking_new_work() {
    fn submit_find(owner: &mut Owner, cursor: u64) -> u64 {
        let (reply, _receive) = oneshot::channel();
        // Retain the request receiver until submission has durably accepted it.
        owner
            .submit(
                Input::Find { cursor },
                Binding::new([0; 32], [0; 32]),
                reply,
            )
            .unwrap();
        owner.journal.next_id - 1
    }
    let (directory, mut owner) = fixture(1);
    let total = crate::resources::limits().resident_jobs * 2;
    for index in 0..total {
        let id = submit_find(&mut owner, index as u64);
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
        owner.reserve(id, 1).unwrap();
        let record = owner.journal.records.get_mut(&id).unwrap();
        record.checkpoint = 1;
        record.state = State::Complete;
        record.result = Some(Output::Question(crate::mocks::create_question(
            index as u64,
        )));
        owner.save().unwrap();
        owner.deliver(id);
    }
    owner.save().unwrap();
    assert!(owner.journal.records.len() < total);
    let end = owner.journal.next_id;
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let skip = journal
        .records
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut after = 0;
    let mut recovered = Vec::new();
    loop {
        let page = disk.recovery_page(after, end, &skip).unwrap();
        assert!(page.records.len() <= crate::resources::limits().terminal_job_page);
        recovered.extend(page.records.into_iter().map(|r| r.id));
        match page.next {
            Some(next) => {
                assert!(next > after);
                after = next;
            }
            None => break,
        }
    }
    let expected = (1..end).filter(|id| !skip.contains(id)).collect::<Vec<_>>();
    assert_eq!(recovered, expected);
    assert_eq!(
        disk.request(
            &Input::Find { cursor: 0 },
            &Binding::new([0; 32], [0; 32]),
            settings.finding
        )
        .unwrap()
        .unwrap()
        .id,
        1
    );
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    let id = submit_find(&mut owner, total as u64);
    assert!(id >= end);
}

#[test]
fn narrower_new_job_defaults_preserve_original_budget_accounts_and_retry_allowances() {
    let (directory, mut owner) = fixture(3);
    let _request = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.checkpoint = 1;
    record.state = State::Failed;
    record.acknowledged = true;
    owner.save().unwrap();
    let original = owner.journal.records[&1].clone();
    let mut settings = owner.settings;
    settings.solving.limits.work_units = 1;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    let _retry = submit(&mut owner, 2);
    let retry = &owner.journal.records[&2];
    assert_eq!(retry.settings, original.settings);
    assert_eq!(retry.created_ms, original.created_ms);
    assert_eq!(retry.expires_ms, original.expires_ms);
    assert_eq!(retry.reserved_units, 1);
    assert_eq!(owner.journal.total_reserved_units, 1);
}
