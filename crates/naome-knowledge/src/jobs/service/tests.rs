use super::*;
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
    (directory, Owner::new(disk, journal, settings))
}
fn generation_request(input: &Input, binding: &Binding) -> crate::generation::Request {
    crate::generation::Request::build(
        input,
        binding,
        &crate::Graph::default(),
        crate::generation::OwnerContext::Unavailable {
            reason: "service fixture has no owner control".into(),
        },
    )
    .unwrap()
}
fn binding(epoch: u8) -> Binding {
    Binding::new(
        [0; 32],
        naome_checker::question::PrefilterPolicy::default().identity(),
    )
    .with_selection([epoch; 32])
}
fn submit(owner: &mut Owner, epoch: u8) -> oneshot::Receiver<Completion> {
    let (reply, receipt) = oneshot::channel();
    let input = Input::Solve {
        question: crate::mocks::create_question(0),
    };
    let binding = binding(epoch);
    let request = generation_request(&input, &binding);
    owner.submit(input, binding, Some(request), reply).unwrap();
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
    assert!(owner.reserve(2, 2).unwrap_err().contains("allowance"));
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
    assert!(owner.reserve(1, 2).is_err());
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
    let mut owner = Owner::new(disk, journal, settings);
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
        for cursor in 0..=TERMINAL_HISTORY as u64 {
            let (reply, mut receipt) = oneshot::channel();
            owner
                .submit(
                    Input::Find { cursor },
                    binding(0),
                    Some(generation_request(&Input::Find { cursor }, &binding(0))),
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
        assert_eq!(owner.journal.records.len(), TERMINAL_HISTORY + 1);
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
        let bytes = fs::read(directory.0.join("research/jobs.json")).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            saved["payload"]["records"]["1"]["state"],
            serde_json::to_value(state).unwrap()
        );
        assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], true);
        owner.save().unwrap();
        assert_eq!(owner.journal.records.len(), TERMINAL_HISTORY);
        assert!(!owner.journal.records.contains_key(&1));
        let account = owner.journal.accounts.values().next().unwrap();
        assert_eq!(account.reserved_units, 1);
        assert!(account.spent_ms > 0);
        let settings = owner.settings;
        drop(owner);
        let (_, recovered) = Disk::open(&directory.0, settings, 0).unwrap();
        assert_eq!(recovered.records.len(), TERMINAL_HISTORY);
        assert_eq!(
            recovered.accounts.values().next().unwrap().reserved_units,
            1
        );
    }
}

#[tokio::test]
async fn failed_clock_accounting_still_drains_all_owned_tasks() {
    let (directory, mut owner) = fixture(4);
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
    let bytes = fs::read(directory.0.join("research/jobs.json")).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["payload"]["records"]["1"]["state"], "in_doubt");
    assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], false);
}

#[test]
fn delivered_cleanup_uncertainty_is_retained_before_clock_failure() {
    let (directory, mut owner) = fixture(4);
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
    let bytes = fs::read(directory.0.join("research/jobs.json")).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["payload"]["records"]["1"]["state"], "in_doubt");
    assert_eq!(saved["payload"]["records"]["1"]["acknowledged"], false);
}

#[test]
fn established_state_and_kernel_slot_identity_cannot_be_silently_replaced() {
    for missing in ["jobs.json", "slot-0.lock", "research"] {
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
    owner.disk.save(&owner.journal).unwrap();
    let settings = owner.settings;
    drop(owner);
    assert!(Disk::open(&directory.0, settings, 0).is_err());
    let (directory, owner) = fixture(4);
    let settings = owner.settings;
    drop(owner);
    fs::hard_link(
        directory.0.join("research/jobs.json"),
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
    let (service, client, _) = Service::open(&directory.0, Settings::default(), 0).unwrap();
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
    for epoch in 1..=8 {
        receipts.push(submit(&mut owner, epoch));
    }
    assert!(
        owner.journal.records.len() < 8,
        "large future results require capacity before execution"
    );
    assert!(receipts.iter_mut().any(|reply| {
        reply
            .try_recv()
            .is_ok_and(|c| c.id == 0 && c.result.is_err())
    }));
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(
            Input::Find { cursor: 0 },
            binding(0),
            Some(generation_request(&Input::Find { cursor: 0 }, &binding(0))),
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

#[test]
fn legacy_generation_migration_retires_candidates_and_preserves_original_allowances() {
    for state in [State::Running, State::Complete, State::InDoubt] {
        let (directory, mut owner) = fixture(4);
        let _receipt = submit(&mut owner, 1);
        owner.journal.records.get_mut(&1).unwrap().state = State::Running;
        owner.reserve(1, 1).unwrap();
        let record = owner.journal.records.get_mut(&1).unwrap();
        record.checkpoint = 1;
        record.state = state;
        if state == State::Complete {
            record.result = Some(Output::NoCandidate);
        }
        record.generation = None;
        let original = record.clone();
        let original_account = owner.journal.accounts.values().next().unwrap().clone();
        owner.disk.save(&owner.journal).unwrap();
        let settings = owner.settings;
        drop(owner);
        let (_, journal) = Disk::open(&directory.0, settings, 777).unwrap();
        let restored = &journal.records[&1];
        assert_eq!(
            restored.state,
            if state == State::InDoubt {
                State::InDoubt
            } else {
                State::Failed
            }
        );
        assert!(restored.result.is_none() && restored.generation.is_none());
        if state != State::InDoubt {
            assert!(
                restored
                    .failure
                    .as_ref()
                    .unwrap()
                    .contains("legacy generation context unavailable")
            );
        }
        assert_eq!(restored.created_ms, original.created_ms);
        assert_eq!(restored.expires_ms, original.expires_ms);
        assert_eq!(restored.reserved_units, original.reserved_units);
        assert_eq!(restored.checkpoint, original.checkpoint);
        assert!(restored.spent_ms >= original.spent_ms);
        let account = journal.accounts.values().next().unwrap();
        assert_eq!(account.created_ms, original_account.created_ms);
        assert_eq!(account.expires_ms, original_account.expires_ms);
        assert_eq!(account.reserved_units, original_account.reserved_units);
        assert_eq!(journal.next_id, 2);
        assert_eq!(journal.next_cursor, 0);
    }
}

#[test]
fn legacy_finding_migration_does_not_reissue_the_consumed_cursor() {
    let (directory, mut owner) = fixture(4);
    let (reply, _receipt) = oneshot::channel();
    let input = Input::Find { cursor: 41 };
    let binding = binding(0);
    let request = generation_request(&input, &binding);
    owner.submit(input, binding, Some(request), reply).unwrap();
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.generation = None;
    owner.disk.save(&owner.journal).unwrap();
    let settings = owner.settings;
    drop(owner);
    let (_, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(journal.next_cursor, 42);
    assert_eq!(journal.records[&1].state, State::Failed);
    assert_eq!(journal.next_id, 2);
}

#[test]
fn changed_request_context_does_not_alias_or_renew_the_original_obligation() {
    let (_directory, mut owner) = fixture(4);
    let _first = submit(&mut owner, 1);
    let input = Input::Solve {
        question: crate::mocks::create_question(0),
    };
    let binding = binding(1);
    let request = crate::generation::Request::build(
        &input,
        &binding,
        &crate::Graph::default(),
        crate::generation::OwnerContext::Unavailable {
            reason: "different explicit fixture context".into(),
        },
    )
    .unwrap();
    let (reply, _receipt) = oneshot::channel();
    owner.submit(input, binding, Some(request), reply).unwrap();
    assert_eq!(owner.journal.records.len(), 2);
    assert_eq!(owner.journal.accounts.len(), 1);
    assert_eq!(
        owner.journal.records[&1].created_ms,
        owner.journal.records[&2].created_ms
    );
    assert_eq!(
        owner.journal.records[&1].expires_ms,
        owner.journal.records[&2].expires_ms
    );
}

#[test]
fn obsolete_complete_requests_retire_without_renewing_time_work_or_finding_cursors() {
    for finding in [false, true] {
        for state in [State::Running, State::Complete, State::InDoubt] {
            let (directory, mut owner) = fixture(4);
            let input = if finding {
                Input::Find { cursor: 41 }
            } else {
                Input::Solve {
                    question: crate::mocks::create_question(0),
                }
            };
            let binding = binding(0);
            let request = generation_request(&input, &binding);
            let (reply, _receipt) = oneshot::channel();
            owner.submit(input, binding, Some(request), reply).unwrap();
            owner.journal.records.get_mut(&1).unwrap().state = State::Running;
            owner.reserve(1, 1).unwrap();
            let record = owner.journal.records.get_mut(&1).unwrap();
            record.checkpoint = 1;
            record.state = state;
            if state == State::Complete {
                record.result = Some(if finding {
                    Output::Question(crate::mocks::create_question(0))
                } else {
                    Output::NoCandidate
                });
            }
            let obsolete = record.generation.clone().unwrap().obsolete_for_test();
            assert!(!obsolete.current_instructions());
            obsolete
                .validate_retained(&record.input, &record.binding)
                .unwrap();
            assert!(obsolete.validate(&record.input, &record.binding).is_err());
            record.generation = Some(obsolete);
            let original = record.clone();
            let original_cursor = owner.journal.next_cursor;
            let original_total_units = owner.journal.total_reserved_units;
            owner.save().unwrap();
            let settings = owner.settings;
            drop(owner);
            let (disk, journal) = Disk::open(&directory.0, settings, 999).unwrap();
            let restored = &journal.records[&1];
            assert_eq!(
                restored.state,
                if state == State::InDoubt {
                    State::InDoubt
                } else {
                    State::Failed
                }
            );
            assert_eq!(restored.generation, original.generation);
            assert!(restored.result.is_none());
            if state != State::InDoubt {
                assert!(
                    restored
                        .failure
                        .as_ref()
                        .unwrap()
                        .contains("instructions changed")
                );
            }
            assert_eq!(restored.created_ms, original.created_ms);
            assert_eq!(restored.expires_ms, original.expires_ms);
            assert_eq!(restored.reserved_units, original.reserved_units);
            assert_eq!(restored.checkpoint, original.checkpoint);
            assert!(restored.spent_ms >= original.spent_ms);
            assert_eq!(journal.next_cursor, original_cursor);
            assert_eq!(journal.next_id, 2);
            assert_eq!(journal.total_reserved_units, original_total_units);
            if !finding {
                let account = journal.accounts.values().next().unwrap();
                assert_eq!(account.created_ms, original.created_ms);
                assert_eq!(account.expires_ms, original.expires_ms);
                assert_eq!(account.reserved_units, original.reserved_units);
            }
            let mut recovered = Owner::new(disk, journal, settings);
            recovered.save().unwrap();
            let record = recovered.journal.records[&1].clone();
            let (reply, _receipt) = oneshot::channel();
            assert!(
                recovered
                    .submit(record.input, record.binding, record.generation, reply)
                    .is_err()
            );
        }
    }
}

#[test]
fn corrupt_request_identity_is_rejected_instead_of_classified_as_an_old_prompt() {
    let (directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    let record = owner.journal.records.get_mut(&1).unwrap();
    let mut value = serde_json::to_value(record.generation.as_ref().unwrap()).unwrap();
    value["system"] =
        serde_json::json!("an altered instruction without its original request identity");
    record.generation = Some(serde_json::from_value(value).unwrap());
    owner.disk.save(&owner.journal).unwrap();
    let settings = owner.settings;
    drop(owner);
    assert!(Disk::open(&directory.0, settings, 0).is_err());
}

#[test]
fn hot_save_preserves_exact_canonical_envelope_and_full_completed_request_bytes() {
    let (directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    owner.save().unwrap();
    #[derive(Serialize)]
    struct PreviousEnvelope<'a> {
        version: u8,
        payload: &'a Journal,
        sha256: String,
    }
    let expected = serde_json::to_vec(&PreviousEnvelope {
        version: 1,
        payload: &owner.journal,
        sha256: identity(&owner.journal),
    })
    .unwrap();
    let path = directory.0.join("research/jobs.json");
    assert_eq!(fs::read(&path).unwrap(), expected);
    let restored: Journal = journal::read(&path, MAX_JOURNAL_BYTES).unwrap().unwrap();
    restored.validate(owner.settings).unwrap();
    let request = restored.records[&1].generation.as_ref().unwrap();
    assert_eq!(
        request,
        owner.journal.records[&1].generation.as_ref().unwrap()
    );
    request
        .recheck_retained(&restored.records[&1].input, &restored.records[&1].binding)
        .unwrap();
}

#[test]
fn checkpoint_write_encodes_payload_once_preserving_escaping_and_exact_limit() {
    use std::cell::Cell;
    struct Counted<'a> {
        value: &'a serde_json::Value,
        calls: &'a Cell<usize>,
    }
    impl Serialize for Counted<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.calls.set(self.calls.get() + 1);
            self.value.serialize(serializer)
        }
    }
    let directory = Directory::new();
    let path = directory.0.join("checkpoint.json");
    let value = serde_json::json!({"text":"quotes \" slash \\ newline \n null \u{0000} lambda λ", "array":[true,false,null,42]});
    #[derive(Serialize)]
    struct PreviousEnvelope<'a> {
        version: u8,
        payload: &'a serde_json::Value,
        sha256: String,
    }
    let expected = serde_json::to_vec(&PreviousEnvelope {
        version: 1,
        payload: &value,
        sha256: identity(&value),
    })
    .unwrap();
    let calls = Cell::new(0);
    journal::write(
        &path,
        &Counted {
            value: &value,
            calls: &calls,
        },
        expected.len(),
    )
    .unwrap();
    assert_eq!(
        calls.get(),
        1,
        "immutable checkpoint payload must be encoded only once"
    );
    assert_eq!(fs::read(&path).unwrap(), expected);
    let restored: serde_json::Value = journal::read(&path, expected.len()).unwrap().unwrap();
    assert_eq!(restored, value);
    assert!(journal::write(&path, &value, expected.len() - 1).is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        expected,
        "oversized write must preserve the prior complete checkpoint"
    );
}

#[test]
fn hot_lifecycle_checks_remain_strict_after_immutable_request_qualification() {
    let (_directory, mut owner) = fixture(4);
    let _receipt = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().reserved_units = 5;
    assert!(owner.save().unwrap_err().contains("budget differs"));
}
