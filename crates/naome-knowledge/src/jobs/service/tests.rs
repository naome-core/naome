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

fn model_input(revision: u64, session_epoch: u8) -> Input {
    let text = "Set theory";
    let owner = crate::interest::Owner {
        version: 1,
        revision,
        digest: crate::hex(&[revision as u8; 32]),
        interest: text.into(),
        text_sha256: crate::hex(&sha2::Sha256::digest(text.as_bytes())),
    };
    let ready = serde_json::json!({"kind":"ready","schema":1,"model_revision":"1cfa9a7208912126459214e8b04321603b3df60c","manifest_hash":"b7d4ab43f8cfc348ff7195e64a5e23fb65ceb0eec55a1761030ac1e9478b018b","prompt_version":"naome:owner-interest:prompt:v1","prompt_hash":"69afc1b7c184eeb83ed7faa55d7fdcfbc67949f0ed10b0c138eaaf0ff5403f98","template_hash":"a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8","device":"mps","load_strategy":"cpu-staged-mps-v1","parameter_bytes":8044936192u64,"labels":{"true":1866,"false":3849},"inventory_hash":crate::hex(&[4;32]),"model_instance":1});
    Input::Interest {
        question: crate::mocks::create_question(0),
        purpose: Purpose::Admission,
        root: None,
        owner: Some(owner),
        model: Some(crate::interest::Session {
            client: crate::hex(&[session_epoch; 32]),
            generation: crate::hex(&[session_epoch; 32]),
            ready,
        }),
    }
}
#[test]
fn owner_and_model_sessions_preserve_legacy_interest_bytes_and_budget_key() {
    let legacy = Input::Interest {
        question: crate::mocks::create_question(0),
        purpose: Purpose::Admission,
        root: None,
        owner: None,
        model: None,
    };
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let expected = "{\"role\":\"interest\",\"question\":\"goal = all(x,eq(x,x))\",\"purpose\":\"admission\",\"root\":null}";
    assert_eq!(bytes, expected.as_bytes());
    let key = identity(&serde_json::from_str::<serde_json::Value>(expected).unwrap());
    // Value's sorted keys are not the historical struct's ordered bytes.
    assert_ne!(legacy.account_key(), key);
    assert_eq!(
        legacy.account_key(),
        "034ba485577441af03ea772a90f67c68efd424a6aca998b2be630aca366fe041"
    );
    for (revision, epoch) in [(1, 1), (2, 1), (1, 2)] {
        let model = model_input(revision, epoch);
        model.validate().unwrap();
        assert_eq!(model.account_key(), legacy.account_key());
        assert_ne!(serde_json::to_vec(&model).unwrap(), bytes);
    }
}
#[test]
fn uncertain_model_holds_original_obligation_after_profile_change_and_reopen() {
    let (directory, mut owner) = fixture(3);
    let binding = Binding::new([0; 32], [0; 32]);
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(model_input(1, 1), binding.clone(), reply)
        .unwrap();
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::InDoubt;
    record.model_allowance_ms = Some(20_000);
    record.model_deadline_ns = Some(monotonic_ns().unwrap() + 20_000_000_000);
    record.spent_ms = 20_000;
    record.reserved_units = 1;
    let account = owner.journal.accounts.values_mut().next().unwrap();
    account.spent_ms = 20_000;
    account.reserved_units = 1;
    owner.journal.total_spent_ms = 20_000;
    owner.journal.total_reserved_units = 1;
    owner.save().unwrap();
    for input in [model_input(2, 1), model_input(1, 2)] {
        let (reply, mut receipt) = oneshot::channel();
        owner.submit(input, binding.clone(), reply).unwrap();
        assert_eq!(receipt.try_recv().unwrap().state, State::InDoubt);
        assert_eq!(owner.journal.next_id, 2);
    }
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings);
    let (reply, mut receipt) = oneshot::channel();
    owner.submit(model_input(3, 3), binding, reply).unwrap();
    assert_eq!(receipt.try_recv().unwrap().state, State::InDoubt);
    assert_eq!(
        owner.journal.accounts.values().next().unwrap().spent_ms,
        20_000
    );
    assert_eq!(owner.journal.total_reserved_units, 1);
}
#[test]
fn prepaid_model_grant_is_not_recharged_or_refunded_on_uncertain_completion() {
    let (_directory, mut owner) = fixture(2);
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(model_input(1, 1), Binding::new([0; 32], [0; 32]), reply)
        .unwrap();
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Running;
    record.model_allowance_ms = Some(20_000);
    record.model_deadline_ns = Some(monotonic_ns().unwrap() + 20_000_000_000);
    record.spent_ms = 20_000;
    record.reserved_units = 1;
    let account = owner.journal.accounts.values_mut().next().unwrap();
    account.spent_ms = 20_000;
    account.reserved_units = 1;
    owner.journal.total_spent_ms = 20_000;
    owner.journal.total_reserved_units = 1;
    owner.reserve(1, 1).unwrap();
    owner.charge(1).unwrap();
    assert_eq!(owner.journal.total_spent_ms, 20_000);
    assert_eq!(owner.journal.total_reserved_units, 1);
    owner
        .complete(
            1,
            process::Outcome {
                state: State::InDoubt,
                result: Err("unconfirmed device quiescence".into()),
            },
        )
        .unwrap();
    assert_eq!(owner.journal.records[&1].state, State::InDoubt);
    assert_eq!(owner.journal.total_spent_ms, 20_000);
}

#[test]
fn queued_same_account_is_not_funded_after_sibling_uncertainty() {
    let (_directory, mut owner) = fixture(8);
    let (first, _first) = oneshot::channel();
    let (second, mut second_receipt) = oneshot::channel();
    let (other, _other) = oneshot::channel();
    owner
        .submit(model_input(1, 1), Binding::new([0; 32], [0; 32]), first)
        .unwrap();
    owner
        .submit(
            model_input(2, 2),
            Binding::new([0; 32], [0; 32]).with_selection([2; 32]),
            second,
        )
        .unwrap();
    let mut different = model_input(3, 3);
    if let Input::Interest { question, .. } = &mut different {
        *question = crate::mocks::create_question(1);
    }
    owner
        .submit(different, Binding::new([0; 32], [0; 32]), other)
        .unwrap();
    owner.journal.records.get_mut(&1).unwrap().state = State::InDoubt;
    owner.save().unwrap();
    let (events, _events) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    assert_eq!(owner.journal.records[&2].state, State::InDoubt);
    assert_eq!(owner.journal.records[&2].model_allowance_ms, None);
    assert_eq!(owner.journal.records[&2].reserved_units, 0);
    assert_eq!(second_receipt.try_recv().unwrap().state, State::InDoubt);
    assert_eq!(owner.journal.records[&3].state, State::Running);
    assert_eq!(owner.journal.records[&3].model_allowance_ms, Some(20_000));
    assert_eq!(owner.journal.total_reserved_units, 1);
    owner.acknowledge(2).unwrap();
    assert!(!owner.journal.records[&2].acknowledged);
}

#[test]
fn already_running_sibling_keeps_prepaid_cost_and_cannot_deliver_late_positive() {
    let (_directory, mut owner) = fixture(8);
    let (first, _first) = oneshot::channel();
    let (second, mut second_receipt) = oneshot::channel();
    owner
        .submit(model_input(1, 1), Binding::new([0; 32], [0; 32]), first)
        .unwrap();
    owner
        .submit(
            model_input(2, 2),
            Binding::new([0; 32], [0; 32]).with_selection([2; 32]),
            second,
        )
        .unwrap();
    let (events, _events) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    assert_eq!(owner.journal.total_reserved_units, 2);
    let charged = owner.journal.total_spent_ms;
    owner
        .complete(
            1,
            process::Outcome {
                state: State::InDoubt,
                result: Err("injected unknown GPU outcome".into()),
            },
        )
        .unwrap();
    assert_eq!(owner.journal.records[&2].state, State::InDoubt);
    assert_eq!(second_receipt.try_recv().unwrap().state, State::InDoubt);
    assert!(owner.reserve(2, 1).is_err());
    owner
        .complete(
            2,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::Interest(true)),
            },
        )
        .unwrap();
    assert_eq!(owner.journal.records[&2].state, State::InDoubt);
    assert!(owner.journal.records[&2].result.is_none());
    assert_eq!(owner.journal.total_reserved_units, 2);
    assert_eq!(owner.journal.total_spent_ms, charged);
}

#[tokio::test]
async fn local_question_consumes_uncertainty_without_disposing_hold_or_stopping_other_role() {
    let (directory, mut owner) = fixture(8);
    let (sender, mut commands) = mpsc::channel(COMMAND_CAPACITY);
    let client = Client { sender };
    type Interest =
        fn(naome_authoring::CompiledQuestion) -> std::future::Ready<Result<bool, String>>;
    let mut questions = crate::question::LocalQuestions::<Interest>::managed(
        client.clone(),
        &directory.0,
        Duration::from_secs(20),
    )
    .unwrap();
    let Input::Interest {
        owner: Some(profile),
        model: Some(session),
        ..
    } = model_input(1, 1)
    else {
        panic!()
    };
    questions.select_native(Some(([1; 32], Some(profile), Some(session))));
    let graph = crate::Graph::default();
    let question =
        naome_authoring::CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    let (_, reply) =
        questions.begin_exchange(&graph, question, Instant::now() + Duration::from_secs(20));
    let Command::Submit(input, binding, sender) = commands.recv().await.unwrap() else {
        panic!("native question did not submit managed job")
    };
    owner.submit(input, binding, sender).unwrap();
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner
        .complete(
            1,
            process::Outcome {
                state: State::InDoubt,
                result: Err("injected actual completion uncertainty".into()),
            },
        )
        .unwrap();
    let completion = questions.completed().await;
    questions.finish(&graph, completion);
    let assessment = reply.await.unwrap();
    assert!(!matches!(
        assessment.interest,
        crate::question::InterestAssessment::Assessed(true)
    ));
    // The consumer must not enqueue an ACK that would treat the hold as a
    // terminal result. Explicit repeated ACK remains a safe owner no-op.
    assert!(commands.try_recv().is_err());
    client.acknowledge(1).unwrap();
    let Command::Acknowledge(id) = commands.recv().await.unwrap() else {
        panic!()
    };
    owner.acknowledge(id).unwrap();
    assert_eq!(owner.journal.records[&1].state, State::InDoubt);
    assert!(!owner.journal.records[&1].acknowledged);
    let (ticket, mut receipt) = oneshot::channel();
    owner
        .submit(
            Input::Find { cursor: 0 },
            Binding::new([0; 32], [0; 32]),
            ticket,
        )
        .unwrap();
    owner.journal.records.get_mut(&2).unwrap().state = State::Running;
    owner.reserve(2, 1).unwrap();
    owner.journal.records.get_mut(&2).unwrap().checkpoint = 1;
    owner
        .complete(
            2,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::Question(crate::mocks::create_question(1))),
            },
        )
        .unwrap();
    assert_eq!(receipt.try_recv().unwrap().state, State::Complete);
    assert_eq!(owner.journal.records[&1].state, State::InDoubt);
}

#[test]
fn expired_original_grant_is_declined_before_connect_without_extra_funding() {
    let (_directory, mut owner) = fixture(8);
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(model_input(1, 1), Binding::new([0; 32], [0; 32]), reply)
        .unwrap();
    let (events, _events) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    let cost = owner.journal.total_spent_ms;
    let units = owner.journal.total_reserved_units;
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.model_deadline_ns = Some(monotonic_ns().unwrap().saturating_sub(1));
    let source = record.clone();
    // This is the actual proxy's preconnect boundary. The invalid slot number
    // is never used, because the original absolute grant already expired.
    assert!(
        crate::interest::score(&source, -1, 20_000, source.model_deadline_ns.unwrap())
            .unwrap_err()
            .contains("before connect")
    );
    assert!(
        owner
            .reserve(1, 1)
            .unwrap_err()
            .contains("original model deadline")
    );
    assert_eq!(owner.journal.records[&1].state, State::Expired);
    assert_eq!(owner.journal.total_spent_ms, cost);
    assert_eq!(owner.journal.total_reserved_units, units);
}

#[test]
fn actual_dispatch_delay_consumes_original_grant_before_connect() {
    let directory = Directory::new();
    let mut settings = Settings::default();
    settings.interest.limits.horizon_ms = 30;
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings);
    let (reply, _receipt) = oneshot::channel();
    owner
        .submit(model_input(1, 1), Binding::new([0; 32], [0; 32]), reply)
        .unwrap();
    let (events, _events) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    let source = owner.journal.records[&1].clone();
    let original = source.model_deadline_ns.unwrap();
    let cost = owner.journal.total_spent_ms;
    let units = owner.journal.total_reserved_units;
    std::thread::sleep(Duration::from_millis(40));
    assert!(
        crate::interest::score(&source, -1, source.model_allowance_ms.unwrap(), original)
            .unwrap_err()
            .contains("before connect")
    );
    assert_eq!(owner.journal.records[&1].model_deadline_ns, Some(original));
    assert_eq!(owner.journal.total_spent_ms, cost);
    assert_eq!(owner.journal.total_reserved_units, units);
}
