use super::*;

#[test]
fn peer_interest_waits_for_a_third_slot_behind_pending_finding_and_solving() {
    const TEST: &str = "jobs::service::tests::fairness::peer_interest_waits_for_a_third_slot_behind_pending_finding_and_solving";
    if std::env::var_os("NAOME_JOB_CAPACITY_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_JOB_CAPACITY_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let mut budget = crate::resources::tests::snapshot(false);
    budget.budget.concurrency = 2;
    crate::resources::adaptive::publish(budget.clone());
    let (_directory, mut owner) = fixture(64);
    let binding = Binding::new([0; 32], [0; 32]);
    let mut tickets = Vec::new();
    for input in [
        Input::Find { cursor: 0 },
        Input::Solve {
            question: crate::mocks::create_question(0),
        },
    ] {
        let (reply, ticket) = oneshot::channel();
        owner.submit(input, binding.clone(), reply).unwrap();
        tickets.push(ticket);
    }
    let (events, _progress) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    let originals = owner.journal.records.values().cloned().collect::<Vec<_>>();
    assert_eq!(owner.running.len(), 2);
    let (reply, ticket) = oneshot::channel();
    owner
        .submit(
            Input::Interest {
                question: crate::mocks::create_question(1),
                purpose: Purpose::Admission,
                root: Some(crate::hex(&[1; 32])),
            },
            binding,
            reply,
        )
        .unwrap();
    tickets.push(ticket);
    owner.schedule(&events).unwrap();
    assert_eq!(owner.running.len(), 2);
    assert_eq!(owner.journal.records[&3].state, State::Queued);
    budget.budget.concurrency = 3;
    crate::resources::adaptive::publish(budget);
    owner.schedule(&events).unwrap();
    assert_eq!(owner.running.len(), 3);
    assert_eq!(owner.journal.records[&3].state, State::Running);
    assert_eq!(owner.journal.records[&3].input.lane(), 3);
    for original in originals {
        let current = &owner.journal.records[&original.id];
        assert_eq!(current.state, State::Running);
        assert_eq!(current.created_ms, original.created_ms);
        assert_eq!(current.expires_ms, original.expires_ms);
        assert_eq!(current.settings, original.settings);
        assert_eq!(current.reserved_units, original.reserved_units);
    }
    // No process future was polled: this checks admission and durable custody,
    // independently of native host pressure or provider service time.
}

#[test]
fn three_roles_use_three_admitted_slots_and_a_reduction_only_drains_them() {
    const TEST: &str = "jobs::service::tests::fairness::three_roles_use_three_admitted_slots_and_a_reduction_only_drains_them";
    if std::env::var_os("NAOME_JOB_CAPACITY_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_JOB_CAPACITY_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let mut budget = crate::resources::tests::snapshot(false);
    budget.budget.concurrency = 3;
    crate::resources::adaptive::publish(budget.clone());
    let (_directory, mut owner) = fixture(64);
    let binding = Binding::new([0; 32], [0; 32]);
    let mut tickets = Vec::new();
    for input in [
        Input::Find { cursor: 0 },
        Input::Solve {
            question: crate::mocks::create_question(0),
        },
        Input::Interest {
            question: crate::mocks::create_question(1),
            purpose: Purpose::Assessment,
            root: None,
        },
    ] {
        let (reply, ticket) = oneshot::channel();
        owner.submit(input, binding.clone(), reply).unwrap();
        tickets.push(ticket);
    }
    let (events, _progress) = mpsc::channel(16);
    owner.schedule(&events).unwrap();
    assert_eq!(owner.running.len(), 3);
    let originals = owner.journal.records.values().cloned().collect::<Vec<_>>();
    assert_eq!(
        originals
            .iter()
            .map(|record| record.input.lane())
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    budget.budget.concurrency = 1;
    crate::resources::adaptive::publish(budget);
    let (reply, ticket) = oneshot::channel();
    owner
        .submit(Input::Find { cursor: 99 }, binding, reply)
        .unwrap();
    tickets.push(ticket);
    owner.schedule(&events).unwrap();
    assert_eq!(
        owner.running.len(),
        3,
        "a reduction must not revoke existing work"
    );
    assert_eq!(owner.journal.records[&4].state, State::Queued);
    // These process futures were never polled: no helper or external effect
    // exists. Complete through the actual durable reservation/accounting path.
    owner.tasks.clear();
    for original in originals {
        owner.reserve(original.id, 1).unwrap();
        owner
            .journal
            .records
            .get_mut(&original.id)
            .unwrap()
            .checkpoint = 1;
        let output = match original.input {
            Input::Find { cursor } => Output::Question(crate::mocks::create_question(cursor)),
            Input::Solve { .. } => Output::NoCandidate,
            Input::Interest { .. } => Output::Interest(true),
        };
        owner
            .complete(
                original.id,
                process::Outcome {
                    state: State::Complete,
                    result: Ok(output),
                },
            )
            .unwrap();
        let completed = &owner.journal.records[&original.id];
        assert_eq!(completed.created_ms, original.created_ms);
        assert_eq!(completed.expires_ms, original.expires_ms);
        assert_eq!(completed.reserved_units, 1);
    }
    owner.schedule(&events).unwrap();
    assert_eq!(
        owner.running.len(),
        1,
        "new work must honor the reduced budget"
    );
    assert_eq!(owner.journal.records[&4].state, State::Running);
}

#[test]
fn busy_events_cannot_steal_single_slot_admission_from_waiting_roles() {
    const TEST: &str = "jobs::service::tests::fairness::busy_events_cannot_steal_single_slot_admission_from_waiting_roles";
    if std::env::var_os("NAOME_JOB_FAIRNESS_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_JOB_FAIRNESS_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let mut budget = crate::resources::tests::snapshot(false);
    budget.budget.concurrency = 1;
    crate::resources::adaptive::publish(budget.clone());
    let (_directory, mut owner) = fixture(64);
    let binding = Binding::new([0; 32], [0; 32]);
    let mut tickets = Vec::new();
    for input in [
        Input::Find { cursor: 0 },
        Input::Solve {
            question: crate::mocks::create_question(0),
        },
        Input::Interest {
            question: crate::mocks::create_question(1),
            purpose: Purpose::Assessment,
            root: None,
        },
        Input::Interest {
            question: crate::mocks::create_question(2),
            purpose: Purpose::Admission,
            root: Some(crate::hex(&[1; 32])),
        },
    ] {
        let (reply, ticket) = oneshot::channel();
        owner.submit(input, binding.clone(), reply).unwrap();
        tickets.push(ticket);
    }
    let (events, _progress) = mpsc::channel(16);
    for (round, expected_lane) in [0, 1, 2, 3, 0].into_iter().enumerate() {
        owner.schedule(&events).unwrap();
        assert_eq!(owner.running.len(), 1, "the one-slot budget must hold");
        let id = *owner.running.keys().next().unwrap();
        let original = owner.journal.records[&id].clone();
        assert_eq!(
            original.input.lane(),
            expected_lane,
            "busy event cadence starved a waiting role"
        );
        // Keep finding traffic ready while all other roles wait. Three busy
        // passes must not phase-lock the next free slot back to finding.
        let (reply, ticket) = oneshot::channel();
        owner
            .submit(
                Input::Find {
                    cursor: round as u64 + 1,
                },
                binding.clone(),
                reply,
            )
            .unwrap();
        tickets.push(ticket);
        for _ in 0..3 {
            owner.schedule(&events).unwrap();
            assert_eq!(owner.running.len(), 1);
        }
        // Complete the admitted unit through its original accounting path.
        // The unpolled process future has no external effect to reconcile.
        owner.reserve(id, 1).unwrap();
        owner.journal.records.get_mut(&id).unwrap().checkpoint = 1;
        owner.tasks.clear();
        let result = match original.input {
            Input::Find { cursor } => Output::Question(crate::mocks::create_question(cursor)),
            Input::Solve { .. } => Output::NoCandidate,
            Input::Interest { .. } => Output::Interest(true),
        };
        owner
            .complete(
                id,
                process::Outcome {
                    state: State::Complete,
                    result: Ok(result),
                },
            )
            .unwrap();
        let completed = &owner.journal.records[&id];
        assert_eq!(completed.created_ms, original.created_ms);
        assert_eq!(completed.expires_ms, original.expires_ms);
        assert_eq!(completed.reserved_units, 1);
    }
}
