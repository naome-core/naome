use super::*;

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
