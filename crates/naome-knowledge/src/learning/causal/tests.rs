use super::{selection::subtract, *};

pub(in crate::learning) fn test_pair(solved: [bool; 2]) -> transfer::Evaluation {
    let make = |solved: bool| transfer::Outcome {
        solved,
        expansions: 32,
        cpu_micros: 1,
        terminal: if solved {
            experience::TerminalEvidence::Unknown
        } else {
            experience::TerminalEvidence::Budget(experience::Budget::Expansions)
        },
        #[cfg(feature = "developer-tools")]
        diagnostic: crate::outcome::GenerationOutcome::Unresolved,
        micros: 1,
        proof_id: solved.then(|| digest(&solved)),
        decisions: Vec::new(),
        typed_decisions: Vec::new(),
    };
    transfer::Evaluation {
        before: make(solved[0]),
        after: make(solved[1]),
    }
}

pub(in crate::learning) fn test_fixture(candidate: &Checkpoint, before: u32, after: u32) -> Trial {
    let mut trial = Trial::default();
    for index in 0..transfer::CASES {
        let bit = 1 << index;
        trial
            .discover(
                index,
                candidate,
                &test_pair([before & bit != 0, after & bit != 0]),
            )
            .unwrap();
    }
    if trial.gained() != 0 {
        trial.screens = SCREEN as u8;
        trial.witness_families = WITNESSES as u8;
        trial.witnessed = trial.gained();
        trial.sufficient = trial.gained();
        trial.removal_losses = trial.gained();
        trial.witness_trace = Some(digest(&trial.sufficient));
        trial.best = Some(Subset {
            spans: vec![Span { start: 0, end: 1 }],
            changed: 1,
            checked: after,
        });
        trial.selected = Some(digest(candidate));
        for index in 0..trial.confirmation_cases().len() {
            trial
                .confirm(index, &test_pair([false, index == 0]))
                .unwrap();
        }
    }
    trial
}

pub(in crate::learning) fn before_freeze(candidate: &Checkpoint, span: Span) -> Trial {
    let mut trial = test_fixture(candidate, 0, 1);
    trial.best.as_mut().unwrap().spans = vec![span];
    trial.selected = None;
    trial.confirmation = transfer::Summary::default();
    trial.confirmation_trace = None;
    trial.confirmation_gains = 0;
    trial
}

#[test]
fn confirmation_uses_independent_related_families_and_cannot_waive_retention() {
    let candidate = Checkpoint::fresh();
    let trial = test_fixture(&candidate, 1, 0b111);
    let cases = trial.confirmation_cases();
    assert!(!cases.is_empty());
    assert!(cases.iter().all(|case| curriculum::reserved(&case.id)));
    assert!(
        cases
            .iter()
            .all(|case| curriculum::owned::case(&case.source).is_none())
    );
    assert!(cases.iter().all(|case| {
        !curriculum::adaptive::BANK
            .transfer
            .iter()
            .any(|discovery| discovery.dependency == case.dependency)
    }));
    assert!(trial.accepts(trial.discovery));
    let without_retention = transfer::Summary {
        after: 0b110,
        ..trial.discovery
    };
    assert!(!trial.accepts(without_retention));
    let mut confirmation_loss = trial.clone();
    confirmation_loss.confirmation.before |= 0b10;
    assert!(!confirmation_loss.accepts(trial.discovery));
    let mut no_witness = trial.clone();
    no_witness.sufficient = 0;
    assert!(!no_witness.accepts(trial.discovery));
}

#[test]
fn opposing_halves_and_interactions_use_only_explicit_coordinates() {
    let left = Span { start: 0, end: 10 };
    let right = Span { start: 10, end: 20 };
    let combined = Subset {
        spans: vec![left, right],
        changed: 20,
        checked: 0b111,
    };
    assert_eq!(
        intervention(0, &[left, right], &combined, 0b110),
        vec![left]
    );
    assert_eq!(
        intervention(2, &[left, right], &combined, 0b110),
        vec![right]
    );
    assert_eq!(
        subtract(&combined.spans, Span { start: 7, end: 12 }),
        vec![Span { start: 0, end: 7 }, Span { start: 12, end: 20 }]
    );
    let incomplete = Subset {
        checked: 0b110,
        ..combined.clone()
    };
    assert!(rank(&combined, 0b110, 0b001) > rank(&incomplete, 0b110, 0b001));
}

#[test]
fn screening_cannot_skip_a_better_checked_update() {
    let (gains, protected) = (0b11000, 0b00111);
    for current in 0..32 {
        let incumbent = Subset {
            spans: Vec::new(),
            changed: 2,
            checked: current,
        };
        for checked in 0..32 {
            for changed in [1, 2, 3] {
                let mut calls = Vec::new();
                let (observed, paid) =
                    selection::screen(&incumbent, changed, gains, protected, |index| {
                        calls.push(index);
                        Ok((checked & (1 << index) != 0, 2))
                    })
                    .unwrap();
                let mut proposal = Subset {
                    spans: Vec::new(),
                    changed,
                    checked,
                };
                let best = rank(&incumbent, gains, protected);
                let improves = rank(&proposal, gains, protected) > best;
                proposal.checked = observed;
                assert_eq!(rank(&proposal, gains, protected) > best, improves);
                if improves {
                    assert_eq!(calls.len(), 5);
                    assert_eq!(observed, checked);
                }
                assert_eq!(paid as usize, 2 * calls.len());
            }
        }
    }
    let incumbent = Subset {
        spans: Vec::new(),
        changed: 2,
        checked: 0b11011,
    };
    let mut calls = Vec::new();
    let (checked, paid) = selection::screen(&incumbent, 3, gains, protected, |index| {
        calls.push(index);
        Ok((false, 32))
    })
    .unwrap();
    assert_eq!((checked, paid), (0, 32));
    assert_eq!(calls, vec![2]);
}

#[test]
fn typed_forks_require_the_same_prefix_and_ordered_menu() {
    let mut sample = test_pair([false, true]);
    let decision = |state, offered, selected| generation::DecisionObservation {
        state: digest(&state),
        offered: digest(&offered),
        selected,
    };
    sample.before.typed_decisions = vec![decision(1, 1, 0), decision(2, 2, 0)];
    sample.after.typed_decisions = vec![decision(1, 1, 0), decision(2, 2, 1)];
    let fork = fork(0, &sample.before, &sample.after).unwrap();
    assert_eq!(
        (fork.route, fork.event, fork.before, fork.after),
        (Route::TypedProgram, 1, 0, 1)
    );
    sample.after.typed_decisions[0] = decision(1, 3, 0);
    assert!(super::fork(0, &sample.before, &sample.after).is_none());
}

#[test]
fn elapsed_time_and_failed_checks_do_not_supply_causal_misses() {
    let mut sample = test_pair([false, true]);
    for terminal in [
        experience::TerminalEvidence::Budget(experience::Budget::Time),
        experience::TerminalEvidence::Interrupted,
        experience::TerminalEvidence::CheckerRejected,
    ] {
        sample.before.terminal = terminal;
        let mut trial = Trial::default();
        trial.discover(0, &Checkpoint::fresh(), &sample).unwrap();
        assert_eq!(trial.gained(), 0);
    }
}

#[test]
fn a_branch_fact_limit_counts_only_with_the_full_paid_allowance_before_the_time_limit() {
    use experience::{Capacity, TerminalEvidence};
    let mut sample = test_pair([false, true]);
    sample.before.terminal = TerminalEvidence::Unsupported(Capacity::Facts);
    sample.before.expansions = transfer::ALLOWANCE - 1;
    assert!(!fixed_search_miss(&sample.before));
    sample.before.expansions = transfer::ALLOWANCE;
    let mut trial = Trial::default();
    trial.discover(0, &Checkpoint::fresh(), &sample).unwrap();
    assert_eq!(trial.gained(), 1);

    sample.before.micros = search::TIME_LIMIT.as_micros().try_into().unwrap();
    assert!(!fixed_search_miss(&sample.before));
    sample.before.micros = 1;
    for capacity in [
        Capacity::Graph,
        Capacity::Certificate,
        Capacity::Dependencies,
    ] {
        sample.before.terminal = TerminalEvidence::Unsupported(capacity);
        assert!(!fixed_search_miss(&sample.before));
    }
}

#[test]
fn the_smallest_promising_module_reaches_each_of_its_eighths() {
    let modules = (0..7)
        .map(|i| Span {
            start: 100 * i,
            end: 100 * (i + 1),
        })
        .collect::<Vec<_>>();
    let best = Subset {
        spans: vec![modules[2]],
        changed: 100,
        checked: 0b111,
    };
    let eighths = (20..28)
        .map(|round| intervention(round, &modules, &best, 0b110)[0])
        .collect::<Vec<_>>();
    assert_eq!(eighths[0].start, modules[2].start);
    assert_eq!(eighths[7].end, modules[2].end);
    assert!(eighths.windows(2).all(|pair| pair[0].end == pair[1].start));
    assert_eq!(
        intervention(30, &modules, &best, 0b110),
        vec![Span {
            start: 200,
            end: 201
        }]
    );
}
