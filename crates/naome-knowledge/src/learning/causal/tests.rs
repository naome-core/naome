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
