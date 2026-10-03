use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use naome_pok::*;

fn core() -> Orchestrator {
    Orchestrator::new(Config {
        top_k: 2.try_into().unwrap(),
        citation_reward_nao: 2.try_into().unwrap(),
    })
}

fn apply(core: &mut Orchestrator, id: u64, input: Input) -> Result<Applied, InputError> {
    core.apply(Event {
        id: EventId(id),
        input,
    })
}

fn candidate(id: u64, solver: u64) -> Candidate {
    Candidate {
        submission: SubmissionId(id),
        question: QuestionId(1),
        result: ResultId(10),
        proof: ProofId(id),
        solver: ParticipantId(solver),
    }
}

fn valid(request: Candidate, steps: u64) -> Input {
    Input::Verified(VerificationReceipt {
        request,
        verdict: Verdict::Valid {
            verified_steps: steps.try_into().unwrap(),
        },
    })
}

fn prepared() -> Orchestrator {
    let mut core = core();
    apply(&mut core, 1, Input::RegisterQuestion(QuestionId(1))).unwrap();
    apply(
        &mut core,
        2,
        Input::Approval {
            question: QuestionId(1),
            participant: ParticipantId(1),
            approved: true,
        },
    )
    .unwrap();
    core
}

#[test]
fn distinct_approvals_ties_withdrawal_and_pool_admission() {
    let mut core = core();
    for q in [3, 2, 1] {
        apply(&mut core, q, Input::RegisterQuestion(QuestionId(q))).unwrap();
        apply(
            &mut core,
            q + 10,
            Input::Approval {
                question: QuestionId(q),
                participant: ParticipantId(1),
                approved: true,
            },
        )
        .unwrap();
    }
    assert_eq!(core.top_questions(), [QuestionId(1), QuestionId(2)]);
    apply(
        &mut core,
        20,
        Input::Approval {
            question: QuestionId(3),
            participant: ParticipantId(1),
            approved: true,
        },
    )
    .unwrap();
    assert_eq!(core.top_questions(), [QuestionId(1), QuestionId(2)]);
    let outside = Candidate {
        question: QuestionId(3),
        ..candidate(30, 1)
    };
    assert_eq!(
        apply(&mut core, 30, Input::Submit(outside)),
        Err(InputError::NotSelected)
    );
    apply(
        &mut core,
        21,
        Input::Approval {
            question: QuestionId(3),
            participant: ParticipantId(2),
            approved: true,
        },
    )
    .unwrap();
    assert_eq!(core.top_questions(), [QuestionId(3), QuestionId(1)]);
    assert_eq!(
        apply(&mut core, 30, Input::Submit(outside)),
        Ok(Applied::Accepted)
    );
    apply(
        &mut core,
        22,
        Input::Approval {
            question: QuestionId(3),
            participant: ParticipantId(2),
            approved: false,
        },
    )
    .unwrap();
    // A previously admitted request survives a ranking change.
    assert_eq!(
        apply(&mut core, 31, valid(outside, 5)),
        Ok(Applied::Selected)
    );
}

#[test]
fn first_receipt_wins_then_only_strict_improvements_for_the_same_result() {
    let mut core = prepared();
    let a = candidate(10, 1);
    let b = candidate(11, 2);
    apply(&mut core, 3, Input::Submit(a)).unwrap();
    apply(&mut core, 4, Input::Submit(b)).unwrap();
    // Receiver order, not submission ID/order or time spent solving, selects the first.
    apply(&mut core, 5, valid(b, 8)).unwrap();
    assert_eq!(core.current(a.question).unwrap().candidate, b);
    assert_eq!(apply(&mut core, 6, valid(a, 8)), Ok(Applied::NotImproved));
    assert!(core.top_questions().is_empty());
    for (id, steps, expected) in [(20, 9, Applied::NotImproved), (21, 7, Applied::Selected)] {
        let c = candidate(id, 1);
        apply(&mut core, id, Input::Submit(c)).unwrap();
        assert_eq!(apply(&mut core, id + 100, valid(c, steps)), Ok(expected));
    }
    let wrong_result = Candidate {
        result: ResultId(999),
        ..candidate(22, 3)
    };
    assert_eq!(
        apply(&mut core, 22, Input::Submit(wrong_result)),
        Err(InputError::ResultMismatch)
    );
    assert_eq!(
        core.current(a.question).unwrap().candidate,
        candidate(21, 1)
    );
    let awards: Vec<_> = core
        .pending_effects()
        .filter_map(|e| match e.kind {
            EffectKind::Reward(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(
        awards,
        [RewardIntent {
            beneficiary: b.solver,
            amount_nao: 1,
            reason: RewardReason::FirstSolution(b.question)
        }]
    );
}

#[test]
fn invalid_and_mismatched_receipts_cannot_change_ownership() {
    let mut core = prepared();
    let a = candidate(10, 1);
    assert_eq!(
        apply(&mut core, 3, valid(a, 1)),
        Err(InputError::UnknownSubmission)
    );
    apply(&mut core, 3, Input::Submit(a)).unwrap();
    for changed in [
        Candidate {
            question: QuestionId(2),
            ..a
        },
        Candidate {
            result: ResultId(11),
            ..a
        },
        Candidate {
            proof: ProofId(11),
            ..a
        },
        Candidate {
            solver: ParticipantId(2),
            ..a
        },
    ] {
        assert_eq!(
            apply(&mut core, 4, valid(changed, 1)),
            Err(InputError::ReceiptMismatch)
        );
        assert!(core.current(a.question).is_none());
        assert_eq!(core.pending_effects().count(), 1);
    }
    assert_eq!(
        apply(
            &mut core,
            4,
            Input::Verified(VerificationReceipt {
                request: a,
                verdict: Verdict::Invalid
            })
        ),
        Ok(Applied::InvalidProof)
    );
    assert!(core.current(a.question).is_none());
    assert_eq!(core.pending_effects().count(), 0);
    assert_eq!(
        apply(&mut core, 5, valid(a, 1)),
        Err(InputError::IdentityConflict)
    );
}

#[test]
fn concurrent_other_result_is_rejected_and_prior_citation_intents_stay_with_their_owner() {
    let mut core = prepared();
    let a = candidate(10, 1);
    let other = Candidate {
        result: ResultId(99),
        ..candidate(11, 2)
    };
    apply(&mut core, 3, Input::Submit(a)).unwrap();
    apply(&mut core, 4, Input::Submit(other)).unwrap();
    apply(&mut core, 5, valid(a, 8)).unwrap();
    assert_eq!(
        apply(&mut core, 6, valid(other, 1)),
        Ok(Applied::DifferentResult)
    );
    let citation = Citation {
        citation: CitationId(1),
        question: a.question,
        result: a.result,
    };
    apply(&mut core, 7, Input::Cite(citation)).unwrap();
    let b = candidate(12, 2);
    apply(&mut core, 8, Input::Submit(b)).unwrap();
    apply(&mut core, 9, valid(b, 4)).unwrap();
    let invalid = candidate(13, 3);
    apply(&mut core, 13, Input::Submit(invalid)).unwrap();
    assert_eq!(
        apply(
            &mut core,
            14,
            Input::Verified(VerificationReceipt {
                request: invalid,
                verdict: Verdict::Invalid
            })
        ),
        Ok(Applied::InvalidProof)
    );
    assert_eq!(core.current(a.question).unwrap().candidate, b);
    assert_eq!(
        apply(&mut core, 10, Input::Cite(citation)),
        Ok(Applied::Duplicate)
    );
    apply(
        &mut core,
        11,
        Input::Cite(Citation {
            citation: CitationId(2),
            ..citation
        }),
    )
    .unwrap();
    assert_eq!(
        apply(
            &mut core,
            12,
            Input::Cite(Citation {
                citation: CitationId(3),
                result: other.result,
                ..citation
            })
        ),
        Err(InputError::ResultMismatch)
    );
    let rewards: Vec<_> = core
        .pending_effects()
        .filter_map(|e| match e.kind {
            EffectKind::Reward(r) if matches!(r.reason, RewardReason::Citation(_)) => {
                Some((r.beneficiary, r.amount_nao))
            }
            _ => None,
        })
        .collect();
    assert_eq!(rewards, [(a.solver, 2), (b.solver, 2)]);
}

#[test]
fn exact_and_logical_retries_do_not_duplicate_effects_or_reuse_identity() {
    let mut core = prepared();
    let a = candidate(10, 1);
    assert_eq!(apply(&mut core, 3, Input::Submit(a)), Ok(Applied::Accepted));
    assert_eq!(
        apply(&mut core, 3, Input::Submit(a)),
        Ok(Applied::Duplicate)
    );
    assert_eq!(
        apply(&mut core, 4, Input::Submit(a)),
        Ok(Applied::Duplicate)
    );
    assert_eq!(core.pending_effects().count(), 1);
    assert_eq!(
        apply(&mut core, 4, Input::Submit(candidate(11, 2))),
        Err(InputError::IdentityConflict)
    );
    assert_eq!(
        apply(
            &mut core,
            5,
            Input::Submit(Candidate {
                proof: ProofId(99),
                ..a
            })
        ),
        Err(InputError::IdentityConflict)
    );
    apply(&mut core, 6, valid(a, 4)).unwrap();
    assert_eq!(apply(&mut core, 7, valid(a, 4)), Ok(Applied::Duplicate));
    let effects: Vec<_> = core.pending_effects().copied().collect();
    assert_eq!(effects.len(), 2);
    for e in effects {
        core.acknowledge(e.id);
        core.acknowledge(e.id);
    }
    assert_eq!(apply(&mut core, 6, valid(a, 4)), Ok(Applied::Duplicate));
    assert_eq!(core.pending_effects().count(), 0);
    let citation = Citation {
        citation: CitationId(1),
        question: a.question,
        result: a.result,
    };
    apply(&mut core, 8, Input::Cite(citation)).unwrap();
    assert_eq!(
        apply(
            &mut core,
            9,
            Input::Cite(Citation {
                result: ResultId(99),
                ..citation
            })
        ),
        Err(InputError::IdentityConflict)
    );
}

#[derive(Default)]
struct UncertainSink {
    accepted: BTreeMap<EffectId, Effect>,
    attempts: usize,
}
impl EffectSink for UncertainSink {
    type Error = ();
    fn deliver(&mut self, effect: Effect) -> Result<(), ()> {
        self.attempts += 1;
        if let Some(old) = self.accepted.insert(effect.id, effect) {
            assert_eq!(old, effect);
        }
        if self.attempts == 1 { Err(()) } else { Ok(()) }
    }
}

#[test]
fn loop_retries_uncertain_delivery_without_duplicate_external_effects() {
    let mut core = prepared();
    let a = candidate(10, 1);
    apply(&mut core, 3, Input::Submit(a)).unwrap();
    apply(&mut core, 4, valid(a, 8)).unwrap();
    let (tx, rx) = mpsc::channel();
    tx.send(Command::RetryEffects).unwrap();
    tx.send(Command::RetryEffects).unwrap();
    tx.send(Command::Event(Event {
        id: EventId(5),
        input: Input::RegisterQuestion(a.question),
    }))
    .unwrap();
    tx.send(Command::Cancel).unwrap();
    let mut sink = UncertainSink::default();
    let report = run(&mut core, &rx, &mut sink);
    assert_eq!(report.stop, StopReason::Cancelled);
    assert_eq!(report.failed_delivery_attempts, 1);
    assert_eq!(sink.attempts, 3);
    assert_eq!(sink.accepted.len(), 2);
    assert_eq!(core.pending_effects().count(), 0);
}

#[test]
fn idle_loop_cancels_and_disconnects_cleanly_and_retains_rejections() {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut core = core();
        let mut sink = UncertainSink::default();
        ready_tx.send(()).unwrap();
        done_tx
            .send((run(&mut core, &rx, &mut sink), sink.attempts))
            .unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    tx.send(Command::Event(Event {
        id: EventId(1),
        input: Input::Submit(candidate(1, 1)),
    }))
    .unwrap();
    tx.send(Command::Cancel).unwrap();
    let (report, attempts) = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(report.stop, StopReason::Cancelled);
    assert_eq!(
        report.rejected_inputs,
        [(EventId(1), InputError::UnknownQuestion)]
    );
    assert_eq!(attempts, 0);
    worker.join().unwrap();
    let (tx, rx) = mpsc::channel();
    drop(tx);
    assert_eq!(
        run(&mut core(), &rx, &mut UncertainSink::default()).stop,
        StopReason::Disconnected
    );
}
