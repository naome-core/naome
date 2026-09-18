use super::*;
use crate::{
    library::ProofPackage,
    test_support::{account, genesis, validator},
    time::SignedTimeReport,
};
use naome_checker::{ArtifactState, check_normal_form_with_state};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep};

fn author(index: u8) -> AccountId {
    AccountId::for_key(account(index).verifying_key().as_bytes())
}
fn time(state: &ResearchState, utc: u64) -> TimeCertificate {
    TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.head(),
                    state.height() + 1,
                    utc,
                    &validator(i),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap()
}
fn apply(state: &mut ResearchState, utc: u64, ops: Vec<SignedOperation>) -> ResearchRecord {
    let before = state.commitment();
    let transition = state.prepare_record(time(state, utc), ops).unwrap();
    assert_eq!(state.commitment(), before);
    let record = transition.record().clone();
    let decoded = ResearchRecord::decode(&record.encode().unwrap(), state.genesis()).unwrap();
    let replay = state.validate_record(&decoded).unwrap().into_state();
    assert_eq!(replay.commitment(), transition.state().commitment());
    assert_eq!(replay.head(), record.id());
    *state = transition.into_state();
    record
}
fn signed(state: &ResearchState, index: u8, body: OperationBody) -> SignedOperation {
    body.sign(
        state.genesis(),
        state.next_nonce(author(index)).unwrap(),
        &account(index),
    )
    .unwrap()
}
fn question(state: &ResearchState, formula: &str) -> CompiledQuestion {
    CompiledQuestion::compile(
        &format!("foundation = \"naome:zfc\"\nstatement = {formula}\n"),
        state.genesis().profile(),
    )
    .unwrap()
}
fn submit(state: &mut ResearchState, formula: &str) -> OperationId {
    let action = signed(
        state,
        4,
        OperationBody::Submit {
            purpose: "test a formal target".into(),
            question: question(state, formula),
        },
    );
    let id = action.id();
    apply(state, state.time(), vec![action]);
    id
}
fn open_and_approve(state: &mut ResearchState) -> SolutionRoundId {
    apply(state, state.time(), vec![]);
    let active = state.active().unwrap();
    let votes = (0..3)
        .map(|i| {
            signed(
                state,
                i,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    apply(state, state.time(), votes);
    assert_eq!(state.active().unwrap().phase, Phase::Voting);
    apply(state, active.deadline.unwrap(), vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::ApprovedWait);
    apply(state, state.time(), vec![]);
    state.active().unwrap().solution_round.unwrap()
}
fn root_package(state: &ResearchState, index: u8) -> ProofPackage {
    let certificate = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(0),
        },
    ])
    .unwrap();
    let checked = check_normal_form_with_state(
        certificate.into_unchecked_normal_form(),
        &ArtifactState::new(),
    )
    .unwrap();
    ProofPackage::new(
        author(index),
        checked.proof_id(),
        vec![(
            checked.proof_id(),
            checked.normal_form().canonical_bytes().to_vec(),
        )],
        state.genesis().profile(),
    )
    .unwrap()
}
fn start_reveal(state: &mut ResearchState) {
    apply(state, state.active().unwrap().deadline.unwrap(), vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::CommitClosedWait);
    apply(state, state.time(), vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::Reveal);
}

#[test]
fn complete_real_proof_settlement_and_replay_are_atomic() {
    let mut state = ResearchState::new(genesis());
    let submitted = submit(&mut state, "forall(x, equal(x,x))");
    let round = open_and_approve(&mut state);
    let original =
        SignedOriginal::sign(state.genesis(), round, root_package(&state, 4), &account(4)).unwrap();
    let secret = [44; 32];
    let commitment = CommitmentId::for_original(
        state.genesis(),
        round,
        author(4),
        original.original_hash(),
        &secret,
    );
    let op = signed(&state, 4, OperationBody::Commit { round, commitment });
    let now = state.time();
    apply(&mut state, now, vec![op]);
    start_reveal(&mut state);
    let op = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    let received = op.id();
    let now = state.time();
    apply(&mut state, now, vec![op]);
    assert_eq!(state.library().len(), 0);
    assert_eq!(state.balances().paid_completions(), 0);
    assert!(state.receipt(received).is_some());
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(&mut state, deadline, vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::SettlementPending);
    apply(&mut state, deadline + 10000, vec![]);
    assert!(state.active().is_none());
    assert_eq!(state.library().len(), 1);
    assert_eq!(state.balances().paid_completions(), 1);
    assert_eq!(state.claims().len(), 1);
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
    assert_eq!(
        state.question(submitted).unwrap().status(),
        QuestionStatus::Completed
    );
    state
        .balances()
        .verify_conservation(state.genesis())
        .unwrap();
    let duplicate = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "opposite label".into(),
            question: question(&state, "not_(forall(x,equal(x,x)))"),
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![duplicate])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
}

#[test]
fn phase_start_deadline_and_nonce_rejections_leave_parent_unchanged() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let before = state.commitment();
    let fabricated = signed(
        &state,
        0,
        OperationBody::Vote {
            question: QuestionId::from_bytes([0; 32]),
            attempt: 1,
            yes: true,
        },
    );
    assert!(
        state
            .prepare_record(time(&state, 100), vec![fabricated])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    apply(&mut state, 100, vec![]);
    let active = state.active().unwrap();
    let late = signed(
        &state,
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, active.deadline.unwrap()), vec![late])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    let wrong = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: true,
    }
    .sign(state.genesis(), 2, &account(0))
    .unwrap();
    assert!(
        state
            .prepare_record(time(&state, 100), vec![wrong])
            .is_err()
    );
    assert_eq!(state.next_nonce(author(0)), Some(1));
    let valid = signed(
        &state,
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    let id = valid.id();
    apply(&mut state, 100, vec![valid.clone()]);
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, 100), vec![valid])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    assert!(state.receipt(id).is_some());
}

#[test]
fn absence_never_counts_yes_and_expiry_never_means_refutation() {
    let mut state = ResearchState::new(genesis());
    let id = submit(&mut state, "forall(x,equal(x,x))");
    apply(&mut state, 100, vec![]);
    let active = state.active().unwrap();
    let votes = (0..2)
        .map(|i| {
            signed(
                &state,
                i,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    apply(&mut state, 100, votes);
    apply(&mut state, active.deadline.unwrap(), vec![]);
    assert!(state.active().is_none());
    assert_eq!(
        state.question(id).unwrap().status(),
        QuestionStatus::NotApproved
    );
    let id = submit(&mut state, "forall(x,equal(x,x))");
    open_and_approve(&mut state);
    assert_eq!(state.active().unwrap().number, 2);
    start_reveal(&mut state);
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(&mut state, deadline, vec![]);
    apply(&mut state, deadline, vec![]);
    assert_eq!(
        state.question(id).unwrap().status(),
        QuestionStatus::Unresolved
    );
    assert!(state.families().is_empty());
    assert!(state.claims().is_empty());
    assert_eq!(state.balances().paid_completions(), 0);
}

#[test]
fn supplied_time_cache_is_recomputed_against_actual_parent() {
    let state = ResearchState::new(genesis());
    let cert = TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(state.genesis(), state.head(), 1, 100, &validator(i))
                    .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        1,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(cert.time(), u64::MAX);
    let op = signed(
        &state,
        4,
        OperationBody::Submit {
            purpose: "time test".into(),
            question: question(&state, "forall(x,equal(x,x))"),
        },
    );
    let transition = state.prepare_record(cert, vec![op]).unwrap();
    assert_eq!(transition.state().time(), 100);
}

fn commit_original(
    state: &mut ResearchState,
    index: u8,
    round: SolutionRoundId,
    secret: [u8; 32],
) -> SignedOriginal {
    let package = if index == 5 {
        let x = FreeVariable::new(0);
        let equality = naome_foundation::Formula::equal(x, x);
        let certificate = ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Simplification {
                antecedent: equality.clone().into(),
                consequent: equality.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: x,
            },
        ])
        .unwrap();
        let checked = check_normal_form_with_state(
            certificate.into_unchecked_normal_form(),
            &ArtifactState::new(),
        )
        .unwrap();
        ProofPackage::new(
            author(index),
            checked.proof_id(),
            vec![(
                checked.proof_id(),
                checked.normal_form().canonical_bytes().to_vec(),
            )],
            state.genesis().profile(),
        )
        .unwrap()
    } else {
        root_package(state, index)
    };
    let original = SignedOriginal::sign(state.genesis(), round, package, &account(index)).unwrap();
    let commitment = CommitmentId::for_original(
        state.genesis(),
        round,
        author(index),
        original.original_hash(),
        &secret,
    );
    let op = signed(state, index, OperationBody::Commit { round, commitment });
    apply(state, state.time(), vec![op]);
    original
}

fn finish(state: &mut ResearchState) {
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(state, deadline, vec![]);
    apply(state, deadline, vec![]);
}

#[test]
fn commitment_order_wins_even_when_reveals_arrive_in_reverse_order() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let first = commit_original(&mut state, 4, round, [4; 32]);
    let second = commit_original(&mut state, 5, round, [5; 32]);
    start_reveal(&mut state);
    let first_root = first.package().root();
    let second_root = second.package().root();
    assert_ne!(first_root, second_root);
    let conclusion = |original: &SignedOriginal| {
        let certificate =
            ProofCertificate::from_canonical_bytes(&original.package().certificates()[0].1)
                .unwrap();
        check_normal_form_with_state(
            certificate.into_unchecked_normal_form(),
            &ArtifactState::new(),
        )
        .unwrap()
        .conclusion()
        .clone()
    };
    assert_eq!(conclusion(&first), conclusion(&second));
    for (index, secret, original) in [(5, [5; 32], second), (4, [4; 32], first)] {
        let op = signed(
            &state,
            index,
            OperationBody::Reveal {
                round,
                secret,
                original,
            },
        );
        let now = state.time();
        apply(&mut state, now, vec![op]);
    }
    finish(&mut state);
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
    assert_eq!(state.balances().account(author(5)), Some(0));
    assert_eq!(state.claims().values().next().unwrap().author, author(4));
    assert!(state.library().lookup(first_root).is_some());
    assert!(state.library().lookup(second_root).is_none());
}

#[test]
fn invalid_or_missing_earlier_reveal_does_not_block_later_eligible_commitment() {
    for try_invalid in [false, true] {
        let mut state = ResearchState::new(genesis());
        submit(&mut state, "forall(x,equal(x,x))");
        let round = open_and_approve(&mut state);
        let first = commit_original(&mut state, 4, round, [4; 32]);
        let second = commit_original(&mut state, 5, round, [5; 32]);
        start_reveal(&mut state);
        let first_root = first.package().root();
        let second_root = second.package().root();
        assert_ne!(first_root, second_root);
        if try_invalid {
            let op = signed(
                &state,
                4,
                OperationBody::Reveal {
                    round,
                    secret: [99; 32],
                    original: first,
                },
            );
            let before = state.commitment();
            assert!(
                state
                    .prepare_record(time(&state, state.time()), vec![op])
                    .is_err()
            );
            assert_eq!(state.commitment(), before);
            assert_eq!(state.active().unwrap().reveals, 0);
        }
        let op = signed(
            &state,
            5,
            OperationBody::Reveal {
                round,
                secret: [5; 32],
                original: second,
            },
        );
        let now = state.time();
        apply(&mut state, now, vec![op]);
        finish(&mut state);
        assert_eq!(state.balances().account(author(5)), Some(700_000_000));
        assert_eq!(state.balances().account(author(4)), Some(0));
        assert!(state.library().lookup(second_root).is_some());
        assert!(state.library().lookup(first_root).is_none());
    }
}

#[test]
fn reveal_at_exact_deadline_and_wrong_original_author_are_rejected() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let original = commit_original(&mut state, 4, round, [4; 32]);
    start_reveal(&mut state);
    let wrong = signed(
        &state,
        5,
        OperationBody::Reveal {
            round,
            secret: [4; 32],
            original: original.clone(),
        },
    );
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![wrong])
            .is_err()
    );
    let valid = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret: [4; 32],
            original,
        },
    );
    let deadline = state.active().unwrap().deadline.unwrap();
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, deadline), vec![valid])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    finish(&mut state);
    assert_eq!(state.balances().paid_completions(), 0);
}

#[test]
fn record_roundtrip_preserves_parent_time_clamp_and_rejects_claimed_effect_tampering() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let transition = state.prepare_record(time(&state, 50), vec![]).unwrap();
    let record = transition.record();
    assert_eq!(record.time(), 100);
    assert_eq!(
        &ResearchRecord::decode(&record.encode().unwrap(), state.genesis()).unwrap(),
        record
    );
    let mut changed = record.encode().unwrap();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        state
            .validate_record(&ResearchRecord::decode(&changed, state.genesis()).unwrap())
            .is_err()
    );
    let mut changed = record.encode().unwrap();
    changed[110] ^= 1;
    assert!(
        state
            .validate_record(&ResearchRecord::decode(&changed, state.genesis()).unwrap())
            .is_err()
    );
    let mut trailing = record.encode().unwrap();
    trailing.push(0);
    assert!(ResearchRecord::decode(&trailing, state.genesis()).is_err());
}

#[test]
fn streaming_state_commitment_matches_materialized_canonical_bytes() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let original = commit_original(&mut state, 4, round, [4; 32]);
    start_reveal(&mut state);
    let op = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret: [4; 32],
            original,
        },
    );
    let now = state.time();
    apply(&mut state, now, vec![op]);
    for snapshot in [state.clone(), {
        finish(&mut state);
        state
    }] {
        let mut writer = Writer::new();
        snapshot.write_state(&mut writer);
        assert_eq!(
            snapshot.commitment().as_bytes(),
            &hash(b"naome:state:state:v1\0", &[&writer.finish()])
        );
    }
}

fn checked_node(
    steps: Vec<ProofStep>,
    context: &mut ArtifactState,
) -> (naome_proof::ProofId, Vec<u8>) {
    let proof = naome_checker::normalize_and_check_with_state(
        ProofCertificate::new(steps).unwrap(),
        context,
    )
    .unwrap();
    let node = (
        proof.proof_id(),
        proof.normal_form().canonical_bytes().to_vec(),
    );
    context.register_proof(proof).unwrap();
    node
}
fn solve(state: &mut ResearchState, index: u8, package: ProofPackage) {
    let round = open_and_approve(state);
    let secret = [index; 32];
    let original = SignedOriginal::sign(state.genesis(), round, package, &account(index)).unwrap();
    let commitment = CommitmentId::for_original(
        state.genesis(),
        round,
        author(index),
        original.original_hash(),
        &secret,
    );
    let op = signed(state, index, OperationBody::Commit { round, commitment });
    apply(state, state.time(), vec![op]);
    start_reveal(state);
    let op = signed(
        state,
        index,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    apply(state, state.time(), vec![op]);
    finish(state);
}

#[test]
fn complete_a_h_b_c_workflow_preserves_attribution_citation_and_once_only_issuance() {
    use naome_foundation::Formula;
    let mut state = ResearchState::new(genesis());
    let mut context = ArtifactState::new();
    let x = FreeVariable::new(0);
    let helper = checked_node(
        vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ],
        &mut context,
    );
    let a = checked_node(
        vec![
            ProofStep::ProofReference { proof_id: helper.0 },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ],
        &mut context,
    );
    let package = ProofPackage::new(
        author(4),
        a.0,
        vec![a, helper.clone()],
        state.genesis().profile(),
    )
    .unwrap();
    submit(&mut state, "forall(y,forall(x,equal(x,x)))");
    solve(&mut state, 4, package);
    let published = state.library().lookup(helper.0).unwrap();
    assert_eq!(published.author(), author(4));
    let admitted = published.coordinate();
    let exported = published.canonical_bytes().to_vec();
    drop(context);
    // The B resolver starts empty and uses only exported, checker-verified H.
    // Actual retrieval across processes is a separate runtime acceptance gate.
    let mut independent = ArtifactState::new();
    let certificate = ProofCertificate::from_canonical_bytes(&exported).unwrap();
    let checked =
        check_normal_form_with_state(certificate.into_unchecked_normal_form(), &independent)
            .unwrap();
    independent.register_proof(checked).unwrap();
    let h = Formula::for_all(x, Formula::equal(x, x));
    let b = checked_node(
        vec![
            ProofStep::ProofReference { proof_id: helper.0 },
            ProofStep::Simplification {
                antecedent: h.clone().into(),
                consequent: h.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ],
        &mut independent,
    );
    let package = ProofPackage::new(author(5), b.0, vec![b], state.genesis().profile()).unwrap();
    let b_id = submit(
        &mut state,
        "not_(implies(forall(x,equal(x,x)),forall(y,equal(y,y))))",
    );
    solve(&mut state, 5, package);
    let b_family = state.question(b_id).unwrap().question().resolution_id();
    assert!(
        matches!(state.families().get(&b_family),Some(FamilyResult::Completed{outcome:ProofOutcome::Refuted,author:a,..}) if *a==author(5))
    );
    assert_eq!(
        state.library().lookup(helper.0).unwrap().coordinate(),
        admitted
    );
    assert_eq!(
        state.library().lookup(helper.0).unwrap().recipient(),
        author(4)
    );
    assert_eq!(state.balances().account(author(4)), Some(800_000_000));
    assert_eq!(state.balances().account(author(5)), Some(600_000_000));
    for index in 0..4 {
        assert_eq!(state.balances().account(author(index)), Some(100_000_000));
    }
    assert_eq!(state.balances().reserve(), 200_000_000);
    assert_eq!(state.claims().len(), 2);
    let c_id = submit(&mut state, "forall(x,equal(x,x))");
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert_eq!(
        state.question(c_id).unwrap().status(),
        QuestionStatus::KnownUnpaid
    );
    assert!(state.active().is_none());
    assert_eq!(state.balances().paid_completions(), 2);
    assert_eq!(state.claims().len(), 2);
    assert_eq!(state.library().len(), 3);
    state
        .balances()
        .verify_conservation(state.genesis())
        .unwrap();
}

#[test]
fn multiple_reveals_share_budget_before_any_additional_checker_call() {
    use crate::profile::{Limits, Profile, TimingKind};
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            checker_calls_per_record: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = ResearchState::new(crate::test_support::genesis_with_profile(profile));
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let first = commit_original(&mut state, 4, round, [4; 32]);
    let second = commit_original(&mut state, 5, round, [5; 32]);
    start_reveal(&mut state);
    let mut used = VerificationWork::default();
    let target = state.active_question().unwrap().question();
    state
        .library()
        .normalize_with_work(
            first.package(),
            target,
            state.genesis().profile(),
            &mut used,
        )
        .unwrap();
    assert_eq!(used.checker_calls, 2);
    let before = used;
    assert!(
        state
            .library()
            .normalize_with_work(
                second.package(),
                target,
                state.genesis().profile(),
                &mut used
            )
            .is_err()
    );
    assert_eq!(used, before); // Rejected before a third checker call is charged or executed.
    let first = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret: [4; 32],
            original: first,
        },
    );
    let second = signed(
        &state,
        5,
        OperationBody::Reveal {
            round,
            secret: [5; 32],
            original: second,
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(
                time(&state, state.time()),
                vec![first.clone(), second.clone()]
            )
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    let now = state.time();
    apply(&mut state, now, vec![first]);
    apply(&mut state, now, vec![second]);
    finish(&mut state);
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
}

#[test]
fn minimum_65_record_run_terminates_before_unfunded_opening_and_preserves_reads() {
    use crate::profile::{Limits, Profile, TimingKind};
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            run_records: 65,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = ResearchState::new(crate::test_support::genesis_with_profile(profile));
    let submitted = submit(&mut state, "forall(x,equal(x,x))");
    assert_eq!(state.remaining_records(), 64);
    assert_eq!(state.reserved_records(), 0);
    assert_eq!(
        state.question(submitted).unwrap().status(),
        QuestionStatus::Queued
    );
    let new_action = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "cannot spend terminal capacity".into(),
            question: question(&state, "forall(x,member(x,x))"),
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![new_action.clone()])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert!(state.terminated());
    assert!(state.active().is_none());
    assert_eq!(state.queued().count(), 0);
    assert_eq!(
        state.question(submitted).unwrap().status(),
        QuestionStatus::CapacityEnd
    );
    assert!(
        state
            .question(submitted)
            .unwrap()
            .opened_question()
            .is_none()
    );
    assert!(state.receipt(submitted).is_some());
    assert_eq!(state.balances().paid_completions(), 0);
    let terminal = state.commitment();
    for operations in [vec![], vec![new_action]] {
        assert!(
            state
                .prepare_record(time(&state, state.time()), operations)
                .is_err()
        );
        assert_eq!(state.commitment(), terminal);
    }
    assert_eq!(state.questions().count(), 1);
    assert_eq!(state.library().len(), 0);
}

#[test]
fn minimum_66_record_run_protects_active_slots_and_settles_timely_reveal_after_pause() {
    use crate::profile::{Limits, Profile, TimingKind};
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            run_records: 66,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = ResearchState::new(crate::test_support::genesis_with_profile(profile));
    let submitted = submit(&mut state, "forall(x,equal(x,x))");
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert_eq!(state.remaining_records(), 64);
    assert_eq!(state.reserved_records(), 63);
    assert_eq!(
        state.remaining_bytes(),
        64 * state.genesis().profile().limits().record_bytes
    );
    assert_eq!(
        state.reserved_bytes(),
        63 * state.genesis().profile().limits().record_bytes
    );
    let unrelated = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "must not consume completion reservation".into(),
            question: question(&state, "forall(x,member(x,x))"),
        },
    );
    let before = state.commitment();
    let nonce = state.next_nonce(author(5));
    assert!(
        state
            .prepare_record(time(&state, now), vec![unrelated])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    assert_eq!(state.next_nonce(author(5)), nonce);
    assert_eq!(state.questions().count(), 1);
    let active = state.active().unwrap();
    let votes = (0..3)
        .map(|index| {
            signed(
                &state,
                index,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    apply(&mut state, now, votes);
    apply(&mut state, active.deadline.unwrap(), vec![]);
    let now = state.time();
    apply(&mut state, now, vec![]);
    let round = state.active().unwrap().solution_round.unwrap();
    let original = commit_original(&mut state, 4, round, [4; 32]);
    let root = original.package().root();
    start_reveal(&mut state);
    let reveal = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret: [4; 32],
            original,
        },
    );
    let now = state.time();
    apply(&mut state, now, vec![reveal]);
    assert!(state.library().lookup(root).is_none());
    assert_eq!(state.balances().paid_completions(), 0);
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(&mut state, deadline, vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::SettlementPending);
    assert_eq!(state.remaining_records(), state.reserved_records() + 1);
    // A later certificate after a pause does not retroactively make the
    // already admitted, timely reveal ineligible for mandatory settlement.
    apply(&mut state, deadline + 10000, vec![]);
    assert_eq!(
        state.question(submitted).unwrap().status(),
        QuestionStatus::Completed
    );
    assert!(state.library().lookup(root).is_some());
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
    assert_eq!(state.claims().len(), 1);
    assert_eq!(state.reserved_records(), 0);
    assert_eq!(state.reserved_bytes(), 0);
    let new_action = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "no unreserved next attempt".into(),
            question: question(&state, "forall(x,member(x,x))"),
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![new_action])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert!(state.terminated());
    assert!(state.library().lookup(root).is_some());
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
    assert_eq!(state.claims().len(), 1);
    assert!(state.prepare_record(time(&state, now), vec![]).is_err());
}

#[test]
fn actual_queue_limit_and_exact_expiry_preserve_state_on_rejection() {
    use crate::profile::{Limits, Profile, TimingKind};
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            queued_questions: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = ResearchState::new(crate::test_support::genesis_with_profile(profile));
    let active = submit(&mut state, "forall(x,equal(x,x))");
    let queued = submit(&mut state, "forall(x,member(x,x))");
    assert_eq!(
        state.question(active).unwrap().status(),
        QuestionStatus::Active
    );
    assert_eq!(state.queued().count(), 1);
    let excess = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "queue already full".into(),
            question: question(&state, "forall(x,forall(y,equal(x,y)))"),
        },
    );
    let before = state.commitment();
    let nonce = state.next_nonce(author(5));
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![excess])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    assert_eq!(state.next_nonce(author(5)), nonce);
    let expires = state.question(queued).unwrap().expires();
    apply(&mut state, expires - 1, vec![]);
    assert_eq!(
        state.question(queued).unwrap().status(),
        QuestionStatus::Queued
    );
    assert_eq!(state.queued().count(), 1);
    apply(&mut state, expires, vec![]);
    assert_eq!(
        state.question(queued).unwrap().status(),
        QuestionStatus::Expired
    );
    assert_eq!(state.queued().count(), 0);
    assert!(state.question(queued).unwrap().opened_question().is_none());
    assert_eq!(state.balances().paid_completions(), 0);
}

mod golden;

mod queue_boundary;

mod capacity_sixteen;
