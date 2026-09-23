use super::*;
use crate::{
    authority::{CandidateAdmissionOffer, HandoffPlan, UnitOrigin},
    operations::JoinIntent,
    test_support::{account, genesis, handoff_plan, period_key},
    time::SignedTimeReport,
};
use ed25519_dalek::SigningKey;

fn time_for(state: &LedgerState) -> TimeCertificate {
    let reports = (0..3)
        .map(|index| {
            SignedTimeReport::sign(
                state.genesis(),
                state.authority(),
                state.head(),
                state.height() + 1,
                state.time(),
                &period_key(index, state.authority().effective_height(), 1),
            )
            .unwrap()
        })
        .collect();
    TimeCertificate::new(
        reports,
        state.genesis(),
        state.authority(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap()
}

fn candidate(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[allow(clippy::too_many_arguments)]
fn join_operation(
    state: &LedgerState,
    account_index: u8,
    family: ResolutionId,
    ordinal: u64,
    nonce: u64,
    consensus: &SigningKey,
    transport: &SigningKey,
    endpoint: &str,
) -> SignedOperation {
    let author_key = account(account_index);
    let author = AccountId::for_key(author_key.verifying_key().as_bytes());
    let intent = JoinIntent::new(
        state.genesis(),
        author,
        nonce,
        family,
        ordinal,
        consensus,
        transport,
        endpoint.into(),
    )
    .unwrap();
    OperationBody::JoinIntent(intent)
        .sign(state.genesis(), nonce, &author_key)
        .unwrap()
}

// Establishes the same conservation relationship as a paid completion while
// focusing these tests on the separate join-admission boundary.
fn state_with_claim() -> (LedgerState, ResolutionId, AccountId) {
    let mut state = LedgerState::new(genesis());
    let family = ResolutionId::from_bytes([88; 32]);
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let genesis = state.genesis().clone();
    let rewards = RewardPlan::new(&genesis, state.authority(), author, vec![]).unwrap();
    state
        .balances
        .apply(&rewards, &genesis, &state.accounts)
        .unwrap();
    state.claims.insert(
        family,
        EligibilityClaim {
            family,
            author,
            completion_ordinal: 1,
        },
    );
    state.families.insert(
        family,
        FamilyResult::Completed {
            proof: ProofId::from_bytes([77; 32]),
            author,
            outcome: ProofOutcome::Proved,
            ordinal: 1,
            normalization_receipt: Arc::from(Vec::<u8>::new()),
        },
    );
    (state, family, author)
}

#[test]
fn only_earlier_paid_claim_author_can_finalize_an_intent() {
    let (state, family, author) = state_with_claim();
    let consensus = candidate(71);
    let transport = candidate(72);
    let join = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    assert!(state.can_submit_join_intent(author, family, 1));
    let original_commitment = state.commitment();
    let execution = state
        .execute(time_for(&state), vec![join.clone()], handoff_plan(&state))
        .unwrap();
    let joined = execution.state();
    let entry = joined.join_intent(family).unwrap();
    assert_eq!(entry.receipt().operation, join.id());
    assert_eq!(entry.signed_operation(), join.encode().as_slice());
    assert_eq!(entry.intent().family(), family);
    assert_eq!(joined.claims().get(&family), state.claims().get(&family));
    assert_eq!(joined.genesis().validators(), state.genesis().validators());
    assert_ne!(joined.commitment(), original_commitment);
    assert!(joined.can_submit_join_intent(author, family, 1));
    let candidate_vote = OperationBody::Vote {
        question: QuestionId::from_bytes([8; 32]),
        attempt: 1,
        yes: true,
    }
    .sign(joined.genesis(), 1, &consensus)
    .unwrap();
    assert!(matches!(
        joined.execute(time_for(joined), vec![candidate_vote], handoff_plan(joined)),
        Err(LedgerError::Invalid("unregistered action account"))
    ));

    let missing = LedgerState::new(genesis());
    let absent = join_operation(
        &missing,
        4,
        family,
        1,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    assert!(matches!(
        missing.execute(time_for(&missing), vec![absent], handoff_plan(&missing)),
        Err(LedgerError::Invalid(
            "join intent requires earlier sealed claim"
        ))
    ));
    let foreign = join_operation(
        &state,
        5,
        family,
        1,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    assert!(matches!(
        state.execute(time_for(&state), vec![foreign], handoff_plan(&state)),
        Err(LedgerError::Invalid("join intent claim attribution"))
    ));
    let wrong_ordinal = join_operation(
        &state,
        4,
        family,
        2,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    assert!(matches!(
        state.execute(time_for(&state), vec![wrong_ordinal], handoff_plan(&state)),
        Err(LedgerError::Invalid("join intent claim attribution"))
    ));
}

#[test]
fn author_can_replace_current_intent_without_gaining_authority() {
    let (state, family, author) = state_with_claim();
    let consensus = candidate(71);
    let transport = candidate(72);
    let join = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    let joined = state
        .execute(time_for(&state), vec![join.clone()], handoff_plan(&state))
        .unwrap()
        .bind_record(RecordId::from_bytes([99; 32]));
    assert_eq!(joined.receipt(join.id()).unwrap().operation, join.id());
    let conflicting_nonce = join_operation(
        &joined,
        4,
        family,
        1,
        1,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    let before = joined.commitment();
    assert!(matches!(
        joined.execute(
            time_for(&joined),
            vec![conflicting_nonce],
            handoff_plan(&joined)
        ),
        Err(LedgerError::Invalid("action is not exact next nonce"))
    ));
    assert_eq!(joined.commitment(), before);
    let second = join_operation(
        &joined,
        4,
        family,
        1,
        2,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    let replaced = joined
        .execute(
            time_for(&joined),
            vec![join.clone(), second.clone()],
            handoff_plan(&joined),
        )
        .unwrap()
        .bind_record(RecordId::from_bytes([98; 32]));
    assert_eq!(
        replaced.join_intent(family).unwrap().receipt().operation,
        second.id()
    );
    assert_eq!(replaced.receipt(join.id()).unwrap().operation, join.id());
    assert_eq!(
        replaced.receipt(second.id()).unwrap().operation,
        second.id()
    );
    assert_eq!(replaced.claims().get(&family), state.claims().get(&family));
    let again = join_operation(
        &replaced,
        4,
        family,
        1,
        3,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    let updated = replaced
        .execute(
            time_for(&replaced),
            vec![again.clone()],
            handoff_plan(&replaced),
        )
        .unwrap()
        .bind_record(RecordId::from_bytes([97; 32]));
    assert_eq!(
        updated.join_intent(family).unwrap().receipt().operation,
        again.id()
    );
    let collision = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &candidate(73),
        &candidate(74),
        &state.genesis().validators()[0].endpoint,
    );
    assert!(
        state
            .execute(time_for(&state), vec![collision], handoff_plan(&state))
            .is_err()
    );
    assert!(
        SignedTimeReport::sign(
            updated.genesis(),
            updated.authority(),
            updated.head(),
            updated.height() + 1,
            updated.time(),
            &consensus,
        )
        .is_err()
    );
    assert!(
        updated
            .genesis()
            .validators()
            .iter()
            .all(|v| v.owner != author)
    );
}

#[test]
fn candidate_key_cannot_reuse_a_later_registered_account_key() {
    let (mut state, family, _) = state_with_claim();
    let reused = candidate(75);
    let account = AccountId::for_key(reused.verifying_key().as_bytes());
    state
        .accounts
        .insert(account, reused.verifying_key().to_bytes());
    state.next_nonce.insert(account, 1);
    state.balances.register(account).unwrap();
    let join = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &reused,
        &candidate(76),
        "127.0.0.1:42000",
    );
    assert!(matches!(
        state.execute(time_for(&state), vec![join], handoff_plan(&state)),
        Err(LedgerError::Invalid("join intent key roles overlap"))
    ));
}

#[test]
fn another_pending_intent_reserves_its_keys_and_endpoint() {
    let (mut state, family, _) = state_with_claim();
    let other_family = ResolutionId::from_bytes([89; 32]);
    let other_author = AccountId::for_key(account(5).verifying_key().as_bytes());
    let genesis = state.genesis().clone();
    let rewards = RewardPlan::new(&genesis, state.authority(), other_author, vec![]).unwrap();
    state
        .balances
        .apply(&rewards, &genesis, &state.accounts)
        .unwrap();
    state.claims.insert(
        other_family,
        EligibilityClaim {
            family: other_family,
            author: other_author,
            completion_ordinal: 2,
        },
    );
    state.families.insert(
        other_family,
        FamilyResult::Completed {
            proof: ProofId::from_bytes([78; 32]),
            author: other_author,
            outcome: ProofOutcome::Proved,
            ordinal: 2,
            normalization_receipt: Arc::from(Vec::<u8>::new()),
        },
    );
    let first = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &candidate(71),
        &candidate(72),
        "127.0.0.1:42000",
    );
    let joined = state
        .execute(time_for(&state), vec![first.clone()], handoff_plan(&state))
        .unwrap()
        .bind_record(RecordId::from_bytes([99; 32]));
    for (consensus, transport, endpoint, reason) in [
        (71, 73, "127.0.0.1:42001", "join intent key roles overlap"),
        (
            73,
            74,
            "127.0.0.1:42000",
            "join intent endpoint already reserved",
        ),
    ] {
        let other = join_operation(
            &joined,
            5,
            other_family,
            2,
            1,
            &candidate(consensus),
            &candidate(transport),
            endpoint,
        );
        let before = joined.commitment();
        assert!(matches!(
            joined.execute(time_for(&joined), vec![other], handoff_plan(&joined)),
            Err(LedgerError::Invalid(message)) if message == reason
        ));
        assert_eq!(joined.commitment(), before);
        assert_eq!(
            joined.join_intent(family).unwrap().receipt().operation,
            first.id()
        );
        assert!(joined.join_intent(other_family).is_none());
    }
}

#[test]
fn selected_claim_handoff_replaces_oldest_slot_and_retires_old_keys() {
    let (state, family, author) = state_with_claim();
    let candidate_consensus = candidate(71);
    let candidate_transport = candidate(72);
    let intent = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &candidate_consensus,
        &candidate_transport,
        "127.0.0.1:42000",
    );
    let joined = state
        .execute(time_for(&state), vec![intent.clone()], handoff_plan(&state))
        .unwrap()
        .bind_record(RecordId::from_bytes([99; 32]));
    assert_eq!(joined.join_queue().front(), Some(&family));
    assert_eq!(
        joined
            .join_intent(family)
            .unwrap()
            .first_receipt()
            .operation,
        intent.id()
    );
    let outgoing = joined.authority().oldest().clone();
    let old_consensus = *outgoing.keys().unwrap().consensus();
    let readiness = CandidateAdmissionOffer::sign(
        joined.authority(),
        joined.head(),
        joined.commitment(),
        family,
        intent.id(),
        &account(4),
        &candidate_consensus,
        &candidate_transport,
        "127.0.0.1:42000".into(),
    )
    .unwrap();
    let plan = HandoffPlan::new(handoff_plan(&joined).offers().to_vec(), Some(readiness)).unwrap();
    assert_eq!(HandoffPlan::decode(&plan.encode()).unwrap(), plan);
    let next = joined
        .execute(time_for(&joined), vec![], plan)
        .unwrap()
        .bind_record(RecordId::from_bytes([100; 32]));
    assert_eq!(next.authority().effective_height(), 3);
    assert_eq!(
        next.authority().slot(outgoing.slot()).unwrap().owner(),
        author
    );
    assert!(
        matches!(next.authority().slot(outgoing.slot()).unwrap().origin(),
        UnitOrigin::Earned { family: installed, completion_ordinal: 1 } if installed == family)
    );
    assert!(next.authority().consensus_unit(&old_consensus).is_none());
    assert!(next.consumed_claims().contains(&family));
    assert!(next.join_queue().is_empty());
    assert!(next.claims().contains_key(&family));
    assert!(next.used_period_keys().contains(&old_consensus));
    assert!(!next.can_submit_join_intent(author, family, 1));
}

#[test]
fn certified_handoff_skips_a_claim_expiring_at_the_record_time() {
    let (mut state, first_family, _) = state_with_claim();
    let second_family = ResolutionId::from_bytes([89; 32]);
    let second_author = AccountId::for_key(account(5).verifying_key().as_bytes());
    let rewards =
        RewardPlan::new(state.genesis(), state.authority(), second_author, vec![]).unwrap();
    state
        .balances
        .apply(&rewards, &state.genesis, &state.accounts)
        .unwrap();
    state.claims.insert(
        second_family,
        EligibilityClaim {
            family: second_family,
            author: second_author,
            completion_ordinal: 2,
        },
    );
    state.families.insert(
        second_family,
        FamilyResult::Completed {
            proof: ProofId::from_bytes([78; 32]),
            author: second_author,
            outcome: ProofOutcome::Proved,
            ordinal: 2,
            normalization_receipt: Arc::from(Vec::<u8>::new()),
        },
    );
    let first = join_operation(
        &state,
        4,
        first_family,
        1,
        1,
        &candidate(71),
        &candidate(72),
        "127.0.0.1:42000",
    );
    let state = state
        .execute(time_for(&state), vec![first], handoff_plan(&state))
        .unwrap()
        .bind_record(RecordId::from_bytes([98; 32]));
    let at = |state: &LedgerState, seconds| {
        let reports = (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.authority(),
                    state.head(),
                    state.height() + 1,
                    seconds,
                    &period_key(i, state.authority().effective_height(), 1),
                )
                .unwrap()
            })
            .collect();
        TimeCertificate::new(
            reports,
            state.genesis(),
            state.authority(),
            state.head(),
            state.height() + 1,
            state.time(),
        )
        .unwrap()
    };
    let second = join_operation(
        &state,
        5,
        second_family,
        2,
        1,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    let state = state
        .execute(
            at(&state, state.time() + 1),
            vec![second.clone()],
            handoff_plan(&state),
        )
        .unwrap()
        .bind_record(RecordId::from_bytes([99; 32]));
    let expires = state.join_intent(first_family).unwrap().expires();
    assert!(state.join_intent(second_family).unwrap().expires() > expires);
    let readiness = CandidateAdmissionOffer::sign(
        state.authority(),
        state.head(),
        state.commitment(),
        second_family,
        second.id(),
        &account(5),
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001".into(),
    )
    .unwrap();
    let plan = HandoffPlan::new(handoff_plan(&state).offers().to_vec(), Some(readiness)).unwrap();
    assert!(state.prepare_handoff(&plan).is_err());
    assert!(
        state
            .prepare_handoff_certified(&plan, &at(&state, expires - 1))
            .is_err()
    );
    let time = at(&state, expires);
    let incoming = state.prepare_handoff_certified(&plan, &time).unwrap();
    let execution = state.execute(time, vec![], plan).unwrap();
    assert_eq!(execution.state().authority(), &incoming);
    assert!(incoming.owner(second_author).is_some());
    assert!(execution.state().consumed_claims().contains(&second_family));
    assert!(!execution.state().consumed_claims().contains(&first_family));
}

#[test]
fn expired_join_admission_cannot_be_revived_by_a_new_revision() {
    let (state, family, _) = state_with_claim();
    let original = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &candidate(71),
        &candidate(72),
        "127.0.0.1:42000",
    );
    let joined = state
        .execute(time_for(&state), vec![original], handoff_plan(&state))
        .unwrap()
        .bind_record(RecordId::from_bytes([94; 32]));
    let entry = joined.join_intent(family).unwrap().clone();
    let reports = (0..3)
        .map(|i| {
            SignedTimeReport::sign(
                joined.genesis(),
                joined.authority(),
                joined.head(),
                joined.height() + 1,
                entry.expires(),
                &period_key(i, joined.authority().effective_height(), 1),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(
        reports,
        joined.genesis(),
        joined.authority(),
        joined.head(),
        joined.height() + 1,
        joined.time(),
    )
    .unwrap();
    let revision = join_operation(
        &joined,
        4,
        family,
        1,
        2,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    assert!(matches!(
        joined.execute(time.clone(), vec![revision], handoff_plan(&joined)),
        Err(LedgerError::Invalid(
            "join intent admission expired or closed"
        ))
    ));
    let expired = joined
        .execute(time, vec![], handoff_plan(&joined))
        .unwrap()
        .bind_record(RecordId::from_bytes([95; 32]));
    assert!(!expired.join_queue().contains(&family));
    assert_eq!(
        expired.join_intent(family).unwrap().first_receipt(),
        entry.first_receipt()
    );
    assert_eq!(
        expired.join_intent(family).unwrap().expires(),
        entry.expires()
    );
    let before = expired.commitment();
    let revision = join_operation(
        &expired,
        4,
        family,
        1,
        2,
        &candidate(73),
        &candidate(74),
        "127.0.0.1:42001",
    );
    assert!(matches!(
        expired.execute(time_for(&expired), vec![revision], handoff_plan(&expired)),
        Err(LedgerError::Invalid(
            "join intent admission expired or closed"
        ))
    ));
    assert_eq!(expired.commitment(), before);
}

#[test]
fn attempt_opening_at_handoff_freezes_outgoing_owners_for_later_ballots() {
    let (state, family, _) = state_with_claim();
    let consensus = candidate(71);
    let transport = candidate(72);
    let intent = join_operation(
        &state,
        4,
        family,
        1,
        1,
        &consensus,
        &transport,
        "127.0.0.1:42000",
    );
    let question = OperationBody::Submit {
        purpose: "frozen research electorate".into(),
        question: crate::question::CompiledQuestion::compile(
            "foundation = \"naome:zfc\" statement = forall(x,equal(x,x))",
            state.genesis().profile(),
        )
        .unwrap(),
    }
    .sign(state.genesis(), 1, &account(5))
    .unwrap();
    let parent = state
        .execute(
            time_for(&state),
            vec![intent.clone(), question],
            handoff_plan(&state),
        )
        .unwrap()
        .bind_record(RecordId::from_bytes([101; 32]));
    let outgoing = parent
        .authority()
        .units()
        .iter()
        .map(|unit| unit.owner())
        .collect::<Vec<_>>();
    let retired = parent.authority().oldest().owner();
    assert_eq!(
        retired,
        AccountId::for_key(account(2).verifying_key().as_bytes())
    );
    let candidate = CandidateAdmissionOffer::sign(
        parent.authority(),
        parent.head(),
        parent.commitment(),
        family,
        intent.id(),
        &account(4),
        &consensus,
        &transport,
        "127.0.0.1:42000".into(),
    )
    .unwrap();
    let plan = HandoffPlan::new(handoff_plan(&parent).offers().to_vec(), Some(candidate)).unwrap();
    let selected = parent
        .execute(time_for(&parent), vec![], plan)
        .unwrap()
        .bind_record(RecordId::from_bytes([102; 32]));
    let active = selected.active().unwrap();
    assert_eq!(active.phase, Phase::Voting);
    assert_eq!(active.electorate.as_slice(), outgoing.as_slice());
    assert!(selected.authority().owner(retired).is_none());
    let time = TimeCertificate::new(
        [0, 1, 3]
            .into_iter()
            .map(|i| {
                SignedTimeReport::sign(
                    selected.genesis(),
                    selected.authority(),
                    selected.head(),
                    selected.height() + 1,
                    selected.time(),
                    &period_key(i, selected.authority().effective_height(), 1),
                )
                .unwrap()
            })
            .collect(),
        selected.genesis(),
        selected.authority(),
        selected.head(),
        selected.height() + 1,
        selected.time(),
    )
    .unwrap();
    let ballot = |i| {
        let owner = AccountId::for_key(account(i).verifying_key().as_bytes());
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        }
        .sign(
            selected.genesis(),
            selected.next_nonce(owner).unwrap(),
            &account(i),
        )
        .unwrap()
    };
    let before = selected.commitment();
    assert!(
        selected
            .execute(time.clone(), vec![ballot(4)], handoff_plan(&selected))
            .is_err()
    );
    assert_eq!(selected.commitment(), before);
    let voted = selected
        .execute(time, vec![ballot(2)], handoff_plan(&selected))
        .unwrap()
        .bind_record(RecordId::from_bytes([103; 32]));
    assert_eq!(voted.active().unwrap().electorate, active.electorate);
    assert_eq!(voted.active().unwrap().votes.get(&retired), Some(&true));
}

#[test]
fn join_endpoint_ownership_comes_from_both_live_rosters_not_genesis_forever() {
    let (state, family, _) = state_with_claim();
    let plan_at_new_endpoints = |parent: &LedgerState| {
        let mut offers: Vec<_> = parent
            .authority()
            .units()
            .iter()
            .map(|unit| {
                let index = (0..4)
                    .find(|i| {
                        AccountId::for_key(account(*i).verifying_key().as_bytes()) == unit.owner()
                    })
                    .unwrap();
                let height = parent.authority().effective_height() + 1;
                crate::authority::NextPeriodKeys::sign(
                    parent.authority(),
                    parent.head(),
                    parent.commitment(),
                    unit.id(),
                    &account(index),
                    &period_key(index, height, 1),
                    &period_key(index, height, 2),
                    format!("127.0.0.1:{}", 43000 + u16::from(index)),
                )
                .unwrap()
            })
            .collect();
        offers.sort_by_key(crate::authority::NextPeriodKeys::unit);
        HandoffPlan::new(offers, None).unwrap()
    };
    let original = state.genesis().validators()[0].endpoint.clone();
    let plan = plan_at_new_endpoints(&state);
    for occupied in [&original, plan.offers()[0].keys().endpoint()] {
        let intent = join_operation(
            &state,
            4,
            family,
            1,
            1,
            &candidate(71),
            &candidate(72),
            occupied,
        );
        assert!(
            state
                .execute(time_for(&state), vec![intent], plan.clone())
                .is_err()
        );
    }
    let rotated = state
        .execute(time_for(&state), vec![], plan)
        .unwrap()
        .bind_record(RecordId::from_bytes([95; 32]));
    let intent = join_operation(
        &rotated,
        4,
        family,
        1,
        1,
        &candidate(71),
        &candidate(72),
        &original,
    );
    let admitted = rotated
        .execute(
            time_for(&rotated),
            vec![intent],
            plan_at_new_endpoints(&rotated),
        )
        .unwrap()
        .bind_record(RecordId::from_bytes([96; 32]));
    assert_eq!(
        admitted.join_intent(family).unwrap().intent().endpoint(),
        original
    );
    assert_eq!(
        admitted.join_queue().iter().copied().collect::<Vec<_>>(),
        vec![family]
    );
}
