use super::*;
use crate::{
    operations::JoinIntent,
    test_support::{account, genesis, validator},
    time::SignedTimeReport,
};
use ed25519_dalek::SigningKey;

fn time_for(state: &LedgerState) -> TimeCertificate {
    let reports = (0..3)
        .map(|index| {
            SignedTimeReport::sign(
                state.genesis(),
                state.head(),
                state.height() + 1,
                state.time(),
                &validator(index),
            )
            .unwrap()
        })
        .collect();
    TimeCertificate::new(
        reports,
        state.genesis(),
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
    let rewards = RewardPlan::new(&genesis, author, vec![]).unwrap();
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
    let execution = state.execute(time_for(&state), vec![join.clone()]).unwrap();
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
        joined.execute(time_for(joined), vec![candidate_vote]),
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
        missing.execute(time_for(&missing), vec![absent]),
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
        state.execute(time_for(&state), vec![foreign]),
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
        state.execute(time_for(&state), vec![wrong_ordinal]),
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
        .execute(time_for(&state), vec![join.clone()])
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
        joined.execute(time_for(&joined), vec![conflicting_nonce]),
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
        .execute(time_for(&joined), vec![join.clone(), second.clone()])
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
        .execute(time_for(&replaced), vec![again.clone()])
        .unwrap()
        .bind_record(RecordId::from_bytes([97; 32]));
    assert_eq!(
        updated.join_intent(family).unwrap().receipt().operation,
        again.id()
    );
    assert!(matches!(
        JoinIntent::new(
            state.genesis(),
            author,
            1,
            family,
            1,
            &candidate(73),
            &candidate(74),
            state.genesis().validators()[0].endpoint.clone(),
        ),
        Err(LedgerError::Invalid("join endpoint already assigned"))
    ));
    assert!(
        SignedTimeReport::sign(
            updated.genesis(),
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
        state.execute(time_for(&state), vec![join]),
        Err(LedgerError::Invalid("join intent key roles overlap"))
    ));
}

#[test]
fn another_pending_intent_reserves_its_keys_and_endpoint() {
    let (mut state, family, _) = state_with_claim();
    let other_family = ResolutionId::from_bytes([89; 32]);
    let other_author = AccountId::for_key(account(5).verifying_key().as_bytes());
    let genesis = state.genesis().clone();
    let rewards = RewardPlan::new(&genesis, other_author, vec![]).unwrap();
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
        .execute(time_for(&state), vec![first.clone()])
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
            joined.execute(time_for(&joined), vec![other]),
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
