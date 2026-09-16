use super::evidence::VoteBody;
use super::*;
use crate::{ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget, ProposalSigningRoot};
use ed25519_dalek::{Signer, SigningKey};
use naome_research::{
    AccountId, ResearchState,
    operations::OperationBody,
    profile::{Genesis, Profile, RESEARCH_CHECKER_PROFILE, ValidatorRegistration},
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};

const MAX_ROUND: u64 = 32;
fn account(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 1; 32])
}
fn validator(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 101; 32])
}
fn validator_key(i: u8) -> ConsensusKey {
    ConsensusKey::from_bytes(validator(i).verifying_key().to_bytes())
}
fn genesis() -> Genesis {
    Genesis::new(
        Profile::short_test(),
        "naome:zfc".into(),
        RESEARCH_CHECKER_PROFILE.into(),
        1,
        100,
        [9; 32],
        (0..6)
            .map(|i| account(i).verifying_key().to_bytes())
            .collect(),
        (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(account(i).verifying_key().as_bytes()),
                consensus_key: validator(i).verifying_key().to_bytes(),
                transport_key: SigningKey::from_bytes(&[201 + i; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 42000 + u16::from(i)),
            })
            .collect(),
    )
    .unwrap()
}
fn branch() -> ResearchBranch {
    ResearchBranch::from_genesis(ResearchState::new(genesis())).unwrap()
}
fn signer_for(key: ConsensusKey) -> SigningKey {
    (0..4)
        .map(validator)
        .find(|sk| sk.verifying_key().as_bytes() == key.as_bytes())
        .unwrap()
}
fn record(branch: &ResearchBranch, purpose: &str) -> Vec<u8> {
    let state = branch.state();
    let genesis = state.genesis();
    let reports = (0..4)
        .map(|i| {
            SignedTimeReport::sign(
                genesis,
                state.head(),
                state.height() + 1,
                state.time(),
                &validator(i),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(
        reports,
        genesis,
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    let question = CompiledQuestion::compile(
        "foundation = \"naome:zfc\"\nstatement = forall(x,equal(x,x))",
        genesis.profile(),
    )
    .unwrap();
    let operation = OperationBody::Submit {
        purpose: purpose.into(),
        question,
    }
    .sign(genesis, 1, &account(4))
    .unwrap();
    state
        .prepare_record(time, vec![operation])
        .unwrap()
        .record()
        .encode()
        .unwrap()
}
fn proposal(
    branch: &ResearchBranch,
    record: Vec<u8>,
    round: u64,
    valid: Option<ResearchQuorum>,
) -> ResearchProposal {
    let signer = branch.proposer(round, MAX_ROUND).unwrap();
    let intent = branch
        .proposal_intent(record, round, signer, valid, MAX_ROUND)
        .unwrap();
    let signature = signer_for(signer).sign(&intent.signing_bytes()).to_bytes();
    intent.complete(signature, branch, MAX_ROUND).unwrap()
}
fn vote(
    branch: &ResearchBranch,
    round: u64,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    index: u8,
) -> ResearchVote {
    let body = VoteBody {
        genesis: branch.state().genesis().id(),
        profile: branch.state().genesis().profile().id(),
        height: branch.next_height().unwrap(),
        round,
        role,
        target,
    };
    let signer = validator_key(index);
    let signature = validator(index)
        .sign(&body.signing_bytes(signer))
        .to_bytes();
    ResearchVote::complete(body, signer, signature, branch.state().genesis()).unwrap()
}
fn quorum(
    branch: &ResearchBranch,
    round: u64,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> ResearchQuorum {
    ResearchQuorum::from_votes(
        (0..3)
            .map(|i| vote(branch, round, role, target, i))
            .collect(),
        branch.state().genesis(),
    )
    .unwrap()
}
fn target(proposal: &ResearchProposal) -> ConsensusVoteTarget {
    ConsensusVoteTarget::Proposal(proposal.value().signing_root())
}
fn lock(
    branch: &ResearchBranch,
    proposal: &ResearchProposal,
    signer: ConsensusKey,
) -> ResearchLockState {
    let mut state = ResearchLockState::new(branch, signer).unwrap();
    state
        .apply(
            branch,
            &ResearchLockEvent::Prevote {
                proposal: Some(proposal.encode().unwrap()),
            },
            MAX_ROUND,
        )
        .unwrap();
    let qc = quorum(branch, 0, ConsensusVoteRole::Prevote, target(proposal));
    state
        .apply(
            branch,
            &ResearchLockEvent::Precommit {
                proposal: Some(proposal.encode().unwrap()),
                quorum: qc.encode(),
            },
            MAX_ROUND,
        )
        .unwrap();
    state
}
fn higher(branch: &ResearchBranch, state: &mut ResearchLockState, round: u64) {
    let votes = ResearchVoteSet::new(
        (0..2)
            .map(|i| {
                vote(
                    branch,
                    round,
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Nil,
                    i,
                )
            })
            .collect(),
        branch.state().genesis(),
    )
    .unwrap();
    state
        .apply(
            branch,
            &ResearchLockEvent::HigherRound {
                votes: votes.encode(),
            },
            MAX_ROUND,
        )
        .unwrap();
}
fn vote_intent(intent: ResearchIntent) -> ResearchVoteIntent {
    match intent {
        ResearchIntent::Vote(v) => v,
        _ => panic!("expected vote"),
    }
}

#[test]
fn verified_control_record_finality_binds_full_state_and_preserves_empty_library() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "first question"), 0, None);
    assert_eq!(p.value().previous_state(), branch.state().commitment());
    assert_ne!(p.value().next_state(), branch.state().commitment());
    let qc = quorum(&branch, 0, ConsensusVoteRole::Precommit, target(&p));
    let finality = branch.verify_finality(&p, &qc, MAX_ROUND).unwrap();
    assert_eq!(finality.branch().state().height(), 1);
    assert_eq!(finality.branch().state().library().len(), 0);
    assert_eq!(finality.branch().state().questions().count(), 1);
    assert_eq!(
        finality.branch().commitment(),
        p.value().next_consensus_commitment()
    );
    let replay = branch
        .decode_finality(&finality.encode().unwrap(), MAX_ROUND)
        .unwrap();
    assert_eq!(replay.branch().commitment(), finality.branch().commitment());
    assert_eq!(replay.branch().state().commitment(), p.value().next_state());
}

#[test]
fn finality_evidence_subset_and_consensus_round_do_not_change_value_or_successor() {
    let branch = branch();
    let bytes = record(&branch, "same content");
    let p0 = proposal(&branch, bytes.clone(), 0, None);
    let p3 = proposal(&branch, bytes, 3, None);
    assert_eq!(p0.value(), p3.value());
    let target = target(&p0);
    let q3 = quorum(&branch, 0, ConsensusVoteRole::Precommit, target);
    let q4 = ResearchQuorum::from_votes(
        (0..4)
            .map(|i| vote(&branch, 0, ConsensusVoteRole::Precommit, target, i))
            .collect(),
        branch.state().genesis(),
    )
    .unwrap();
    let a = branch.verify_finality(&p0, &q3, MAX_ROUND).unwrap();
    let b = branch.verify_finality(&p0, &q4, MAX_ROUND).unwrap();
    assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    assert_eq!(a.branch().commitment(), b.branch().commitment());
    let late = branch
        .verify_finality(
            &p3,
            &quorum(&branch, 3, ConsensusVoteRole::Precommit, target),
            MAX_ROUND,
        )
        .unwrap();
    assert_eq!(a.branch().commitment(), late.branch().commitment());
}

#[test]
fn two_votes_never_finalize_and_duplicate_signers_never_add_weight() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let t = target(&p);
    let two: Vec<_> = (0..2)
        .map(|i| vote(&branch, 0, ConsensusVoteRole::Precommit, t, i))
        .collect();
    assert!(ResearchQuorum::from_votes(two.clone(), branch.state().genesis()).is_err());
    let mut duplicates = two;
    duplicates.push(duplicates[0].clone());
    assert!(ResearchQuorum::from_votes(duplicates, branch.state().genesis()).is_err());
    let wrong_role = quorum(&branch, 0, ConsensusVoteRole::Prevote, t);
    assert!(branch.verify_finality(&p, &wrong_role, MAX_ROUND).is_err());
    let wrong_target = quorum(
        &branch,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    assert!(
        branch
            .verify_finality(&p, &wrong_target, MAX_ROUND)
            .is_err()
    );
}

#[test]
fn current_prevote_quorum_locks_exact_record_and_rejects_second_votes() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let mut state = lock(&branch, &p, validator_key(0));
    assert_eq!(state.locked_value(), Some((p.value(), 0)));
    assert_eq!(state.valid_value(), Some((p.value(), 0)));
    assert_eq!(state.retained_record(), Some(p.record_bytes()));
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(&branch, &ResearchLockEvent::ProposalTimeout, MAX_ROUND)
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
}

#[test]
fn lock_survives_missing_or_conflicting_proposal_and_higher_round_catchup() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "first"), 0, None);
    let mut state = lock(&branch, &p, validator_key(0));
    higher(&branch, &mut state, 1);
    let conflict = proposal(&branch, record(&branch, "conflict"), 1, None);
    let intent = vote_intent(
        state
            .apply(
                &branch,
                &ResearchLockEvent::Prevote {
                    proposal: Some(conflict.encode().unwrap()),
                },
                MAX_ROUND,
            )
            .unwrap(),
    );
    assert_eq!(intent.target(), target(&p));
    assert_eq!(state.locked_value(), Some((p.value(), 0)));
    higher(&branch, &mut state, 2);
    let intent = vote_intent(
        state
            .apply(&branch, &ResearchLockEvent::ProposalTimeout, MAX_ROUND)
            .unwrap(),
    );
    assert_eq!(intent.target(), target(&p));
    assert_eq!(state.locked_value(), Some((p.value(), 0)));
}

#[test]
fn only_strictly_newer_valid_round_unlocks_a_different_value() {
    let branch = branch();
    let a = proposal(&branch, record(&branch, "a"), 0, None);
    let bbytes = record(&branch, "b");
    let b0 = proposal(&branch, bbytes.clone(), 0, None);
    let mut state = lock(&branch, &a, validator_key(0));
    higher(&branch, &mut state, 2);
    let stale = proposal(
        &branch,
        bbytes.clone(),
        2,
        Some(quorum(&branch, 0, ConsensusVoteRole::Prevote, target(&b0))),
    );
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::Prevote {
                    proposal: Some(stale.encode().unwrap())
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    let newer = proposal(
        &branch,
        bbytes,
        2,
        Some(quorum(&branch, 1, ConsensusVoteRole::Prevote, target(&b0))),
    );
    let intent = vote_intent(
        state
            .apply(
                &branch,
                &ResearchLockEvent::Prevote {
                    proposal: Some(newer.encode().unwrap()),
                },
                MAX_ROUND,
            )
            .unwrap(),
    );
    assert_eq!(intent.target(), target(&newer));
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), Some((newer.value(), 1)));
}

#[test]
fn retained_proposal_is_mandatory_and_keeps_exact_body_and_valid_qc() {
    let branch = branch();
    let bytes = record(&branch, "retained");
    let a = proposal(&branch, bytes.clone(), 0, None);
    let signer = branch.proposer(1, MAX_ROUND).unwrap();
    let mut state = lock(&branch, &a, signer);
    higher(&branch, &mut state, 1);
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::Author {
                    record: Some(record(&branch, "fresh forbidden"))
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    let intent = state
        .apply(
            &branch,
            &ResearchLockEvent::Author { record: None },
            MAX_ROUND,
        )
        .unwrap();
    let ResearchIntent::Proposal(intent) = intent else {
        panic!("proposal intent")
    };
    assert_eq!(intent.record_bytes(), bytes);
    assert_eq!(intent.value(), a.value());
    assert_eq!(intent.valid_quorum().unwrap().round(), 0);
    let signed = intent
        .complete(
            signer_for(signer).sign(&intent.signing_bytes()).to_bytes(),
            &branch,
            MAX_ROUND,
        )
        .unwrap();
    assert_eq!(signed.value(), a.value());
    assert_eq!(signed.record_bytes(), a.record_bytes());
}

#[test]
fn author_intent_cannot_conflict_or_use_unscheduled_signer() {
    let branch = branch();
    let signer = branch.proposer(0, MAX_ROUND).unwrap();
    let mut state = ResearchLockState::new(&branch, signer).unwrap();
    let event = ResearchLockEvent::Author {
        record: Some(record(&branch, "a")),
    };
    let first = state.apply(&branch, &event, MAX_ROUND).unwrap();
    assert_eq!(state.apply(&branch, &event, MAX_ROUND).unwrap(), first);
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::Author {
                    record: Some(record(&branch, "b"))
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    let other = (0..4)
        .map(validator_key)
        .find(|key| *key != signer)
        .unwrap();
    let mut wrong = ResearchLockState::new(&branch, other).unwrap();
    assert!(wrong.apply(&branch, &event, MAX_ROUND).is_err());
}

#[test]
fn quorum_progress_timers_require_correct_role_position_and_denominator() {
    let branch = branch();
    let mut state = ResearchLockState::new(&branch, validator_key(0)).unwrap();
    state
        .apply(&branch, &ResearchLockEvent::ProposalTimeout, MAX_ROUND)
        .unwrap();
    let votes = |count, role| {
        ResearchVoteSet::new(
            (0..count)
                .map(|i| {
                    vote(
                        &branch,
                        0,
                        role,
                        if i == 0 {
                            ConsensusVoteTarget::Nil
                        } else {
                            ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([i; 32]))
                        },
                        i,
                    )
                })
                .collect(),
            branch.state().genesis(),
        )
        .unwrap()
        .encode()
    };
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::PrevoteTimeout {
                    votes: votes(2, ConsensusVoteRole::Prevote)
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::PrevoteTimeout {
                    votes: votes(3, ConsensusVoteRole::Precommit)
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    let intent = vote_intent(
        state
            .apply(
                &branch,
                &ResearchLockEvent::PrevoteTimeout {
                    votes: votes(3, ConsensusVoteRole::Prevote),
                },
                MAX_ROUND,
            )
            .unwrap(),
    );
    assert_eq!(intent.role(), ConsensusVoteRole::Precommit);
    assert_eq!(intent.target(), ConsensusVoteTarget::Nil);
    state
        .apply(
            &branch,
            &ResearchLockEvent::PrecommitTimeout {
                votes: votes(3, ConsensusVoteRole::Precommit),
            },
            MAX_ROUND,
        )
        .unwrap();
    assert_eq!(state.phase(), ResearchPhase::Proposal);
    assert_eq!(state.round(), 1);
}

#[test]
fn higher_round_needs_two_distinct_signers_and_bounded_work() {
    let branch = branch();
    let mut state = ResearchLockState::new(&branch, validator_key(0)).unwrap();
    let singleton = ResearchVoteSet::new(
        vec![vote(
            &branch,
            2,
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
            0,
        )],
        branch.state().genesis(),
    )
    .unwrap();
    let before = state.snapshot().unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::HigherRound {
                    votes: singleton.encode()
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    let huge = ResearchVoteSet::new(
        (0..2)
            .map(|i| {
                vote(
                    &branch,
                    u64::MAX,
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Nil,
                    i,
                )
            })
            .collect(),
        branch.state().genesis(),
    )
    .unwrap();
    assert!(
        state
            .apply(
                &branch,
                &ResearchLockEvent::HigherRound {
                    votes: huge.encode()
                },
                MAX_ROUND
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap(), before);
    higher(&branch, &mut state, 2);
    assert_eq!(state.round(), 2);
    assert_eq!(state.phase(), ResearchPhase::Proposal);
}

#[test]
fn replay_events_restore_identical_lock_body_and_intents_before_any_key_use() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let signer = validator_key(0);
    let qc = quorum(&branch, 0, ConsensusVoteRole::Prevote, target(&p));
    let events = [
        ResearchLockEvent::Prevote {
            proposal: Some(p.encode().unwrap()),
        },
        ResearchLockEvent::Precommit {
            proposal: Some(p.encode().unwrap()),
            quorum: qc.encode(),
        },
    ];
    let mut live = ResearchLockState::new(&branch, signer).unwrap();
    let mut recovered = ResearchLockState::new(&branch, signer).unwrap();
    for event in events {
        let intent = live.apply(&branch, &event, MAX_ROUND).unwrap();
        let encoded = event.encode().unwrap();
        let decoded = ResearchLockEvent::decode(&encoded, branch.state().genesis()).unwrap();
        let replay = recovered.apply(&branch, &decoded, MAX_ROUND).unwrap();
        assert_eq!(intent, replay);
        assert_eq!(live.snapshot().unwrap(), recovered.snapshot().unwrap());
        let bytes = intent.signing_bytes().unwrap();
        let signature = validator(0).sign(&bytes).to_bytes();
        assert_eq!(
            intent.complete(signature, &branch, MAX_ROUND).unwrap(),
            replay.complete(signature, &branch, MAX_ROUND).unwrap()
        );
    }
    assert_eq!(live.retained_record(), recovered.retained_record());
    assert_eq!(live.retained_quorum(), recovered.retained_quorum());
}

#[test]
fn strict_evidence_and_proposal_decoders_reject_mutation_truncation_and_reordering() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let genesis = branch.state().genesis();
    let vote = vote(&branch, 0, ConsensusVoteRole::Prevote, target(&p), 0);
    let wire = vote.encode();
    assert_eq!(wire.len(), RESEARCH_VOTE_BYTES);
    for index in 0..wire.len() {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        assert!(
            ResearchVote::decode(&bad, genesis).is_err(),
            "vote byte {index}"
        );
    }
    let qc = quorum(&branch, 0, ConsensusVoteRole::Prevote, target(&p));
    let wire = qc.encode();
    for end in 0..wire.len() {
        assert!(ResearchQuorum::decode(&wire[..end], genesis).is_err());
    }
    let mut reordered = wire.clone();
    let a = reordered[1..1 + RESEARCH_VOTE_BYTES].to_vec();
    let b = reordered[1 + RESEARCH_VOTE_BYTES..1 + 2 * RESEARCH_VOTE_BYTES].to_vec();
    reordered[1..1 + RESEARCH_VOTE_BYTES].copy_from_slice(&b);
    reordered[1 + RESEARCH_VOTE_BYTES..1 + 2 * RESEARCH_VOTE_BYTES].copy_from_slice(&a);
    assert!(ResearchQuorum::decode(&reordered, genesis).is_err());
    let wire = p.encode().unwrap();
    for end in 0..wire.len() {
        assert!(branch.verify_proposal(&wire[..end], MAX_ROUND).is_err());
    }
    let mut bad = wire.clone();
    bad.push(0);
    assert!(branch.verify_proposal(&bad, MAX_ROUND).is_err());
    let mut bad = wire;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(branch.verify_proposal(&bad, MAX_ROUND).is_err());
}

#[test]
fn nil_quorums_have_separate_unlock_and_round_advance_effects() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let mut state = lock(&branch, &p, validator_key(0));
    let nil = quorum(
        &branch,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    state
        .apply(
            &branch,
            &ResearchLockEvent::NilPrecommit {
                quorum: nil.encode(),
            },
            MAX_ROUND,
        )
        .unwrap();
    assert_eq!(state.round(), 1);
    assert_eq!(state.locked_value(), Some((p.value(), 0)));
    state
        .apply(&branch, &ResearchLockEvent::ProposalTimeout, MAX_ROUND)
        .unwrap();
    let nil = quorum(
        &branch,
        1,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    state
        .apply(
            &branch,
            &ResearchLockEvent::Precommit {
                proposal: None,
                quorum: nil.encode(),
            },
            MAX_ROUND,
        )
        .unwrap();
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), Some((p.value(), 0)));
}

#[test]
fn height_handoff_requires_exact_verified_parent_and_clears_prior_lock() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "q"), 0, None);
    let mut state = lock(&branch, &p, validator_key(0));
    let finality = branch
        .verify_finality(
            &p,
            &quorum(&branch, 0, ConsensusVoteRole::Precommit, target(&p)),
            MAX_ROUND,
        )
        .unwrap();
    state.advance_height(&finality).unwrap();
    assert_eq!(state.height(), 2);
    assert_eq!(state.round(), 0);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);
    let before = state.snapshot().unwrap();
    assert!(state.advance_height(&finality).is_err());
    assert_eq!(state.snapshot().unwrap(), before);
    assert!(
        state
            .apply(&branch, &ResearchLockEvent::ProposalTimeout, MAX_ROUND)
            .is_err()
    );
}

#[test]
fn finality_authentication_rejects_missing_quorum_before_record_decoding() {
    let branch = branch();
    let p = proposal(&branch, record(&branch, "authenticated header"), 0, None);
    let qc = quorum(&branch, 0, ConsensusVoteRole::Precommit, target(&p));
    let proof = branch
        .verify_finality(&p, &qc, MAX_ROUND)
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        ResearchFinality::authenticate(&proof, branch.state().genesis(), MAX_ROUND).unwrap(),
        p.value()
    );
    let mut proposal = p.encode().unwrap();
    // Keep the correctly signed header, but corrupt the first record byte.
    let record_length = p.record_bytes().len();
    let first = proposal.len() - record_length;
    proposal[first] ^= 1;
    let mut bytes = b"NRCF1".to_vec();
    super::codec::bytes(&mut bytes, &proposal).unwrap();
    super::codec::bytes(&mut bytes, &[0]).unwrap();
    assert_eq!(
        ResearchFinality::authenticate(&bytes, branch.state().genesis(), MAX_ROUND),
        Err(ResearchConsensusError::Limit("vote set"))
    );
    let mut authenticated_bad = b"NRCF1".to_vec();
    super::codec::bytes(&mut authenticated_bad, &proposal).unwrap();
    super::codec::bytes(&mut authenticated_bad, &qc.encode()).unwrap();
    assert!(matches!(
        ResearchFinality::authenticate(&authenticated_bad, branch.state().genesis(), MAX_ROUND),
        Err(ResearchConsensusError::Research(_))
    ));
}

mod golden;
