use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};

use super::*;

fn keys(index: u8) -> [SigningKey; 3] {
    std::array::from_fn(|role| {
        let mut seed = [index; 32];
        seed[0] = role as u8;
        SigningKey::from_bytes(&seed)
    })
}

fn candidate() -> (MembershipBranch, MembershipValue, Vec<u8>) {
    candidate_with_axiom(ZfcAxiom::Pairing)
}
fn candidate_with_axiom(axiom: ZfcAxiom) -> (MembershipBranch, MembershipValue, Vec<u8>) {
    let artifacts = ArtifactChainState::new(ArtifactChainDefinition::new([94; 32]));
    let branch =
        MembershipBranch::genesis(artifacts.branch_snapshot(), (1..=4).map(member).collect())
            .unwrap();
    let payload = ArtifactPayload::Proof(
        ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
            .unwrap()
            .into_unchecked_normal_form()
            .certificate()
            .clone(),
    )
    .to_canonical_bytes();
    let id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let value = branch
        .value(artifacts.prepare_block(id).unwrap(), None)
        .unwrap();
    (branch, value, payload)
}
fn quorum_certificate(
    branch: &MembershipBranch,
    round: u64,
    role: MembershipVoteRole,
    root: Option<[u8; 32]>,
) -> MembershipCertificate {
    let coordinate = branch.vote_coordinate(round, role, root).unwrap();
    let votes: Vec<_> = (1..=3)
        .map(|id| MembershipVote::sign(coordinate, &keys(id)[0]))
        .collect();
    MembershipCertificate::from_votes(&votes, branch.next_snapshot().unwrap()).unwrap()
}

#[test]
fn producer_authenticates_valid_round_presence_and_exact_witness() {
    let (branch, value, payload) = candidate();
    let certificate =
        quorum_certificate(&branch, 0, MembershipVoteRole::Prevote, Some(value.root()));
    let key = (1..=4)
        .map(keys)
        .find(|key| key[0].verifying_key().to_bytes() == branch.proposer(1, 64).unwrap())
        .unwrap();
    let proposal = MembershipProposal::sign(value, 1, Some(certificate.clone()), &key[0]);
    branch
        .verify_proposal(proposal.clone(), payload.clone(), 64)
        .unwrap();
    let mut stripped = proposal.clone();
    stripped.valid_round = None;
    assert!(
        branch
            .verify_proposal(stripped, payload.clone(), 64)
            .is_err()
    );
    let votes: Vec<_> = (2..=4)
        .map(|id| MembershipVote::sign(certificate.coordinate(), &keys(id)[0]))
        .collect();
    let mut replaced = proposal;
    replaced.valid_round =
        Some(MembershipCertificate::from_votes(&votes, branch.next_snapshot().unwrap()).unwrap());
    assert!(branch.verify_proposal(replaced, payload, 64).is_err());
}

#[test]
fn replayed_old_nil_certificates_cannot_block_current_self_finalization() {
    let (branch, value, payload) = candidate();
    let mut machine = MembershipMachine::new(
        branch.clone(),
        Some(keys(1)[0].verifying_key().to_bytes()),
        128,
    )
    .unwrap();
    let mut old = Vec::new();
    for round in 0..40 {
        for role in [MembershipVoteRole::Prevote, MembershipVoteRole::Precommit] {
            let certificate = quorum_certificate(&branch, round, role, None);
            machine = machine
                .prepare(MembershipMachineEvent::Certificate(certificate.clone()))
                .unwrap()
                .into_machine();
            old.push(certificate);
        }
    }
    machine = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 39,
            phase: MembershipPhase::Precommit,
        })
        .unwrap()
        .into_machine();
    let before = machine.state_id();
    for certificate in old {
        machine = machine
            .prepare(MembershipMachineEvent::Certificate(certificate))
            .unwrap()
            .into_machine();
        assert_eq!(machine.state_id(), before);
    }
    let signer = (1..=4)
        .map(keys)
        .find(|key| key[0].verifying_key().to_bytes() == branch.proposer(40, 128).unwrap())
        .unwrap();
    let proposal = MembershipProposal::sign(value.clone(), 40, None, &signer[0]);
    machine = machine
        .prepare(MembershipMachineEvent::Proposal { proposal, payload })
        .unwrap()
        .into_machine();
    let coordinate = branch
        .vote_coordinate(40, MembershipVoteRole::Precommit, Some(value.root()))
        .unwrap();
    for id in 2..=3 {
        machine = machine
            .prepare(MembershipMachineEvent::Vote(MembershipVote::sign(
                coordinate,
                &keys(id)[0],
            )))
            .unwrap()
            .into_machine();
    }
    let transition = machine
        .prepare(MembershipMachineEvent::Certificate(quorum_certificate(
            &branch,
            40,
            MembershipVoteRole::Prevote,
            Some(value.root()),
        )))
        .unwrap();
    assert_eq!(transition.intents().len(), 1);
    let own = transition.intents()[0].complete(&keys(1)[0]).unwrap();
    let finality = transition.into_machine().prepare(own.to_event()).unwrap();
    assert!(finality.finalized().is_some());
    assert_eq!(finality.next().branch().height(), 1);
}

#[test]
fn distant_or_near_future_votes_cannot_displace_current_signing_slots() {
    let (branch, _, _) = candidate();
    let mut machine = MembershipMachine::new(
        branch.clone(),
        Some(keys(1)[0].verifying_key().to_bytes()),
        64,
    )
    .unwrap();
    for round in 57..=64 {
        let vote = MembershipVote::sign(
            branch
                .vote_coordinate(round, MembershipVoteRole::Prevote, None)
                .unwrap(),
            &keys(4)[0],
        );
        let before = machine.state_id();
        assert!(machine.prepare(MembershipMachineEvent::Vote(vote)).is_err());
        assert_eq!(machine.state_id(), before);
    }
    for round in 1..=7 {
        let vote = MembershipVote::sign(
            branch
                .vote_coordinate(round, MembershipVoteRole::Prevote, None)
                .unwrap(),
            &keys(4)[0],
        );
        machine = machine
            .prepare(MembershipMachineEvent::Vote(vote))
            .unwrap()
            .into_machine();
    }
    let transition = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 0,
            phase: MembershipPhase::Proposal,
        })
        .unwrap();
    assert_eq!(transition.intents().len(), 1);
    let signed = transition.intents()[0].complete(&keys(1)[0]).unwrap();
    machine = transition.into_machine();
    machine = machine.prepare(signed.to_event()).unwrap().into_machine();
    assert_eq!(machine.round(), 0);
    assert_eq!(machine.phase(), MembershipPhase::Prevote);
    let transition = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 0,
            phase: MembershipPhase::Prevote,
        })
        .unwrap();
    let signed = transition.intents()[0].complete(&keys(1)[0]).unwrap();
    machine = transition
        .into_machine()
        .prepare(signed.to_event())
        .unwrap()
        .into_machine();
    machine = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 0,
            phase: MembershipPhase::Precommit,
        })
        .unwrap()
        .into_machine();
    assert_eq!(machine.round(), 1);
}

#[test]
fn old_set_authorizes_voluntary_exit_and_forced_removal_with_identical_delay() {
    let snapshot = snapshot(5);
    let exit = MembershipRequest::exit(&snapshot, [5; 32], &keys(5)[1]).unwrap();
    assert!(MembershipRequest::exit(&snapshot, [5; 32], &keys(4)[1]).is_err());
    let remove = MembershipRequest::remove(&snapshot, [5; 32]).unwrap();
    for request in [exit, remove] {
        let approvals: Vec<_> = (1..=4)
            .map(|id| {
                MembershipApproval::sign(&request, &snapshot, [id; 32], &keys(id)[1]).unwrap()
            })
            .collect();
        assert!(
            ApprovedMembershipRequest::new(request.clone(), approvals[..3].to_vec(), &snapshot)
                .is_err()
        );
        let approved = ApprovedMembershipRequest::new(request, approvals, &snapshot).unwrap();
        let scheduled = MembershipState::genesis(snapshot.clone())
            .unwrap()
            .transition(8193, Some(&approved))
            .unwrap();
        assert_eq!(scheduled.active_at(24576).members().len(), 5);
        assert_eq!(scheduled.active_at(24577).members().len(), 4);
        assert!(scheduled.active_at(24577).member(&[5; 32]).is_none());
        assert!(approved.validate(scheduled.active_at(24577)).is_err());
    }
}
fn member(index: u8) -> Member {
    let keys = keys(index);
    Member {
        organization: [index; 32],
        consensus_key: keys[0].verifying_key().to_bytes(),
        approval_key: keys[1].verifying_key().to_bytes(),
        network_key: keys[2].verifying_key().to_bytes(),
    }
}
fn snapshot(count: u8) -> MembershipSnapshot {
    MembershipSnapshot::genesis(
        MembershipContext([9; 32]),
        (1..=count).map(member).collect(),
    )
    .unwrap()
}
fn approved_join(snapshot: &MembershipSnapshot, index: u8) -> ApprovedMembershipRequest {
    let applicant = keys(index);
    let request = MembershipRequest::join(
        snapshot,
        member(index),
        [&applicant[0], &applicant[1], &applicant[2]],
    )
    .unwrap();
    let approvals = snapshot
        .members()
        .iter()
        .take(snapshot.quorum())
        .map(|member| {
            MembershipApproval::sign(
                &request,
                snapshot,
                member.organization,
                &keys(member.organization[0])[1],
            )
            .unwrap()
        })
        .collect();
    ApprovedMembershipRequest::new(request, approvals, snapshot).unwrap()
}

#[test]
fn quorum_is_strict_and_organization_count_cannot_drop_below_four() {
    for (count, required) in [(4, 3), (5, 4), (6, 5), (7, 5), (10, 7)] {
        assert_eq!(snapshot(count).quorum(), required);
    }
    assert_eq!(
        MembershipSnapshot::genesis(MembershipContext([9; 32]), (1..4).map(member).collect())
            .unwrap_err(),
        MembershipError::MinimumMembers
    );
    assert_eq!(
        MembershipRequest::remove(&snapshot(4), [1; 32]).unwrap_err(),
        MembershipError::MinimumMembers
    );
    assert_eq!(
        MembershipRequest::exit(&snapshot(4), [1; 32], &keys(1)[1]).unwrap_err(),
        MembershipError::MinimumMembers
    );
}

#[test]
fn approval_is_not_activation_and_pending_changes_are_serialized() {
    let original = snapshot(4);
    let approval = approved_join(&original, 5);
    let state = MembershipState::genesis(original.clone()).unwrap();
    assert_eq!(state.active_at(16385).members().len(), 4);
    let scheduled = state.transition(1, Some(&approval)).unwrap();
    assert_eq!(scheduled.pending_activation(), Some(16385));
    assert_eq!(scheduled.active_at(16384), &original);
    assert_eq!(scheduled.active_at(16385).members().len(), 5);
    assert_eq!(
        scheduled
            .transition(2, Some(&approved_join(&original, 6)))
            .unwrap_err(),
        MembershipError::PendingTransition
    );
    let activated = scheduled.transition(16385, None).unwrap();
    assert_eq!(activated.pending_activation(), None);
    assert_eq!(
        approval.validate(activated.active_at(16386)),
        Err(MembershipError::StaleRequest)
    );
    assert_eq!(state.active_at(16385), &original);
}

#[test]
fn epoch_boundary_delay_and_overflow_are_exact() {
    let snapshot = snapshot(4);
    let approved = approved_join(&snapshot, 5);
    let state = MembershipState::genesis(snapshot).unwrap();
    for (height, activation) in [(1, 16385), (8192, 16385), (8193, 24577), (16384, 24577)] {
        assert_eq!(
            state
                .transition(height, Some(&approved))
                .unwrap()
                .pending_activation(),
            Some(activation)
        );
    }
    assert_eq!(
        state.transition(0, Some(&approved)).unwrap_err(),
        MembershipError::Encoding
    );
    assert_eq!(
        state.transition(u64::MAX, Some(&approved)).unwrap_err(),
        MembershipError::Overflow
    );
}

#[test]
fn canonical_requests_and_approvals_reject_forgery_replay_duplicates_and_trailing_bytes() {
    let snapshot = snapshot(4);
    let approved = approved_join(&snapshot, 5);
    let bytes = approved.to_bytes();
    let decoded = ApprovedMembershipRequest::from_bytes(&bytes).unwrap();
    decoded.validate(&snapshot).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    for length in 0..bytes.len() {
        assert!(ApprovedMembershipRequest::from_bytes(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ApprovedMembershipRequest::from_bytes(&trailing).is_err());
    let mut forged = bytes;
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        ApprovedMembershipRequest::from_bytes(&forged)
            .unwrap()
            .validate(&snapshot),
        Err(MembershipError::InvalidSignature)
    );
    let request = approved.request().clone();
    let one = MembershipApproval::sign(&request, &snapshot, [1; 32], &keys(1)[1]).unwrap();
    assert_eq!(
        ApprovedMembershipRequest::new(request.clone(), vec![one.clone(); 3], &snapshot)
            .unwrap_err(),
        MembershipError::Duplicate
    );
    assert_eq!(
        ApprovedMembershipRequest::new(request.clone(), vec![one], &snapshot).unwrap_err(),
        MembershipError::Quorum
    );
    assert_eq!(
        MembershipApproval::sign(&request, &snapshot, [1; 32], &keys(1)[0]).unwrap_err(),
        MembershipError::InvalidKey
    );
    let other =
        MembershipSnapshot::genesis(MembershipContext([8; 32]), snapshot.members().to_vec())
            .unwrap();
    assert_eq!(approved.validate(&other), Err(MembershipError::Context));
}

#[test]
fn key_and_organization_aliases_are_not_additional_votes() {
    let original = snapshot(4);
    let mut members = original.members().to_vec();
    members[1].approval_key = members[0].consensus_key;
    assert_eq!(
        MembershipSnapshot::genesis(original.context(), members).unwrap_err(),
        MembershipError::Duplicate
    );
    let mut members = original.members().to_vec();
    members[1].organization = members[0].organization;
    assert_eq!(
        MembershipSnapshot::genesis(original.context(), members).unwrap_err(),
        MembershipError::Duplicate
    );
    let mut members = original.members().to_vec();
    members[1].network_key = [0; 32];
    assert_eq!(
        MembershipSnapshot::genesis(original.context(), members).unwrap_err(),
        MembershipError::InvalidKey
    );
}

#[test]
fn finality_commits_membership_and_requires_old_set_consensus_signatures() {
    let definition = ArtifactChainDefinition::new([44; 32]);
    let artifact_state = ArtifactChainState::new(definition);
    let branch = MembershipBranch::genesis(
        artifact_state.branch_snapshot(),
        (1..=4).map(member).collect(),
    )
    .unwrap();
    let approval = approved_join(branch.next_snapshot().unwrap(), 5);
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    let payload = ArtifactPayload::Proof(certificate).to_canonical_bytes();
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let artifact = artifact_state.prepare_block(artifact_id).unwrap();
    let value = branch.value(artifact, Some(approval)).unwrap();
    assert_eq!(
        MembershipValue::from_bytes(&value.to_bytes()).unwrap(),
        value
    );
    let proposer = branch.proposer(0, 16).unwrap();
    let signer = (1..=4)
        .map(keys)
        .find(|keys| keys[0].verifying_key().to_bytes() == proposer)
        .unwrap();
    let proposal = MembershipProposal::sign(value.clone(), 0, None, &signer[0]);
    assert_eq!(
        MembershipProposal::from_bytes(&proposal.to_bytes()).unwrap(),
        proposal
    );
    branch
        .verify_proposal(proposal.clone(), payload.clone(), 16)
        .unwrap();
    assert_eq!(branch.membership().pending_activation(), None);
    let coordinate = branch
        .vote_coordinate(0, MembershipVoteRole::Precommit, Some(value.root()))
        .unwrap();
    let votes: Vec<_> = (1..=3)
        .map(|id| MembershipVote::sign(coordinate, &keys(id)[0]))
        .collect();
    let certificate =
        MembershipCertificate::from_votes(&votes, branch.next_snapshot().unwrap()).unwrap();
    assert_eq!(
        MembershipCertificate::from_bytes(&certificate.to_bytes()).unwrap(),
        certificate
    );
    let outsider = MembershipVote::sign(coordinate, &keys(5)[0]);
    assert!(branch.verify_vote(&outsider, 16).is_err());
    assert!(
        MembershipCertificate::from_votes(
            &[votes[0].clone(), votes[1].clone(), outsider],
            branch.next_snapshot().unwrap()
        )
        .is_err()
    );
    let finalized = branch
        .verify_finality(proposal.clone(), payload.clone(), certificate.clone(), 16)
        .unwrap();
    let child = finalized.into_branch();
    assert_eq!(child.height(), 1);
    assert_eq!(child.membership().pending_activation(), Some(16385));
    assert_eq!(child.next_snapshot().unwrap().members().len(), 4);
    assert!(
        child
            .verify_finality(proposal, payload, certificate, 16)
            .is_err()
    );
    let mut wrong_parent = votes[0].clone();
    wrong_parent.coordinate.parent = [0; 32];
    assert!(branch.verify_vote(&wrong_parent, 16).is_err());
}

#[test]
fn locking_refuses_unjustified_value_change_and_accepts_higher_valid_round() {
    let (branch, first, first_bytes) = candidate();
    let (_, second, second_bytes) = candidate_with_axiom(ZfcAxiom::Union);
    let propose = |value: MembershipValue, payload: Vec<u8>, round, certificate| {
        let key = (1..=4)
            .map(keys)
            .find(|key| key[0].verifying_key().to_bytes() == branch.proposer(round, 64).unwrap())
            .unwrap();
        MembershipMachineEvent::Proposal {
            proposal: MembershipProposal::sign(value, round, certificate, &key[0]),
            payload,
        }
    };
    let mut machine = MembershipMachine::new(
        branch.clone(),
        Some(keys(1)[0].verifying_key().to_bytes()),
        64,
    )
    .unwrap();
    machine = machine
        .prepare(propose(first.clone(), first_bytes, 0, None))
        .unwrap()
        .into_machine();
    machine = machine
        .prepare(MembershipMachineEvent::Certificate(quorum_certificate(
            &branch,
            0,
            MembershipVoteRole::Prevote,
            Some(first.root()),
        )))
        .unwrap()
        .into_machine();
    assert_eq!(machine.locked(), Some((0, first.root())));
    machine = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 0,
            phase: MembershipPhase::Precommit,
        })
        .unwrap()
        .into_machine();
    let rejected = machine
        .prepare(propose(second.clone(), second_bytes.clone(), 1, None))
        .unwrap();
    let MembershipPublication::Vote(vote) = rejected.intents()[0].complete(&keys(1)[0]).unwrap()
    else {
        panic!("vote intent")
    };
    assert_eq!(vote.coordinate.target, None);
    machine = rejected.into_machine();
    assert_eq!(machine.locked(), Some((0, first.root())));
    // A later quorum can safely supersede the old lock, independently of our nil vote.
    let certificate =
        quorum_certificate(&branch, 1, MembershipVoteRole::Prevote, Some(second.root()));
    machine = machine
        .prepare(MembershipMachineEvent::Certificate(certificate.clone()))
        .unwrap()
        .into_machine();
    assert_eq!(machine.locked(), Some((1, second.root())));
    machine = machine
        .prepare(MembershipMachineEvent::Timeout {
            height: 1,
            round: 1,
            phase: MembershipPhase::Precommit,
        })
        .unwrap()
        .into_machine();
    let accepted = machine
        .prepare(propose(second.clone(), second_bytes, 2, Some(certificate)))
        .unwrap();
    let MembershipPublication::Vote(vote) = accepted.intents()[0].complete(&keys(1)[0]).unwrap()
    else {
        panic!("vote intent")
    };
    assert_eq!(vote.coordinate.target, Some(second.root()));
    assert_eq!(
        accepted.next().retained_value().unwrap().0.root(),
        second.root()
    );
}
