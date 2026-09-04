use ed25519_dalek::{
    Digest, Sha512,
    hazmat::{ExpandedSecretKey, raw_sign},
};
use naome_consensus::{
    ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    ArtifactBlockCandidateStoreError, CandidateBackedFinalityErrorV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorVoteSafetyJournalErrorV0,
};
use std::path::Path;

use super::super::current_round_finality_inbox::{
    CurrentRoundFinalityClassificationV0, CurrentRoundFinalityInboxInsertOutcomeV0,
    CurrentRoundFinalityInboxV0, CurrentRoundFinalityPreclassificationV0,
};
use super::super::current_round_inbox::{
    CurrentRoundInboxInsertOutcomeV0, CurrentRoundInboxV0, CurrentRoundQuorumSelectionV0,
};
use super::super::current_round_nil_precommit_inbox::{
    CurrentRoundNilPrecommitInboxInsertOutcomeV0, CurrentRoundNilPrecommitInboxV0,
    CurrentRoundNilPrecommitQuorumSelectionV0,
};
use super::super::driver::FixedValidatorNodeDriverCurrentFinalityClassificationV0;
use super::super::proposal_deferral::verify_deferred_proposal_at_round;
use super::finality::{candidate_backed_batch_finality_inputs, expect_continuation};
use super::*;

mod candidate_backed;
mod higher_round;
mod lower_round_pair;
mod proposal_authoring;

type DrainedEvidence = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);
type DrainedCurrentEvidence = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>, Vec<Vec<u8>>);
type DrainedCurrentFinalityEvidence = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);
type DrainedCurrentNilPrecommitEvidence = Vec<Vec<u8>>;
type DriverPermutationResult = (
    naome_storage::FixedValidatorSignedVoteV0,
    [Vec<(String, Vec<u8>)>; 4],
);

fn driver<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    max_entries: usize,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    driver_with_inbox_limits(scope, max_entries, max_entries, maximum_round)
}

fn driver_with_inbox_limits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    higher_max_entries: usize,
    current_max_entries: usize,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    driver_with_limits(
        scope,
        higher_max_entries,
        1024 * 1024,
        current_max_entries,
        1024 * 1024,
        maximum_round,
    )
}

fn driver_with_limits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    higher_max_entries: usize,
    higher_max_bytes: u64,
    current_max_entries: usize,
    current_max_bytes: u64,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    driver_with_finality_limits(
        scope,
        higher_max_entries,
        higher_max_bytes,
        current_max_entries,
        current_max_bytes,
        8,
        1024 * 1024,
        maximum_round,
    )
}

#[allow(clippy::too_many_arguments)]
fn driver_with_finality_limits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    higher_max_entries: usize,
    higher_max_bytes: u64,
    current_max_entries: usize,
    current_max_bytes: u64,
    finality_max_entries: usize,
    finality_max_bytes: u64,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    driver_with_all_limits(
        scope,
        higher_max_entries,
        higher_max_bytes,
        current_max_entries,
        current_max_bytes,
        finality_max_entries,
        finality_max_bytes,
        8,
        1024 * 1024,
        maximum_round,
    )
}

fn driver_with_nil_precommit_limits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    nil_precommit_max_entries: usize,
    nil_precommit_max_bytes: u64,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    driver_with_all_limits(
        scope,
        8,
        1024 * 1024,
        8,
        1024 * 1024,
        8,
        1024 * 1024,
        nil_precommit_max_entries,
        nil_precommit_max_bytes,
        maximum_round,
    )
}

#[allow(clippy::too_many_arguments)]
fn driver_with_all_limits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    higher_max_entries: usize,
    higher_max_bytes: u64,
    current_max_entries: usize,
    current_max_bytes: u64,
    finality_max_entries: usize,
    finality_max_bytes: u64,
    nil_precommit_max_entries: usize,
    nil_precommit_max_bytes: u64,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    FixedValidatorNodeDriverV0::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(higher_max_entries, higher_max_bytes)
            .unwrap(),
        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(current_max_entries, current_max_bytes)
            .unwrap(),
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
            finality_max_entries,
            finality_max_bytes,
        )
        .unwrap(),
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(
            nil_precommit_max_entries,
            nil_precommit_max_bytes,
        )
        .unwrap(),
        ConsensusRound::new(maximum_round),
    )
    .unwrap()
}

fn step_arm<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodePhaseTimeoutV0,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(timeout) => (*driver, timeout),
            FixedValidatorNodeDriverCommandV0::PublishVote { .. }
            | FixedValidatorNodeDriverCommandV0::PublishProposal { .. } => {
                panic!("expected timeout-arm command")
            }
        },
        _ => panic!("expected one timeout-arm command"),
    }
}

fn step_publish<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    naome_storage::FixedValidatorSignedVoteV0,
    Option<Box<FixedValidatorNodeDeferredProposalV0>>,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::PublishVote {
                vote,
                released_proposal,
            } => (*driver, vote, released_proposal),
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_)
            | FixedValidatorNodeDriverCommandV0::PublishProposal { .. } => {
                panic!("expected vote-publication command")
            }
        },
        _ => panic!("expected one vote-publication command"),
    }
}

fn step_transition<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Transitioned { driver } => *driver,
        _ => panic!("expected exactly one driver transition"),
    }
}

fn step_finality<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Finality { driver, selection } => {
            (*driver, selection)
        }
        _ => panic!("expected exactly one current-round finality transition"),
    }
}

fn step_idle<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
        _ => panic!("expected an idle driver step"),
    }
}

fn admit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    event: FixedValidatorNodeDriverEventV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodeDriverAdmissionDispositionV0,
) {
    match driver.admit_event(event).unwrap() {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
            driver,
            disposition,
        } => (*driver, disposition),
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { .. } => {
            panic!("expected driver event admission")
        }
    }
}

fn admit_due<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    timeout: FixedValidatorNodePhaseTimeoutV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodeDriverAdmissionDispositionV0,
) {
    admit(driver, FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
}

fn reject_prevote<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_signed_prevote: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(prevote_event(canonical_signed_prevote))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                    canonical_signed_prevote: returned,
                } => assert_eq!(returned.as_ref(), canonical_signed_prevote),
                _ => panic!("rejected proposal prevote must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid proposal prevote must be rejected")
        }
    }
}

fn reject_current_prevote<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_signed_prevote: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(current_prevote_event(canonical_signed_prevote))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                    canonical_signed_prevote: returned,
                } => assert_eq!(returned.as_ref(), canonical_signed_prevote),
                _ => panic!("rejected current prevote must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid current prevote must be rejected")
        }
    }
}

fn reject_current_nil_prevote<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_signed_prevote: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(current_nil_prevote_event(canonical_signed_prevote))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                    canonical_signed_prevote: returned,
                } => assert_eq!(returned.as_ref(), canonical_signed_prevote),
                _ => panic!("rejected current nil prevote must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid current nil prevote must be rejected")
        }
    }
}

fn reject_current_finality_precommit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_signed_precommit: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(current_finality_precommit_event(canonical_signed_precommit))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                    canonical_signed_precommit: returned,
                } => assert_eq!(returned.as_ref(), canonical_signed_precommit),
                _ => panic!("rejected current finality precommit must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid current finality precommit must be rejected")
        }
    }
}

fn reject_current_nil_precommit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_signed_precommit: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(current_nil_precommit_event(canonical_signed_precommit))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
                    canonical_signed_precommit: returned,
                } => assert_eq!(returned.as_ref(), canonical_signed_precommit),
                _ => panic!("rejected current nil precommit must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid current nil precommit must be rejected")
        }
    }
}

fn reject_current_finality_proposal<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: &[u8],
    assert_rejection: impl FnOnce(&FixedValidatorNodeDriverAdmissionRejectionV0),
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
        .admit_event(current_finality_proposal_event(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        ))
        .unwrap()
    {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
            driver,
            event,
            rejection,
        } => {
            match *event {
                FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                    canonical_proposal_control_bytes: returned_control,
                    canonical_artifact_bytes: returned_artifact,
                } => {
                    assert_eq!(returned_control.as_ref(), canonical_proposal_control_bytes);
                    assert_eq!(returned_artifact.as_ref(), canonical_artifact_bytes);
                }
                _ => panic!("rejected current finality proposal must return its exact event"),
            }
            assert_rejection(rejection.as_ref());
            *driver
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("invalid current finality proposal must be rejected")
        }
    }
}

fn drained_contents(drained: FixedValidatorNodeHigherRoundInboxDrainV0) -> DrainedEvidence {
    let mut proposals = Vec::new();
    let mut prevotes = Vec::new();
    for item in drained {
        match item {
            FixedValidatorNodeHigherRoundInboxDrainItemV0::Proposal(proposal) => proposals.push((
                proposal.canonical_proposal_control_bytes().to_vec(),
                proposal.canonical_artifact_bytes().to_vec(),
            )),
            FixedValidatorNodeHigherRoundInboxDrainItemV0::ProposalPrevote(prevote) => {
                prevotes.push(prevote.to_vec());
            }
        }
    }
    proposals.sort_unstable();
    prevotes.sort_unstable();
    (proposals, prevotes)
}

fn drained_current_contents(
    drained: FixedValidatorNodeCurrentRoundInboxDrainV0,
) -> DrainedCurrentEvidence {
    let mut proposals = Vec::new();
    let mut proposal_prevotes = Vec::new();
    let mut nil_prevotes = Vec::new();
    for item in drained {
        match item {
            FixedValidatorNodeCurrentRoundInboxDrainItemV0::Proposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => proposals.push((
                canonical_proposal_control_bytes.into_vec(),
                canonical_artifact_bytes.into_vec(),
            )),
            FixedValidatorNodeCurrentRoundInboxDrainItemV0::ProposalPrevote(prevote) => {
                proposal_prevotes.push(prevote.to_vec());
            }
            FixedValidatorNodeCurrentRoundInboxDrainItemV0::NilPrevote(prevote) => {
                nil_prevotes.push(prevote.to_vec());
            }
        }
    }
    proposals.sort_unstable();
    proposal_prevotes.sort_unstable();
    nil_prevotes.sort_unstable();
    (proposals, proposal_prevotes, nil_prevotes)
}

fn drained_current_finality_contents(
    drained: FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
) -> DrainedCurrentFinalityEvidence {
    let mut proposals = Vec::new();
    let mut precommits = Vec::new();
    for item in drained {
        match item {
            FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0::Proposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => proposals.push((
                canonical_proposal_control_bytes.into_vec(),
                canonical_artifact_bytes.into_vec(),
            )),
            FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0::ProposalPrecommit(
                precommit,
            ) => precommits.push(precommit.to_vec()),
        }
    }
    proposals.sort_unstable();
    precommits.sort_unstable();
    (proposals, precommits)
}

fn drained_current_nil_precommit_contents(
    drained: FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
) -> DrainedCurrentNilPrecommitEvidence {
    let mut precommits = drained
        .map(|precommit| precommit.to_vec())
        .collect::<Vec<_>>();
    precommits.sort_unstable();
    precommits
}

fn close_empty_round<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    proposal_timeout: FixedValidatorNodePhaseTimeoutV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodePhaseTimeoutV0,
) {
    let (driver, _) = admit_due(driver, proposal_timeout);
    let driver = step_transition(driver);
    let (driver, prevote, released_proposal) = step_publish(driver);
    assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
    assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
    assert!(released_proposal.is_none());
    let (driver, prevote_timeout) = step_arm(driver);

    let (driver, _) = admit_due(driver, prevote_timeout);
    let driver = step_transition(driver);
    let (driver, precommit, released_proposal) = step_publish(driver);
    assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
    assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
    assert!(released_proposal.is_none());
    let (driver, precommit_timeout) = step_arm(driver);

    let (driver, _) = admit_due(driver, precommit_timeout);
    let driver = step_transition(driver);
    step_arm(driver)
}

fn next_anchor_collision(directory: &Path, sequence: u64) -> PathBuf {
    let anchor_name = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .expect("one typed anchor file must exist");
    let collision = directory.join(format!("{anchor_name}.tmp-{sequence:016x}"));
    fs::write(&collision, b"deterministic driver anchor collision").unwrap();
    collision
}

fn flip_last_store_byte(directory: &Path) {
    let path = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "log"))
        .expect("one typed store log must exist");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes
        .last_mut()
        .expect("a committed store image cannot be empty");
    *last ^= 0x01;
    fs::write(path, bytes).unwrap();
}

fn fixed_branch(fixture: &Fixture) -> FixedConsensusBranchV0 {
    FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap()
}

fn round_at(branch: &FixedConsensusBranchV0, round: u64) -> FixedConsensusRoundV0<'_> {
    let mut cursor = branch.begin_round_zero().unwrap();
    for _ in 0..round {
        cursor = cursor.advance_round().unwrap();
    }
    cursor
}

fn proposal_inputs(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    proposal_round: u64,
    axiom: ZfcAxiom,
) -> (ConsensusValueV0, Vec<u8>, Vec<u8>) {
    proposal_inputs_with_signing_key(
        fixture,
        branch,
        proposal_round,
        axiom,
        &fixture.signing_key(),
    )
}

fn proposal_inputs_with_signing_key(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    proposal_round: u64,
    axiom: ZfcAxiom,
    signing_key: &SigningKey,
) -> (ConsensusValueV0, Vec<u8>, Vec<u8>) {
    let payload = proof_payload(axiom);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let round = round_at(branch, proposal_round);
    let value = round.value_for_artifact_block(block);
    let mut control = value.to_canonical_bytes().to_vec();
    control.extend_from_slice(&authorization_bytes(
        value.context(),
        round.position(),
        value.proposal_signing_root(),
        signing_key,
    ));
    control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    (value, control, payload)
}

fn proposal_control_with_valid_round(
    fixture: &Fixture,
    value: ConsensusValueV0,
    position: ConsensusPosition,
    valid_round_certificate: &[u8],
) -> Vec<u8> {
    let mut control = value.to_canonical_bytes().to_vec();
    control.extend_from_slice(&authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    control.push(VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG);
    control.extend_from_slice(valid_round_certificate);
    control
}

fn signed_vote_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => body[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }
    let signer_key = consensus_key(signer);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = domain.to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer_key.as_bytes());
    let mut bytes = body.to_vec();
    bytes.extend_from_slice(signer_key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn signed_vote_bytes_with_test_only_nonce_prefix(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
    prefix_tweak: u8,
) -> Vec<u8> {
    assert_ne!(prefix_tweak, 0);
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => body[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }
    let signer_key = consensus_key(signer);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = domain.to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer_key.as_bytes());

    // Test-only alternate nonce derivation produces another valid signature
    // for the same key and message without changing production signing.
    let digest = Sha512::digest(signer.to_bytes());
    let mut expanded_bytes = [0_u8; 64];
    expanded_bytes.copy_from_slice(&digest);
    let mut expanded = ExpandedSecretKey::from_bytes(&expanded_bytes);
    expanded.hash_prefix[0] ^= prefix_tweak;
    let signature = raw_sign::<Sha512>(&expanded, &transcript, &signer.verifying_key());

    let mut bytes = body.to_vec();
    bytes.extend_from_slice(signer_key.as_bytes());
    bytes.extend_from_slice(&signature.to_bytes());
    bytes
}

fn proposal_event(round: u64, control: &[u8], payload: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposal {
        proposal_round: ConsensusRound::new(round),
        canonical_proposal_control_bytes: control.into(),
        canonical_artifact_bytes: payload.into(),
    }
}

fn prevote_event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
        canonical_signed_prevote: bytes.into(),
    }
}

fn current_proposal_event(control: &[u8], payload: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
        canonical_proposal_control_bytes: control.into(),
        canonical_artifact_bytes: payload.into(),
    }
}

fn current_prevote_event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
        canonical_signed_prevote: bytes.into(),
    }
}

fn current_nil_prevote_event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
        canonical_signed_prevote: bytes.into(),
    }
}

fn current_finality_proposal_event(
    control: &[u8],
    payload: &[u8],
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
        canonical_proposal_control_bytes: control.into(),
        canonical_artifact_bytes: payload.into(),
    }
}

fn current_finality_precommit_event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
        canonical_signed_precommit: bytes.into(),
    }
}

fn current_nil_precommit_event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
        canonical_signed_precommit: bytes.into(),
    }
}

fn run_actionable_permutation(
    fixture: &Fixture,
    label: &str,
    control: &[u8],
    payload: &[u8],
    prevote: &[u8],
    due_before_evidence: bool,
) -> DriverPermutationResult {
    let layout = TestLayout::new(label);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let driver = if due_before_evidence {
                let (driver, _) = admit_due(driver, timeout);
                let (driver, _) = admit(driver, proposal_event(2, control, payload));
                let (driver, _) = admit(driver, prevote_event(prevote));
                driver
            } else {
                let (driver, _) = admit(driver, prevote_event(prevote));
                let (driver, _) = admit(driver, proposal_event(2, control, payload));
                let (driver, _) = admit_due(driver, timeout);
                driver
            };

            let driver = step_transition(driver);
            let durable_images = layout.images();
            let (driver, vote, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("higher-round publication must transfer the selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), payload);
            assert_eq!(layout.images(), durable_images);
            let (driver, timeout) = step_arm(driver);
            assert_eq!(layout.images(), durable_images);
            assert_eq!(timeout.position(), driver.position());
            assert_eq!(timeout.phase(), driver.phase());
            (vote, durable_images)
        })
        .unwrap()
}

#[test]
fn driver_serializes_exact_due_phase_transitions_and_commands() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-timeout-phases");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(proposal_timeout.context(), fixture.context);
            assert_eq!(proposal_timeout.position(), driver.position());
            assert_eq!(
                proposal_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert_eq!(proposal_timeout.generation(), 0);

            let (driver, disposition) = admit_due(driver, proposal_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let (driver, disposition) = admit_due(driver, proposal_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);

            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let (driver, prevote_timeout) = step_arm(driver);
            assert_eq!(prevote_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(prevote_timeout.generation(), 1);

            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_eq!(precommit_timeout.generation(), 2);

            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            let (driver, round_one_timeout) = step_arm(driver);
            assert_eq!(round_one_timeout.position(), driver.position());
            assert_eq!(
                round_one_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert_eq!(round_one_timeout.generation(), 3);
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { .. } => {}
                _ => panic!("driver without evidence or due state must be idle"),
            }
        })
        .unwrap();
}

#[test]
fn precommit_due_round_capacity_rejection_is_stable_and_retryable() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-precommit-due-capacity");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 0));
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);

            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);

            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, disposition) = admit_due(driver, precommit_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let before_rejection = layout.images();

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Rejected { driver, rejection } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    ));
                    *driver
                }
                _ => panic!("Precommit due must reject an unavailable destination round"),
            };
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), before_rejection);

            let (driver, disposition) = admit_due(driver, precommit_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Rejected { driver, rejection } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    ));
                    assert_eq!(driver.position().round(), ConsensusRound::new(0));
                    assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                    assert!(driver.timeout_is_due());
                    assert_eq!(layout.images(), before_rejection);
                }
                _ => panic!("the exact retained due state must retry the same rejection"),
            }
        })
        .unwrap();
}

#[test]
fn pending_commands_precede_event_admission_and_publication_is_already_durable() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-pending-command-order");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = match driver(scope, 8, 4)
                .admit_event(proposal_event(2, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                            ..
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                control.as_slice()
                            );
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("pending-command rejection must return the exact event"),
                    }
                    *driver
                }
                _ => panic!("initial arm command must transfer before event admission"),
            };

            let (driver, initial_timeout) = step_arm(driver);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            assert_eq!(initial_timeout.generation(), 0);
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let durable = layout.images();
            assert_ne!(durable, before);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);

            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(initial_timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == initial_timeout
                    ));
                    *driver
                }
                _ => panic!("pending vote custody must transfer before another event"),
            };

            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("higher-round publication must transfer the selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), payload);
            assert_eq!(layout.images(), durable);
            assert_eq!(signed.position(), position);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            let (_, successor_timeout) = step_arm(driver);
            assert_eq!(layout.images(), durable);
            assert_eq!(successor_timeout.position(), position);
            assert_eq!(
                successor_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
        })
        .unwrap();
}

#[test]
fn actionable_higher_round_evidence_precedes_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-evidence-before-timeout");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));

            let driver = step_transition(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == timeout
                    ));
                    *driver
                }
                _ => panic!("the completed vote must transfer before another event"),
            };
            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("higher-round publication must transfer the selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), payload);
            assert_eq!(signed.position(), position);
            assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            let (driver, later_timeout) = step_arm(driver);
            assert_eq!(later_timeout.position(), position);
            assert_eq!(later_timeout.phase(), FixedValidatorLockPhaseV0::Precommit);

            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver, rejection, ..
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert_eq!(driver.position(), position);
                }
                _ => panic!("superseded due ticket must be rejected"),
            }
        })
        .unwrap();
}

#[test]
fn grouped_higher_round_selection_ignores_vote_only_rounds_and_precedes_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-grouped-higher-round-selection");
    let branch = fixed_branch(&fixture);
    let (round_one_value, _, _) = proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let (round_two_value, _, _) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let (round_three_value, _, _) = proposal_inputs(&fixture, &branch, 3, ZfcAxiom::PowerSet);
    let (selected_value, selected_control, selected_payload) =
        proposal_inputs(&fixture, &branch, 4, ZfcAxiom::Extensionality);
    let round_one_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_one_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_two_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_two_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_three_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 3).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_three_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let selected_position = round_at(&branch, 4).position();
    let selected_root = selected_value.proposal_signing_root();
    let selected_prevote = signed_vote_bytes(
        fixture.context,
        selected_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(selected_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, prevote_event(&round_three_prevote));
            let (driver, _) = admit(
                driver,
                proposal_event(4, &selected_control, &selected_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_one_prevote));
            let (driver, _) = admit(driver, prevote_event(&selected_prevote));
            let (driver, _) = admit(driver, prevote_event(&round_two_prevote));
            let (driver, _) = admit_due(driver, timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.position(), selected_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("the sole actionable proposal must transfer with its precommit");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                selected_control
            );
            assert_eq!(
                released_proposal.canonical_artifact_bytes(),
                selected_payload
            );
            assert_eq!(signed.position(), selected_position);
            assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(selected_root)
            );
            assert_eq!(driver.inbox_len(), 4);
        })
        .unwrap();
}

#[test]
fn complete_snapshot_permutations_select_the_same_durable_precommit() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    let (due_first_vote, due_first_images) = run_actionable_permutation(
        &fixture,
        "driver-permutation-due-first",
        &control,
        &payload,
        &prevote,
        true,
    );
    let (evidence_first_vote, evidence_first_images) = run_actionable_permutation(
        &fixture,
        "driver-permutation-evidence-first",
        &control,
        &payload,
        &prevote,
        false,
    );

    assert_eq!(due_first_vote, evidence_first_vote);
    assert_eq!(due_first_images, evidence_first_images);
    assert_eq!(due_first_vote.position(), position);
    assert_eq!(due_first_vote.role(), ConsensusVoteRole::Precommit);
    assert_eq!(
        due_first_vote.target(),
        ConsensusVoteTarget::Proposal(value.proposal_signing_root())
    );
}

#[test]
fn incomplete_evidence_does_not_starve_an_exact_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-incomplete-evidence");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit_due(driver, timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 1);
            let (_, signed, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
            assert_eq!(signed.target(), ConsensusVoteTarget::Nil);
        })
        .unwrap();
}

#[test]
fn untrusted_event_forms_are_returned_and_mutation_free_while_duplicates_are_no_growth() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-event-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let round_zero = round_at(&branch, 0).position();
    let round_two = round_at(&branch, 2).position();
    let round_five = round_at(&branch, 5).position();
    let root = value.proposal_signing_root();
    let malformed = vec![0x01, 0x02, 0x03];
    let non_higher = signed_vote_bytes(
        fixture.context,
        round_zero,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let over_ceiling = signed_vote_bytes(
        fixture.context,
        round_five,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_role = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &inactive_signer,
    );
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid_prevote.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let oversized_payload = vec![0_u8; naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES + 1];
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_prevote(driver, &malformed, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(_)
                ));
            });
            let driver = reject_prevote(driver, &non_higher, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteNotHigher { .. }
                ));
            });
            let driver = reject_prevote(driver, &over_ceiling, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRoundWorkLimitExceeded {
                        ..
                    }
                ));
            });
            let driver = reject_prevote(driver, &wrong_role, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &inactive, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &invalid_signature, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(_)
                ));
            });
            let driver = match driver
                .admit_event(proposal_event(0, &control, &oversized_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeProposalDeferralRejectionV0::NotHigherThanSigner {
                                    ..
                                }
                            )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_artifact_bytes,
                            ..
                        } => assert_eq!(
                            canonical_artifact_bytes.as_ref(),
                            oversized_payload.as_slice()
                        ),
                        _ => panic!("route-preflight rejection must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("proposal route preflight must precede payload inspection"),
            };
            let driver = match driver
                .admit_event(proposal_event(2, &control, &oversized_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                            actual,
                            maximum: naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES,
                        } if actual == oversized_payload.len()
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_artifact_bytes,
                            ..
                        } => assert_eq!(
                            canonical_artifact_bytes.as_ref(),
                            oversized_payload.as_slice()
                        ),
                        _ => panic!("oversized proposal must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("oversized proposal payload must be rejected before copying"),
            };
            let driver = match driver
                .admit_event(proposal_event(3, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(_)
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            proposal_round,
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(proposal_round, ConsensusRound::new(3));
                            assert_eq!(canonical_proposal_control_bytes.as_ref(), control.as_slice());
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("rejected proposal must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("descriptive proposal route must match authenticated position"),
            };
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), before);

            let (driver, disposition) = admit(driver, proposal_event(2, &control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, proposal_event(2, &control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.inbox_len(), 1);
            let (driver, disposition) = admit(driver, prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.inbox_len(), 2);
            assert_eq!(layout.images(), before);

            let (_, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(prevotes, vec![valid_prevote.clone()]);
        })
        .unwrap();
}

#[test]
fn valid_route_rejects_malformed_control_before_consuming_a_maximum_payload() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-proposal-control-framing");
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let maximum_payload = vec![0_u8; naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES].into_boxed_slice();
    let control_pointer = malformed_control.as_ptr();
    let payload_pointer = maximum_payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                    proposal_round: ConsensusRound::new(2),
                    canonical_proposal_control_bytes: malformed_control,
                    canonical_artifact_bytes: maximum_payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    match rejection.as_ref() {
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(source) => {
                            match source.as_ref() {
                                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(source) => {
                                    assert!(matches!(
                                        source.as_ref(),
                                        naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                            actual,
                                            minimum,
                                        } if *actual == 3
                                            && *minimum
                                                == VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH
                                    ));
                                }
                                _ => panic!("valid route must reach proposal-control framing"),
                            }
                        }
                        _ => panic!("malformed control must be a proposal rejection"),
                    }
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            proposal_round,
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(proposal_round, ConsensusRound::new(2));
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ptr(),
                                control_pointer
                            );
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                            assert_eq!(canonical_proposal_control_bytes.as_ref(), [0x01, 0x02, 0x03]);
                            assert_eq!(
                                canonical_artifact_bytes.len(),
                                naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES
                            );
                        }
                        _ => panic!("proposal-control rejection must return its exact event"),
                    }
                    assert_eq!(driver.inbox_len(), 0);
                    assert!(!driver.timeout_is_due());
                    assert!(!driver.has_pending_command());
                }
                _ => panic!("malformed proposal control must be rejected"),
            }
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn competing_actions_block_timeout_until_lossless_full_reset() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-ambiguity");
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let position = round_at(&branch, 2).position();
    let first_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &second_control, &second_payload));
            let (driver, _) = admit(driver, prevote_event(&first_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &first_control, &first_payload));
            let (driver, _) = admit(driver, prevote_event(&second_prevote));

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    match reason {
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second } => {
                            assert!(first < second);
                            assert_eq!(first.position(), position);
                            assert_eq!(second.position(), position);
                        }
                        _ => panic!("expected same-class evidence ambiguity"),
                    }
                    *driver
                }
                _ => panic!("competing actionable roots must block"),
            };
            assert_eq!(layout.images(), before);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { .. }
                    ));
                    *driver
                }
                _ => panic!("latched ambiguity must keep blocking"),
            };

            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 4);
            let (proposals, prevotes) = drained_contents(drained);
            let mut expected_proposals = vec![
                (first_control.clone(), first_payload.clone()),
                (second_control.clone(), second_payload.clone()),
            ];
            expected_proposals.sort_unstable();
            let mut expected_prevotes = vec![first_prevote.clone(), second_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(proposals, expected_proposals);
            assert_eq!(prevotes, expected_prevotes);
            assert_eq!(driver.inbox_len(), 0);
            assert!(driver.timeout_is_due());
            let driver = step_transition(*driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn competing_actionable_positions_block_without_round_preference() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-position-ambiguity");
    let branch = fixed_branch(&fixture);
    let (round_two_value, round_two_control, round_two_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (round_three_value, round_three_control, round_three_payload) =
        proposal_inputs(&fixture, &branch, 3, ZfcAxiom::Union);
    let round_two = round_at(&branch, 2).position();
    let round_three = round_at(&branch, 3).position();
    let round_two_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_two_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_three_prevote = signed_vote_bytes(
        fixture.context,
        round_three,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_three_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(
                driver,
                proposal_event(3, &round_three_control, &round_three_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_three_prevote));
            let (driver, _) = admit(
                driver,
                proposal_event(2, &round_two_control, &round_two_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_two_prevote));

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    match reason {
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second } => {
                            assert_eq!(first.position(), round_two);
                            assert_eq!(second.position(), round_three);
                        }
                        _ => panic!("expected cross-position evidence ambiguity"),
                    }
                    *driver
                }
                _ => panic!("the driver must not prefer a lower or earlier actionable round"),
            };
            assert_eq!(layout.images(), before);
            assert!(driver.timeout_is_due());

            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            let mut expected_proposals = vec![
                (round_two_control.clone(), round_two_payload.clone()),
                (round_three_control.clone(), round_three_payload.clone()),
            ];
            expected_proposals.sort_unstable();
            let mut expected_prevotes =
                vec![round_two_prevote.clone(), round_three_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(proposals, expected_proposals);
            assert_eq!(prevotes, expected_prevotes);

            let driver = step_transition(*driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn saturation_blocks_a_retained_prefix_until_lossless_reset() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-saturation");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 1, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let driver = match driver.admit_event(prevote_event(&prevote)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                            canonical_signed_prevote,
                        } => assert_eq!(canonical_signed_prevote.as_ref(), prevote.as_slice()),
                        _ => panic!("saturation must return the rejected prevote"),
                    }
                    *driver
                }
                _ => panic!("distinct input above the cap must saturate"),
            };
            assert_eq!(driver.inbox_len(), 1);
            let driver = match driver
                .admit_event(proposal_event(2, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::Saturated(_)
                        )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                            ..
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                control.as_slice()
                            );
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("blocked admission must return the exact proposal event"),
                    }
                    *driver
                }
                _ => panic!("latched saturation must deny even a duplicate admission"),
            };
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Saturated(_)
                    ));
                    *driver
                }
                _ => panic!("latched saturation must keep blocking"),
            };
            assert_eq!(layout.images(), before);
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 1);
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert!(prevotes.is_empty());
            assert!(driver.timeout_is_due());
            let driver = step_transition(*driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn fresh_driver_lineage_rejects_a_previous_driver_ticket_after_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-ticket-restart");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let old_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 4, 2));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit_due(driver, timeout);
            assert_eq!(driver.inbox_len(), 1);
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            drop(driver);
            timeout
        })
        .unwrap();
    let before_vote = layout.images();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let superseded_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, new_timeout) = step_arm(driver(scope, 4, 2));
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert_eq!(old_timeout.context(), new_timeout.context());
            assert_eq!(old_timeout.position(), new_timeout.position());
            assert_eq!(old_timeout.phase(), new_timeout.phase());
            assert_eq!(old_timeout.generation(), new_timeout.generation());
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(old_timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver, rejection, ..
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    *driver
                }
                _ => panic!("old driver lineage must not authorize a fresh driver"),
            };
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, disposition) = admit_due(driver, new_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 1);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_ne!(layout.images(), before_vote);
            drop(driver);
            new_timeout
        })
        .unwrap();

    let durable_vote = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 4, 2);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());

            let (driver, fresh_timeout) = step_arm(driver);
            assert_eq!(fresh_timeout.generation(), 0);
            assert_eq!(fresh_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(layout.images(), durable_vote);
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(
                    superseded_timeout,
                ))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == superseded_timeout
                    ));
                    *driver
                }
                _ => panic!("restart must not reconstruct the dropped publication or timer"),
            };
            let (_, disposition) = admit_due(driver, fresh_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
        })
        .unwrap();
}

#[test]
fn evidence_pending_publication_is_not_reconstructed_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-evidence-pending-restart");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let root = value.proposal_signing_root();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_at(&branch, 2)
        .build_quorum_certificate_from_signed_votes(
            &[prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let dropped_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            let driver = step_transition(driver);

            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.inbox_len(), 1);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_ne!(layout.images(), before);
            drop(driver);
            timeout
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position(), position);
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
            let locked = signing
                .locked_value()
                .expect("higher-round precommit must recover its exact lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("higher-round precommit must recover its valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );

            let driver = driver(scope, 8, 4);
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            let (driver, fresh_timeout) = step_arm(driver);
            assert_eq!(fresh_timeout.position(), position);
            assert_eq!(fresh_timeout.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(fresh_timeout.generation(), 0);
            assert_eq!(layout.images(), durable);

            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(dropped_timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == dropped_timeout
                    ));
                    assert_eq!(driver.inbox_len(), 0);
                    assert!(!driver.timeout_is_due());
                }
                _ => panic!("strict restart must not reconstruct the dropped publication"),
            }
        })
        .unwrap();
}

#[test]
fn fatal_vote_anchor_failure_returns_no_driver_command_and_reopens_strictly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-vote-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            match driver.step() {
                Err(error) => error,
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Command { .. }) => {
                    panic!("fatal anchored-vote failure must emit no command")
                }
                Ok(_) => panic!("fatal anchored-vote failure must return no live driver"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeDriverStepErrorV0::Vote(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeVoteExecutionErrorV0::Prepare(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                    )
            )
    ));

    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn fatal_finality_handoff_failure_returns_no_driver_and_reopens_strictly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-handoff-failure");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            match driver.step() {
                Err(error) => error,
                Ok(_) => panic!("fatal finality handoff failure must return no live driver"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeDriverStepErrorV0::CurrentFinality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } if matches!(
                            selection.as_ref(),
                            FixedValidatorNodeFinalitySelectionV0::Finalized {
                                position: finalized,
                                ..
                            } if *finalized == position
                        ) && matches!(
                            source.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                        )
                    )
            )
    ));

    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn current_nil_prevote_variants_share_capacity_and_select_canonically() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let standard = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let preferred = if standard < alternate {
        standard.as_slice()
    } else {
        alternate.as_slice()
    };
    let expected_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &[preferred],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
        )
        .unwrap()
        .to_canonical_bytes();

    for (first, second) in [
        (standard.as_slice(), alternate.as_slice()),
        (alternate.as_slice(), standard.as_slice()),
    ] {
        let limits = FixedValidatorNodeCurrentRoundInboxLimitsV0::new(
            2,
            u64::try_from(first.len() + second.len()).unwrap(),
        )
        .unwrap();
        let mut inbox = CurrentRoundInboxV0::new(limits);
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, first),
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
        ));
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, first),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained)
        ));
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, second),
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
        ));
        assert_eq!(inbox.len(), 2);
        assert_eq!(
            inbox.total_canonical_input_bytes(),
            u64::try_from(first.len() + second.len()).unwrap()
        );
        match inbox.select_nil_quorum(&round) {
            Ok(CurrentRoundQuorumSelectionV0::One {
                canonical_certificate,
            }) => assert_eq!(canonical_certificate, expected_certificate),
            _ => panic!("the canonical nil quorum must be actionable"),
        }
        let (_, proposal_prevotes, mut nil_prevotes) =
            drained_current_contents(inbox.drain_and_reset());
        assert!(proposal_prevotes.is_empty());
        nil_prevotes.sort_unstable();
        let mut expected = vec![first.to_vec(), second.to_vec()];
        expected.sort_unstable();
        assert_eq!(nil_prevotes, expected);
    }
}

#[test]
fn current_nil_prevote_admission_is_target_typed_and_shares_current_limits() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-prevote-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive_nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &inactive_signer,
    );
    let wrong_position_nil_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_nil_prevote = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut invalid_signature_nil_prevote = nil_prevote.clone();
    *invalid_signature_nil_prevote.last_mut().unwrap() ^= 0x01;
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver_with_inbox_limits(scope, 8, 1, 4));
            let driver = reject_current_nil_prevote(driver, &proposal_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::ProposalTarget {
                            actual
                        }
                    ) if *actual == value.proposal_signing_root()
                ));
            });
            let driver = reject_current_nil_prevote(driver, &nil_precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Precommit
                        }
                    )
                ));
            });
            let driver = reject_current_nil_prevote(driver, &inactive_nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::InactiveSigner { .. }
                    )
                ));
            });
            let driver = reject_current_nil_prevote(
                driver,
                &wrong_position_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::PositionMismatch {
                                ..
                            }
                        )
                    ));
                },
            );
            let driver = reject_current_nil_prevote(
                driver,
                &wrong_context_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_nil_prevote(
                driver,
                &invalid_signature_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                },
            );
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(layout.images(), before);

            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let driver = reject_current_nil_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        position: saturated_position,
                        newly_saturated: true,
                        ..
                    } if *saturated_position == position
                ));
            });
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(layout.images(), before);
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) =
                drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert!(proposal_prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn exact_due_progression_preserves_populated_lock_and_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-due-lock-valid-retention-no-quorum");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let evidence_position = round_at(&branch, 2).position();
    let root = value.proposal_signing_root();
    let prevote = signed_vote_bytes(
        fixture.context,
        evidence_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_at(&branch, 2)
        .build_quorum_certificate_from_signed_votes(
            &[prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            let driver = step_transition(driver);
            let durable_evidence = layout.images();
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_some());
            assert_eq!(precommit.position(), evidence_position);
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            let (driver, precommit_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), durable_evidence);
            let (driver, proposal_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let after_due_vote = layout.images();
            assert_ne!(after_due_vote, durable_evidence);
            let (driver, locked_prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(locked_prevote.position(), driver.position());
            assert_eq!(locked_prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(locked_prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert_eq!(layout.images(), after_due_vote);

            let (driver, prevote_timeout) = step_arm(driver);
            assert_eq!(prevote_timeout.position(), driver.position());
            assert_eq!(prevote_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let after_due_precommit = layout.images();
            assert_ne!(after_due_precommit, after_due_vote);
            let (driver, nil_precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(nil_precommit.position(), driver.position());
            assert_eq!(nil_precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(nil_precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(layout.images(), after_due_precommit);
            drop(driver);
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position().round(), ConsensusRound::new(3));
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
            let locked = signing
                .locked_value()
                .expect("exact due progression must preserve the existing lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("exact due progression must preserve valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );
            assert_eq!(layout.images(), durable);
        })
        .unwrap();
}

#[test]
fn current_nil_quorum_precedes_due_and_preserves_populated_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-nil-quorum-lock-valid-retention");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let evidence_position = round_at(&branch, 2).position();
    let root = value.proposal_signing_root();
    let prevote = signed_vote_bytes(
        fixture.context,
        evidence_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_at(&branch, 2)
        .build_quorum_certificate_from_signed_votes(
            &[prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let round_three_nil_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 3).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            let driver = step_transition(driver);
            let durable_evidence = layout.images();
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_some());
            assert_eq!(precommit.position(), evidence_position);
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            let (driver, precommit_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), durable_evidence);
            let (driver, proposal_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let after_due_vote = layout.images();
            assert_ne!(after_due_vote, durable_evidence);
            let (driver, locked_prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(locked_prevote.position(), driver.position());
            assert_eq!(locked_prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(locked_prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert_eq!(layout.images(), after_due_vote);

            let (driver, prevote_timeout) = step_arm(driver);
            assert_eq!(prevote_timeout.position(), driver.position());
            assert_eq!(prevote_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            let (driver, disposition) =
                admit(driver, current_nil_prevote_event(&round_three_nil_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let after_due_precommit = layout.images();
            assert_ne!(after_due_precommit, after_due_vote);
            let (driver, nil_precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(nil_precommit.position(), driver.position());
            assert_eq!(nil_precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(nil_precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(layout.images(), after_due_precommit);
            drop(driver);
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position().round(), ConsensusRound::new(3));
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(
                signing.locked_value().is_none(),
                "the nil quorum must clear the prior lock"
            );
            let valid = signing
                .valid_value()
                .expect("the nil quorum must preserve complete valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );
            assert_eq!(layout.images(), durable);
        })
        .unwrap();
}

#[test]
fn current_proposal_and_explicit_prevote_loopback_drive_anchored_precommit() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-two-phase");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let (other_value, _, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let mismatched_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(other_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 1);
            let (driver, _) = admit_due(driver, proposal_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_inbox_len(), 1);
            let after_prevote_anchor = layout.images();
            assert_eq!(after_prevote_anchor[0], before[0]);
            assert_eq!(after_prevote_anchor[1], before[1]);
            assert_ne!(after_prevote_anchor, before);

            let driver = match driver
                .admit_event(current_prevote_event(&expected_prevote))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == expected_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("current loopback must wait for publication custody transfer"),
            };
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let canonical_prevote = prevote.canonical_bytes().to_vec();
            assert_eq!(canonical_prevote, expected_prevote);
            let (driver, prevote_timeout) = step_arm(driver);

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("the driver must not count its own prevote before explicit loopback"),
            };
            let (driver, disposition) = admit(driver, current_prevote_event(&mismatched_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("a quorum for another root must not authorize this proposal"),
            };
            let (driver, disposition) = admit(driver, current_prevote_event(&canonical_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_prevote_event(&canonical_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                u64::try_from(
                    control.len()
                        + payload.len()
                        + mismatched_prevote.len()
                        + canonical_prevote.len()
                )
                .unwrap()
            );
            let (driver, _) = admit_due(driver, prevote_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 3);
            let after_precommit_anchor = layout.images();
            assert_eq!(after_precommit_anchor[0], before[0]);
            assert_eq!(after_precommit_anchor[1], before[1]);
            assert_ne!(after_precommit_anchor, after_prevote_anchor);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(precommit_timeout.position(), driver.position());
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            let driver = reject_current_prevote(driver, &canonical_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });

            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            let mut expected_prevotes = vec![canonical_prevote, mismatched_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(prevotes, expected_prevotes);
            assert!(nil_prevotes.is_empty());
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_inbox_canonical_input_bytes(), 0);
        })
        .unwrap();
}

#[test]
fn current_nil_prevote_loopback_drives_anchored_precommit_ahead_of_due() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-prevote-quorum");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let expected_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let after_prevote_anchor = layout.images();
            assert_ne!(after_prevote_anchor, before);

            let driver = match driver
                .admit_event(current_nil_prevote_event(&expected_prevote))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == expected_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("nil loopback must wait for publication custody transfer"),
            };
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.position(), position);
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            assert_eq!(prevote.canonical_bytes(), expected_prevote.as_slice());
            let (driver, prevote_timeout) = step_arm(driver);

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("the driver must not self-observe its published nil prevote"),
            };
            let (driver, disposition) = admit(driver, current_nil_prevote_event(&expected_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_nil_prevote_event(&expected_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                u64::try_from(expected_prevote.len()).unwrap()
            );
            let (driver, _) = admit_due(driver, prevote_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            assert_eq!(driver.current_inbox_len(), 1);
            let after_precommit_anchor = layout.images();
            assert_ne!(after_precommit_anchor, after_prevote_anchor);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.position(), position);
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(layout.images(), after_precommit_anchor);
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(precommit_timeout.position(), position);
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            let driver = reject_current_nil_prevote(driver, &expected_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) = drained_current_contents(drained);
            assert!(proposals.is_empty());
            assert!(proposal_prevotes.is_empty());
            assert_eq!(nil_prevotes, vec![expected_prevote.clone()]);
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert!(scope.signing_session().locked_value().is_none());
            assert!(scope.signing_session().valid_value().is_none());
            assert_eq!(layout.images(), durable);
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_nil_prevote(driver, &expected_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(layout.images(), durable);
        })
        .unwrap();
}

#[test]
fn current_proposal_and_nil_quorums_fail_closed_with_higher_escape() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_position = round_at(&branch, 0).position();
    let current_root = current_value.proposal_signing_root();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );

    for (label, nil_first) in [
        ("driver-current-cross-target-proposal-first", false),
        ("driver-current-cross-target-nil-first", true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 16, 4));
                let (driver, _) = admit(
                    driver,
                    current_proposal_event(&current_control, &current_payload),
                );
                let (driver, _) = if nil_first {
                    admit(driver, current_nil_prevote_event(&nil_prevote))
                } else {
                    admit(driver, current_prevote_event(&proposal_prevote))
                };
                let (driver, _) = if nil_first {
                    admit(driver, current_prevote_event(&proposal_prevote))
                } else {
                    admit(driver, current_nil_prevote_event(&nil_prevote))
                };

                let driver = step_transition(driver);
                let (driver, local_prevote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(
                    local_prevote.target(),
                    ConsensusVoteTarget::Proposal(current_root)
                );
                let (driver, prevote_timeout) = step_arm(driver);
                let (driver, _) = admit_due(driver, prevote_timeout);
                let before_ambiguity = layout.images();
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            } if position == current_position
                                && proposal_signing_root == current_root
                        ));
                        *driver
                    }
                    _ => panic!("competing proposal and nil quorums must fail closed"),
                };
                assert_eq!(driver.current_inbox_len(), 3);
                assert!(driver.timeout_is_due());
                assert_eq!(layout.images(), before_ambiguity);

                let driver = reject_current_nil_prevote(driver, &nil_prevote, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            }
                        ) if *position == current_position
                            && *proposal_signing_root == current_root
                    ));
                });
                assert_eq!(layout.images(), before_ambiguity);

                let (driver, _) =
                    admit(driver, proposal_event(2, &higher_control, &higher_payload));
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let driver = step_transition(driver);
                assert_eq!(driver.position(), higher_position);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                let (driver, higher_vote, released_proposal) = step_publish(driver);
                assert_eq!(
                    higher_vote.target(),
                    ConsensusVoteTarget::Proposal(higher_root)
                );
                assert!(released_proposal.is_some());
                let (driver, _) = step_arm(driver);
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            } if position == current_position
                                && proposal_signing_root == current_root
                        ));
                        *driver
                    }
                    _ => panic!("current quorum ambiguity must remain latched until drain"),
                };

                let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
                let (proposals, proposal_prevotes, nil_prevotes) =
                    drained_current_contents(drained);
                assert_eq!(
                    proposals,
                    vec![(current_control.clone(), current_payload.clone())]
                );
                assert_eq!(proposal_prevotes, vec![proposal_prevote.clone()]);
                assert_eq!(nil_prevotes, vec![nil_prevote.clone()]);
                assert_eq!(driver.current_inbox_len(), 0);
                assert!(matches!(
                    driver.step().unwrap(),
                    FixedValidatorNodeDriverStepOutcomeV0::Idle { .. }
                ));
            })
            .unwrap();
    }
}

#[test]
fn current_signature_variants_select_one_per_signer_independent_of_insertion_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let preferred = if standard < alternate {
        standard.as_slice()
    } else {
        alternate.as_slice()
    };
    let expected_certificate = round_at(&branch, 0)
        .build_quorum_certificate_from_signed_votes(
            &[preferred],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let orders = [
        (
            "driver-current-signature-standard-first",
            &standard,
            &alternate,
        ),
        (
            "driver-current-signature-alternate-first",
            &alternate,
            &standard,
        ),
    ];
    let mut outcomes = Vec::new();

    for (label, first, second) in orders {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let precommit_bytes = ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
                let (driver, _) = admit(driver, current_prevote_event(first));
                let (driver, _) = admit(driver, current_prevote_event(second));
                assert_eq!(driver.current_inbox_len(), 3);

                let driver = step_transition(driver);
                let (driver, published_prevote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(
                    published_prevote.target(),
                    ConsensusVoteTarget::Proposal(root)
                );
                let (driver, _) = step_arm(driver);
                let driver = step_transition(driver);
                let (driver, precommit, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
                assert_eq!(driver.current_inbox_len(), 3);
                precommit.canonical_bytes().to_vec()
            })
            .unwrap();

        let durable = layout.images();
        assert_eq!(durable[0], before[0]);
        assert_eq!(durable[1], before[1]);
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|mut scope| {
                let signing = scope.signing_session();
                assert_eq!(signing.position(), position);
                assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
                let locked = signing
                    .locked_value()
                    .expect("current proposal quorum must restore its exact lock");
                assert_eq!(locked.round(), ConsensusRound::new(0));
                assert_eq!(locked.proposal_signing_root(), root);
                let valid = signing
                    .valid_value()
                    .expect("current proposal quorum must restore valid evidence");
                assert_eq!(valid.round(), ConsensusRound::new(0));
                assert_eq!(valid.value().proposal_signing_root(), root);
                assert_eq!(
                    valid.canonical_prevote_certificate(),
                    expected_certificate.as_slice()
                );
                assert_eq!(layout.images(), durable);
            })
            .unwrap();
        outcomes.push((precommit_bytes, durable));
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn current_evidence_after_due_is_returned_without_mutation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-due-fence");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let control = control.into_boxed_slice();
    let payload = payload.into_boxed_slice();
    let control_pointer = control.as_ptr();
    let payload_pointer = payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let position = driver.position();
            let (driver, _) = admit_due(driver, timeout);
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                    canonical_proposal_control_bytes: control,
                    canonical_artifact_bytes: payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                            position: rejected_position,
                            phase: FixedValidatorLockPhaseV0::Proposal,
                        } if rejected_position == position
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                        }
                        _ => panic!("due-fenced proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("current proposal after due must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);
            assert!(driver.timeout_is_due());
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let valid_nil_prevote = prevote.canonical_bytes().to_vec();
            assert_eq!(driver.current_inbox_len(), 0);
            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = reject_current_prevote(driver, &valid_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                        position: rejected_position,
                        phase: FixedValidatorLockPhaseV0::Prevote,
                    } if *rejected_position == position
                ));
            });
            let driver = reject_current_nil_prevote(driver, &valid_nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                        position: rejected_position,
                        phase: FixedValidatorLockPhaseV0::Prevote,
                    } if *rejected_position == position
                ));
            });
            assert!(driver.timeout_is_due());
            assert_eq!(driver.current_inbox_len(), 0);
            let driver = step_transition(driver);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(driver.current_inbox_len(), 0);
        })
        .unwrap();
}

#[test]
fn byte_distinct_same_root_current_proposals_fail_closed() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-same-root-ambiguity");
    let branch = fixed_branch(&fixture);
    let (round_one_value, round_one_control, round_one_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let (round_two_value, plain_control, payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = round_two_value.proposal_signing_root();
    assert_eq!(round_one_value.proposal_signing_root(), root);
    assert_eq!(round_one_payload, payload);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, round_zero_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _round_one_timeout) = close_empty_round(driver, round_zero_timeout);
            assert_eq!(driver.position(), round_at(&branch, 1).position());
            let (driver, _) = admit(
                driver,
                current_proposal_event(&round_one_control, &round_one_payload),
            );
            let driver = step_transition(driver);
            let (driver, valid_round_prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(
                valid_round_prevote.target(),
                ConsensusVoteTarget::Proposal(root)
            );
            let valid_round_prevote = valid_round_prevote.canonical_bytes().to_vec();
            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            let (driver, nil_precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(nil_precommit.target(), ConsensusVoteTarget::Nil);
            let (driver, precommit_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            let (driver, _round_two_timeout) = step_arm(driver);
            assert_eq!(driver.position(), round_at(&branch, 2).position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());

            let valid_round_certificate = round_at(&branch, 1)
                .build_quorum_certificate_from_signed_votes(
                    &[valid_round_prevote.as_slice()],
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(root),
                )
                .unwrap()
                .to_canonical_bytes();
            let proof_control = proposal_control_with_valid_round(
                &fixture,
                round_two_value,
                round_at(&branch, 2).position(),
                &valid_round_certificate,
            );
            assert_ne!(plain_control, proof_control);
            let before_ambiguity = layout.images();

            let (driver, _) = admit(driver, current_proposal_event(&plain_control, &payload));
            let (driver, _) = admit(driver, current_proposal_event(&proof_control, &payload));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                            position,
                            first,
                            second,
                        } if position == round_at(&branch, 2).position()
                            && first == root
                            && second == root
                    ));
                    *driver
                }
                _ => panic!("byte-distinct same-root proposals must block current action"),
            };
            assert_eq!(driver.current_inbox_len(), 3);
            assert!(!driver.timeout_is_due());
            assert_eq!(layout.images(), before_ambiguity);
            let driver = match driver
                .admit_event(current_proposal_event(&plain_control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                                position,
                                first,
                                second,
                            }
                        ) if *position == round_at(&branch, 2).position()
                            && *first == root
                            && *second == root
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } if canonical_proposal_control_bytes.as_ref() == plain_control.as_slice()
                            && canonical_artifact_bytes.as_ref() == payload.as_slice()
                    ));
                    *driver
                }
                _ => panic!("live current ambiguity must deny later current proposals"),
            };
            let ambiguity_prevote = signed_vote_bytes(
                fixture.context,
                round_at(&branch, 2).position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let driver = match driver
                .admit_event(current_prevote_event(&ambiguity_prevote))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous { .. }
                        )
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == ambiguity_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("live current ambiguity must deny later current prevotes"),
            };
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(layout.images(), before_ambiguity);
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut first_expected = vec![
                (round_one_control.clone(), round_one_payload.clone()),
                (plain_control.clone(), payload.clone()),
                (proof_control.clone(), payload.clone()),
            ];
            first_expected.sort_unstable();
            assert_eq!(proposals, first_expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());

            let (driver, _) = admit(*driver, current_proposal_event(&proof_control, &payload));
            let (driver, _) = admit(driver, current_proposal_event(&plain_control, &payload));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                            first,
                            second,
                            ..
                        } if first == root && second == root
                    ));
                    *driver
                }
                _ => panic!("reverse insertion must produce the same ambiguity"),
            };
            assert_eq!(layout.images(), before_ambiguity);
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut expected = vec![
                (plain_control.clone(), payload.clone()),
                (proof_control.clone(), payload.clone()),
            ];
            expected.sort_unstable();
            assert_eq!(proposals, expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn current_ambiguity_is_round_local_and_higher_evidence_escapes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-ambiguity-higher-escape");
    let branch = fixed_branch(&fixture);
    let (_, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&first_control, &first_payload),
            );
            let (driver, _) = admit(
                driver,
                current_proposal_event(&second_control, &second_payload),
            );
            let (driver, _) = admit_due(driver, timeout);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous { .. }
                    ));
                    *driver
                }
                _ => panic!("competing current proposals must block current action"),
            };

            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 2);
            assert!(!driver.timeout_is_due());
            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(higher_root));
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("stale current ambiguity must not block the advanced position"),
            };

            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut expected = vec![
                (first_control.clone(), first_payload.clone()),
                (second_control.clone(), second_payload.clone()),
            ];
            expected.sort_unstable();
            assert_eq!(proposals, expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn actionable_higher_evidence_precedes_healthy_current_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-higher-before-current");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 2);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert_eq!(
                precommit.target(),
                ConsensusVoteTarget::Proposal(higher_root)
            );
            let released_proposal =
                released_proposal.expect("higher action must transfer its selected token");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                higher_control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), higher_payload);
            assert_eq!(driver.current_inbox_len(), 2);
        })
        .unwrap();
}

#[test]
fn current_saturation_uses_a_separate_budget_and_preserves_higher_escape() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-separate-saturation");
    let branch = fixed_branch(&fixture);
    let (_, retained_control, retained_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, rejected_control, rejected_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let higher_position = round_at(&branch, 2).position();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, current_timeout) = step_arm(driver_with_inbox_limits(scope, 4, 1, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&retained_control, &retained_payload),
            );
            let driver = match driver
                .admit_event(current_proposal_event(&rejected_control, &rejected_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                            newly_saturated: true,
                            ..
                        }
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                rejected_control.as_slice()
                            );
                            assert_eq!(
                                canonical_artifact_bytes.as_ref(),
                                rejected_payload.as_slice()
                            );
                        }
                        _ => panic!("current saturation must return the rejected event"),
                    }
                    *driver
                }
                _ => panic!("the second current input must exceed its separate cap"),
            };
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 0);
            let (driver, _) = admit_due(driver, current_timeout);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }
                    ));
                    *driver
                }
                _ => panic!("current saturation must block the exact due path"),
            };

            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            assert_eq!(driver.inbox_len(), 2);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, _, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }
                    ));
                    *driver
                }
                _ => panic!("current saturation must require an explicit drain after advance"),
            };

            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(
                proposals,
                vec![(retained_control.clone(), retained_payload.clone())]
            );
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.inbox_len(), 1);
            assert!(matches!(
                driver.step().unwrap(),
                FixedValidatorNodeDriverStepOutcomeV0::Idle { .. }
            ));
        })
        .unwrap();
}

#[test]
fn current_byte_saturation_does_not_consume_higher_inbox_capacity() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-separate-byte-saturation");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let current_exact_bytes = u64::try_from(current_control.len() + current_payload.len()).unwrap();
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver_with_limits(
                scope,
                4,
                1024 * 1024,
                4,
                current_exact_bytes,
                4,
            ));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_exact_bytes
            );
            let driver = reject_current_prevote(driver, &current_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        saturation:
                            FixedValidatorNodeCurrentRoundInboxSaturationV0::Capacity { .. },
                        newly_saturated: true,
                        ..
                    }
                ));
            });
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 0);

            let (driver, _) = admit(
                driver,
                proposal_event(2, &higher_control, &higher_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            assert_eq!(driver.inbox_len(), 2);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(higher_root));
            assert!(released_proposal.is_some());
            assert_eq!(driver.current_inbox_len(), 1);
        })
        .unwrap();
}

#[test]
fn current_admission_returns_invalid_inputs_and_deduplicates_verified_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_position_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_prevote = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &inactive_signer,
    );
    let mut invalid_signature_prevote = valid_prevote.clone();
    *invalid_signature_prevote.last_mut().unwrap() ^= 0x01;
    let mismatched_payload = proof_payload(ZfcAxiom::Union);
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let malformed_payload = payload.clone().into_boxed_slice();
    let malformed_control_pointer = malformed_control.as_ptr();
    let malformed_payload_pointer = malformed_payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                    canonical_proposal_control_bytes: malformed_control,
                    canonical_artifact_bytes: malformed_payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(source)
                            if matches!(
                                source.as_ref(),
                                naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                    actual: 3,
                                    ..
                                }
                            )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ptr(),
                                malformed_control_pointer
                            );
                            assert_eq!(
                                canonical_artifact_bytes.as_ptr(),
                                malformed_payload_pointer
                            );
                        }
                        _ => panic!("invalid current proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("malformed current proposal must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);

            let driver = match driver
                .admit_event(current_proposal_event(&control, &mismatched_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(_)
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } if canonical_proposal_control_bytes.as_ref() == control.as_slice()
                            && canonical_artifact_bytes.as_ref() == mismatched_payload.as_slice()
                    ));
                    *driver
                }
                _ => panic!("a mismatched current proposal payload must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);

            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            let driver = reject_current_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &wrong_position_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &wrong_context_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                        naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::Vote(
                            naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                        )
                    )
                ));
            });
            let driver = reject_current_prevote(driver, &inactive_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                        naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::InactiveSigner {
                            ..
                        }
                    )
                ));
            });
            let driver =
                reject_current_prevote(driver, &invalid_signature_prevote, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                            naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                });
            let (driver, disposition) = admit(driver, current_prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 2);
            assert_eq!(layout.images(), before);

            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(prevotes, vec![valid_prevote.clone()]);
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn current_evidence_is_volatile_and_can_be_readmitted_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-restart-readmission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let canonical_prevote = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let canonical_prevote = prevote.canonical_bytes().to_vec();
            let (driver, _) = step_arm(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_inbox_len(), 1);
            drop(driver);
            canonical_prevote
        })
        .unwrap();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position(),
                round_at(&branch, 0).position()
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.current_inbox_len(), 0);
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_prevote_event(&canonical_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            assert_eq!(driver.current_inbox_len(), 2);
        })
        .unwrap();
}

#[test]
fn current_finality_executes_from_every_phase_and_due_state() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let finality_bytes = u64::try_from(control.len() + payload.len() + precommit.len()).unwrap();
    let child_height = position.height().value().checked_add(1).unwrap();

    for (label, expected_phase, mark_due) in [
        (
            "driver-current-finality-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-current-finality-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-current-finality-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-current-finality-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-current-finality-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-current-finality-precommit-due",
            FixedValidatorLockPhaseV0::Precommit,
            true,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
                let (driver, active_timeout) = match expected_phase {
                    FixedValidatorLockPhaseV0::Proposal => (driver, proposal_timeout),
                    FixedValidatorLockPhaseV0::Prevote => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        let (driver, prevote_timeout) = step_arm(driver);
                        let (driver, _) = admit_due(driver, prevote_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                };
                let driver = if mark_due {
                    let (driver, disposition) = admit_due(driver, active_timeout);
                    assert_eq!(
                        disposition,
                        FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                    );
                    driver
                } else {
                    driver
                };
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);
                let before_finality = layout.images();

                let (driver, _) =
                    admit(driver, current_finality_proposal_event(&control, &payload));
                let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                        if action.position() == position
                            && action.proposal_signing_root() == root
                ));
                let (driver, selection) = step_finality(driver);
                assert!(matches!(
                    selection,
                    FixedValidatorNodeFinalitySelectionV0::Finalized {
                        position: finalized,
                        ..
                    } if finalized == position
                ));
                assert_eq!(driver.position().height().value(), child_height);
                assert_eq!(driver.position().round().value(), 0);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                assert_eq!(driver.current_finality_inbox_len(), 2);
                assert_eq!(
                    driver.current_finality_inbox_canonical_input_bytes(),
                    finality_bytes
                );
                let after_finality = layout.images();
                for (before, after) in before_finality.iter().zip(after_finality.iter()) {
                    assert_ne!(before, after, "each authority image must advance");
                }

                let (driver, child_timeout) = step_arm(driver);
                assert_eq!(child_timeout.position(), driver.position());
                assert_eq!(child_timeout.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert_eq!(
                    child_timeout.generation(),
                    active_timeout.generation().checked_add(1).unwrap()
                );
                let driver = match driver
                    .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(active_timeout))
                    .unwrap()
                {
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                        driver,
                        event,
                        rejection,
                    } => {
                        assert!(matches!(
                            *event,
                            FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                                if returned == active_timeout
                        ));
                        assert!(matches!(
                            rejection.as_ref(),
                            FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                        ));
                        *driver
                    }
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
                        panic!("the pre-finality timer must be stale")
                    }
                };
                let (driver, drained) =
                    driver.drain_current_finality_inbox_and_reset().into_parts();
                let (proposals, precommits) = drained_current_finality_contents(drained);
                assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
                assert_eq!(precommits, vec![precommit.clone()]);
                assert_eq!(driver.position().height().value(), child_height);
            })
            .unwrap();

        let reopened = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|mut scope| {
                assert_eq!(
                    scope.signing_session().position().height().value(),
                    child_height
                );
                assert_eq!(scope.signing_session().position().round().value(), 0);
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
            })
            .unwrap();
    }
}

#[test]
fn current_finality_precommit_rejections_preserve_each_typed_admission_error() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-precommit-errors");
    let branch = fixed_branch(&fixture);
    let (value, _, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let valid = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_position = round_at(&branch, 1).position();
    let wrong_position_precommit = signed_vote_bytes(
        fixture.context,
        wrong_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive = SigningKey::from_bytes(&signing_seed(2));
    let inactive_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &inactive,
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_precommit = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid;
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_finality_precommit(
                driver,
                &wrong_context_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_finality_precommit(
                driver,
                &invalid_signature,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_finality_precommit(
                driver,
                &wrong_position_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::PositionMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == position && *actual == wrong_position
                    ));
                },
            );
            let driver = reject_current_finality_precommit(driver, &prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                        naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Prevote,
                        }
                    )
                ));
            });
            let driver = reject_current_finality_precommit(driver, &nil_precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                        naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::NilTarget
                    )
                ));
            });
            let driver = reject_current_finality_precommit(
                driver,
                &inactive_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::InactiveSigner {
                                signer,
                            }
                        ) if *signer == consensus_key(&inactive)
                    ));
                },
            );
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            let _driver = step_idle(driver);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_finality_budget_accounting_saturation_and_lossless_drain_are_isolated() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-budget-drain");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let root = value.proposal_signing_root();
    let position = round_at(&branch, 0).position();
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let proposal_bytes = u64::try_from(control.len() + payload.len()).unwrap();
    let exact_finality_bytes = proposal_bytes + u64::try_from(standard.len()).unwrap();
    let attempted_finality_bytes = exact_finality_bytes + u64::try_from(alternate.len()).unwrap();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                1,
                1024 * 1024,
                1,
                1024 * 1024,
                2,
                exact_finality_bytes,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) =
                admit(driver, proposal_event(1, &higher_control, &higher_payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) =
                admit(driver, current_finality_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                proposal_bytes
            );
            let (driver, disposition) =
                admit(driver, current_finality_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                proposal_bytes
            );

            let (driver, disposition) = admit(driver, current_finality_precommit_event(&standard));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );
            let (driver, disposition) = admit(driver, current_finality_precommit_event(&standard));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );

            let driver = reject_current_finality_precommit(driver, &alternate, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                        position: saturated_position,
                        saturation:
                            FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                attempted_entries: 3,
                                maximum_entries: 2,
                                attempted_canonical_input_bytes,
                                maximum_canonical_input_bytes,
                            },
                        newly_saturated: true,
                    } if *saturated_position == position
                        && *attempted_canonical_input_bytes == attempted_finality_bytes
                        && *maximum_canonical_input_bytes == exact_finality_bytes
                ));
            });
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position: saturated_position,
                    saturation:
                        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                            attempted_entries: 3,
                            maximum_entries: 2,
                            ..
                        },
                } if saturated_position == position
            ));

            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(precommits, vec![standard.clone()]);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) =
                admit(*driver, current_finality_precommit_event(&alternate));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                u64::try_from(alternate.len()).unwrap()
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_finality_same_signer_variants_choose_one_certificate_in_every_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = round
        .decode_and_verify_proposal_control(&control, payload)
        .unwrap()
        .proposal_signing_root();
    let standard = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let preferred = if standard < alternate {
        standard.as_slice()
    } else {
        alternate.as_slice()
    };
    let expected_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &[preferred],
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();

    for (first, second) in [
        (standard.as_slice(), alternate.as_slice()),
        (alternate.as_slice(), standard.as_slice()),
    ] {
        let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
            2,
            u64::try_from(first.len() + second.len()).unwrap(),
        )
        .unwrap();
        let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
        assert!(matches!(
            inbox.try_insert_precommit(&round, first),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        assert!(matches!(
            inbox.try_insert_precommit(&round, second),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        match inbox.classify(&round) {
            Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
                proposal_signing_root,
                canonical_precommit_certificate,
            }) => {
                assert_eq!(proposal_signing_root, root);
                assert_eq!(canonical_precommit_certificate, expected_certificate);
            }
            Ok(_) => panic!("same-signer variants must yield one canonical proposal quorum"),
            Err(_) => panic!("individually admitted votes must satisfy classifier invariants"),
        }
        let (_, mut precommits) = drained_current_finality_contents(inbox.drain_and_reset());
        precommits.sort_unstable();
        let mut expected = vec![first.to_vec(), second.to_vec()];
        expected.sort_unstable();
        assert_eq!(precommits, expected);
    }
}

#[test]
fn finality_classifier_skips_a_lower_missing_proposal_and_pairs_the_first_two_complete_roots() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let mut candidates = [ZfcAxiom::Pairing, ZfcAxiom::Union, ZfcAxiom::PowerSet]
        .into_iter()
        .map(|axiom| {
            let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, axiom);
            let root = value.proposal_signing_root();
            let precommit = signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            (root, control, payload, precommit)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|candidate| candidate.0);
    assert!(candidates.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let retained_bytes = candidates
        .iter()
        .map(|(_, control, payload, precommit)| control.len() + payload.len() + precommit.len())
        .sum::<usize>()
        - candidates[0].1.len()
        - candidates[0].2.len();
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
        5,
        u64::try_from(retained_bytes).unwrap(),
    )
    .unwrap();
    let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
    for (_, _, _, precommit) in &candidates {
        assert!(matches!(
            inbox.try_insert_precommit(&round, precommit),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    for (_, control, payload, _) in &candidates[1..] {
        let proposal = verify_deferred_proposal_at_round(&round, control, payload.clone()).unwrap();
        assert!(matches!(
            inbox.try_insert_proposal(proposal),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    match inbox.classify(&round) {
        Ok(CurrentRoundFinalityClassificationV0::Pair { first, second }) => {
            assert_eq!(first.proposal_signing_root, candidates[1].0);
            assert_eq!(second.proposal_signing_root, candidates[2].0);
            assert_eq!(first.canonical_proposal_control_bytes, candidates[1].1);
            assert_eq!(first.canonical_artifact_bytes, candidates[1].2);
            assert_eq!(second.canonical_proposal_control_bytes, candidates[2].1);
            assert_eq!(second.canonical_artifact_bytes, candidates[2].2);
        }
        Ok(_) => panic!("a missing lower proposal must not hide two later complete roots"),
        Err(_) => panic!("individually verified retained evidence must classify"),
    }
}

#[test]
fn missing_proposal_blocks_preselection_pair_until_completion_then_halts() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-preselection-pair-missing-proposal");
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let first_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_roots =
        if first_value.proposal_signing_root() < second_value.proposal_signing_root() {
            (
                first_value.proposal_signing_root(),
                second_value.proposal_signing_root(),
            )
        } else {
            (
                second_value.proposal_signing_root(),
                first_value.proposal_signing_root(),
            )
        };
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let stopped = ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                4,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_precommit_event(&first_precommit));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&second_control, &second_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&second_precommit));
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position: classified_position,
                    first,
                    second,
                } if classified_position == position && (first, second) == expected_roots
            ));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                            position: blocked_position,
                            first,
                            second,
                        } if blocked_position == position && (first, second) == expected_roots
                    ));
                    *driver
                }
                _ => panic!("a quorate root missing its proposal must block pair execution"),
            };
            assert_eq!(layout.images(), before);

            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&first_control, &first_payload),
            );
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                _ => panic!("completing the second proposal-backed root must halt"),
            }
        })
        .unwrap();
    assert_eq!(
        stopped.finality_halt().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(
        stopped.signer_stop().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    let stopped_images = layout.images();
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => assert_eq!(reopened, stopped),
        _ => panic!("strict restart must recover the completed preselection-pair stop"),
    }
    assert_eq!(layout.images(), stopped_images);
}

#[test]
fn current_finality_classifier_is_four_way_and_variant_order_stable() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let other_root = ProposalSigningRoot::from_bytes([0xf3; 32]);
    assert_ne!(root, other_root);
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    let conflicting = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(other_root),
        &fixture.signing_key(),
    );
    let expected_roots = if root < other_root {
        (root, other_root)
    } else {
        (other_root, root)
    };
    let mut outcomes = Vec::new();

    for (label, first, second) in [
        (
            "driver-current-finality-standard-first",
            standard.as_slice(),
            alternate.as_slice(),
        ),
        (
            "driver-current-finality-alternate-first",
            alternate.as_slice(),
            standard.as_slice(),
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let outcome = ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
                ));

                let (driver, _) = admit(driver, current_finality_precommit_event(first));
                let missing = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                        action,
                    ) => {
                        assert_eq!(action.position(), position);
                        assert_eq!(action.proposal_signing_root(), root);
                        (action.position(), action.proposal_signing_root())
                    }
                    _ => panic!("one quorate root without proposal must be classified explicitly"),
                };
                let (driver, _) = admit(driver, current_finality_precommit_event(second));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                        action,
                    ) if action.position() == position
                        && action.proposal_signing_root() == root
                ));
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                                position: blocked_position,
                                proposal_signing_root,
                            } if blocked_position == position && proposal_signing_root == root
                        ));
                        *driver
                    }
                    _ => panic!("a finality quorum missing its proposal must block"),
                };
                assert_eq!(layout.images(), before);

                let (driver, _) =
                    admit(driver, current_finality_proposal_event(&control, &payload));
                let ready = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action) => {
                        assert_eq!(action.position(), position);
                        assert_eq!(action.proposal_signing_root(), root);
                        (action.position(), action.proposal_signing_root())
                    }
                    _ => panic!("one proposal-bearing quorum must be ready"),
                };

                let (driver, _) = admit(driver, current_finality_precommit_event(&conflicting));
                let conflict = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                        position: classified_position,
                        first,
                        second,
                    } => {
                        assert_eq!(classified_position, position);
                        assert_eq!((first, second), expected_roots);
                        (classified_position, first, second)
                    }
                    _ => panic!("two quorate roots must fail closed without selection"),
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                                position: blocked_position,
                                first,
                                second,
                            } if blocked_position == position
                                && (first, second) == expected_roots
                        ));
                        *driver
                    }
                    _ => panic!("conflicting finality quorums must choose no winner and block"),
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                assert_eq!(layout.images(), before);
                (missing, ready, conflict)
            })
            .unwrap();
        outcomes.push(outcome);
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn complete_preselection_pair_preempts_other_work_survives_saturation_and_restarts() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left_value, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (right_value, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::PowerSet);
    let position = round_at(&branch, 0).position();
    let left_root = left_value.proposal_signing_root();
    let right_root = right_value.proposal_signing_root();
    assert_ne!(left_root, right_root);
    let standard_left_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left_root),
        &fixture.signing_key(),
    );
    let right_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(right_root),
        &fixture.signing_key(),
    );
    let alternate_left_precommit = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left_root),
        &fixture.signing_key(),
        0x01,
    );
    let (left_precommit, denied_precommit) = if standard_left_precommit < alternate_left_precommit {
        (alternate_left_precommit, standard_left_precommit)
    } else {
        (standard_left_precommit, alternate_left_precommit)
    };
    assert!(denied_precommit < left_precommit);
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_position = round_at(&branch, 1).position();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_roots = if left_root < right_root {
        (left_root, right_root)
    } else {
        (right_root, left_root)
    };
    let expected_ancestries = if left_root < right_root {
        (left_value.ancestry_id(), right_value.ancestry_id())
    } else {
        (right_value.ancestry_id(), left_value.ancestry_id())
    };
    let mut outcomes = Vec::new();

    for (label, reverse_evidence, latch_saturation) in [
        ("driver-preselection-pair-baseline", false, false),
        ("driver-preselection-pair-saturated-reversed", true, true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let stop = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    4,
                    1024 * 1024,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                assert_eq!(timeout.generation(), 0);
                let (driver, _) = admit(
                    driver,
                    current_proposal_event(&left_control, &left_payload),
                );
                let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));
                let (driver, _) = admit(
                    driver,
                    proposal_event(1, &higher_control, &higher_payload),
                );
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let (driver, _) = admit_due(driver, timeout);
                let driver = if reverse_evidence {
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&right_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&right_control, &right_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&left_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&left_control, &left_payload),
                    );
                    driver
                } else {
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&left_control, &left_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&left_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&right_control, &right_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&right_precommit),
                    );
                    driver
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                        position: classified_position,
                        first,
                        second,
                    } if classified_position == position && (first, second) == expected_roots
                ));
                let driver = if latch_saturation {
                    let driver = reject_current_finality_precommit(
                        driver,
                        &denied_precommit,
                        |rejection| {
                            assert!(matches!(
                                rejection,
                                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                    position: saturated_position,
                                    saturation:
                                        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                            attempted_entries: 5,
                                            maximum_entries: 4,
                                            ..
                                        },
                                    newly_saturated: true,
                                } if *saturated_position == position
                            ));
                        },
                    );
                    assert_eq!(driver.current_finality_inbox_len(), 4);
                    assert!(matches!(
                        driver.classify_current_finality_evidence().unwrap(),
                        FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                            position: classified_position,
                            first,
                            second,
                        } if classified_position == position && (first, second) == expected_roots
                    ));
                    driver
                } else {
                    driver
                };
                let mut driver = driver;
                driver.set_timer_generation_for_test(u64::MAX);
                match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                    _ => panic!(
                        "two complete finality roots must preempt due, current, higher, and nil work"
                    ),
                }
            })
            .unwrap();
        assert_eq!(
            stop.finality_halt().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(stop.finality_halt().height(), position.height());
        assert_eq!(stop.finality_halt().first_ancestry(), expected_ancestries.0);
        assert_eq!(
            stop.finality_halt().second_ancestry(),
            expected_ancestries.1
        );
        assert_eq!(
            stop.signer_stop().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(
            stop.signer_stop().finality_state_id(),
            stop.finality_halt().state_id()
        );
        let stopped_images = layout.images();
        let reopened = fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap();
        match reopened {
            FixedValidatorNodeStartupV0::FinalityStopped(reopened_stop) => {
                assert_eq!(reopened_stop, stop);
            }
            _ => panic!("strict restart must recover the exact preselection-pair stop"),
        }
        assert_eq!(layout.images(), stopped_images);
        outcomes.push((stop, stopped_images));
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn complete_preselection_pair_preempts_every_phase_and_due_state() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let first_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    for (label, expected_phase, mark_due) in [
        (
            "driver-preselection-pair-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-preselection-pair-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-preselection-pair-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-preselection-pair-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-preselection-pair-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-preselection-pair-precommit-due",
            FixedValidatorLockPhaseV0::Precommit,
            true,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let stopped = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    4,
                    1024 * 1024,
                    4,
                );
                let (driver, proposal_timeout) = step_arm(driver);
                let (driver, active_timeout) = match expected_phase {
                    FixedValidatorLockPhaseV0::Proposal => (driver, proposal_timeout),
                    FixedValidatorLockPhaseV0::Prevote => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        let (driver, prevote_timeout) = step_arm(driver);
                        let (driver, _) = admit_due(driver, prevote_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                };
                let driver = if mark_due {
                    let (driver, disposition) = admit_due(driver, active_timeout);
                    assert_eq!(
                        disposition,
                        FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                    );
                    driver
                } else {
                    driver
                };
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);

                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&first_control, &first_payload),
                );
                let (driver, _) = admit(driver, current_finality_precommit_event(&first_precommit));
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&second_control, &second_payload),
                );
                let (driver, _) =
                    admit(driver, current_finality_precommit_event(&second_precommit));
                match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                    _ => panic!("a complete pair must preempt every phase and due state"),
                }
            })
            .unwrap();
        assert_eq!(
            stopped.finality_halt().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(stopped.finality_halt().height(), position.height());
        assert_eq!(
            stopped.signer_stop().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        let stopped_images = layout.images();
        match fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap()
        {
            FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                assert_eq!(reopened, stopped)
            }
            _ => panic!("strict restart must recover the exact preselection-pair stop"),
        }
        assert_eq!(layout.images(), stopped_images);
    }
}

#[test]
fn current_finality_evidence_is_volatile_and_readmittable_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-restart-readmission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == position
                        && action.proposal_signing_root() == root
            ));
            assert_eq!(layout.images(), before);
            drop(driver);
        })
        .unwrap();
    assert_eq!(layout.images(), before);

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == position
                        && action.proposal_signing_root() == root
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn pending_command_precedes_and_malformed_finality_events_are_returned_losslessly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-custody-malformed");
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let malformed_payload = vec![0x04, 0x05].into_boxed_slice();
    let control_pointer = malformed_control.as_ptr();
    let payload_pointer = malformed_payload.as_ptr();
    let malformed_precommit = vec![0x06, 0x07, 0x08].into_boxed_slice();
    let precommit_pointer = malformed_precommit.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let (driver, malformed_control, malformed_payload) = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                        canonical_proposal_control_bytes: malformed_control,
                        canonical_artifact_bytes: malformed_payload,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                            (
                                *driver,
                                canonical_proposal_control_bytes,
                                canonical_artifact_bytes,
                            )
                        }
                        _ => panic!("pending custody must return the exact finality proposal"),
                    }
                }
                _ => panic!("pending timeout command must precede finality proposal inspection"),
            };
            let (driver, malformed_precommit) = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                        canonical_signed_precommit: malformed_precommit,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                            canonical_signed_precommit,
                        } => {
                            assert_eq!(canonical_signed_precommit.as_ptr(), precommit_pointer);
                            (*driver, canonical_signed_precommit)
                        }
                        _ => panic!("pending custody must return the exact finality precommit"),
                    }
                }
                _ => panic!("pending timeout command must precede finality precommit inspection"),
            };
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(layout.images(), before);

            let (driver, _) = step_arm(driver);
            let driver = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                        canonical_proposal_control_bytes: malformed_control,
                        canonical_artifact_bytes: malformed_payload,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityProposal(
                            source
                        ) if matches!(
                            source.as_ref(),
                            naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                actual: 3,
                                ..
                            }
                        )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                        }
                        _ => panic!("malformed finality proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("malformed finality proposal must be rejected after custody clears"),
            };
            let driver =
                reject_current_finality_precommit(driver, &malformed_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::Decode(
                                    naome_consensus::ConsensusVoteDecodeError::InvalidLength {
                                        actual: 3,
                                        ..
                                    }
                                )
                            )
                        )
                    ));
                });
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn finality_admission_bypasses_latched_current_and_higher_saturation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-bypasses-voting-saturation");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let current_position = round_at(&branch, 0).position();
    let higher_position = round_at(&branch, 1).position();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let finality_precommit = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let current_input_bytes = u64::try_from(current_control.len() + current_payload.len()).unwrap();
    let finality_input_bytes = current_input_bytes
        .checked_add(u64::try_from(finality_precommit.len()).unwrap())
        .unwrap();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                1,
                1024 * 1024,
                1,
                1024 * 1024,
                2,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let mut current_saturation = None;
            let driver =
                reject_current_prevote(driver, &current_prevote, |rejection| match rejection {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        saturation,
                        newly_saturated: true,
                        ..
                    } => current_saturation = Some(*saturation),
                    _ => panic!("current voting inbox must newly saturate"),
                });
            let current_saturation = current_saturation.unwrap();
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );

            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let mut higher_saturation = None;
            let driver = reject_prevote(driver, &higher_prevote, |rejection| match rejection {
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(source) => {
                    match source.as_ref() {
                        FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Saturated {
                            saturation,
                            newly_saturated: true,
                        } => higher_saturation = Some(*saturation),
                        _ => panic!("higher voting inbox must newly saturate"),
                    }
                }
                _ => panic!("higher prevote must be rejected by its inbox"),
            });
            let higher_saturation = higher_saturation.unwrap();
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(
                driver,
                current_finality_precommit_event(&finality_precommit),
            );
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                finality_input_bytes
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == current_position
                        && action.proposal_signing_root()
                            == current_value.proposal_signing_root()
            ));
            assert_eq!(layout.images(), before);

            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: finalized,
                    ..
                } if finalized == current_position
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                finality_input_bytes
            );
            assert_ne!(layout.images(), before);

            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Saturated(saturation)
                            if saturation == higher_saturation
                    ));
                    *driver
                }
                _ => panic!("stale higher saturation must remain until its explicit drain"),
            };
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(
                proposals,
                vec![(higher_control.clone(), higher_payload.clone())]
            );
            assert!(prevotes.is_empty());

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated {
                            position,
                            saturation,
                        } if position == current_position && saturation == current_saturation
                    ));
                    *driver
                }
                _ => panic!("stale current saturation must remain until its explicit drain"),
            };
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert!(proposal_prevotes.is_empty());
            assert!(nil_prevotes.is_empty());

            let driver = step_idle(*driver);
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert_eq!(precommits, vec![finality_precommit.clone()]);
            assert_eq!(driver.position().height().value(), 2);
        })
        .unwrap();
}

#[test]
fn ready_current_finality_precedes_higher_current_and_due_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-priority");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let current_position = round_at(&branch, 0).position();
    let higher_position = round_at(&branch, 1).position();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let finality_precommit = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 16, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(
                driver,
                current_finality_precommit_event(&finality_precommit),
            );

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                            position,
                            proposal_signing_root,
                        } if position == current_position
                            && proposal_signing_root == current_value.proposal_signing_root()
                    ));
                    *driver
                }
                _ => panic!("missing finality proposal must block every lower-priority action"),
            };
            assert_eq!(layout.images(), before);
            assert!(driver.timeout_is_due());

            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position,
                    ..
                } if position == current_position
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_eq!(driver.inbox_len(), 2);
            assert_eq!(driver.current_inbox_len(), 2);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_ne!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn finality_count_and_byte_saturation_latch_and_reset_independently() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let proposal_bytes = u64::try_from(control.len() + payload.len()).unwrap();
    let attempted_bytes = proposal_bytes + u64::try_from(precommit.len()).unwrap();

    for (label, max_entries, max_bytes) in [
        (
            "driver-current-finality-count-saturation",
            1,
            attempted_bytes,
        ),
        ("driver-current-finality-byte-saturation", 2, proposal_bytes),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    2,
                    1024 * 1024,
                    2,
                    1024 * 1024,
                    max_entries,
                    max_bytes,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                let (driver, _) =
                    admit(driver, current_proposal_event(&control, &payload));
                let (driver, _) = admit(
                    driver,
                    proposal_event(1, &higher_control, &higher_payload),
                );
                let (driver, _) = admit_due(driver, timeout);
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&control, &payload),
                );
                let driver = reject_current_finality_precommit(
                    driver,
                    &precommit,
                    |rejection| {
                        assert!(matches!(
                            rejection,
                            FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                position: saturated_position,
                                saturation:
                                    FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                        attempted_entries: 2,
                                        maximum_entries,
                                        attempted_canonical_input_bytes,
                                        maximum_canonical_input_bytes,
                                    },
                                newly_saturated: true,
                            } if *saturated_position == position
                                && *maximum_entries == max_entries
                                && *attempted_canonical_input_bytes == attempted_bytes
                                && *maximum_canonical_input_bytes == max_bytes
                        ));
                    },
                );
                assert_eq!(driver.current_finality_inbox_len(), 1);
                assert_eq!(
                    driver.current_finality_inbox_canonical_input_bytes(),
                    proposal_bytes
                );
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());

                let driver = reject_current_finality_precommit(
                    driver,
                    &precommit,
                    |rejection| {
                        assert!(matches!(
                            rejection,
                            FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                position: saturated_position,
                                newly_saturated: false,
                                ..
                            } if *saturated_position == position
                        ));
                    },
                );
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                        position: saturated_position,
                        ..
                    } if saturated_position == position
                ));

                let (driver, drained) = driver
                    .drain_current_finality_inbox_and_reset()
                    .into_parts();
                let (proposals, precommits) =
                    drained_current_finality_contents(drained);
                assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
                assert!(precommits.is_empty());
                assert_eq!(driver.current_finality_inbox_len(), 0);
                assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());

                let (driver, disposition) = admit(
                    *driver,
                    current_finality_precommit_event(&precommit),
                );
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
                );
                assert_eq!(driver.current_finality_inbox_len(), 1);
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());
                assert_eq!(layout.images(), before);
            })
            .unwrap();
    }
}

#[test]
fn finality_saturation_supersedes_healthy_missing_proposal_block() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-block-then-saturation");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                1,
                1024 * 1024,
                4,
            );
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                            position: blocked_position,
                            proposal_signing_root,
                        } if blocked_position == position
                            && proposal_signing_root == value.proposal_signing_root()
                    ));
                    *driver
                }
                _ => panic!("healthy missing-proposal finality must block due work"),
            };
            assert_eq!(layout.images(), before);

            let driver = reject_current_finality_proposal(
                driver,
                &control,
                &payload,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                            position: saturated_position,
                            newly_saturated: true,
                            ..
                        } if *saturated_position == position
                    ));
                },
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position: saturated_position,
                    ..
                } if saturated_position == position
            ));
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let (_driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
            assert!(released_proposal.is_none());
        })
        .unwrap();
}

#[test]
fn saturated_finality_inbox_leaves_due_step_and_authority_state_unchanged() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let mut outcomes = Vec::new();

    for (label, saturate_finality) in [
        ("driver-current-finality-step-baseline", false),
        ("driver-current-finality-step-saturated", true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let outcome = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    1,
                    1024 * 1024,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                let driver = if saturate_finality {
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&control, &payload),
                    );
                    let driver = reject_current_finality_precommit(
                        driver,
                        &precommit,
                        |rejection| {
                            assert!(matches!(
                                rejection,
                                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                    newly_saturated: true,
                                    ..
                                }
                            ));
                        },
                    );
                    assert!(matches!(
                        driver.classify_current_finality_evidence().unwrap(),
                        FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }
                    ));
                    driver
                } else {
                    driver
                };
                let (driver, disposition) = admit_due(driver, timeout);
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                );
                let driver = step_transition(driver);
                let (driver, vote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                (
                    vote.canonical_bytes().to_vec(),
                    driver.position(),
                    driver.phase(),
                    driver.timeout_is_due(),
                    driver.has_pending_command(),
                    layout.images(),
                )
            })
            .unwrap();
        outcomes.push(outcome);
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn incomplete_current_finality_evidence_becomes_nonmatching_after_position_advance() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-former-position");
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let current_round = round_at(&branch, 0);
    let current_proposer = signing_keys
        .iter()
        .find(|key| consensus_key(key) == current_round.proposer())
        .unwrap();
    let (current_value, current_control, current_payload) =
        proposal_inputs_with_signing_key(&fixture, &branch, 0, ZfcAxiom::Pairing, current_proposer);
    let current_precommit = signed_vote_bytes(
        fixture.context,
        current_round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &signing_keys[0],
    );
    let higher_round = round_at(&branch, 1);
    let higher_proposer = signing_keys
        .iter()
        .find(|key| consensus_key(key) == higher_round.proposer())
        .unwrap();
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs_with_signing_key(&fixture, &branch, 1, ZfcAxiom::Union, higher_proposer);
    let higher_position = higher_round.position();
    let higher_prevotes = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                higher_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
                key,
            )
        })
        .collect::<Vec<_>>();
    let retained_bytes =
        u64::try_from(current_control.len() + current_payload.len() + current_precommit.len())
            .unwrap();
    let ready = provision_with_fixed_entries(&fixture, &layout, &entries)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&current_precommit));
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                retained_bytes
            );

            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let mut driver = driver;
            for higher_prevote in &higher_prevotes {
                (driver, _) = admit(driver, prevote_event(higher_prevote));
            }
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                retained_bytes
            );

            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert_eq!(precommits, vec![current_precommit.clone()]);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
        })
        .unwrap();
}

#[test]
fn current_finality_preclassification_routes_only_matching_precommits_to_round_work() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let next_round = round_at(&branch, 1);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let precommit = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 1024 * 1024).unwrap();

    let empty = CurrentRoundFinalityInboxV0::new(limits);
    assert_eq!(
        empty.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );

    let mut proposal_only = CurrentRoundFinalityInboxV0::new(limits);
    let proposal = verify_deferred_proposal_at_round(&round, &control, payload.clone()).unwrap();
    assert!(matches!(
        proposal_only.try_insert_proposal(proposal),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        proposal_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );

    let mut precommit_only = CurrentRoundFinalityInboxV0::new(
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(1, 1024 * 1024).unwrap(),
    );
    assert!(matches!(
        precommit_only.try_insert_precommit(&round, &precommit),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        precommit_only.preclassify(next_round.parent_coordinate(), next_round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );
    assert_eq!(
        precommit_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NeedsRound
    );

    let proposal = verify_deferred_proposal_at_round(&round, &control, payload).unwrap();
    assert!(precommit_only.try_insert_proposal(proposal).is_err());
    let (saturated_position, saturation) = precommit_only.saturation().unwrap();
    assert_eq!(
        precommit_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::Saturated {
            position: saturated_position,
            saturation,
        }
    );
}

#[test]
fn current_finality_classifier_keeps_offline_weight_in_exact_two_thirds_denominator() {
    let fixture = Fixture::new();
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let root = ProposalSigningRoot::from_bytes([0xa7; 32]);
    let votes = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                key,
            )
        })
        .collect::<Vec<_>>();
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
        3,
        u64::try_from(votes.iter().map(Vec::len).sum::<usize>()).unwrap(),
    )
    .unwrap();
    let mut inbox = CurrentRoundFinalityInboxV0::new(limits);

    for vote in &votes[..2] {
        assert!(matches!(
            inbox.try_insert_precommit(&round, vote),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    assert!(matches!(
        inbox.classify(&round),
        Ok(CurrentRoundFinalityClassificationV0::None)
    ));

    assert!(matches!(
        inbox.try_insert_precommit(&round, &votes[2]),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert!(matches!(
        inbox.classify(&round),
        Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
            proposal_signing_root,
            ..
        }) if proposal_signing_root == root
    ));
}

#[test]
fn current_finality_same_root_proposal_variants_select_lexicographically_in_every_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, plain_control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let prior_round = round_at(&branch, 1);
    let prior_prevote = signed_vote_bytes(
        fixture.context,
        prior_round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let valid_round_certificate = prior_round
        .build_quorum_certificate_from_signed_votes(
            &[prior_prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let round = round_at(&branch, 2);
    let proof_control = proposal_control_with_valid_round(
        &fixture,
        value,
        round.position(),
        &valid_round_certificate,
    );
    assert_ne!(plain_control, proof_control);
    let selected_control = if plain_control < proof_control {
        plain_control.as_slice()
    } else {
        proof_control.as_slice()
    };
    let precommit = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &[precommit.as_slice()],
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let total_bytes = u64::try_from(
        plain_control.len() + payload.len() + proof_control.len() + payload.len() + precommit.len(),
    )
    .unwrap();

    for (first, second) in [
        (plain_control.as_slice(), proof_control.as_slice()),
        (proof_control.as_slice(), plain_control.as_slice()),
    ] {
        let limits =
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(3, total_bytes).unwrap();
        let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
        for control in [first, second] {
            let proposal = verify_deferred_proposal_at_round(&round, control, payload.clone())
                .expect("both same-root proposal representations must verify");
            assert!(matches!(
                inbox.try_insert_proposal(proposal),
                Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
            ));
        }
        assert!(matches!(
            inbox.try_insert_precommit(&round, &precommit),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        match inbox.classify(&round) {
            Ok(CurrentRoundFinalityClassificationV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }) => {
                assert_eq!(proposal_signing_root, root);
                assert_eq!(canonical_proposal_control_bytes, selected_control);
                assert_eq!(canonical_artifact_bytes, payload);
                assert_eq!(canonical_precommit_certificate, expected_certificate);
            }
            Ok(_) => panic!("one same-root proposal quorum must have one stable representative"),
            Err(_) => panic!("fully admitted proposal-finality inputs must classify"),
        }
        assert_eq!(inbox.len(), 3);
        assert_eq!(inbox.total_canonical_input_bytes(), total_bytes);
        let (mut proposals, precommits) =
            drained_current_finality_contents(inbox.drain_and_reset());
        proposals.sort_unstable();
        let mut expected_proposals = vec![
            (first.to_vec(), payload.clone()),
            (second.to_vec(), payload.clone()),
        ];
        expected_proposals.sort_unstable();
        assert_eq!(proposals, expected_proposals);
        assert_eq!(precommits, vec![precommit.clone()]);
    }
}

#[test]
fn current_nil_precommit_admission_is_exact_typed_and_duplicate_no_growth() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-admission");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let root = ProposalSigningRoot::from_bytes([0x71; 32]);
    let valid = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let proposal_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_position = round_at(&branch, 1).position();
    let wrong_position_precommit = signed_vote_bytes(
        fixture.context,
        wrong_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive = SigningKey::from_bytes(&signing_seed(2));
    let inactive_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &inactive,
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_precommit = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let malformed = valid[..valid.len() - 1].to_vec();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_nil_precommit(driver, &malformed, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                        naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                            naome_consensus::ConsensusVoteVerifyError::Decode(_)
                        )
                    )
                ));
            });
            let driver = reject_current_nil_precommit(
                driver,
                &wrong_context_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver =
                reject_current_nil_precommit(driver, &invalid_signature, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                });
            let driver = reject_current_nil_precommit(
                driver,
                &wrong_position_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::PositionMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == position && *actual == wrong_position
                    ));
                },
            );
            let driver = reject_current_nil_precommit(driver, &prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                        naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Prevote,
                        }
                    )
                ));
            });
            let driver =
                reject_current_nil_precommit(driver, &proposal_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::ProposalTarget {
                                actual,
                            }
                        ) if *actual == root
                    ));
                });
            let driver =
                reject_current_nil_precommit(driver, &inactive_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::InactiveSigner {
                                signer,
                            }
                        ) if *signer == consensus_key(&inactive)
                    ));
                });
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(driver.current_nil_precommit_inbox_canonical_input_bytes(), 0);

            let (driver, disposition) = admit(driver, current_nil_precommit_event(&valid));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let retained_bytes = u64::try_from(valid.len()).unwrap();
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                retained_bytes
            );
            let (driver, disposition) = admit(driver, current_nil_precommit_event(&valid));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                retained_bytes
            );
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_quorum_is_strict_and_selects_smallest_signer_variants() {
    let fixture = Fixture::new();
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let standard = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                key,
            )
        })
        .collect::<Vec<_>>();
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[0],
        0x41,
    );
    assert_ne!(standard[0], alternate);

    let limits = FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(
        4,
        u64::try_from(standard.iter().map(Vec::len).sum::<usize>() + alternate.len()).unwrap(),
    )
    .unwrap();
    let mut exact_two_thirds = CurrentRoundNilPrecommitInboxV0::new(limits);
    for vote in &standard[..2] {
        assert!(matches!(
            exact_two_thirds.try_insert_nil_precommit(&round, vote),
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
        ));
    }
    assert!(matches!(
        exact_two_thirds.select_nil_quorum(&round),
        Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None)
    ));
    assert!(matches!(
        exact_two_thirds.try_insert_nil_precommit(&round, &standard[2]),
        Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
    ));
    assert!(matches!(
        exact_two_thirds.select_nil_quorum(&round),
        Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One { .. })
    ));

    let preferred_first = standard[0].as_slice().min(alternate.as_slice()).to_vec();
    let mut expected = vec![
        (consensus_key(&signing_keys[0]), preferred_first),
        (consensus_key(&signing_keys[1]), standard[1].clone()),
        (consensus_key(&signing_keys[2]), standard[2].clone()),
    ];
    expected.sort_unstable_by_key(|entry| entry.0);
    let expected = expected
        .into_iter()
        .map(|(_, vote)| vote)
        .collect::<Vec<_>>();
    let all_votes = [&standard[0], &alternate, &standard[1], &standard[2]];
    let mut expected_retained = all_votes
        .iter()
        .map(|vote| vote.as_slice().to_vec())
        .collect::<Vec<_>>();
    expected_retained.sort_unstable();
    for order in [
        [0, 1, 2, 3],
        [1, 0, 3, 2],
        [2, 3, 0, 1],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [1, 3, 0, 2],
    ] {
        let mut inbox = CurrentRoundNilPrecommitInboxV0::new(limits);
        for index in order {
            assert!(matches!(
                inbox.try_insert_nil_precommit(&round, all_votes[index]),
                Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
            ));
        }
        match inbox.select_nil_quorum(&round) {
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One {
                canonical_signed_precommits,
            }) => assert_eq!(
                canonical_signed_precommits
                    .into_iter()
                    .map(Vec::from)
                    .collect::<Vec<_>>(),
                expected
            ),
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None) => {
                panic!("three active signers must exceed the exact two-thirds threshold")
            }
            Err(_) => panic!("fully admitted nil precommits must classify"),
        }
        assert_eq!(inbox.len(), all_votes.len());
        assert_eq!(
            drained_current_nil_precommit_contents(inbox.drain_and_reset()),
            expected_retained
        );
    }
}

#[test]
fn current_nil_precommit_advances_from_every_phase_and_due_state_without_writes() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let retained_bytes = u64::try_from(nil_precommit.len()).unwrap();

    for (label, expected_phase, mark_due) in [
        (
            "driver-current-nil-precommit-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-current-nil-precommit-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-current-nil-precommit-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-current-nil-precommit-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-current-nil-precommit-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-current-nil-precommit-precommit-due",
            FixedValidatorLockPhaseV0::Precommit,
            true,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
                let (driver, active_timeout) = match expected_phase {
                    FixedValidatorLockPhaseV0::Proposal => (driver, proposal_timeout),
                    FixedValidatorLockPhaseV0::Prevote => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        let (driver, prevote_timeout) = step_arm(driver);
                        let (driver, _) = admit_due(driver, prevote_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                };
                let driver = if mark_due {
                    let (driver, disposition) = admit_due(driver, active_timeout);
                    assert_eq!(
                        disposition,
                        FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                    );
                    driver
                } else {
                    driver
                };
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);
                let (driver, disposition) =
                    admit(driver, current_nil_precommit_event(&nil_precommit));
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    retained_bytes
                );
                let before_advance = layout.images();

                let driver = step_transition(driver);
                assert_eq!(driver.position().height(), position.height());
                assert_eq!(driver.position().round(), ConsensusRound::new(1));
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(layout.images(), before_advance);

                let (driver, successor_timeout) = step_arm(driver);
                assert_eq!(successor_timeout.position(), driver.position());
                assert_eq!(
                    successor_timeout.phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
                assert_eq!(
                    successor_timeout.generation(),
                    active_timeout.generation().checked_add(1).unwrap()
                );
                assert_eq!(layout.images(), before_advance);
            })
            .unwrap();
    }
}

#[test]
fn current_nil_precommit_round_advance_preserves_populated_lock_and_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-lock-valid");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let round_two = round_at(&branch, 2);
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        round_two.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_two
        .build_quorum_certificate_from_signed_votes(
            &[proposal_prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        round_two.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&proposal_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.position(), round_two.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let before_nil_advance = layout.images();
            let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));

            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before_nil_advance);
            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(layout.images(), before_nil_advance);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert_eq!(prevote.position(), driver.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_none());
            drop(driver);
        })
        .unwrap();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position().round(), ConsensusRound::new(3));
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Prevote);
            let locked = signing
                .locked_value()
                .expect("nil-precommit round advance must preserve the existing lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("nil-precommit round advance must preserve valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_saturation_is_independent_and_retained_quorum_still_advances() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let current = round_at(&branch, 0);
    let higher = round_at(&branch, 1);
    let root = ProposalSigningRoot::from_bytes([0x72; 32]);
    let (_, finality_control, finality_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let retained = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let denied = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x42,
    );
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let vote_bytes = u64::try_from(retained.len()).unwrap();

    for (label, maximum_entries, maximum_bytes) in [
        (
            "driver-current-nil-precommit-count-saturation",
            1,
            vote_bytes.checked_mul(2).unwrap(),
        ),
        (
            "driver-current-nil-precommit-byte-saturation",
            2,
            vote_bytes,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver_with_nil_precommit_limits(
                    scope,
                    maximum_entries,
                    maximum_bytes,
                    4,
                ));
                let (driver, _) = admit(driver, current_nil_prevote_event(&current_prevote));
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&finality_control, &finality_payload),
                );
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let (driver, _) = admit(driver, current_nil_precommit_event(&retained));
                let before_other_counts = (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                );
                let before_images = layout.images();
                let driver = reject_current_nil_precommit(driver, &denied, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                            position,
                            saturation:
                                FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::Capacity {
                                    attempted_entries: 2,
                                    maximum_entries: actual_maximum_entries,
                                    attempted_canonical_input_bytes,
                                    maximum_canonical_input_bytes,
                                },
                            newly_saturated: true,
                        } if *position == current.position()
                            && *actual_maximum_entries == maximum_entries
                            && *attempted_canonical_input_bytes
                                == vote_bytes.checked_mul(2).unwrap()
                            && *maximum_canonical_input_bytes == maximum_bytes
                    ));
                });
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    vote_bytes
                );
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(layout.images(), before_images);

                let driver = reject_current_nil_precommit(driver, &denied, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                            position,
                            newly_saturated: false,
                            ..
                        } if *position == current.position()
                    ));
                });
                let driver = step_transition(driver);
                assert_eq!(driver.position(), higher.position());
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(layout.images(), before_images);

                let (driver, drained) = driver
                    .drain_current_nil_precommit_inbox_and_reset()
                    .into_parts();
                assert_eq!(
                    drained_current_nil_precommit_contents(drained),
                    vec![retained.clone()]
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    0
                );
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(layout.images(), before_images);
            })
            .unwrap();
    }
}

#[test]
fn saturated_nonquorate_nil_precommit_prefix_falls_through_to_idle_and_due() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-nonquorum-saturation");
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let position = branch.begin_round_zero().unwrap().position();
    let first = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[0],
    );
    let second = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[1],
    );
    let ready = provision_with_fixed_entries(&fixture, &layout, &entries)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver_with_nil_precommit_limits(
                scope,
                1,
                u64::try_from(first.len() + second.len()).unwrap(),
                4,
            ));
            let (driver, _) = admit(driver, current_nil_precommit_event(&first));
            let driver = reject_current_nil_precommit(driver, &second, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                        newly_saturated: true,
                        ..
                    }
                ));
            });
            let driver = step_idle(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_priority_follows_finality_then_higher_evidence() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let current_root = current_value.proposal_signing_root();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let current_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let current_nil_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher = round_at(&branch, 2);
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    let finality_layout = TestLayout::new("driver-current-nil-precommit-finality-first");
    let ready = fixture
        .provision(&finality_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&current_precommit));
            let (driver, _) = admit_due(driver, timeout);
            let custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            );

            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position == current.position()
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                    driver.current_nil_precommit_inbox_len(),
                ),
                custody
            );
        })
        .unwrap();

    let higher_layout = TestLayout::new("driver-current-nil-precommit-higher-first");
    let ready = fixture
        .provision(&higher_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            let custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            );

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                    driver.current_nil_precommit_inbox_len(),
                ),
                (custody.0 - 1, custody.1, custody.2, custody.3)
            );
            let (_driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.position(), higher.position());
            let released_proposal =
                released_proposal.expect("higher action transfers its selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                higher_control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), higher_payload);
        })
        .unwrap();

    let current_layout = TestLayout::new("driver-current-nil-precommit-before-current-action");
    let ready = fixture
        .provision(&current_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = current_layout.images();
    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);

            let driver = step_transition(driver);
            assert_eq!(driver.position().height(), current.position().height());
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(current_layout.images(), before);

            let (driver, successor) = step_arm(driver);
            assert_eq!(successor.position(), driver.position());
            assert_eq!(successor.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(current_layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_precedes_competing_current_votes_and_due_without_custody_loss() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-before-current-and-due");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let root = value.proposal_signing_root();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_prevote_event(&proposal_prevote));
            let (driver, _) = admit(driver, current_nil_prevote_event(&nil_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let (driver, local_prevote, released_proposal) = step_publish(driver);
            assert_eq!(local_prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_none());
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            let before_block = layout.images();
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                            position,
                            proposal_signing_root,
                        } if position == current.position() && proposal_signing_root == root
                    ));
                    *driver
                }
                _ => panic!("competing exact-current proposal and nil quorums must block"),
            };
            assert!(driver.timeout_is_due());
            assert_eq!(layout.images(), before_block);

            let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            let before = layout.images();

            let driver = step_transition(driver);
            assert_eq!(driver.position().height(), current.position().height());
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);
            let (driver, successor) = step_arm(driver);
            assert_eq!(successor.position(), driver.position());
            assert_eq!(successor.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before);
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                            position,
                            proposal_signing_root,
                        } if position == current.position() && proposal_signing_root == root
                    ));
                    assert_eq!(driver.position().round(), ConsensusRound::new(1));
                    assert_eq!(driver.current_inbox_len(), 3);
                    assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                }
                _ => panic!("the old-position current ambiguity latch must remain until drain"),
            }
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_bypasses_current_inbox_saturation_without_custody_loss() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-current-saturation-escape");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let retained_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let denied_prevote = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x43,
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_all_limits(
                scope,
                8,
                1024 * 1024,
                1,
                1024 * 1024,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_nil_prevote_event(&retained_prevote));
            let driver = reject_current_nil_prevote(driver, &denied_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        position: saturated_position,
                        newly_saturated: true,
                        ..
                    } if *saturated_position == position
                ));
            });
            assert_eq!(driver.current_inbox_len(), 1);
            let (driver, disposition) = admit(driver, current_nil_precommit_event(&nil_precommit));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let before = layout.images();

            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_preclassification_routes_only_the_exact_retained_position() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let current = round_at(&branch, 0);
    let next = round_at(&branch, 1);
    let vote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let limits =
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 1024 * 1024).unwrap();
    let mut inbox = CurrentRoundNilPrecommitInboxV0::new(limits);
    assert_eq!(
        inbox.preclassify(current.parent_coordinate(), current.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
    );
    assert!(matches!(
        inbox.try_insert_nil_precommit(&current, &vote),
        Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        inbox.preclassify(current.parent_coordinate(), current.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NeedsRound
    );
    assert_eq!(
        inbox.preclassify(next.parent_coordinate(), next.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
    );
}

#[test]
fn stale_nil_precommit_custody_is_lossless_class_only_and_empty_after_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-stale-drain-restart");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let current_nil_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher = round_at(&branch, 2);
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(driver.has_pending_command());
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            let other_custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
            );
            let before_drain = layout.images();

            let (driver, drained) = driver
                .drain_current_nil_precommit_inbox_and_reset()
                .into_parts();
            assert_eq!(
                drained_current_nil_precommit_contents(drained),
                vec![current_nil_precommit.clone()]
            );
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                0
            );
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                ),
                other_custody
            );
            assert!(driver.has_pending_command());
            assert_eq!(layout.images(), before_drain);

            let (driver, precommit, released_proposal) = step_publish(*driver);
            assert_eq!(precommit.position(), higher.position());
            assert_eq!(
                precommit.target(),
                ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root())
            );
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            drop(driver);
        })
        .unwrap();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                0
            );
        })
        .unwrap();
}

#[test]
fn pending_commands_precede_candidate_backed_terminal_conflict_processing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-command-pending");
    let branch = fixed_branch(&fixture);
    let (value, control, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let target = value.artifact_block().id();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 0);
            let authority_before_arm_gate = layout.images();
            let sources_before_arm_gate = layout.source_images();
            let driver = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[],
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    driver,
                } => *driver,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    _,
                ) => panic!("a pending arm must prevent terminal conflict processing"),
            };
            assert_eq!(layout.images(), authority_before_arm_gate);
            assert_eq!(layout.source_images(), sources_before_arm_gate);
            assert!(driver.has_pending_command());

            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(proposal_timeout.position(), driver.position());
            assert_eq!(
                proposal_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert!(driver.has_pending_command());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);

            let authority_before_publish_gate = layout.images();
            let sources_before_publish_gate = layout.source_images();
            let driver = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[],
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    driver,
                } => *driver,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    _,
                ) => panic!("a pending publication must prevent terminal conflict processing"),
            };
            assert_eq!(layout.images(), authority_before_publish_gate);
            assert_eq!(layout.source_images(), sources_before_publish_gate);
            assert!(driver.has_pending_command());

            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
            assert!(released_proposal.is_none());
            drop(driver);
        })
        .unwrap();
}

#[test]
fn candidate_backed_terminal_conflict_uses_the_driver_round_ceiling() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-round-ceiling");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let (transition, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Pairing,
                0,
            );
            let target = transition.value().artifact_block().id();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let driver = driver(scope, 8, 1);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            let authority_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::EvidenceRoundWorkLimitExceeded {
                            required,
                            maximum,
                        } if *required == ConsensusRound::new(2)
                            && *maximum == ConsensusRound::new(1)
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}

#[test]
fn selected_value_conflict_attempt_consumes_driver_without_source_or_authority_writes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-selected-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let (transition, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Pairing,
                0,
            );
            let target = transition.value().artifact_block().id();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let driver = driver(scope, 8, 0);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            let authority_before = layout.images();
            let sources_before = layout.source_images();

            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height }
                            if height.value() == 1
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}

#[test]
fn candidate_backed_historical_conflict_stops_driver_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-terminal");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let (stopped, authority_after) = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let selected_ancestry = first.value().ancestry_id();
            let (sibling, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                &genesis,
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Union,
                2,
            );
            let target = sibling.value().artifact_block().id();
            let sibling_ancestry = sibling.value().ancestry_id();
            let sibling_envelope_id = sibling.envelope_id();

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(second).unwrap());
            let driver = driver(scope, 8, 2);
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, timeout);
            assert!(driver.timeout_is_due());

            let authority_before = layout.images();
            let sources_before = layout.source_images();
            let stopped = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    stopped,
                ) => *stopped,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    ..
                } => panic!("the transferred arm must not block terminal conflict processing"),
            };
            let authority_after = layout.images();
            for (index, (before, after)) in
                authority_before.iter().zip(&authority_after).enumerate()
            {
                assert_ne!(before, after, "authority image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before);
            assert_eq!(
                stopped.finality_halt().kind(),
                naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling
            );
            assert_eq!(stopped.finality_halt().height().value(), 1);
            assert_eq!(stopped.finality_halt().first_ancestry(), selected_ancestry);
            assert_eq!(stopped.finality_halt().second_ancestry(), sibling_ancestry);
            assert_eq!(
                stopped.finality_halt().second_envelope_id(),
                sibling_envelope_id
            );
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                stopped.finality_halt().state_id()
            );
            (stopped, authority_after)
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must recover the driver-routed terminal conflict"),
    }
    assert_eq!(layout.images(), authority_after);
}

#[test]
fn candidate_corruption_consumes_terminal_driver_and_poisons_only_its_source() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-corrupt-source");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let (sibling, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                &genesis,
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Union,
                2,
            );
            let target = sibling.value().artifact_block().id();
            let artifact_id = sibling.value().artifact_block().artifact_id();

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(second).unwrap());
            let driver = driver(scope, 8, 2);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            flip_last_store_byte(&layout.candidate_store);
            let authority_before = layout.images();
            let sources_before = layout.source_images();

            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::CandidateStore(
                            ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id }
                        ) if *block_id == target
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            assert!(matches!(
                candidates.contains(target),
                Err(ArtifactBlockCandidateStoreError::Poisoned)
            ));
            assert!(payloads.contains(artifact_id).unwrap());
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}
