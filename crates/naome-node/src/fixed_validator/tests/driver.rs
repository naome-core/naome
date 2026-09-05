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
mod current_round_finality;
mod current_round_pair;
mod higher_round;
mod historical_conflict;
mod lower_round_finality;
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

mod admission;
mod current_finality;
mod nil_progression;
mod precedence;
mod preselection_conflict;
mod recovery;
mod terminal_conflict;
mod voting;
