use naome_consensus::{
    ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorVoteSafetyJournalErrorV0,
};
use std::path::Path;

use super::*;

type DrainedEvidence = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);
type DriverPermutationResult = (
    naome_storage::FixedValidatorSignedVoteV0,
    [Vec<(String, Vec<u8>)>; 4],
);

fn driver<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    max_entries: usize,
    maximum_round: u64,
) -> FixedValidatorNodeDriverV0<'node> {
    FixedValidatorNodeDriverV0::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(max_entries, 1024 * 1024).unwrap(),
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
            FixedValidatorNodeDriverCommandV0::PublishVote { .. } => {
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
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_) => {
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
        &fixture.signing_key(),
    ));
    control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    (value, control, payload)
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
fn exact_due_progression_preserves_populated_lock_and_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-due-lock-valid-retention");
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
