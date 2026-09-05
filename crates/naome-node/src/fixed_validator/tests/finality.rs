use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusEnvelopeVerifyError, ConsensusProposalVerifyError, ConsensusVoteRole,
    ConsensusVoteTarget, FixedConsensusBoundedSeparateFinalityVerifyError,
    FixedConsensusPrecommitBatchSealErrorV0, PrecommitCertificateVerifyError,
    ProducerAuthorizationVerifyError, QuorumCertificateBuildError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    CandidateBackedFinalityErrorV0, FixedValidatorAnchoredFinalityJournalErrorV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorFinalityJournalErrorV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::super::finality::{
    FixedValidatorNodeCurrentRoundFinalityErrorV0, FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeLowerRoundFinalityErrorV0, FixedValidatorNodeLowerRoundFinalityOutcomeV0,
    FixedValidatorNodeLowerRoundFinalityRejectionV0,
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0,
};
use super::*;

pub(super) fn expect_continuation(
    outcome: FixedValidatorNodeFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection } => (*scope, selection),
        FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn expect_current_round_finality(
    outcome: FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(outcome) => {
            expect_continuation(outcome)
        }
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected exact-current-round finality")
        }
    }
}

fn expect_current_round_finality_rejection(
    outcome: FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(_) => {
            panic!("expected a no-effect current-round finality rejection")
        }
    }
}

fn expect_current_round_preselection_conflict_rejection(
    outcome: FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
            scope,
            rejection,
        } => (*scope, *rejection),
        FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(_) => {
            panic!("expected a no-effect paired-finality rejection")
        }
    }
}

fn expect_lower_round_finality(
    outcome: FixedValidatorNodeLowerRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(outcome) => {
            expect_continuation(outcome)
        }
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected strictly lower-round finality")
        }
    }
}

fn expect_lower_round_finality_rejection(
    outcome: FixedValidatorNodeLowerRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeLowerRoundFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(_) => {
            panic!("expected a no-effect lower-round finality rejection")
        }
    }
}

fn expect_lower_round_preselection_conflict_rejection(
    outcome: FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0,
) {
    match outcome {
        FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected {
            scope,
            rejection,
        } => (*scope, *rejection),
        FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(_) => {
            panic!("expected a no-effect lower-round paired-finality rejection")
        }
    }
}

fn expect_candidate_backed_finality(
    outcome: FixedValidatorNodeCandidateBackedFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Finality(outcome) => {
            expect_continuation(outcome)
        }
        FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected candidate-backed exact-batch finality")
        }
    }
}

fn expect_candidate_backed_finality_rejection(
    outcome: FixedValidatorNodeCandidateBackedFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeCandidateBackedFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Finality(_) => {
            panic!("expected a no-effect candidate-backed finality rejection")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigningScopeDiagnosticsV0 {
    branch_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    locked_value: Option<FixedValidatorLockedValueV0>,
    valid_value: Option<FixedValidatorValidValueV0>,
}

fn signing_scope_diagnostics(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
) -> SigningScopeDiagnosticsV0 {
    let branch_coordinate = scope.branch().coordinate();
    let session = scope.signing_session();
    SigningScopeDiagnosticsV0 {
        branch_coordinate,
        position: session.position(),
        phase: session.phase(),
        locked_value: session.locked_value(),
        valid_value: session.valid_value().cloned(),
    }
}

fn proposal_control_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        proposer,
    ));
    bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    bytes
}

fn vote_body_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
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
    body
}

fn signed_vote_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let body = vote_body_bytes(context, position, role, target);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let key = consensus_key(signer);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());

    let mut bytes = body.to_vec();
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn quorum_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signers: &[&SigningKey],
) -> Vec<u8> {
    let body = vote_body_bytes(context, position, role, target);

    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut entries = signers
        .iter()
        .map(|signer| {
            let key = consensus_key(signer);
            let mut transcript = Vec::new();
            transcript.extend_from_slice(domain);
            transcript.extend_from_slice(&body);
            transcript.extend_from_slice(key.as_bytes());
            (key, signer.sign(&transcript).to_bytes())
        })
        .collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(key, _)| *key);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        &u16::try_from(entries.len())
            .expect("test certificates remain within the validator bound")
            .to_be_bytes(),
    );
    for (key, signature) in entries {
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&signature);
    }
    bytes
}

fn round_at(branch: &FixedConsensusBranchV0, round: u64) -> FixedConsensusRoundV0<'_> {
    let mut cursor = branch.begin_round_zero().unwrap();
    for _ in 0..round {
        cursor = cursor.advance_round().unwrap();
    }
    cursor
}

fn advance_signer_round_without_writing(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    next_round: &FixedConsensusRoundV0<'_>,
) {
    let _ = scope
        .signing_session_mut()
        .decide_prevote_without_proposal()
        .unwrap();
    let _ = scope
        .signing_session_mut()
        .decide_precommit_without_quorum()
        .unwrap();
    scope
        .signing_session_mut()
        .advance_round(next_round)
        .unwrap();
}

fn current_round_finality_inputs(
    branch: &FixedConsensusBranchV0,
    selected: &ArtifactChainState,
    axiom: ZfcAxiom,
    round: u64,
    proposer: &SigningKey,
    certificate_signers: &[&SigningKey],
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    ConsensusPosition,
    ConsensusValueV0,
) {
    let payload = proof_payload(axiom);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let cursor = round_at(branch, round);
    let position = cursor.position();
    let value = cursor.value_for_artifact_block(block);
    let root = value.proposal_signing_root();
    let control = proposal_control_bytes(value, position, proposer);
    let certificate = quorum_certificate_bytes(
        value.context(),
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        certificate_signers,
    );
    (control, payload, certificate, position, value)
}

fn run_current_round_preselection_pair(
    fixture: &Fixture,
    label: &str,
    reverse_inputs: bool,
    use_vote_batches: bool,
) -> FixedValidatorNodeFinalityStoppedV0 {
    let layout = TestLayout::new(label);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();
    let stopped = ready
        .run_with_signing_session(|scope| {
            match commit_complete_current_round_preselection_pair(
                scope,
                fixture,
                &selected,
                reverse_inputs,
                use_vote_batches,
            )
            .unwrap()
            {
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                    stopped,
                ) => *stopped,
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                    ..
                } => {
                    panic!("the complete exact-current pair must halt")
                }
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
    assert_eq!(stopped.finality_halt().height().value(), 1);
    assert_eq!(
        stopped.signer_stop().finality_state_id(),
        stopped.finality_halt().state_id()
    );
    let after = layout.images();
    for index in 0..after.len() {
        assert_ne!(after[index], before[index], "durable image index {index}");
    }
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must expose the exact-current terminal pair"),
    }
    stopped
}

fn commit_complete_current_round_preselection_pair<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    fixture: &Fixture,
    selected: &ArtifactChainState,
    reverse_inputs: bool,
    use_vote_batches: bool,
) -> Result<
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0<'node>,
    FixedValidatorNodeCurrentRoundFinalityErrorV0,
> {
    let branch = scope.branch().clone();
    let proposer = fixture.signing_key();
    let (first_control, first_payload, first_certificate, first_position, first_value) =
        current_round_finality_inputs(
            &branch,
            selected,
            ZfcAxiom::Pairing,
            0,
            &proposer,
            &[&proposer],
        );
    let (second_control, second_payload, second_certificate, second_position, second_value) =
        current_round_finality_inputs(
            &branch,
            selected,
            ZfcAxiom::Union,
            0,
            &proposer,
            &[&proposer],
        );
    assert_eq!(second_position, first_position);
    let first_precommit = signed_vote_bytes(
        fixture.context,
        first_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &proposer,
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        second_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &proposer,
    );
    let first_batch = [first_precommit.as_slice()];
    let second_batch = [second_precommit.as_slice()];

    if use_vote_batches {
        if reverse_inputs {
            scope.commit_current_round_preselection_conflict_vote_batches(
                &second_control,
                second_payload,
                &second_batch,
                &first_control,
                first_payload,
                &first_batch,
                ConsensusRound::new(0),
            )
        } else {
            scope.commit_current_round_preselection_conflict_vote_batches(
                &first_control,
                first_payload,
                &first_batch,
                &second_control,
                second_payload,
                &second_batch,
                ConsensusRound::new(0),
            )
        }
    } else if reverse_inputs {
        scope.commit_current_round_preselection_conflict(
            &second_control,
            second_payload,
            &second_certificate,
            &first_control,
            first_payload,
            &first_certificate,
            ConsensusRound::new(0),
        )
    } else {
        scope.commit_current_round_preselection_conflict(
            &first_control,
            first_payload,
            &first_certificate,
            &second_control,
            second_payload,
            &second_certificate,
            ConsensusRound::new(0),
        )
    }
}

fn run_lower_round_preselection_pair(
    fixture: &Fixture,
    label: &str,
    reverse_inputs: bool,
) -> FixedValidatorNodeFinalityStoppedV0 {
    let layout = TestLayout::new(label);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();
    let stopped =
        ready
            .run_with_signing_session(|scope| match commit_complete_lower_round_preselection_pair(
                scope,
                fixture,
                &selected,
                reverse_inputs,
            )
            .unwrap()
            {
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(
                    stopped,
                ) => *stopped,
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected { .. } => {
                    panic!("the complete same-position lower-round pair must halt")
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
    assert_eq!(stopped.finality_halt().height().value(), 1);
    assert_eq!(
        stopped.signer_stop().height(),
        stopped.finality_halt().height()
    );
    assert_eq!(
        stopped.signer_stop().finality_state_id(),
        stopped.finality_halt().state_id()
    );
    let after = layout.images();
    for index in 0..after.len() {
        assert_ne!(after[index], before[index], "durable image index {index}");
    }
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must expose the exact neutral terminal pair"),
    }
    stopped
}

fn commit_complete_lower_round_preselection_pair<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    fixture: &Fixture,
    selected: &ArtifactChainState,
    reverse_inputs: bool,
) -> Result<
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'node>,
    FixedValidatorNodeLowerRoundFinalityErrorV0,
> {
    let branch = scope.branch().clone();
    let round_one = round_at(&branch, 1);
    advance_signer_round_without_writing(&mut scope, &round_one);
    let round_two = round_at(&branch, 2);
    advance_signer_round_without_writing(&mut scope, &round_two);
    let proposer = fixture.signing_key();
    let (first_control, first_payload, first_certificate, _, _) = current_round_finality_inputs(
        &branch,
        selected,
        ZfcAxiom::Pairing,
        1,
        &proposer,
        &[&proposer],
    );
    let (second_control, second_payload, second_certificate, _, _) = current_round_finality_inputs(
        &branch,
        selected,
        ZfcAxiom::Union,
        1,
        &proposer,
        &[&proposer],
    );
    if reverse_inputs {
        scope.commit_lower_round_preselection_conflict(
            &second_control,
            second_payload,
            &second_certificate,
            &first_control,
            first_payload,
            &first_certificate,
            ConsensusRound::new(1),
        )
    } else {
        scope.commit_lower_round_preselection_conflict(
            &first_control,
            first_payload,
            &first_certificate,
            &second_control,
            second_payload,
            &second_certificate,
            ConsensusRound::new(1),
        )
    }
}

fn run_lower_round_preselection_batch_pair(
    fixture: &Fixture,
    label: &str,
    reverse_inputs: bool,
) -> FixedValidatorNodeFinalityStoppedV0 {
    let layout = TestLayout::new(label);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();
    let stopped = ready
        .run_with_signing_session(
            |scope| match commit_complete_lower_round_preselection_batch_pair(
                scope,
                fixture,
                &selected,
                reverse_inputs,
            )
            .unwrap()
            {
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(
                    stopped,
                ) => *stopped,
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected { .. } => {
                    panic!("the complete same-position lower-round batch pair must halt")
                }
            },
        )
        .unwrap();

    assert_eq!(
        stopped.finality_halt().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(
        stopped.signer_stop().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(stopped.finality_halt().height().value(), 1);
    assert_eq!(
        stopped.signer_stop().height(),
        stopped.finality_halt().height()
    );
    assert_eq!(
        stopped.signer_stop().finality_state_id(),
        stopped.finality_halt().state_id()
    );
    let after = layout.images();
    for index in 0..after.len() {
        assert_ne!(after[index], before[index], "durable image index {index}");
    }
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must expose the exact neutral terminal batch pair"),
    }
    stopped
}

fn commit_complete_lower_round_preselection_batch_pair<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    fixture: &Fixture,
    selected: &ArtifactChainState,
    reverse_inputs: bool,
) -> Result<
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'node>,
    FixedValidatorNodeLowerRoundFinalityErrorV0,
> {
    let branch = scope.branch().clone();
    let round_one = round_at(&branch, 1);
    advance_signer_round_without_writing(&mut scope, &round_one);
    let round_two = round_at(&branch, 2);
    advance_signer_round_without_writing(&mut scope, &round_two);
    let proposer = fixture.signing_key();
    let (first_control, first_payload, _, first_position, first_value) =
        current_round_finality_inputs(
            &branch,
            selected,
            ZfcAxiom::Pairing,
            1,
            &proposer,
            &[&proposer],
        );
    let (second_control, second_payload, _, second_position, second_value) =
        current_round_finality_inputs(
            &branch,
            selected,
            ZfcAxiom::Union,
            1,
            &proposer,
            &[&proposer],
        );
    assert_eq!(second_position, first_position);
    let first_precommit = signed_vote_bytes(
        fixture.context,
        first_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &proposer,
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        second_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &proposer,
    );
    let first_batch = [first_precommit.as_slice()];
    let second_batch = [second_precommit.as_slice()];
    let route =
        FixedValidatorNodeFinalityRoundRouteV0::new(ConsensusRound::new(1), ConsensusRound::new(1));
    if reverse_inputs {
        scope.commit_lower_round_preselection_conflict_vote_batches(
            &second_control,
            second_payload,
            &second_batch,
            &first_control,
            first_payload,
            &first_batch,
            route,
        )
    } else {
        scope.commit_lower_round_preselection_conflict_vote_batches(
            &first_control,
            first_payload,
            &first_batch,
            &second_control,
            second_payload,
            &second_batch,
            route,
        )
    }
}

pub(super) fn candidate_backed_batch_finality_inputs(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    selected: &ArtifactChainState,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    axiom: ZfcAxiom,
    round: u64,
) -> (OwnedVerifiedFixedConsensusTransitionV0, Vec<u8>, Vec<u8>) {
    let transition = fixture.transition(branch, selected, axiom, round);
    retain_transition_inputs(candidates, payloads, branch, &transition);
    let control = proposal_control_bytes(
        transition.value(),
        transition.position(),
        &fixture.signing_key(),
    );
    let precommit = signed_vote_bytes(
        fixture.context,
        transition.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(transition.value().proposal_signing_root()),
        &fixture.signing_key(),
    );
    (transition, control, precommit)
}

fn provision_with_finality_round_limit<'layout>(
    fixture: &'layout Fixture,
    layout: &'layout TestLayout,
    finality_maximum_round: u64,
    recovery_maximum_round: u64,
) -> FixedValidatorNodeProvisionV0<'layout> {
    FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(finality_maximum_round).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(recovery_maximum_round),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
}

fn next_anchor_collision(directory: &Path, sequence: u64) -> PathBuf {
    let anchor_name = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .expect("one typed anchor file must exist");
    let collision = directory.join(format!("{anchor_name}.tmp-{sequence:016x}"));
    fs::write(&collision, b"deterministic anchor collision").unwrap();
    collision
}

mod candidate_backed;
mod current_round;
mod faults;
mod lower_round;
mod paired_conflict;
