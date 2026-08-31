use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusGenesisId, ConsensusHeight,
    ConsensusProtocolVersion, ConsensusSignature, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusBranchV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateV0,
    OwnedVerifiedFixedConsensusTransitionV0, VerifiedFixedConsensusProposalV0,
    VerifiedProducerAuthorizationV0, VerifiedReplayFixedValidatorVoteIntentV0,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
use crate::fault_io::{ScriptedIo, all_append_faults};
use crate::{
    FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0,
    FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalV0,
    FixedValidatorFinalityReplayLimitV0,
};

const AUTHORIZATION_BODY_BYTES: usize = 116;
const VOTE_BODY_BYTES: usize = 118;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-vote-safety-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("temporary directory failed: {error}"),
            }
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key(seed: u8) -> ConsensusKey {
    consensus_key(&signing_key(seed))
}

fn proof_payload() -> Vec<u8> {
    proof_payload_for(ZfcAxiom::Pairing)
}

fn proof_payload_for(axiom: ZfcAxiom) -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: naome_consensus::ProposalSigningRoot,
    proposer: &SigningKey,
) -> [u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH] {
    let mut body = [0_u8; AUTHORIZATION_BODY_BYTES];
    body[..32].copy_from_slice(context.chain_id().as_bytes());
    body[32..64].copy_from_slice(context.genesis_id().as_bytes());
    body[64..68].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[68..76].copy_from_slice(&position.height().value().to_be_bytes());
    body[76..84].copy_from_slice(&position.round().value().to_be_bytes());
    body[84..].copy_from_slice(root.as_bytes());
    let proposer_key = consensus_key(proposer);
    let mut transcript = b"naome:consensus-producer-authorization:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(proposer_key.as_bytes());
    let mut bytes = [0_u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body);
    bytes[AUTHORIZATION_BODY_BYTES..AUTHORIZATION_BODY_BYTES + 32]
        .copy_from_slice(proposer_key.as_bytes());
    bytes[AUTHORIZATION_BODY_BYTES + 32..].copy_from_slice(&proposer.sign(&transcript).to_bytes());
    bytes
}

fn vote_body(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
    let mut bytes = [0_u8; VOTE_BODY_BYTES];
    bytes[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    bytes[1..33].copy_from_slice(context.chain_id().as_bytes());
    bytes[33..65].copy_from_slice(context.genesis_id().as_bytes());
    bytes[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    bytes[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    bytes[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => bytes[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            bytes[85] = 1;
            bytes[86..].copy_from_slice(root.as_bytes());
        }
    }
    bytes
}

fn certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let body = vote_body(context, position, role, target);
    let signer_key = consensus_key(signer);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer_key.as_bytes());
    let signature = signer.sign(&transcript).to_bytes();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(signer_key.as_bytes());
    bytes.extend_from_slice(&signature);
    bytes
}

struct Fixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    signer_seed: u8,
    replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
}

impl Fixture {
    fn new(max_prepared_votes: u64) -> Self {
        let definition = ArtifactChainDefinition::new([0x31; 32]);
        Self {
            definition,
            context: ConsensusContextV0::new(
                definition.id(),
                ConsensusGenesisId::from_bytes([0x42; 32]),
                ConsensusProtocolVersion::new(7),
            ),
            signer_seed: 0x51,
            replay_limit: FixedValidatorVoteSafetyReplayLimitV0::new(max_prepared_votes).unwrap(),
        }
    }

    fn signing_key(&self) -> SigningKey {
        signing_key(self.signer_seed)
    }

    fn signer(&self) -> ConsensusKey {
        consensus_key(&self.signing_key())
    }

    fn entries(&self) -> [ActiveAgreementEntry; 1] {
        [ActiveAgreementEntry::new(
            self.signer(),
            AgreementWeight::new(1),
        )]
    }

    fn branch(&self) -> FixedConsensusBranchV0 {
        FixedConsensusBranchV0::try_from_virtual_genesis(
            self.context,
            &self.entries(),
            ArtifactChainState::new(self.definition).branch_snapshot(),
        )
        .unwrap()
    }

    fn owned_transition(&self) -> OwnedVerifiedFixedConsensusTransitionV0 {
        self.owned_transition_for(ZfcAxiom::Pairing)
    }

    fn owned_transition_for(&self, axiom: ZfcAxiom) -> OwnedVerifiedFixedConsensusTransitionV0 {
        self.owned_transition_for_round(axiom, 0)
    }

    fn owned_transition_for_round(
        &self,
        axiom: ZfcAxiom,
        round_value: u64,
    ) -> OwnedVerifiedFixedConsensusTransitionV0 {
        let payload = proof_payload_for(axiom);
        let artifact_state = ArtifactChainState::new(self.definition);
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = artifact_state.prepare_block(artifact_id).unwrap();
        let branch = self.branch();
        let mut round = branch.begin_round_zero().unwrap();
        for _ in 0..round_value {
            round = round.advance_round().unwrap();
        }
        let value = round.value_for_artifact_block(block);
        let root = value.proposal_signing_root();
        let mut envelope = value.to_canonical_bytes().to_vec();
        envelope.extend_from_slice(&authorization_bytes(
            self.context,
            round.position(),
            root,
            &self.signing_key(),
        ));
        envelope.extend_from_slice(&certificate_bytes(
            self.context,
            round.position(),
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(root),
            &self.signing_key(),
        ));
        round
            .decode_and_verify(&envelope, payload)
            .unwrap()
            .into_owned()
    }

    fn fixed_set_id(&self) -> FixedAgreementSetId {
        self.branch().fixed_agreement_set_id()
    }

    fn alternate_fixed_set_id(&self) -> FixedAgreementSetId {
        FixedConsensusBranchV0::try_from_virtual_genesis(
            self.context,
            &[
                ActiveAgreementEntry::new(self.signer(), AgreementWeight::new(1)),
                ActiveAgreementEntry::new(key(0x99), AgreementWeight::new(1)),
            ],
            ArtifactChainState::new(self.definition).branch_snapshot(),
        )
        .unwrap()
        .fixed_agreement_set_id()
    }

    fn create(&self, directory: &TestDirectory) -> FixedValidatorVoteSafetyJournalV0 {
        FixedValidatorVoteSafetyJournalV0::create(
            &directory.0,
            self.context,
            self.fixed_set_id(),
            self.signing_key(),
            self.replay_limit,
        )
        .unwrap()
    }

    fn create_finality(&self, directory: &TestDirectory) -> FixedValidatorFinalityJournalV0 {
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            self.definition,
            self.context,
            &self.entries(),
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap()
    }

    fn open_finality(
        &self,
        directory: &TestDirectory,
        expected: FixedValidatorFinalityJournalStateIdV0,
    ) -> FixedValidatorFinalityJournalV0 {
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            self.definition,
            self.context,
            &self.entries(),
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            expected,
        )
        .unwrap()
    }

    fn open(
        &self,
        directory: &TestDirectory,
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorVoteSafetyJournalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            self.context,
            self.fixed_set_id(),
            self.signing_key(),
            self.replay_limit,
            expected,
        )
    }

    fn nil_prevote_intent(&self) -> FixedValidatorVoteIntentV0 {
        let branch = self.branch();
        let round = branch.begin_round_zero().unwrap();
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
        let effect = state.decide_prevote_without_proposal().unwrap();
        state
            .prepare_vote_intent(&round, effect, self.signer())
            .unwrap()
    }

    fn proposal_prevote_intent(&self) -> FixedValidatorVoteIntentV0 {
        let branch = self.branch();
        let round = branch.begin_round_zero().unwrap();
        let payload = proof_payload();
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = ArtifactChainState::new(self.definition)
            .prepare_block(artifact_id)
            .unwrap();
        let value = round.value_for_artifact_block(block);
        let authorization = authorization_bytes(
            self.context,
            round.position(),
            value.proposal_signing_root(),
            &self.signing_key(),
        );
        let mut proposal_bytes = value.to_canonical_bytes().to_vec();
        proposal_bytes.extend_from_slice(&authorization);
        proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
        let proposal = round
            .decode_and_verify_proposal_control(&proposal_bytes, payload)
            .unwrap();
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
        let effect = state.decide_prevote_for_proposal(&proposal).unwrap();
        state
            .prepare_vote_intent(&round, effect, self.signer())
            .unwrap()
    }

    fn proposal_precommit_intent(&self) -> FixedValidatorVoteIntentV0 {
        let branch = self.branch();
        let round = branch.begin_round_zero().unwrap();
        let payload = proof_payload();
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = ArtifactChainState::new(self.definition)
            .prepare_block(artifact_id)
            .unwrap();
        let value = round.value_for_artifact_block(block);
        let root = value.proposal_signing_root();
        let authorization =
            authorization_bytes(self.context, round.position(), root, &self.signing_key());
        let mut proposal_bytes = value.to_canonical_bytes().to_vec();
        proposal_bytes.extend_from_slice(&authorization);
        proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
        let proposal = round
            .decode_and_verify_proposal_control(&proposal_bytes, payload)
            .unwrap();
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
        let _ = state.decide_prevote_for_proposal(&proposal).unwrap();
        let quorum = certificate_bytes(
            self.context,
            round.position(),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
            &self.signing_key(),
        );
        let effect = state
            .decide_precommit_for_proposal_quorum(&round, &proposal, &quorum)
            .unwrap();
        state
            .prepare_vote_intent(&round, effect, self.signer())
            .unwrap()
    }

    fn round_zero_nil_intents(&self) -> (FixedValidatorVoteIntentV0, FixedValidatorVoteIntentV0) {
        let branch = self.branch();
        let round = branch.begin_round_zero().unwrap();
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
        let prevote = state.decide_prevote_without_proposal().unwrap();
        let prevote = state
            .prepare_vote_intent(&round, prevote, self.signer())
            .unwrap();
        let precommit = state.decide_precommit_without_quorum().unwrap();
        let precommit = state
            .prepare_vote_intent(&round, precommit, self.signer())
            .unwrap();
        (prevote, precommit)
    }

    fn round_one_nil_prevote_intent(&self) -> FixedValidatorVoteIntentV0 {
        let branch = self.branch();
        let round_zero = branch.begin_round_zero().unwrap();
        let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
        let _ = state.decide_prevote_without_proposal().unwrap();
        let _ = state.decide_precommit_without_quorum().unwrap();
        state.advance_round(&round_one).unwrap();
        let effect = state.decide_prevote_without_proposal().unwrap();
        state
            .prepare_vote_intent(&round_one, effect, self.signer())
            .unwrap()
    }

    fn round_two_nil_prevote_intents_with_distinct_state(
        &self,
    ) -> (FixedValidatorVoteIntentV0, FixedValidatorVoteIntentV0) {
        let branch = self.branch();
        let round_zero = branch.begin_round_zero().unwrap();
        let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
        let round_two = branch
            .begin_round_zero()
            .unwrap()
            .advance_round()
            .unwrap()
            .advance_round()
            .unwrap();

        let mut empty = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
        let _ = empty.decide_prevote_without_proposal().unwrap();
        let _ = empty.decide_precommit_without_quorum().unwrap();
        empty.advance_round(&round_one).unwrap();
        let _ = empty.decide_prevote_without_proposal().unwrap();
        let _ = empty.decide_precommit_without_quorum().unwrap();
        empty.advance_round(&round_two).unwrap();
        let empty_effect = empty.decide_prevote_without_proposal().unwrap();
        let empty_intent = empty
            .prepare_vote_intent(&round_two, empty_effect, self.signer())
            .unwrap();

        let payload = proof_payload();
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = ArtifactChainState::new(self.definition)
            .prepare_block(artifact_id)
            .unwrap();
        let value = round_zero.value_for_artifact_block(block);
        let root = value.proposal_signing_root();
        let authorization = authorization_bytes(
            self.context,
            round_zero.position(),
            root,
            &self.signing_key(),
        );
        let mut proposal_bytes = value.to_canonical_bytes().to_vec();
        proposal_bytes.extend_from_slice(&authorization);
        proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
        let proposal = round_zero
            .decode_and_verify_proposal_control(&proposal_bytes, payload)
            .unwrap();
        let mut retained = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
        let _ = retained.decide_prevote_for_proposal(&proposal).unwrap();
        let proposal_quorum = certificate_bytes(
            self.context,
            round_zero.position(),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
            &self.signing_key(),
        );
        let _ = retained
            .decide_precommit_for_proposal_quorum(&round_zero, &proposal, &proposal_quorum)
            .unwrap();
        retained.advance_round(&round_one).unwrap();
        let _ = retained.decide_prevote_without_proposal().unwrap();
        let nil_quorum = certificate_bytes(
            self.context,
            round_one.position(),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
            &self.signing_key(),
        );
        let _ = retained
            .decide_precommit_for_nil_quorum(&round_one, &nil_quorum)
            .unwrap();
        retained.advance_round(&round_two).unwrap();
        let retained_effect = retained.decide_prevote_without_proposal().unwrap();
        let retained_intent = retained
            .prepare_vote_intent(&round_two, retained_effect, self.signer())
            .unwrap();

        assert_eq!(empty_intent.position(), retained_intent.position());
        assert_eq!(empty_intent.role(), retained_intent.role());
        assert_eq!(empty_intent.target(), retained_intent.target());
        assert_ne!(
            empty_intent.canonical_state_and_vote_intent_bytes(),
            retained_intent.canonical_state_and_vote_intent_bytes()
        );
        (empty_intent, retained_intent)
    }

    fn prefix(&self) -> Vec<u8> {
        canonical_prefix(
            self.context,
            self.fixed_set_id(),
            self.signer(),
            self.replay_limit,
        )
        .unwrap()
    }

    fn scripted_core(&self, io: ScriptedIo) -> FixedValidatorVoteSafetyJournalCore<ScriptedIo> {
        let prefix = self.prefix();
        FixedValidatorVoteSafetyJournalCore::empty(
            io,
            self.context,
            self.fixed_set_id(),
            self.signer(),
            self.replay_limit,
            genesis_state_id(&prefix),
        )
    }

    fn replay_scripted(
        &self,
        io: ScriptedIo,
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<
        FixedValidatorVoteSafetyJournalCore<ScriptedIo>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        FixedValidatorVoteSafetyJournalCore::replay(
            io,
            self.context,
            self.fixed_set_id(),
            self.signer(),
            self.replay_limit,
            self.prefix(),
            expected,
        )
    }
}

fn prepared(outcome: FixedValidatorVotePrepareOutcomeV0) -> FixedValidatorPreparedVoteV0 {
    match outcome {
        FixedValidatorVotePrepareOutcomeV0::Prepared(prepared)
        | FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(prepared) => prepared,
        other => panic!("expected prepared outcome, got {other:?}"),
    }
}

fn signed(outcome: FixedValidatorVoteSignOutcomeV0) -> FixedValidatorSignedVoteV0 {
    match outcome {
        FixedValidatorVoteSignOutcomeV0::Signed(signed)
        | FixedValidatorVoteSignOutcomeV0::AlreadySigned(signed) => signed,
    }
}

fn issue_session<'journal>(
    journal: &'journal mut FixedValidatorVoteSafetyJournalV0,
    round: &FixedConsensusRoundV0<'_>,
) -> FixedValidatorVoteSafetySigningSessionV0<'journal> {
    let state = journal.bind_signing_lineage(round).unwrap();
    journal.issue_signing_session(round, state).unwrap()
}

fn signed_vote_bytes(intent: &FixedValidatorVoteIntentV0, signing_key: &SigningKey) -> Vec<u8> {
    let signature =
        ConsensusSignature::from_bytes(signing_key.sign(intent.signing_transcript()).to_bytes());
    intent
        .complete_with_signature(signature)
        .unwrap()
        .to_canonical_bytes()
        .to_vec()
}

fn append_test_record(
    image: &mut Vec<u8>,
    prior: FixedValidatorVoteSafetyJournalStateIdV0,
    body: &[u8],
) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let next = step_state_id(prior, length, body);
    image.extend_from_slice(&length);
    image.extend_from_slice(body);
    image.extend_from_slice(next.as_bytes());
    next
}

#[test]
fn signing_session_is_issued_once_even_after_drop_or_forget() {
    let fixture = Fixture::new(2);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();

    let dropped_directory = TestDirectory::new("session-drop");
    let mut dropped_journal = fixture.create(&dropped_directory);
    let session = issue_session(&mut dropped_journal, &round);
    assert_eq!(session.position(), round.position());
    drop(session);
    assert!(matches!(
        dropped_journal.issue_signing_session(&round, dropped_journal.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let forgotten_directory = TestDirectory::new("session-forget");
    let mut forgotten_journal = fixture.create(&forgotten_directory);
    let session = issue_session(&mut forgotten_journal, &round);
    std::mem::forget(session);
    assert!(matches!(
        forgotten_journal.issue_signing_session(&round, forgotten_journal.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));
}

#[test]
fn initial_signing_lineage_requires_an_exact_external_anchor_and_reopens_exactly() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("initial-signing-lineage");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();

    assert!(matches!(
        journal.issue_signing_session(&round, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    let bound = journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(bound, genesis);
    let bound_image = fs::read(&journal_path).unwrap();
    assert_eq!(journal.bind_signing_lineage(&round).unwrap(), bound);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);
    assert!(matches!(
        journal.bind_signing_lineage(&child_round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(1)
            && actual_height == ConsensusHeight::new(2)
    ));
    assert_eq!(journal.state_id().unwrap(), bound);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == genesis && actual == bound
    ));
    let mut reopened = fixture.open(&directory, bound).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
            required,
            acknowledged,
        }) if required == bound && acknowledged == genesis
    ));
    assert!(matches!(
        reopened.issue_signing_session(&child_round, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(1)
            && actual_height == ConsensusHeight::new(2)
    ));
    let session = reopened.issue_signing_session(&round, bound).unwrap();
    assert_eq!(session.position(), round.position());
}

#[test]
fn session_requires_exact_external_prepare_acknowledgement_before_signing() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-anchor-ack");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect.clone()).unwrap());
    let prepared_bytes = fs::read(&journal_path).unwrap();
    assert!(matches!(
        session.prepare_vote(&round, effect).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(actual) if actual == prepared
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_bytes);
    let wrong_state = FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xa5; 32]);
    assert_ne!(wrong_state, prepared.state_id());

    assert!(matches!(
        session.acknowledge_prepared_vote_is_externally_durable(prepared, wrong_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalPrepareAnchorMismatch { .. })
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_bytes);
    assert!(matches!(
        session.decide_precommit_without_quorum(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. })
    ));

    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(signed.position(), round.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
    assert_ne!(fs::read(journal_path).unwrap(), prepared_bytes);
}

#[test]
fn external_prepare_acknowledgement_is_bound_to_its_signing_session() {
    let fixture = Fixture::new(2);
    let first_directory = TestDirectory::new("session-ack-first");
    let second_directory = TestDirectory::new("session-ack-second");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut first_journal = fixture.create(&first_directory);
    let mut second_journal = fixture.create(&second_directory);
    let mut first_session = issue_session(&mut first_journal, &round);
    let mut second_session = issue_session(&mut second_journal, &round);

    let first_effect = first_session.decide_prevote_without_proposal().unwrap();
    let first_prepared = prepared(first_session.prepare_vote(&round, first_effect).unwrap());
    let first_acknowledgement = first_session
        .acknowledge_prepared_vote_is_externally_durable(first_prepared, first_prepared.state_id())
        .unwrap();
    let second_effect = second_session.decide_prevote_without_proposal().unwrap();
    let second_prepared = prepared(second_session.prepare_vote(&round, second_effect).unwrap());
    assert_eq!(first_prepared.state_id(), second_prepared.state_id());
    let (_, second_path) = keyed_paths(&second_directory.0, fixture.signer()).unwrap();
    let second_prepared_bytes = fs::read(&second_path).unwrap();

    assert!(matches!(
        second_session.sign_prepared_vote(first_acknowledgement),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignPrepareAcknowledgement)
    ));
    assert_eq!(fs::read(second_path).unwrap(), second_prepared_bytes);
}

#[test]
fn same_post_state_effect_from_parallel_kernel_is_rejected_without_a_journal_write() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-parallel-kernel");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round);
    let local_effect = session.decide_prevote_without_proposal().unwrap();

    let payload = proof_payload();
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id)
        .unwrap();
    let value = round.value_for_artifact_block(block);
    let mut proposal_bytes = value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        round.position(),
        value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = round
        .decode_and_verify_proposal_control(&proposal_bytes, payload)
        .unwrap();
    let mut fresh = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let foreign_effect = fresh.decide_prevote_for_proposal(&proposal).unwrap();
    assert_eq!(session.phase(), fresh.phase());
    assert_eq!(session.locked_value(), fresh.locked_value());
    assert_eq!(session.valid_value(), fresh.valid_value());
    assert_ne!(local_effect.target(), foreign_effect.target());
    let before = fs::read(&journal_path).unwrap();
    assert!(matches!(
        session.prepare_vote(&round, foreign_effect),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent(
                FixedValidatorVoteIntentError::EffectLineageMismatch
            )
        )
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), before);

    assert!(matches!(
        session.prepare_vote(&round, local_effect).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::Prepared(_)
    ));
    assert_ne!(fs::read(journal_path).unwrap(), before);
}

#[test]
fn session_preserves_lineage_across_skipped_unsigned_roles_and_rounds() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-skipped-roles");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let mut session = issue_session(&mut journal, &round_zero);

    let _ = session.decide_prevote_without_proposal().unwrap();
    let _ = session.decide_precommit_without_quorum().unwrap();
    session.advance_round(&round_one).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round_one, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(signed.position(), round_one.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
}

#[test]
fn session_advances_only_with_externally_anchored_durable_finality() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-child-height");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let transition = fixture.owned_transition();
    let expected_ancestry = transition.value().ancestry_id();
    let mut finality = fixture.create_finality(&directory);
    let genesis_state = finality.state_id().unwrap();
    assert!(matches!(
        finality.commit_verified(transition).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let finalized_state = finality.state_id().unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let before_wrong_anchor = fs::read(&finality_path).unwrap();
    assert!(matches!(
        finality.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == finalized_state && acknowledged == genesis_state
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), before_wrong_anchor);
    let mut vote_journal = fixture.create(&directory);
    let vote_genesis_state = vote_journal.state_id().unwrap();
    assert!(matches!(
        vote_journal.issue_signing_session(&round, vote_genesis_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    let vote_state = vote_journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(vote_state, vote_genesis_state);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(finality);

    let finality = fixture.open_finality(&directory, finalized_state);
    vote_journal = fixture.open(&directory, vote_state).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&round, vote_state)
        .unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finalized_state,
        )
        .unwrap();

    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let height_state = prepared_height.state_id();
    let height_image = fs::read(&vote_path).unwrap();
    assert_ne!(height_image, vote_image);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(session.position(), round.position());
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, height_state)
        .unwrap();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(child.coordinate(), finality.head().unwrap().coordinate());
    assert_eq!(session.position().height(), ConsensusHeight::new(2));
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);
    assert_eq!(finality.state_id().unwrap(), finalized_state);
    assert_eq!(session.journal.state_id().unwrap(), height_state);

    let replay = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finalized_state,
        )
        .unwrap();
    let advanced_position = session.position();
    let vote_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(replay),
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(
            FixedValidatorLockStateError::HeightTransitionParentMismatch,
        ))
    ));
    assert_eq!(session.position(), advanced_position);
    assert_eq!(session.journal.state_id().unwrap(), vote_state);
    assert_eq!(finality.state_id().unwrap(), finalized_state);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);

    let child_round = child.begin_round_zero().unwrap();
    let conflict = fixture.owned_transition_for(ZfcAxiom::Union);
    let mut finality = finality;
    let halt = match finality.commit_verified(conflict).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal finality halt, got {other:?}"),
    };
    assert_eq!(finality.halt().unwrap(), Some(halt));
    drop(finality);
    drop(session);
    drop(vote_journal);

    let mut vote_journal = fixture.open(&directory, height_state).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&child_round, height_state)
        .unwrap();
    assert_eq!(session.position(), child_round.position());
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&child_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed_state = session
        .sign_prepared_vote(acknowledgement)
        .unwrap()
        .state_id();
    drop(session);
    drop(vote_journal);
    let mut reopened = fixture.open(&directory, signed_state).unwrap();
    let resumed = issue_session(&mut reopened, &child_round);
    assert_eq!(resumed.position(), child_round.position());
}

#[test]
fn anchored_child_lineage_reopens_after_crash_before_live_height_acknowledgement() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("child-lineage-pre-ack-crash");
    let branch = fixture.branch();
    let parent_round = branch.begin_round_zero().unwrap();
    let expected_child = fixture.owned_transition().into_branch();
    let child_round = expected_child.begin_round_zero().unwrap();
    let sibling_child = fixture.owned_transition_for(ZfcAxiom::Union).into_branch();
    let sibling_round = sibling_child.begin_round_zero().unwrap();

    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let finality_image = fs::read(&finality_path).unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &parent_round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let child_lineage_state = prepared_height.state_id();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let child_lineage_image = fs::read(&vote_path).unwrap();

    drop(prepared_height);
    drop(session);
    drop(vote_journal);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);

    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal finality halt, got {other:?}"),
    };
    assert_eq!(finality.halt().unwrap(), Some(halt));
    let halted_finality_image = fs::read(&finality_path).unwrap();
    assert_ne!(halted_finality_image, finality_image);
    drop(finality);

    let mut reopened = fixture.open(&directory, child_lineage_state).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&parent_round, child_lineage_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(2)
            && actual_height == ConsensusHeight::new(1)
    ));
    assert!(matches!(
        reopened.issue_signing_session(&sibling_round, child_lineage_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(2)
            && actual_height == ConsensusHeight::new(2)
    ));
    let mut session = reopened
        .issue_signing_session(&child_round, child_lineage_state)
        .unwrap();
    assert_eq!(session.position(), child_round.position());
    assert_eq!(fs::read(&vote_path).unwrap(), child_lineage_image);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&child_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(fs::read(finality_path).unwrap(), halted_finality_image);
}

#[test]
fn pending_height_advance_blocks_mutation_and_wrong_anchor_recovers_only_by_reopen() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-height-misuse");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let expected_child = fixture.owned_transition().into_branch();
    let child_round = expected_child.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let position = session.position();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prepared_image = fs::read(&vote_path).unwrap();

    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    assert!(matches!(
        session.advance_round(&round_one),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    let second_durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(second_durable),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    assert_eq!(session.position(), position);
    assert_eq!(fs::read(&vote_path).unwrap(), prepared_image);

    let wrong_state = FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0x7c; 32]);
    assert_ne!(wrong_state, prepared_state);
    assert!(matches!(
        session.acknowledge_prepared_height_is_externally_durable(
            prepared_height,
            wrong_state,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalHeightAnchorMismatch {
            prepared,
            acknowledged,
        }) if prepared == prepared_state && acknowledged == wrong_state
    ));
    assert_eq!(session.position(), position);
    assert_eq!(fs::read(&vote_path).unwrap(), prepared_image);
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    drop(session);
    drop(vote_journal);
    drop(finality);

    let mut reopened = fixture.open(&directory, prepared_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&child_round, prepared_state)
        .unwrap();
    assert_eq!(resumed.position(), child_round.position());
}

#[test]
fn content_equivalent_finality_journal_can_supply_signer_handoff() {
    let fixture = Fixture::new(2);
    let primary_directory = TestDirectory::new("primary-finality-handoff");
    let equivalent_directory = TestDirectory::new("equivalent-finality-handoff");
    let vote_directory = TestDirectory::new("equivalent-finality-vote");
    let mut primary = fixture.create_finality(&primary_directory);
    let mut equivalent = fixture.create_finality(&equivalent_directory);
    let _ = primary.commit_verified(fixture.owned_transition()).unwrap();
    let _ = equivalent
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let state = primary.state_id().unwrap();
    assert_eq!(equivalent.state_id().unwrap(), state);
    assert_eq!(
        equivalent.head().unwrap().coordinate(),
        primary.head().unwrap().coordinate()
    );
    let primary_record = primary
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    let expected_envelope_id = primary_record.envelope_id();
    let expected_envelope = primary_record.canonical_envelope_bytes().to_vec();
    let expected_payload = primary_record.canonical_artifact_bytes().to_vec();
    drop(equivalent);
    drop(primary);

    let equivalent = fixture.open_finality(&equivalent_directory, state);
    let primary = fixture.open_finality(&primary_directory, state);
    let equivalent_record = equivalent
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    let primary_record = primary
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(equivalent_record.envelope_id(), expected_envelope_id);
    assert_eq!(primary_record.envelope_id(), expected_envelope_id);
    assert_eq!(
        equivalent_record.canonical_envelope_bytes(),
        expected_envelope
    );
    assert_eq!(primary_record.canonical_envelope_bytes(), expected_envelope);
    assert_eq!(
        equivalent_record.canonical_artifact_bytes(),
        expected_payload
    );
    assert_eq!(primary_record.canonical_artifact_bytes(), expected_payload);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&vote_directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let durable = equivalent
        .acknowledge_signer_height_transition_is_externally_durable(ConsensusHeight::new(1), state)
        .unwrap();
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_height_state = prepared_height.state_id();
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, prepared_height_state)
        .unwrap();
    assert_eq!(child.coordinate(), equivalent.head().unwrap().coordinate());
    assert_eq!(child.coordinate(), primary.head().unwrap().coordinate());
}

#[test]
fn maximum_round_finality_transition_advances_the_exact_signer_child() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("maximum-round-signer-handoff");
    let mut finality = fixture.create_finality(&directory);
    let transition = fixture.owned_transition_for_round(ZfcAxiom::Pairing, 8);
    let expected_position = transition.position();
    let expected_envelope = transition.envelope_id();
    let expected_ancestry = transition.value().ancestry_id();
    let expected_envelope_bytes = transition.canonical_envelope_bytes().to_vec();
    let expected_payload_bytes = transition.canonical_artifact_bytes().to_vec();
    let _ = finality.commit_verified(transition).unwrap();
    let finality_state = finality.state_id().unwrap();
    drop(finality);
    let finality = fixture.open_finality(&directory, finality_state);
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    assert_eq!(durable.verified_transition().position(), expected_position);
    assert_eq!(
        durable.verified_transition().envelope_id(),
        expected_envelope
    );
    assert_eq!(
        durable.verified_transition().value().ancestry_id(),
        expected_ancestry
    );
    assert_eq!(
        durable.verified_transition().canonical_envelope_bytes(),
        expected_envelope_bytes
    );
    assert_eq!(
        durable.verified_transition().canonical_artifact_bytes(),
        expected_payload_bytes
    );

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, prepared_state)
        .unwrap();
    assert_eq!(child.coordinate(), finality.head().unwrap().coordinate());
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(session.position().height(), ConsensusHeight::new(2));
}

#[test]
fn prepared_height_advance_is_bound_to_its_exact_signing_session() {
    let fixture = Fixture::new(2);
    let first_finality_directory = TestDirectory::new("height-seal-finality-first");
    let second_finality_directory = TestDirectory::new("height-seal-finality-second");
    let first_vote_directory = TestDirectory::new("height-seal-vote-first");
    let second_vote_directory = TestDirectory::new("height-seal-vote-second");
    let mut first_finality = fixture.create_finality(&first_finality_directory);
    let mut second_finality = fixture.create_finality(&second_finality_directory);
    let _ = first_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let _ = second_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = first_finality.state_id().unwrap();
    assert_eq!(second_finality.state_id().unwrap(), finality_state);
    let first_durable = first_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let second_durable = second_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut first_vote = fixture.create(&first_vote_directory);
    let mut second_vote = fixture.create(&second_vote_directory);
    let mut first_session = issue_session(&mut first_vote, &round);
    let mut second_session = issue_session(&mut second_vote, &round);
    let first_prepared = first_session
        .prepare_height_with_durable_finality(first_durable)
        .unwrap();
    let second_prepared = second_session
        .prepare_height_with_durable_finality(second_durable)
        .unwrap();
    let prepared_state = first_prepared.state_id();
    assert_eq!(second_prepared.state_id(), prepared_state);
    let (_, second_vote_path) = keyed_paths(&second_vote_directory.0, fixture.signer()).unwrap();
    let second_image = fs::read(&second_vote_path).unwrap();

    assert!(matches!(
        second_session
            .acknowledge_prepared_height_is_externally_durable(first_prepared, prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHeightAdvance)
    ));
    assert_eq!(second_session.position(), round.position());
    assert_eq!(fs::read(&second_vote_path).unwrap(), second_image);
    let child = second_session
        .acknowledge_prepared_height_is_externally_durable(second_prepared, prepared_state)
        .unwrap();
    assert_eq!(second_session.position().height(), ConsensusHeight::new(2));
    assert_eq!(
        child.coordinate(),
        second_finality.head().unwrap().coordinate()
    );
}

#[test]
fn pending_vote_blocks_durable_finality_handoff_without_mutation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-blocks-finality-handoff");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();

    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    let vote_state = prepared.state_id();
    let position = session.position();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(durable),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position: pending_position,
            role: ConsensusVoteRole::Prevote,
        }) if pending_position == round.position()
    ));
    assert_eq!(session.position(), position);
    assert_eq!(session.journal.state_id().unwrap(), vote_state);
    assert_eq!(finality.state_id().unwrap(), finality_state);
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn completed_replay_issues_one_exact_session_but_pending_replay_issues_none() {
    let fixture = Fixture::new(3);
    let completed_directory = TestDirectory::new("session-completed-replay");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&completed_directory);
    let completed_state = {
        let mut session = issue_session(&mut journal, &round);
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session
            .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
            .unwrap();
        session
            .sign_prepared_vote(acknowledgement)
            .unwrap()
            .state_id()
    };
    drop(journal);

    let mut reopened = fixture.open(&completed_directory, completed_state).unwrap();
    let resumed = issue_session(&mut reopened, &round);
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    drop(resumed);
    assert!(matches!(
        reopened.issue_signing_session(&round, reopened.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let pending_directory = TestDirectory::new("session-pending-replay");
    let mut pending_journal = fixture.create(&pending_directory);
    let pending_state = {
        let mut session = issue_session(&mut pending_journal, &round);
        let effect = session.decide_prevote_without_proposal().unwrap();
        prepared(session.prepare_vote(&round, effect).unwrap()).state_id()
    };
    drop(pending_journal);
    let mut pending_reopen = fixture.open(&pending_directory, pending_state).unwrap();
    assert!(matches!(
        pending_reopen.issue_signing_session(&round, pending_reopen.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
}

#[test]
fn terminal_halt_never_issues_a_signing_session() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("session-halt-replay");
    let nil = fixture.nil_prevote_intent();
    let conflict = fixture.proposal_prevote_intent();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(nil).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    let halt = match journal.prepare_vote(conflict).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal halt, got {other:?}"),
    };
    drop(journal);

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut reopened = fixture.open(&directory, halt.state_id()).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round, reopened.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}

#[test]
fn header_and_two_stage_record_framing_are_exact() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("framing");
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prefix = fixture.prefix();
    assert_eq!(fs::read(&journal_path).unwrap(), prefix);
    assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);

    let intent = fixture.nil_prevote_intent();
    let canonical_intent = intent.canonical_state_and_vote_intent_bytes().to_vec();
    let prepared = prepared(journal.prepare_vote(intent).unwrap());
    let prepare_body = tagged_record(PREPARE_RECORD, &canonical_intent, 0).unwrap();
    let prepare_length = u32::try_from(prepare_body.len()).unwrap().to_be_bytes();
    let prepare_state = step_state_id(genesis_state_id(&prefix), prepare_length, &prepare_body);
    assert_eq!(prepared.state_id(), prepare_state);
    let mut expected = prefix;
    expected.extend_from_slice(&prepare_length);
    expected.extend_from_slice(&prepare_body);
    expected.extend_from_slice(prepare_state.as_bytes());
    assert_eq!(fs::read(&journal_path).unwrap(), expected);

    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let completion_body = tagged_record(COMPLETE_RECORD, completed.canonical_bytes(), 0).unwrap();
    let completion_length = u32::try_from(completion_body.len()).unwrap().to_be_bytes();
    let completion_state = step_state_id(prepare_state, completion_length, &completion_body);
    assert_eq!(completed.state_id(), completion_state);
    expected.extend_from_slice(&completion_length);
    expected.extend_from_slice(&completion_body);
    expected.extend_from_slice(completion_state.as_bytes());
    assert_eq!(fs::read(journal_path).unwrap(), expected);
}

#[test]
fn signing_lineage_record_framing_and_state_identity_are_exact() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("lineage-framing");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let lineage_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let body = signing_lineage_record(round.position().height(), lineage_id, 0).unwrap();
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);

    assert_eq!(body.len(), SIGNING_LINEAGE_BODY_BYTES);
    assert_eq!(body[0], SIGNING_LINEAGE_RECORD);
    assert_eq!(
        journal.bind_signing_lineage(&round).unwrap(),
        expected_state
    );
    let mut expected = prefix;
    expected.extend_from_slice(&length);
    expected.extend_from_slice(&body);
    expected.extend_from_slice(expected_state.as_bytes());
    assert_eq!(fs::read(journal_path).unwrap(), expected);
}

#[test]
fn exact_intent_is_idempotent_and_completed_bytes_reopen_and_release() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("idempotent");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    assert!(matches!(
        journal.prepare_vote(intent.clone()).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(actual) if actual == prepared
    ));
    let first = signed(journal.sign_prepared_vote(prepared).unwrap());
    let second = signed(journal.sign_prepared_vote(prepared).unwrap());
    assert_eq!(second, first);
    assert!(matches!(
        journal.prepare_vote(intent.clone()).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadySigned(ref actual) if actual == &first
    ));
    let completed_state = first.state_id();
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    assert_eq!(
        reopened
            .retained_signed_vote(first.position(), first.role())
            .unwrap(),
        Some(first.clone())
    );
    assert!(matches!(
        reopened.prepare_vote(intent).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadySigned(actual) if actual == first
    ));
}

#[test]
fn anchored_pending_reopen_is_diagnostic_but_never_signable() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-restart");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    let prepared_state = prepared.state_id();
    drop(journal);

    let mut reopened = fixture.open(&directory, prepared_state).unwrap();
    let pending = reopened.pending_vote().unwrap().unwrap();
    assert_eq!(pending.position(), prepared.position());
    assert_eq!(pending.role(), prepared.role());
    assert_eq!(pending.target(), prepared.target());
    assert_eq!(pending.state_id(), prepared_state);
    assert!(matches!(
        reopened.pending_prepared_vote(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
    assert!(matches!(
        reopened.sign_prepared_vote(prepared),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
    assert!(matches!(
        reopened.prepare_vote(intent),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
}

#[test]
fn nonidentical_same_slot_durably_halts_and_disables_release() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("conflict");
    let mut journal = fixture.create(&directory);
    let nil_intent = fixture.nil_prevote_intent();
    let proposal_intent = fixture.proposal_prevote_intent();
    assert_eq!(nil_intent.position(), proposal_intent.position());
    assert_eq!(nil_intent.role(), proposal_intent.role());
    assert_ne!(nil_intent.target(), proposal_intent.target());
    let prepared = prepared(journal.prepare_vote(nil_intent).unwrap());
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let halt = match journal.prepare_vote(proposal_intent).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected durable halt, got {other:?}"),
    };
    assert!(halt.changes_target());
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert!(matches!(
        journal.retained_signed_vote(completed.position(), completed.role()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
    let halt_state = halt.state_id();
    drop(journal);

    let reopened = fixture.open(&directory, halt_state).unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert!(matches!(
        reopened.retained_signed_vote(completed.position(), completed.role()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}

#[test]
fn same_target_with_nonidentical_post_state_durably_halts() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("same-target-state-conflict");
    let (empty_state, retained_valid_state) =
        fixture.round_two_nil_prevote_intents_with_distinct_state();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(empty_state).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    let halt = match journal.prepare_vote(retained_valid_state).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected same-target state halt, got {other:?}"),
    };
    assert!(!halt.changes_target());
    assert_eq!(halt.retained_target(), halt.conflicting_target());
    assert_eq!(journal.halt().unwrap(), Some(halt));
}

#[test]
fn slot_order_is_strictly_monotonic_without_mandating_every_role() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("monotonic-lower");
    let (prevote, precommit) = fixture.round_zero_nil_intents();
    let mut journal = fixture.create(&directory);
    let precommit_prepared = prepared(journal.prepare_vote(precommit).unwrap());
    let _ = journal.sign_prepared_vote(precommit_prepared).unwrap();
    assert!(matches!(
        journal.prepare_vote(prevote),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicSlot {
            previous_role: ConsensusVoteRole::Precommit,
            actual_role: ConsensusVoteRole::Prevote,
            ..
        })
    ));

    let skip_directory = TestDirectory::new("monotonic-skip-role");
    let mut skip_journal = fixture.create(&skip_directory);
    let prevote_zero = fixture.nil_prevote_intent();
    let prevote_one = fixture.round_one_nil_prevote_intent();
    let first = prepared(skip_journal.prepare_vote(prevote_zero).unwrap());
    let _ = skip_journal.sign_prepared_vote(first).unwrap();
    let later = prepared(skip_journal.prepare_vote(prevote_one).unwrap());
    assert_eq!(later.role(), ConsensusVoteRole::Prevote);
    assert_eq!(later.position().round().value(), 1);
}

#[test]
fn completed_state_recovery_returns_only_the_latest_slot() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("latest-completed-recovery");
    let (prevote, precommit) = fixture.round_zero_nil_intents();
    let prevote_bytes = prevote.canonical_state_and_vote_intent_bytes().to_vec();
    let precommit_bytes = precommit.canonical_state_and_vote_intent_bytes().to_vec();
    let mut journal = fixture.create(&directory);

    let prevote_prepared = prepared(journal.prepare_vote(prevote).unwrap());
    let _ = journal.sign_prepared_vote(prevote_prepared).unwrap();
    let precommit_prepared = prepared(journal.prepare_vote(precommit).unwrap());
    let completed = signed(journal.sign_prepared_vote(precommit_prepared).unwrap());
    let completed_state = completed.state_id();

    let retained = journal
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap();
    assert_eq!(retained, precommit_bytes);
    assert_ne!(retained, prevote_bytes);
    drop(journal);

    let reopened = fixture.open(&directory, completed_state).unwrap();
    let retained = reopened
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap();
    assert_eq!(retained, precommit_bytes);
    assert_ne!(retained, prevote_bytes);
}

#[test]
fn completed_intent_restores_typed_lock_state_but_pending_and_halt_deny_recovery() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("typed-recovery");
    let intent = fixture.proposal_precommit_intent();
    let position = intent.position();
    let mut journal = fixture.create(&directory);
    let completed_prepared = prepared(journal.prepare_vote(intent).unwrap());
    let _ = journal.sign_prepared_vote(completed_prepared).unwrap();
    let retained = journal
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap()
        .to_vec();
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let replay = VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
        &retained,
        &round,
        fixture.signer(),
    )
    .unwrap();
    let mut recovered = replay.into_lock_state();
    assert_eq!(recovered.position(), position);
    assert_eq!(recovered.phase(), FixedValidatorLockPhaseV0::Precommit);
    assert!(recovered.locked_value().is_some());
    assert!(recovered.valid_value().is_some());

    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    recovered.advance_round(&round_one).unwrap();
    let pending_effect = recovered.decide_prevote_without_proposal().unwrap();
    let pending_intent = recovered
        .prepare_vote_intent(&round_one, pending_effect, fixture.signer())
        .unwrap();
    let pending = prepared(journal.prepare_vote(pending_intent).unwrap());
    assert!(matches!(
        journal.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
    let pending_state = pending.state_id();
    drop(journal);
    let reopened = fixture.open(&directory, pending_state).unwrap();
    assert!(matches!(
        reopened.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));

    let halt_directory = TestDirectory::new("typed-recovery-halt");
    let mut halted = fixture.create(&halt_directory);
    let nil = fixture.nil_prevote_intent();
    let conflict = fixture.proposal_prevote_intent();
    let prepared = prepared(halted.prepare_vote(nil).unwrap());
    let _ = halted.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        halted.prepare_vote(conflict).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::Halted(_)
    ));
    assert!(matches!(
        halted.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}

#[test]
fn complete_unanchored_suffix_and_corruption_fail_closed() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("anchor-corruption");
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let prepared_state = prepared.state_id();
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let completed_state = completed.state_id();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual
        }) if expected == prepared_state && actual == completed_state
    ));
    let mut image = fs::read(&journal_path).unwrap();
    let prepare_payload_offset = JOURNAL_PREFIX_BYTES + 4 + 1;
    image[prepare_payload_offset] ^= 0x80;
    fs::write(&journal_path, image).unwrap();
    assert!(matches!(
        fixture.open(&directory, completed_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { .. })
    ));
}

#[test]
fn header_replay_rejects_wrong_context_set_limit_and_key_path() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("wrong-header");
    let journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    drop(journal);

    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x43; 32]),
        fixture.context.protocol_version(),
    );
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            wrong_context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.alternate_fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            FixedValidatorVoteSafetyReplayLimitV0::new(4).unwrap(),
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            signing_key(0x99),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Open { source })
            if source.kind() == io::ErrorKind::NotFound
    ));
}

#[test]
fn replay_rejects_duplicate_reordered_mismatched_and_post_halt_records() {
    let fixture = Fixture::new(4);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let nil = fixture.nil_prevote_intent();
    let proposal = fixture.proposal_prevote_intent();
    let nil_prepare = tagged_record(
        PREPARE_RECORD,
        nil.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let proposal_halt = tagged_record(
        CONFLICT_HALT_RECORD,
        proposal.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let nil_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&nil, &fixture.signing_key()),
        0,
    )
    .unwrap();
    let proposal_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&proposal, &fixture.signing_key()),
        0,
    )
    .unwrap();

    let mut completion_first = prefix.clone();
    let completion_first_state = append_test_record(&mut completion_first, genesis, &nil_complete);
    let io = ScriptedIo::from_images(completion_first.clone(), completion_first);
    assert!(matches!(
        fixture.replay_scripted(io, completion_first_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::CompletionWithoutPrepare { entry: 0 })
    ));

    let mut duplicate = prefix.clone();
    let state = append_test_record(&mut duplicate, genesis, &nil_prepare);
    let state = append_test_record(&mut duplicate, state, &nil_complete);
    let duplicate_state = append_test_record(&mut duplicate, state, &nil_prepare);
    let io = ScriptedIo::from_images(duplicate.clone(), duplicate);
    assert!(matches!(
        fixture.replay_scripted(io, duplicate_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::DuplicatePrepare { entry: 2 })
    ));

    let mut mismatched = prefix.clone();
    let state = append_test_record(&mut mismatched, genesis, &nil_prepare);
    let mismatched_state = append_test_record(&mut mismatched, state, &proposal_complete);
    let io = ScriptedIo::from_images(mismatched.clone(), mismatched);
    assert!(matches!(
        fixture.replay_scripted(io, mismatched_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::CompletionMismatch {
            entry: 1,
            reason: FixedValidatorVoteCompletionMismatchV0::Target,
        })
    ));

    let mut post_halt = prefix;
    let state = append_test_record(&mut post_halt, genesis, &nil_prepare);
    let state = append_test_record(&mut post_halt, state, &nil_complete);
    let state = append_test_record(&mut post_halt, state, &proposal_halt);
    let post_halt_state = append_test_record(&mut post_halt, state, &proposal_complete);
    let io = ScriptedIo::from_images(post_halt.clone(), post_halt);
    assert!(matches!(
        fixture.replay_scripted(io, post_halt_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[test]
fn replay_rejects_invalid_signing_lineage_order_and_votes_outside_it() {
    let fixture = Fixture::new(4);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let first_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let first_lineage = signing_lineage_record(round.position().height(), first_id, 0).unwrap();
    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let child_id = signing_lineage_id(
        child_round.parent_coordinate(),
        child_round.position().height(),
        fixture.signer(),
    );
    let child_lineage =
        signing_lineage_record(child_round.position().height(), child_id, 1).unwrap();

    let mut duplicate = prefix.clone();
    let state = append_test_record(&mut duplicate, genesis, &first_lineage);
    let duplicate_state = append_test_record(&mut duplicate, state, &first_lineage);
    let io = ScriptedIo::from_images(duplicate.clone(), duplicate);
    assert!(matches!(
        fixture.replay_scripted(io, duplicate_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
            entry: 1,
            expected,
            actual,
        }) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(1)
    ));

    let skipped_lineage = signing_lineage_record(ConsensusHeight::new(3), child_id, 1).unwrap();
    let mut skipped = prefix.clone();
    let state = append_test_record(&mut skipped, genesis, &first_lineage);
    let skipped_state = append_test_record(&mut skipped, state, &skipped_lineage);
    let io = ScriptedIo::from_images(skipped.clone(), skipped);
    assert!(matches!(
        fixture.replay_scripted(io, skipped_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
            entry: 1,
            expected,
            actual,
        }) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(3)
    ));

    let prepare = tagged_record(
        PREPARE_RECORD,
        fixture
            .nil_prevote_intent()
            .canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let mut pending = prefix.clone();
    let state = append_test_record(&mut pending, genesis, &first_lineage);
    let state = append_test_record(&mut pending, state, &prepare);
    let pending_state = append_test_record(&mut pending, state, &child_lineage);
    let io = ScriptedIo::from_images(pending.clone(), pending);
    assert!(matches!(
        fixture.replay_scripted(io, pending_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageWhilePending { entry: 2 })
    ));

    let mut outside = prefix;
    let state = append_test_record(&mut outside, genesis, &child_lineage);
    let outside_state = append_test_record(&mut outside, state, &prepare);
    let io = ScriptedIo::from_images(outside.clone(), outside);
    assert!(matches!(
        fixture.replay_scripted(io, outside_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
            entry: 1,
            lineage_height,
            vote_height,
        }) if lineage_height == ConsensusHeight::new(2)
            && vote_height == ConsensusHeight::new(1)
    ));

    let nil = fixture.nil_prevote_intent();
    let proposal = fixture.proposal_prevote_intent();
    let nil_prepare = tagged_record(
        PREPARE_RECORD,
        nil.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let nil_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&nil, &fixture.signing_key()),
        0,
    )
    .unwrap();
    let proposal_halt = tagged_record(
        CONFLICT_HALT_RECORD,
        proposal.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let mut post_halt = fixture.prefix();
    let state = append_test_record(&mut post_halt, genesis, &first_lineage);
    let state = append_test_record(&mut post_halt, state, &nil_prepare);
    let state = append_test_record(&mut post_halt, state, &nil_complete);
    let state = append_test_record(&mut post_halt, state, &proposal_halt);
    let post_halt_state = append_test_record(&mut post_halt, state, &child_lineage);
    let io = ScriptedIo::from_images(post_halt.clone(), post_halt);
    assert!(matches!(
        fixture.replay_scripted(io, post_halt_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[test]
fn legacy_completed_history_can_add_one_exact_current_lineage_binding() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("legacy-lineage-binding");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let legacy_state = completed.state_id();
    let bound_state = journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(bound_state, legacy_state);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, legacy_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == legacy_state && actual == bound_state
    ));
    let mut reopened = fixture.open(&directory, bound_state).unwrap();
    let session = reopened.issue_signing_session(&round, bound_state).unwrap();
    assert_eq!(session.position(), completed.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[test]
fn incomplete_tail_is_recovered_only_after_anchor_equality() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("tail-recovery");
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let prepared_state = prepared.state_id();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(journal);
    let anchored = fs::read(&journal_path).unwrap();
    let mut incomplete = anchored.clone();
    incomplete.extend_from_slice(&u32::try_from(MIN_RECORD_BODY_BYTES).unwrap().to_be_bytes());
    incomplete.extend_from_slice(&[COMPLETE_RECORD, 0xaa, 0xbb]);
    fs::write(&journal_path, incomplete).unwrap();

    assert!(matches!(
        fixture.open(
            &directory,
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xee; 32])
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_ne!(fs::read(&journal_path).unwrap(), anchored);
    let reopened = fixture.open(&directory, prepared_state).unwrap();
    assert_eq!(fs::read(journal_path).unwrap(), anchored);
    assert!(reopened.pending_vote().unwrap().is_some());
}

#[test]
fn create_never_overwrites_and_locking_is_per_consensus_key() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("exclusive");
    let journal = fixture.create(&directory);
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::create(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Locked)
    ));
    let other = FixedValidatorVoteSafetyJournalV0::create(
        &directory.0,
        fixture.context,
        fixture.fixed_set_id(),
        signing_key(0x99),
        fixture.replay_limit,
    )
    .unwrap();
    drop(other);
    drop(journal);
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::create(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Create { source })
            if source.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_ne!(fixture.signer(), key(0x99));
}

#[test]
fn replay_limit_counts_unique_preparations_not_their_completions() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("replay-limit");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        journal.prepare_vote(intent),
        Ok(FixedValidatorVotePrepareOutcomeV0::AlreadySigned(_))
    ));

    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = round_zero.advance_round().unwrap();
    let mut state =
        FixedValidatorLockStateV0::try_from_round_zero(&branch.begin_round_zero().unwrap())
            .unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();
    state.advance_round(&round_one).unwrap();
    let effect = state.decide_prevote_without_proposal().unwrap();
    let later = state
        .prepare_vote_intent(&round_one, effect, fixture.signer())
        .unwrap();
    assert!(matches!(
        journal.prepare_vote(later),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded { maximum: 1 })
    ));
}

#[test]
fn every_prepare_append_fault_poisons_and_reopens_only_from_durable_anchor() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let prototype_intent = fixture.nil_prevote_intent();
    let prepare_body = tagged_record(
        PREPARE_RECORD,
        prototype_intent.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let prepared_state = step_state_id(
        genesis,
        u32::try_from(prepare_body.len()).unwrap().to_be_bytes(),
        &prepare_body,
    );
    let complete_length = prefix.len() + 4 + prepare_body.len() + 32;

    for fault in all_append_faults(4 + prepare_body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        assert!(
            matches!(
                core.prepare_vote(prototype_intent.clone()),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        let replay_io = ScriptedIo::from_images(durable.clone(), durable.clone());
        if durable.len() == complete_length {
            assert!(
                matches!(
                    fixture.replay_scripted(replay_io, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual
                    }) if expected == genesis && actual == prepared_state
                ),
                "fault {fault:?}"
            );
        } else {
            let reopened = fixture.replay_scripted(replay_io, genesis).unwrap();
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
        }
    }
}

#[test]
fn every_signing_lineage_append_fault_poisons_and_reopens_only_from_durable_anchor() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let body = signing_lineage_record(round.position().height(), lineage_id, 0).unwrap();
    let state = step_state_id(
        genesis,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = prefix.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        assert!(
            matches!(
                core.bind_signing_lineage(&round),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(core.lineage.is_none(), "fault {fault:?}");
        assert_eq!(core.state_id, genesis, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor_io = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor_io, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == genesis && actual == state
                ),
                "fault {fault:?}"
            );
            let exact_anchor_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact_anchor_io, state).unwrap();
            assert_eq!(reopened.lineage.unwrap().height, ConsensusHeight::new(1));
            assert_eq!(reopened.state_id, state);
        } else {
            let replay_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(replay_io, genesis).unwrap();
            assert!(reopened.lineage.is_none(), "fault {fault:?}");
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
        }
    }
}

#[test]
fn every_child_lineage_append_fault_preserves_the_anchored_parent_lineage() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let first_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let first_body = signing_lineage_record(round.position().height(), first_id, 0).unwrap();
    let first_state = step_state_id(
        genesis,
        u32::try_from(first_body.len()).unwrap().to_be_bytes(),
        &first_body,
    );
    let mut first_image = prefix;
    let _ = append_test_record(&mut first_image, genesis, &first_body);

    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let child_height = child_round.position().height();
    let child_id = signing_lineage_id(
        child_round.parent_coordinate(),
        child_height,
        fixture.signer(),
    );
    let child_body = signing_lineage_record(child_height, child_id, 0).unwrap();
    let child_state = step_state_id(
        first_state,
        u32::try_from(child_body.len()).unwrap().to_be_bytes(),
        &child_body,
    );
    let complete_length = first_image.len() + 4 + child_body.len() + 32;

    for fault in all_append_faults(4 + child_body.len(), 32) {
        let io = ScriptedIo::from_images(first_image.clone(), first_image.clone());
        let mut core = fixture.replay_scripted(io, first_state).unwrap();
        core.file.inject_fault(fault.clone());
        assert!(
            matches!(
                core.append_signing_lineage(child_height, child_id),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert_eq!(core.lineage.unwrap().height, ConsensusHeight::new(1));
        assert_eq!(core.state_id, first_state, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor_io = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor_io, first_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == first_state && actual == child_state
                ),
                "fault {fault:?}"
            );
            let exact_anchor_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture
                .replay_scripted(exact_anchor_io, child_state)
                .unwrap();
            assert_eq!(reopened.lineage.unwrap().height, child_height);
            assert_eq!(reopened.state_id, child_state);
        } else {
            let replay_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(replay_io, first_state).unwrap();
            assert_eq!(
                reopened.lineage.unwrap().height,
                ConsensusHeight::new(1),
                "fault {fault:?}"
            );
            assert_eq!(reopened.file.volatile.get_ref(), &first_image);
        }
    }
}

#[test]
fn every_completion_append_fault_withholds_bytes_and_requires_exact_durable_anchor() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let intent = fixture.nil_prevote_intent();
    let prepare_body = tagged_record(
        PREPARE_RECORD,
        intent.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let prepared_state = step_state_id(
        genesis_state_id(&prefix),
        u32::try_from(prepare_body.len()).unwrap().to_be_bytes(),
        &prepare_body,
    );

    for fault in all_append_faults(4 + SIGNED_VOTE_BODY_BYTES, 32) {
        let io = ScriptedIo::new(prefix.clone(), None);
        let mut core = fixture.scripted_core(io);
        let prepared = prepared(core.prepare_vote(intent.clone()).unwrap());
        assert_eq!(prepared.state_id(), prepared_state);
        let prepared_image = core.file.durable.clone();
        core.file = ScriptedIo::new(prepared_image.clone(), Some(fault.clone()));
        let error = core
            .sign_prepared_vote(&fixture.signing_key(), prepared)
            .unwrap_err();
        let proposed_state = match error {
            FixedValidatorVoteSafetyJournalErrorV0::Commit {
                proposed_state_id, ..
            } => proposed_state_id,
            other => panic!("fault {fault:?} returned {other:?}"),
        };
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        let complete_length = prepared_image.len() + 4 + SIGNED_VOTE_BODY_BYTES + 32;
        if durable.len() == complete_length {
            let stale = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(stale, prepared_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual
                    }) if expected == prepared_state && actual == proposed_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, proposed_state).unwrap();
            assert!(reopened.pending.is_none());
        } else {
            let partial = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(partial, prepared_state).unwrap();
            assert!(reopened.restarted_pending().is_some());
            assert_eq!(
                reopened.file.volatile.get_ref(),
                &prepared_image,
                "fault {fault:?}"
            );
        }
    }
}

#[test]
fn recovery_and_stabilization_io_failures_are_reported_without_a_handle() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let mut incomplete = prefix.clone();
    incomplete.extend_from_slice(&u32::try_from(MIN_RECORD_BODY_BYTES).unwrap().to_be_bytes());
    incomplete.extend_from_slice(&[PREPARE_RECORD, 0xaa]);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        fixture.replay_scripted(recovery_io, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Recovery { .. })
    ));

    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix);
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        fixture.replay_scripted(stabilize_io, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Stabilize { .. })
    ));
}
