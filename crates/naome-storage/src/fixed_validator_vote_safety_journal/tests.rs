use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{ArtifactBlock, ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusGenesisId, ConsensusHeight,
    ConsensusProtocolVersion, ConsensusSignature, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusBranchV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateV0,
    ObservedFixedValidatorHigherRoundCheckpointV0, OwnedVerifiedFixedConsensusTransitionV0,
    QuorumCertificateVerifyError, VerifiedFixedConsensusProposalV0,
    VerifiedProducerAuthorizationV0, VerifiedReplayFixedValidatorVoteIntentV0,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
#[cfg(unix)]
use crate::FixedValidatorAnchoredFinalityJournalV0;
use crate::fault_io::{ScriptedIo, all_append_faults};
use crate::{
    FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorFinalityJournalV0, FixedValidatorFinalityReplayLimitV0,
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

    #[cfg(unix)]
    fn vote_anchor(&self, signer: ConsensusKey) -> PathBuf {
        let signer_hex: String = signer
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.0
            .join(format!("fixed-validator-vote-safety-{signer_hex}.anchor"))
    }

    #[cfg(unix)]
    fn vote_anchor_temporary(&self, signer: ConsensusKey, sequence: u64) -> PathBuf {
        let anchor = self.vote_anchor(signer);
        let file_name = anchor.file_name().unwrap().to_string_lossy();
        self.0.join(format!("{file_name}.tmp-{sequence:016x}"))
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

    fn proposal_candidate_for(&self, axiom: ZfcAxiom) -> (ArtifactBlock, Vec<u8>) {
        let payload = proof_payload_for(axiom);
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = ArtifactChainState::new(self.definition)
            .prepare_block(artifact_id)
            .unwrap();
        (block, payload)
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

    #[cfg(unix)]
    fn create_anchored(
        &self,
        journal_directory: &TestDirectory,
        anchor_directory: &TestDirectory,
    ) -> FixedValidatorAnchoredVoteSafetyJournalV0 {
        FixedValidatorAnchoredVoteSafetyJournalV0::create(
            &journal_directory.0,
            &anchor_directory.0,
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

    #[cfg(unix)]
    fn create_anchored_finality(
        &self,
        journal_directory: &TestDirectory,
        anchor_directory: &TestDirectory,
    ) -> FixedValidatorAnchoredFinalityJournalV0 {
        FixedValidatorAnchoredFinalityJournalV0::create(
            &journal_directory.0,
            &anchor_directory.0,
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

    #[cfg(unix)]
    fn open_anchored(
        &self,
        journal_directory: &TestDirectory,
        anchor_directory: &TestDirectory,
    ) -> Result<
        FixedValidatorAnchoredVoteSafetyJournalV0,
        FixedValidatorAnchoredVoteSafetyJournalErrorV0,
    > {
        FixedValidatorAnchoredVoteSafetyJournalV0::open(
            &journal_directory.0,
            &anchor_directory.0,
            self.context,
            self.fixed_set_id(),
            self.signing_key(),
            self.replay_limit,
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
            None,
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

fn prepared_proposal(
    outcome: FixedValidatorProposalPrepareOutcomeV0,
) -> FixedValidatorPreparedProposalV0 {
    match outcome {
        FixedValidatorProposalPrepareOutcomeV0::Prepared(prepared)
        | FixedValidatorProposalPrepareOutcomeV0::AlreadyPrepared(prepared) => prepared,
        other => panic!("expected prepared proposal outcome, got {other:?}"),
    }
}

fn signed(outcome: FixedValidatorVoteSignOutcomeV0) -> FixedValidatorSignedVoteV0 {
    match outcome {
        FixedValidatorVoteSignOutcomeV0::Signed(signed)
        | FixedValidatorVoteSignOutcomeV0::AlreadySigned(signed) => signed,
    }
}

fn activate_proposal_authoring(
    journal: &mut FixedValidatorVoteSafetyJournalV0,
) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(64).unwrap())
        .unwrap()
}

#[cfg(unix)]
fn activate_anchored_proposal_authoring(
    journal: &mut FixedValidatorAnchoredVoteSafetyJournalV0,
) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(64).unwrap())
        .unwrap()
}

fn issue_session<'journal>(
    journal: &'journal mut FixedValidatorVoteSafetyJournalV0,
    round: &FixedConsensusRoundV0<'_>,
) -> FixedValidatorVoteSafetySigningSessionV0<'journal> {
    let _ = activate_proposal_authoring(journal);
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
fn session_and_recovery_issuance_require_proposal_authoring_activation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-requires-proposal-activation");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let bound = journal.bind_signing_lineage(&round).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let unactivated_image = fs::read(&journal_path).unwrap();

    assert!(matches!(
        journal.issue_signing_session(&round, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)
    ));
    assert!(matches!(
        journal.acknowledge_signer_recovery_is_externally_durable(bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), unactivated_image);

    let activated = activate_proposal_authoring(&mut journal);
    let recovery = journal
        .acknowledge_signer_recovery_is_externally_durable(activated)
        .unwrap();
    drop(recovery);
    let session = journal.issue_signing_session(&round, activated).unwrap();
    assert_eq!(session.position(), round.position());
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
    let activated = activate_proposal_authoring(&mut journal);

    assert!(matches!(
        journal.issue_signing_session(&round, activated),
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

#[cfg(unix)]
#[test]
fn anchored_vote_journal_persists_lineage_prepare_and_completion_before_release() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchored-vote-journal");
    let anchor_directory = TestDirectory::new("anchored-vote-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let anchor_path = anchor_directory.vote_anchor(fixture.signer());
    let (_, journal_path) = keyed_paths(&journal_directory.0, fixture.signer()).unwrap();
    let genesis_anchor = fs::read(&anchor_path).unwrap();
    assert_eq!(genesis_anchor.len(), 256);
    assert_eq!(&genesis_anchor[184..192], &0_u64.to_be_bytes());
    assert_eq!(
        &genesis_anchor[192..224],
        journal.state_id().unwrap().as_bytes()
    );

    let _ = activate_anchored_proposal_authoring(&mut journal);
    let lineage_state = journal.bind_signing_lineage(&round).unwrap();
    assert_eq!(journal.journal.core.record_sequence, 2);
    let lineage_anchor = fs::read(&anchor_path).unwrap();
    assert_eq!(&lineage_anchor[184..192], &2_u64.to_be_bytes());
    assert_eq!(&lineage_anchor[192..224], lineage_state.as_bytes());
    let lineage_journal = fs::read(&journal_path).unwrap();
    assert_eq!(journal.bind_signing_lineage(&round).unwrap(), lineage_state);
    assert_eq!(journal.journal.core.record_sequence, 2);
    assert_eq!(fs::read(&anchor_path).unwrap(), lineage_anchor);
    assert_eq!(fs::read(&journal_path).unwrap(), lineage_journal);

    let mut session = journal.issue_signing_session(&round).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[192..224],
        prepared.state_id().as_bytes()
    );
    let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[184..192],
        &4_u64.to_be_bytes()
    );
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[192..224],
        signed.state_id().as_bytes()
    );
    drop(session);
    assert_eq!(journal.journal.core.record_sequence, 4);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 4);
    assert_eq!(reopened.state_id().unwrap(), signed.state_id());
    assert_eq!(
        reopened
            .retained_signed_vote(round.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed)
    );
    let resumed = reopened.issue_signing_session(&round).unwrap();
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[cfg(unix)]
#[test]
fn anchored_proposal_authoring_activates_signs_replays_and_recovers_exactly() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("anchored-proposal-journal");
    let anchor_directory = TestDirectory::new("anchored-proposal-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let proposal_limit = FixedValidatorProposalReplayLimitV0::new(2).unwrap();
    let activation = journal.activate_proposal_authoring(proposal_limit).unwrap();
    let activated_images = (
        fs::read(
            keyed_paths(&journal_directory.0, fixture.signer())
                .unwrap()
                .1,
        )
        .unwrap(),
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
    );
    assert_eq!(journal.proposal_replay_limit(), Some(proposal_limit));
    assert_eq!(
        journal.activate_proposal_authoring(proposal_limit).unwrap(),
        activation
    );
    assert_eq!(
        activated_images,
        (
            fs::read(
                keyed_paths(&journal_directory.0, fixture.signer())
                    .unwrap()
                    .1
            )
            .unwrap(),
            fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        )
    );
    assert!(matches!(
        journal.activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(3).unwrap()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ProposalReplayLimitMismatch {
                retained: 2,
                supplied: 3,
            }
        )
    ));

    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (artifact_block, payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let prepared = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload.clone(),
                },
            )
            .unwrap(),
    );
    let acknowledgement = session.acknowledge_prepared_proposal(prepared).unwrap();
    let signed = session.sign_prepared_proposal(acknowledgement).unwrap();
    let verified = round
        .decode_and_verify_proposal_control(
            signed.canonical_proposal_control_bytes(),
            payload.clone(),
        )
        .unwrap();
    assert_eq!(
        verified.proposal_signing_root(),
        signed.proposal_signing_root()
    );
    let completed_images = (
        fs::read(
            keyed_paths(&journal_directory.0, fixture.signer())
                .unwrap()
                .1,
        )
        .unwrap(),
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
    );
    assert!(matches!(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload,
                },
            )
            .unwrap(),
        FixedValidatorProposalPrepareOutcomeV0::AlreadySigned(ref replay)
            if replay == &signed
    ));
    assert_eq!(
        completed_images,
        (
            fs::read(
                keyed_paths(&journal_directory.0, fixture.signer())
                    .unwrap()
                    .1
            )
            .unwrap(),
            fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        )
    );
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.proposal_replay_limit(), Some(proposal_limit));
    assert_eq!(
        reopened.retained_signed_proposal(round.position()).unwrap(),
        Some(signed)
    );
    let resumed = reopened.issue_signing_session(&round).unwrap();
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Proposal);
}

#[cfg(unix)]
#[test]
fn anchored_pending_proposal_is_diagnostic_only_after_restart() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("pending-proposal-journal");
    let anchor_directory = TestDirectory::new("pending-proposal-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(2).unwrap())
        .unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (artifact_block, payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let prepared = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload,
                },
            )
            .unwrap(),
    );
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    let pending = reopened.pending_proposal().unwrap().unwrap();
    assert_eq!(pending.position(), prepared.position());
    assert_eq!(pending.state_id(), prepared.state_id());
    assert!(matches!(
        reopened.issue_signing_session(&round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingProposalRecoveryDenied {
            position,
        }) if position == round.position()
    ));
}

#[cfg(unix)]
#[test]
fn conflicting_same_slot_proposal_intent_terminally_stops_only_the_signer() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("proposal-conflict-journal");
    let anchor_directory = TestDirectory::new("proposal-conflict-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(1).unwrap())
        .unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (first_block, first_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let first = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: first_block,
                    canonical_artifact_bytes: first_payload,
                },
            )
            .unwrap(),
    );
    let acknowledgement = session.acknowledge_prepared_proposal(first).unwrap();
    let _ = session.sign_prepared_proposal(acknowledgement).unwrap();

    let (second_block, second_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let halt = match session
        .prepare_proposal(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: second_block,
                canonical_artifact_bytes: second_payload,
            },
        )
        .unwrap()
    {
        FixedValidatorProposalPrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected proposal halt, got {other:?}"),
    };
    assert_eq!(halt.position(), round.position());
    assert_ne!(halt.retained_root(), halt.conflicting_root());
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalProposalHalt {
            position,
        }) if position == round.position()
    ));
}

#[cfg(unix)]
#[test]
fn anchor_update_failure_releases_no_signed_vote_and_strict_reopen_fails_behind() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchor-failure-vote-journal");
    let anchor_directory = TestDirectory::new("anchor-failure-vote-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = activate_anchored_proposal_authoring(&mut journal);
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    assert_eq!(session.session.journal.core.record_sequence, 3);
    let anchor_before = fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap();

    fs::create_dir(anchor_directory.vote_anchor_temporary(fixture.signer(), 4)).unwrap();
    let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
    assert!(matches!(
        session.sign_prepared_vote(acknowledgement),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    assert_eq!(
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        anchor_before
    );
    assert!(matches!(
        session.decide_precommit_without_quorum(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
    ));
    drop(session);
    drop(journal);

    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                anchored_sequence: 3,
                journal_sequence: 4,
                }
            )
    ));
}

#[cfg(unix)]
#[test]
fn anchor_operation_failures_withhold_signed_vote_until_exact_stabilized_reopen() {
    use crate::fixed_validator_anchor::faults::{Operation, REPLACEMENT_OPERATIONS, inject};

    let fixture = Fixture::new(2);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let (expected_signed, expected_images) = {
        let journal_directory = TestDirectory::new("anchor-fault-vote-control-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-vote-control-anchor");
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let _ = activate_anchored_proposal_authoring(&mut journal);
        let _ = journal.bind_signing_lineage(&round).unwrap();
        let mut session = journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
        let signed = session.sign_prepared_vote(acknowledgement).unwrap();
        (
            signed,
            (
                fs::read(
                    keyed_paths(&journal_directory.0, fixture.signer())
                        .unwrap()
                        .1,
                )
                .unwrap(),
                fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
            ),
        )
    };

    for operation in REPLACEMENT_OPERATIONS {
        let journal_directory = TestDirectory::new("anchor-fault-vote-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-vote-anchor");
        let anchor_path = anchor_directory.vote_anchor(fixture.signer());
        let temporary_path = anchor_directory.vote_anchor_temporary(fixture.signer(), 4);
        let journal_path = keyed_paths(&journal_directory.0, fixture.signer())
            .unwrap()
            .1;
        let images = || {
            (
                fs::read(&journal_path).unwrap(),
                fs::read(&anchor_path).unwrap(),
            )
        };
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let _ = activate_anchored_proposal_authoring(&mut journal);
        let _ = journal.bind_signing_lineage(&round).unwrap();
        let mut session = journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
        let before = images();
        let fault = inject(&anchor_path, operation);
        assert!(
            matches!(
                session.sign_prepared_vote(acknowledgement),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "{operation:?}"
        );
        fault.assert_fired();
        drop(fault);
        assert!(matches!(
            session.decide_precommit_without_quorum(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        drop(session);
        assert!(matches!(
            journal.state_id(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        assert!(matches!(
            journal.retained_signed_vote(round.position(), ConsensusVoteRole::Prevote),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        assert!(matches!(
            journal.issue_signing_session(&round),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let after = images();
        assert_eq!(after.0, expected_images.0, "{operation:?}");
        assert_ne!(after.0, before.0);
        match operation {
            Operation::CreateTemporary | Operation::SyncReplacementDirectory => {
                assert!(!temporary_path.exists())
            }
            Operation::WriteTemporary => assert!(fs::read(&temporary_path).unwrap().is_empty()),
            Operation::SyncTemporary | Operation::Rename => {
                assert_eq!(fs::read(&temporary_path).unwrap(), expected_images.1)
            }
            Operation::StabilizeFile | Operation::StabilizeDirectory => unreachable!(),
        }
        drop(journal);

        if operation != Operation::SyncReplacementDirectory {
            assert_eq!(after.1, before.1);
            let temporary_before = fs::read(&temporary_path).ok();
            for _ in 0..2 {
                assert!(matches!(
                    fixture.open_anchored(&journal_directory, &anchor_directory),
                    Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
                        if matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { anchored_sequence: 3, journal_sequence: 4 })
                ));
                assert_eq!(images(), after);
                assert_eq!(fs::read(&temporary_path).ok(), temporary_before);
            }
            continue;
        }

        assert_eq!(after, expected_images);
        for stabilization in [Operation::StabilizeFile, Operation::StabilizeDirectory] {
            let fault = inject(&anchor_path, stabilization);
            assert!(matches!(
                fixture.open_anchored(&journal_directory, &anchor_directory),
                Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor(
                    FixedValidatorAnchorErrorV0::Stabilize { .. }
                ))
            ));
            fault.assert_fired();
            drop(fault);
            assert_eq!(images(), after);
        }
        let mut reopened = fixture
            .open_anchored(&journal_directory, &anchor_directory)
            .unwrap();
        assert_eq!(reopened.state_id().unwrap(), expected_signed.state_id());
        assert_eq!(
            reopened
                .retained_signed_vote(round.position(), ConsensusVoteRole::Prevote)
                .unwrap()
                .as_ref(),
            Some(&expected_signed)
        );
        let resumed = reopened.issue_signing_session(&round).unwrap();
        assert_eq!(resumed.position(), round.position());
        assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
        assert_eq!(images(), after);
    }
}

#[cfg(unix)]
#[test]
fn anchored_height_handoff_and_finality_stop_advance_both_authority_files() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("anchored-handoff-finality-journal");
    let finality_anchor_directory = TestDirectory::new("anchored-handoff-finality-anchor");
    let vote_directory = TestDirectory::new("anchored-handoff-vote-journal");
    let vote_anchor_directory = TestDirectory::new("anchored-handoff-vote-anchor");
    let mut finality = crate::FixedValidatorAnchoredFinalityJournalV0::create(
        &finality_directory.0,
        &finality_anchor_directory.0,
        fixture.definition,
        fixture.context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
    )
    .unwrap();
    let mut vote = fixture.create_anchored(&vote_directory, &vote_anchor_directory);
    let parent = fixture.branch();
    let round = parent.begin_round_zero().unwrap();
    let _ = activate_anchored_proposal_authoring(&mut vote);
    let _ = vote.bind_signing_lineage(&round).unwrap();
    let mut session = vote.issue_signing_session(&round).unwrap();

    let first = fixture.owned_transition_for(ZfcAxiom::Pairing);
    assert!(matches!(
        finality.commit_verified(first).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    assert_eq!(
        &fs::read(
            finality_anchor_directory
                .0
                .join("fixed-validator-finality.anchor")
        )
        .unwrap()[149..157],
        &1_u64.to_be_bytes()
    );
    let handoff = finality
        .acknowledge_signer_height_transition(ConsensusHeight::new(1))
        .unwrap();
    let prepared_height = session
        .prepare_height_with_durable_finality(handoff)
        .unwrap();
    assert_eq!(
        &fs::read(vote_anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    let child = session
        .acknowledge_prepared_height(prepared_height)
        .unwrap();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));

    let conflict = fixture.owned_transition_for(ZfcAxiom::Union);
    assert!(matches!(
        finality.commit_verified(conflict).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    assert_eq!(
        &fs::read(
            finality_anchor_directory
                .0
                .join("fixed-validator-finality.anchor")
        )
        .unwrap()[149..157],
        &2_u64.to_be_bytes()
    );
    let stop = finality.acknowledge_signer_stop().unwrap();
    let _ = session.stop_after_durable_finality_conflict(stop).unwrap();
    assert_eq!(
        &fs::read(vote_anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &4_u64.to_be_bytes()
    );
    drop(session);
    assert_eq!(vote.journal.core.record_sequence, 4);
    assert!(vote.finality_conflict_stop().unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn anchored_higher_round_checkpoint_reopens_at_the_persisted_phase_floor() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchored-checkpoint-vote-journal");
    let anchor_directory = TestDirectory::new("anchored-checkpoint-vote-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = activate_anchored_proposal_authoring(&mut journal);
    let _ = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero).unwrap();
    let prepared = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    assert_eq!(
        &fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    let target_round = session.acknowledge_prepared_higher_round(prepared).unwrap();
    assert_eq!(target_round.position(), target_position);
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 3);
    let resumed = reopened.issue_signing_session(&target_round).unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[cfg(unix)]
#[test]
fn anchored_vote_reopen_classifies_old_ahead_and_divergent_anchor_images() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("vote-anchor-classification-journal");
    let anchor_directory = TestDirectory::new("vote-anchor-classification-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let anchor_path = anchor_directory.vote_anchor(fixture.signer());
    let (_, journal_path) = keyed_paths(&journal_directory.0, fixture.signer()).unwrap();
    let genesis_anchor = fs::read(&anchor_path).unwrap();
    let genesis_journal = fs::read(&journal_path).unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let current_anchor = fs::read(&anchor_path).unwrap();
    let current_journal = fs::read(&journal_path).unwrap();
    drop(journal);

    fs::write(&anchor_path, &genesis_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                anchored_sequence: 0,
                journal_sequence: 1,
                }
            )
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), current_journal);

    fs::write(&anchor_path, &current_anchor).unwrap();
    fs::write(&journal_path, &genesis_journal).unwrap();
    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorAhead {
                anchored_sequence: 1,
                journal_sequence: 0,
                }
            )
    ));

    let left_journal = TestDirectory::new("vote-anchor-divergent-left-journal");
    let left_anchor = TestDirectory::new("vote-anchor-divergent-left-anchor");
    let right_journal = TestDirectory::new("vote-anchor-divergent-right-journal");
    let right_anchor = TestDirectory::new("vote-anchor-divergent-right-anchor");
    let mut left = fixture.create_anchored(&left_journal, &left_anchor);
    let mut right = fixture.create_anchored(&right_journal, &right_anchor);
    let left_branch = fixture.branch();
    let left_round = left_branch.begin_round_zero().unwrap();
    let right_branch = fixture.branch();
    let right_round = right_branch.begin_round_zero().unwrap();
    let _ = activate_anchored_proposal_authoring(&mut left);
    let _ = activate_anchored_proposal_authoring(&mut right);
    let _ = left.bind_signing_lineage(&left_round).unwrap();
    let _ = right.bind_signing_lineage(&right_round).unwrap();
    let mut left_session = left.issue_signing_session(&left_round).unwrap();
    let mut right_session = right.issue_signing_session(&right_round).unwrap();
    let left_effect = left_session.decide_prevote_without_proposal().unwrap();
    let left_prepared = prepared(left_session.prepare_vote(&left_round, left_effect).unwrap());
    let right_payload = proof_payload();
    let right_artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(right_payload.clone())
        .unwrap()
        .artifact_id();
    let right_block = ArtifactChainState::new(fixture.definition)
        .prepare_block(right_artifact_id)
        .unwrap();
    let right_value = right_round.value_for_artifact_block(right_block);
    let mut right_proposal_bytes = right_value.to_canonical_bytes().to_vec();
    right_proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        right_round.position(),
        right_value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    right_proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let right_proposal = right_round
        .decode_and_verify_proposal_control(&right_proposal_bytes, right_payload)
        .unwrap();
    let right_effect = right_session
        .decide_prevote_for_proposal(&right_proposal)
        .unwrap();
    let right_prepared = prepared(
        right_session
            .prepare_vote(&right_round, right_effect)
            .unwrap(),
    );
    assert_ne!(left_prepared.state_id(), right_prepared.state_id());
    let divergent_anchor = fs::read(right_anchor.vote_anchor(fixture.signer())).unwrap();
    drop(left_session);
    drop(right_session);
    drop(left);
    drop(right);
    fs::write(left_anchor.vote_anchor(fixture.signer()), divergent_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&left_journal, &left_anchor),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorStateMismatch { sequence: 3 }
            )
    ));
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
fn nil_precommit_quorum_advances_session_and_next_vote_reopens_at_exact_anchor() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("nil-precommit-round-advance");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let bound_image = fs::read(&journal_path).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let certificate = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );

    let round_one = session
        .advance_round_for_nil_precommit_quorum(&round_zero, &certificate)
        .unwrap();

    assert_eq!(
        round_one.position().height(),
        round_zero.position().height()
    );
    assert_eq!(
        round_one.position().round(),
        ConsensusRound::new(round_zero.position().round().value() + 1)
    );
    assert_eq!(session.position(), round_one.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);

    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round_one, effect).unwrap());
    assert_eq!(prepared.position(), round_one.position());
    assert_eq!(prepared.role(), ConsensusVoteRole::Prevote);
    let prepared_image = fs::read(&journal_path).unwrap();
    assert_ne!(prepared_image, bound_image);
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    let completed_state = signed.state_id();
    assert_eq!(signed.position(), round_one.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
    assert_eq!(signed.target(), ConsensusVoteTarget::Nil);
    drop(session);

    assert_eq!(journal.state_id().unwrap(), completed_state);
    assert_eq!(
        journal
            .retained_signed_vote(round_one.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed.clone())
    );
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    assert_eq!(
        reopened
            .retained_signed_vote(round_one.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed)
    );
    let resumed = reopened
        .issue_signing_session(&round_one, completed_state)
        .unwrap();
    assert_eq!(resumed.position(), round_one.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(resumed.locked_value(), None);
    assert_eq!(resumed.valid_value(), None);
}

#[test]
fn pending_preparation_blocks_nil_precommit_quorum_advance_without_mutation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("nil-precommit-pending-vote");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round_zero);
    let _ = session.decide_prevote_without_proposal().unwrap();
    let effect = session.decide_precommit_without_quorum().unwrap();
    let _prepared = prepared(session.prepare_vote(&round_zero, effect).unwrap());
    let prepared_image = fs::read(&journal_path).unwrap();
    let before_position = session.position();
    let before_phase = session.phase();
    let before_lock = session.locked_value();
    assert_eq!(session.valid_value(), None);
    let certificate = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let higher_certificate = certificate_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );

    assert!(matches!(
        session.advance_round_for_nil_precommit_quorum(&round_zero, &certificate),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round_zero.position()
    ));
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round_zero,
            &higher_certificate,
            ConsensusRound::new(2),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round_zero.position()
    ));
    assert_eq!(session.position(), before_position);
    assert_eq!(session.phase(), before_phase);
    assert_eq!(session.locked_value(), before_lock);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_image);
}

#[test]
fn higher_round_checkpoint_requires_exact_anchor_then_preserves_vote_capacity_and_reopen() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("higher-round-checkpoint-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let bound_image = fs::read(&journal_path).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let before_position = session.position();
    let before_phase = session.phase();

    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    assert_eq!(
        checkpoint_state.as_bytes(),
        &[
            0x25, 0x93, 0x02, 0xfe, 0x57, 0x35, 0xc4, 0x3f, 0xf8, 0x05, 0xf5, 0x4c, 0x98, 0xc9,
            0x03, 0x61, 0x7c, 0xe8, 0x17, 0x15, 0x84, 0x1d, 0x7d, 0xdf, 0x7b, 0x61, 0x39, 0xd9,
            0x75, 0xd6, 0x71, 0x7a,
        ]
    );
    let checkpoint_image = fs::read(&journal_path).unwrap();
    assert_eq!(session.position(), before_position);
    assert_eq!(session.phase(), before_phase);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_ne!(checkpoint_image, bound_image);

    let frame = &checkpoint_image[bound_image.len()..];
    let body_length = usize::try_from(u32::from_be_bytes(frame[..4].try_into().unwrap())).unwrap();
    assert_eq!(body_length, MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES);
    assert_eq!(
        ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH,
        606
    );
    assert_eq!(
        ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        50_370
    );
    assert_eq!(MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES, 607);
    assert_eq!(MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES, 50_371);
    assert_eq!(
        body_length,
        1 + ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH
    );
    assert_eq!(frame[4], HIGHER_ROUND_CHECKPOINT_RECORD);
    assert_eq!(frame.len(), 4 + body_length + 32);
    assert_eq!(frame.len(), 643);
    assert_eq!(4 + MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES + 32, 50_407);
    let body = &frame[4..4 + body_length];
    assert_eq!(
        checkpoint_state,
        step_state_id(
            bound,
            u32::try_from(body_length).unwrap().to_be_bytes(),
            body
        )
    );
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round_zero,
            &certificate,
            ConsensusRound::new(3),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), checkpoint_image);

    let target_round = session
        .acknowledge_prepared_higher_round_is_externally_durable(checkpoint, checkpoint_state)
        .unwrap();
    assert_eq!(target_round.position(), target_position);
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(fs::read(&journal_path).unwrap(), checkpoint_image);

    let effect = session.decide_precommit_without_quorum().unwrap();
    let vote = prepared(session.prepare_vote(&target_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(vote, vote.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    let completed_state = signed.state_id();
    assert_eq!(signed.position(), target_position);
    assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, completed_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn higher_round_checkpoint_durably_preserves_nonempty_lock_and_valid_proof() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("higher-round-checkpoint-retained-lock");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let payload = proof_payload();
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id)
        .unwrap();
    let value = round_zero.value_for_artifact_block(block);
    let root = value.proposal_signing_root();
    let mut proposal_bytes = value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        round_zero.position(),
        root,
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = round_zero
        .decode_and_verify_proposal_control(&proposal_bytes, payload)
        .unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();

    let prevote_effect = session.decide_prevote_for_proposal(&proposal).unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let proposal_quorum = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let precommit_effect = session
        .decide_precommit_for_proposal_quorum(&round_zero, &proposal, &proposal_quorum)
        .unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let expected_lock = session.locked_value();
    let expected_valid = session.valid_value().cloned();
    assert!(expected_lock.is_some());
    assert!(expected_valid.is_some());

    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    session.advance_round(&round_one).unwrap();
    let target_position =
        ConsensusPosition::new(round_one.position().height(), ConsensusRound::new(3));
    let catchup_quorum = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let before_checkpoint = fs::read(&journal_path).unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_one, &catchup_quorum, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    let checkpoint_image = fs::read(&journal_path).unwrap();
    let frame = &checkpoint_image[before_checkpoint.len()..];
    let body_length = usize::try_from(u32::from_be_bytes(frame[..4].try_into().unwrap())).unwrap();
    assert!(body_length > MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES);
    let target_round = session
        .acknowledge_prepared_higher_round_is_externally_durable(checkpoint, checkpoint_state)
        .unwrap();
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(session.locked_value(), expected_lock);
    assert_eq!(session.valid_value(), expected_valid.as_ref());
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, checkpoint_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(resumed.locked_value(), expected_lock);
    assert_eq!(resumed.valid_value(), expected_valid.as_ref());
    assert_eq!(fs::read(journal_path).unwrap(), checkpoint_image);
}

#[test]
fn wrong_higher_round_anchor_blocks_live_state_and_exact_reopen_rejects_lower_round() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("higher-round-checkpoint-wrong-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    assert!(matches!(
        session.acknowledge_prepared_higher_round_is_externally_durable(checkpoint, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalHigherRoundAnchorMismatch {
            prepared,
            acknowledged,
        }) if prepared == checkpoint_state && acknowledged == bound
    ));
    assert_eq!(session.position(), round_zero.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round_zero, checkpoint_state),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay(
                FixedValidatorHigherRoundCheckpointErrorV0::State(
                    FixedValidatorVoteIntentError::RoundPositionMismatch { .. }
                )
            )
        )
    ));
    let target_round = round_zero.advance_round().unwrap().advance_round().unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, checkpoint_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn successive_higher_round_checkpoints_replay_only_the_latest_exact_state() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("successive-higher-round-checkpoints");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_two_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let round_four_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(4));
    let first_certificate = certificate_bytes(
        fixture.context,
        round_two_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let second_certificate = certificate_bytes(
        fixture.context,
        round_four_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();

    let first = session
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &first_certificate,
            ConsensusRound::new(2),
        )
        .unwrap();
    let first_state = first.state_id();
    let round_two = session
        .acknowledge_prepared_higher_round_is_externally_durable(first, first_state)
        .unwrap();
    assert_eq!(session.position(), round_two_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);

    let second = session
        .prepare_higher_round_quorum_advance(
            &round_two,
            &second_certificate,
            ConsensusRound::new(4),
        )
        .unwrap();
    let second_state = second.state_id();
    assert_ne!(second_state, first_state);
    let round_four = session
        .acknowledge_prepared_higher_round_is_externally_durable(second, second_state)
        .unwrap();
    assert_eq!(session.position(), round_four_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Precommit);
    drop(session);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == first_state && actual == second_state
    ));
    let mut reopened = fixture.open(&directory, second_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&round_four, second_state)
        .unwrap();
    assert_eq!(resumed.position(), round_four_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn higher_round_checkpoint_rejects_stale_sources_and_nonadvancing_vote_state() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_two_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let round_four_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(4));
    let first_certificate = certificate_bytes(
        fixture.context,
        round_two_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let stale_source_certificate = certificate_bytes(
        fixture.context,
        round_four_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let first = state
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &first_certificate,
            ConsensusRound::new(2),
        )
        .unwrap();
    let stale_source = state
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &stale_source_certificate,
            ConsensusRound::new(4),
        )
        .unwrap();

    let mut core = fixture.scripted_core(ScriptedIo::new(prefix, None));
    let _ = core.bind_signing_lineage(&round_zero).unwrap();
    let checkpoint_state = core
        .append_higher_round_checkpoint(first.canonical_checkpoint_bytes())
        .unwrap();
    let checkpoint_image = core.file.volatile.get_ref().clone();
    let checkpoint_durable = core.file.durable.clone();
    assert!(matches!(
        core.append_higher_round_checkpoint(stale_source.canonical_checkpoint_bytes()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointSourceBehindState {
                current_position,
                current_phase: FixedValidatorLockPhaseV0::Prevote,
                source_position,
                source_phase: FixedValidatorLockPhaseV0::Proposal,
                ..
            }
        ) if current_position == round_two_position && source_position == round_zero.position()
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &checkpoint_image);
    assert_eq!(core.file.durable, checkpoint_durable);
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));

    let (same_state_vote, _) = fixture.round_two_nil_prevote_intents_with_distinct_state();
    assert!(matches!(
        core.prepare_vote(same_state_vote),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::VoteStateDoesNotFollowHigherRoundCheckpoint {
                checkpoint_position,
                checkpoint_phase: FixedValidatorLockPhaseV0::Prevote,
                vote_position,
                vote_phase: FixedValidatorLockPhaseV0::Prevote,
                ..
            }
        ) if checkpoint_position == round_two_position && vote_position == round_two_position
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &checkpoint_image);
    assert_eq!(core.file.durable, checkpoint_durable);
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));
}

#[test]
fn anchored_signer_recovery_derives_checkpoint_round_under_explicit_limit() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("higher-round-checkpoint-recovery-limit");
    let finality = fixture.create_finality(&directory);
    let finality_state = finality.state_id().unwrap();
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let prepared = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = prepared.state_id();
    let _ = session
        .acknowledge_prepared_higher_round_is_externally_durable(prepared, checkpoint_state)
        .unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(session);
    drop(journal);
    drop(round_zero);
    drop(branch);
    drop(finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(checkpoint_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    assert!(matches!(
        reopened.issue_recovered_signing_session(
            recovered_branch,
            checkpoint_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(2),
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                required: 3,
                maximum: 2,
            }
        )
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(checkpoint_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            checkpoint_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(3),
        )
        .unwrap();
    assert_eq!(recovered.session().position(), target_position);
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Precommit
    );
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn checkpoint_file_replay_defers_quorum_signature_authority_to_typed_restore() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round_zero.parent_coordinate(),
        round_zero.position().height(),
        fixture.signer(),
    );
    let lineage_body =
        signing_lineage_record(round_zero.position().height(), lineage_id, 0).unwrap();
    let mut image = prefix;
    let lineage_state = append_test_record(&mut image, genesis, &lineage_body);
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let transition = state
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let mut checkpoint = transition.canonical_checkpoint_bytes().to_vec();
    *checkpoint.last_mut().unwrap() ^= 0x80;
    let body = tagged_record(HIGHER_ROUND_CHECKPOINT_RECORD, &checkpoint, 0).unwrap();
    let checkpoint_state = append_test_record(&mut image, lineage_state, &body);

    let io = ScriptedIo::from_images(image.clone(), image.clone());
    let core = fixture.replay_scripted(io, checkpoint_state).unwrap();
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));
    let target_round = round_zero.advance_round().unwrap().advance_round().unwrap();
    assert!(matches!(
        core.recover_lock_state_for_round(&target_round),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay(
                FixedValidatorHigherRoundCheckpointErrorV0::Certificate(
                    QuorumCertificateVerifyError::InvalidSignature { .. }
                )
            )
        )
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &image);
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
    let activated_vote_state = activate_proposal_authoring(&mut vote_journal);
    assert!(matches!(
        vote_journal.issue_signing_session(&round, activated_vote_state),
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
    let expected_child_coordinate = fixture.owned_transition().into_branch().coordinate();

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

    drop(prepared_height);
    drop(session);
    drop(vote_journal);
    drop(parent_round);
    drop(branch);
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
    let halted_finality_state = halt.state_id();
    drop(finality);

    let halted_finality = fixture.open_finality(&directory, halted_finality_state);
    let mut reopened = fixture.open(&directory, child_lineage_state).unwrap();
    let vote_image_before_recovery = fs::read(&vote_path).unwrap();
    assert!(matches!(
        halted_finality.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(child_lineage_state)
        .unwrap();
    let recovered_branch = halted_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            child_lineage_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), expected_child_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0))
    );
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Proposal
    );
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image_before_recovery);
    assert_eq!(fs::read(&finality_path).unwrap(), halted_finality_image);
    assert_eq!(halted_finality.state_id().unwrap(), halted_finality_state);
    assert_eq!(halted_finality.halt().unwrap(), Some(halt));

    let (child, mut session) = recovered.into_parts();
    let child_round = child.begin_round_zero().unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&child_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(fs::read(finality_path).unwrap(), halted_finality_image);
}

#[test]
fn durable_finality_conflict_preempts_live_prepared_vote_before_key_use() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-live-prepared");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&directory);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut vote_journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let pre_stop_image = fs::read(&vote_path).unwrap();

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    assert_eq!(stopped.finality_state_id(), halt.state_id());
    assert_eq!(stopped.height(), halt.height());
    assert_eq!(stopped.kind(), halt.kind());
    assert_eq!(stopped.first_ancestry(), halt.first_ancestry());
    assert_eq!(stopped.second_ancestry(), halt.second_ancestry());
    let stopped_image = fs::read(&vote_path).unwrap();
    assert_ne!(stopped_image, pre_stop_image);

    assert!(matches!(
        session.sign_prepared_vote(acknowledgement),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(session.journal.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(
        session.journal.finality_conflict_stop().unwrap(),
        Some(stopped)
    );
    assert_eq!(fs::read(&vote_path).unwrap(), stopped_image);
}

#[test]
fn durable_finality_conflict_preempts_pending_higher_round_checkpoint() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-pending-higher-round");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut vote_journal);
    let bound = vote_journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&round_zero, bound)
        .unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    let checkpoint_image = fs::read(&vote_path).unwrap();
    assert_eq!(session.journal.state_id().unwrap(), checkpoint_state);

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let stopped_image = fs::read(&vote_path).unwrap();
    assert_ne!(stopped_image, checkpoint_image);
    assert_ne!(stopped.vote_state_id(), checkpoint_state);

    assert!(matches!(
        session.acknowledge_prepared_higher_round_is_externally_durable(
            checkpoint,
            checkpoint_state,
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(
        session.journal.finality_conflict_stop().unwrap(),
        Some(stopped)
    );
    drop(session);
    drop(vote_journal);

    assert!(matches!(
        fixture.open(&directory, checkpoint_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == checkpoint_state && actual == stopped.vote_state_id()
    ));
    let mut reopened = fixture.open(&directory, stopped.vote_state_id()).unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    let target_round = branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap()
        .advance_round()
        .unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&target_round, stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn exact_restart_preserves_finality_stop_and_exact_repeat_is_no_write() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-restart-repeat");
    let alternate_finality_directory =
        TestDirectory::new("finality-stop-restart-alternate-conflict");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let signed = signed(vote_journal.sign_prepared_vote(prepared).unwrap());
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let stopped_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(finality);

    let finality = fixture.open_finality(&directory, halt.state_id());
    let mut reopened = fixture.open(&directory, stopped.vote_state_id()).unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    assert!(matches!(
        reopened.issue_signing_session(&round, stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        reopened.retained_signed_vote(signed.position(), signed.role()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        reopened.acknowledge_signer_recovery_is_externally_durable(stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));

    let repeated_conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        reopened
            .stop_after_durable_finality_conflict(repeated_conflict)
            .unwrap(),
        FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing)
            if existing == stopped
    ));
    assert_eq!(reopened.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(&vote_path).unwrap(), stopped_image);

    let mut alternate_finality = fixture.create_finality(&alternate_finality_directory);
    let _ = alternate_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let alternate_halt = match alternate_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::PowerSet))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected alternate finality halt, got {other:?}"),
    };
    let alternate_conflict = alternate_finality
        .acknowledge_signer_stop_is_externally_durable(alternate_halt.state_id())
        .unwrap();
    assert!(matches!(
        reopened.stop_after_durable_finality_conflict(alternate_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == halt.height() && incoming_height == alternate_halt.height()
    ));
    assert_eq!(reopened.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn unavailable_or_mismatched_finality_stop_authority_never_changes_vote_state() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("finality-stop-mismatch-source");
    let primary_directory = TestDirectory::new("finality-stop-mismatch-primary");
    let context_directory = TestDirectory::new("finality-stop-mismatch-context");
    let set_directory = TestDirectory::new("finality-stop-mismatch-set");
    let mut finality = fixture.create_finality(&finality_directory);
    let primary = fixture.create(&primary_directory);
    let (_, primary_path) = keyed_paths(&primary_directory.0, fixture.signer()).unwrap();
    let primary_state = primary.state_id().unwrap();
    let primary_image = fs::read(&primary_path).unwrap();

    assert!(matches!(
        finality.acknowledge_signer_stop_is_externally_durable(finality.state_id().unwrap()),
        Err(FixedValidatorFinalityJournalErrorV0::SignerStopConflictRequired)
    ));
    assert_eq!(primary.state_id().unwrap(), primary_state);
    assert_eq!(fs::read(&primary_path).unwrap(), primary_image);

    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };
    let wrong_finality_anchor = FixedValidatorFinalityJournalStateIdV0::from_bytes([0x93; 32]);
    assert!(matches!(
        finality.acknowledge_signer_stop_is_externally_durable(wrong_finality_anchor),
        Err(
            FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                required,
                acknowledged,
            }
        ) if required == halt.state_id() && acknowledged == wrong_finality_anchor
    ));
    assert_eq!(primary.state_id().unwrap(), primary_state);
    assert_eq!(fs::read(&primary_path).unwrap(), primary_image);

    let wrong_context = ConsensusContextV0::new(
        fixture.context.chain_id(),
        ConsensusGenesisId::from_bytes([0x93; 32]),
        fixture.context.protocol_version(),
    );
    let mut context_vote = FixedValidatorVoteSafetyJournalV0::create(
        &context_directory.0,
        wrong_context,
        fixture.fixed_set_id(),
        fixture.signing_key(),
        fixture.replay_limit,
    )
    .unwrap();
    let (_, context_path) = keyed_paths(&context_directory.0, fixture.signer()).unwrap();
    let context_state = context_vote.state_id().unwrap();
    let context_image = fs::read(&context_path).unwrap();
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        context_vote.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictContextMismatch)
    ));
    assert_eq!(context_vote.state_id().unwrap(), context_state);
    assert_eq!(fs::read(context_path).unwrap(), context_image);

    let mut set_vote = FixedValidatorVoteSafetyJournalV0::create(
        &set_directory.0,
        fixture.context,
        fixture.alternate_fixed_set_id(),
        fixture.signing_key(),
        fixture.replay_limit,
    )
    .unwrap();
    let (_, set_path) = keyed_paths(&set_directory.0, fixture.signer()).unwrap();
    let set_state = set_vote.state_id().unwrap();
    let set_image = fs::read(&set_path).unwrap();
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        set_vote.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictFixedSetMismatch)
    ));
    assert_eq!(set_vote.state_id().unwrap(), set_state);
    assert_eq!(fs::read(set_path).unwrap(), set_image);
}

#[test]
fn finality_stop_preempts_held_height_advance_authority() {
    let fixture = Fixture::new(2);
    let height_directory = TestDirectory::new("finality-stop-held-height-source");
    let conflict_directory = TestDirectory::new("finality-stop-held-height-conflict");
    let vote_directory = TestDirectory::new("finality-stop-held-height-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();

    let mut height_finality = fixture.create_finality(&height_directory);
    let _ = height_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let height_finality_state = height_finality.state_id().unwrap();
    let durable_height = height_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            height_finality_state,
        )
        .unwrap();

    let mut conflict_finality = fixture.create_finality(&conflict_directory);
    let _ = conflict_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match conflict_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&vote_directory);
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut vote_journal, &round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable_height)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let parent_position = session.position();

    let conflict = conflict_finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let stopped_image = fs::read(&vote_path).unwrap();

    assert!(matches!(
        session.acknowledge_prepared_height_is_externally_durable(
            prepared_height,
            prepared_state,
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(session.position(), parent_position);
    assert_eq!(session.journal.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn finality_stop_bypasses_exhausted_preparation_ceiling() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-exhausted-source");
    let vote_directory = TestDirectory::new("finality-stop-exhausted-vote");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&vote_directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let _ = vote_journal.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        vote_journal.prepare_vote(fixture.round_one_nil_prevote_intent()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded { maximum: 1 })
    ));
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let exhausted_image = fs::read(&vote_path).unwrap();

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    assert_ne!(fs::read(&vote_path).unwrap(), exhausted_image);
    assert_eq!(vote_journal.state_id().unwrap(), stopped.vote_state_id());
    assert!(matches!(
        vote_journal.prepare_vote(fixture.round_one_nil_prevote_intent()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
}

#[test]
fn existing_same_slot_halt_cannot_be_replaced_by_finality_stop() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("finality-stop-existing-halt-source");
    let vote_directory = TestDirectory::new("finality-stop-existing-halt-vote");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&vote_directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let _ = vote_journal.sign_prepared_vote(prepared).unwrap();
    let vote_halt = match vote_journal
        .prepare_vote(fixture.proposal_prevote_intent())
        .unwrap()
    {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected vote-safety halt, got {other:?}"),
    };
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let halted_image = fs::read(&vote_path).unwrap();

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(finality_halt.state_id())
        .unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
            position,
            role,
        }) if position == vote_halt.position() && role == vote_halt.role()
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_halt.state_id());
    assert_eq!(vote_journal.halt().unwrap(), Some(vote_halt));
    assert_eq!(vote_journal.finality_conflict_stop().unwrap(), None);
    assert_eq!(fs::read(vote_path).unwrap(), halted_image);
}

#[test]
fn finality_stop_codec_has_an_independent_golden_and_strict_adversarial_replay() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-codec-source");
    let vote_directory = TestDirectory::new("finality-stop-codec-vote");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let mut body = Vec::with_capacity(169);
    body.push(0x05);
    body.extend_from_slice(halt.state_id().as_bytes());
    body.extend_from_slice(&halt.height().value().to_be_bytes());
    body.extend_from_slice(halt.first_ancestry().as_bytes());
    body.extend_from_slice(halt.first_envelope_id().as_bytes());
    body.extend_from_slice(halt.second_ancestry().as_bytes());
    body.extend_from_slice(halt.second_envelope_id().as_bytes());
    assert_eq!(body.len(), 169);
    let length = 169_u32.to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);
    assert_eq!(
        expected_state,
        FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([
            0xf1, 0x8b, 0xbd, 0x44, 0xc6, 0x81, 0x4c, 0xfa, 0x2e, 0xb8, 0xff, 0x4e, 0x53, 0xab,
            0x52, 0x09, 0xc0, 0xae, 0xa7, 0xc1, 0x2f, 0x9c, 0x81, 0xb2, 0x14, 0x4a, 0x77, 0x2e,
            0x7f, 0x24, 0xe3, 0x8f,
        ])
    );
    let mut expected_image = prefix.clone();
    expected_image.extend_from_slice(&length);
    expected_image.extend_from_slice(&body);
    expected_image.extend_from_slice(expected_state.as_bytes());
    assert_eq!(expected_image.len() - prefix.len(), 205);

    let mut vote_journal = fixture.create(&vote_directory);
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    assert_eq!(stopped.vote_state_id(), expected_state);
    assert_eq!(fs::read(vote_path).unwrap(), expected_image);

    let mut wrong_width = prefix.clone();
    let mut wrong_width_body = vec![0_u8; 41];
    wrong_width_body[0] = 0x05;
    let wrong_width_state = append_test_record(&mut wrong_width, genesis, &wrong_width_body);
    let io = ScriptedIo::from_images(wrong_width.clone(), wrong_width);
    assert!(matches!(
        fixture.replay_scripted(io, wrong_width_state),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStopLength {
                entry: 0,
                actual: 40,
            }
        )
    ));

    let mut zero_height = prefix.clone();
    let mut zero_height_body = body.clone();
    zero_height_body[33..41].fill(0);
    let zero_height_state = append_test_record(&mut zero_height, genesis, &zero_height_body);
    let io = ScriptedIo::from_images(zero_height.clone(), zero_height);
    assert!(matches!(
        fixture.replay_scripted(io, zero_height_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStop { entry: 0 })
    ));

    let mut mutated_footer = expected_image.clone();
    *mutated_footer.last_mut().unwrap() ^= 0x01;
    let io = ScriptedIo::from_images(mutated_footer.clone(), mutated_footer);
    assert!(matches!(
        fixture.replay_scripted(io, expected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));

    let mut post_stop = expected_image;
    let post_stop_state = append_test_record(&mut post_stop, expected_state, &body);
    let io = ScriptedIo::from_images(post_stop.clone(), post_stop);
    assert!(matches!(
        fixture.replay_scripted(io, post_stop_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[cfg(unix)]
#[test]
fn preselection_pair_stop_uses_tag_0b_and_replays_as_a_distinct_idempotent_kind() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("preselection-stop-finality");
    let finality_anchor_directory = TestDirectory::new("preselection-stop-finality-anchor");
    let selected_finality_directory = TestDirectory::new("preselection-stop-selected-finality");
    let vote_directory = TestDirectory::new("preselection-stop-vote");
    let vote_anchor_directory = TestDirectory::new("preselection-stop-vote-anchor");
    let selected_vote_directory = TestDirectory::new("preselection-stop-selected-vote");
    let selected_vote_anchor_directory =
        TestDirectory::new("preselection-stop-selected-vote-anchor");
    let mut finality =
        fixture.create_anchored_finality(&finality_directory, &finality_anchor_directory);
    let first = fixture.owned_transition_for_round(ZfcAxiom::Pairing, 2);
    let second = fixture.owned_transition_for_round(ZfcAxiom::Union, 2);
    let halt = finality
        .commit_verified_preselection_conflict(second, first)
        .unwrap();
    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    let mut selected_finality = fixture.create_finality(&selected_finality_directory);
    let _ = selected_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let selected_halt = match selected_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::PowerSet))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected selected-sibling finality halt, got {other:?}"),
    };

    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let pair_shape = FixedValidatorFinalityConflictSignerStopV0 {
        kind: FixedValidatorFinalityHaltKindV0::PreselectionPair,
        finality_state_id: halt.state_id(),
        height: halt.height(),
        first_ancestry: halt.first_ancestry(),
        first_envelope_id: halt.first_envelope_id(),
        second_ancestry: halt.second_ancestry(),
        second_envelope_id: halt.second_envelope_id(),
        vote_state_id: genesis,
    };
    let selected_shape = FixedValidatorFinalityConflictSignerStopV0 {
        kind: FixedValidatorFinalityHaltKindV0::SelectedSibling,
        ..pair_shape
    };
    assert!(!pair_shape.same_conflict(selected_shape));
    let body = finality_conflict_stop_record(pair_shape, 0).unwrap();
    let selected_body = finality_conflict_stop_record(selected_shape, 0).unwrap();
    assert_eq!(body.len(), 169);
    assert_eq!(body[0], PRESELECTION_CONFLICT_STOP_RECORD);
    assert_eq!(selected_body[0], FINALITY_CONFLICT_STOP_RECORD);
    assert_eq!(&body[1..], &selected_body[1..]);
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);
    let selected_state = step_state_id(genesis, length, &selected_body);
    assert_ne!(selected_state, expected_state);
    let mut expected_image = prefix.clone();
    expected_image.extend_from_slice(&length);
    expected_image.extend_from_slice(&body);
    expected_image.extend_from_slice(expected_state.as_bytes());
    assert_eq!(expected_image.len() - prefix.len(), 205);

    let mut pair_retagged_as_selected = expected_image.clone();
    pair_retagged_as_selected[prefix.len() + 4] = FINALITY_CONFLICT_STOP_RECORD;
    let io = ScriptedIo::from_images(pair_retagged_as_selected.clone(), pair_retagged_as_selected);
    assert!(matches!(
        fixture.replay_scripted(io, expected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));
    let mut selected_image = prefix.clone();
    selected_image.extend_from_slice(&length);
    selected_image.extend_from_slice(&selected_body);
    selected_image.extend_from_slice(selected_state.as_bytes());
    selected_image[prefix.len() + 4] = PRESELECTION_CONFLICT_STOP_RECORD;
    let io = ScriptedIo::from_images(selected_image.clone(), selected_image);
    assert!(matches!(
        fixture.replay_scripted(io, selected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));

    let mut vote_journal = fixture.create_anchored(&vote_directory, &vote_anchor_directory);
    let conflict = finality.acknowledge_signer_stop().unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new preselection signer stop, got {other:?}"),
    };
    assert_eq!(
        stopped.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(stopped.finality_state_id(), halt.state_id());
    assert_eq!(stopped.height(), halt.height());
    assert_eq!(stopped.first_ancestry(), halt.first_ancestry());
    assert_eq!(stopped.first_envelope_id(), halt.first_envelope_id());
    assert_eq!(stopped.second_ancestry(), halt.second_ancestry());
    assert_eq!(stopped.second_envelope_id(), halt.second_envelope_id());
    assert_eq!(stopped.vote_state_id(), expected_state);
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    assert_eq!(fs::read(&vote_path).unwrap(), expected_image);
    let vote_anchor_path = vote_anchor_directory.vote_anchor(fixture.signer());
    let stopped_anchor = fs::read(&vote_anchor_path).unwrap();
    assert_eq!(&stopped_anchor[184..192], &1_u64.to_be_bytes());
    assert_eq!(&stopped_anchor[192..224], expected_state.as_bytes());

    let selected_conflict = selected_finality
        .acknowledge_signer_stop_is_externally_durable(selected_halt.state_id())
        .unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(selected_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == halt.height() && incoming_height == selected_halt.height()
    ));
    assert_eq!(vote_journal.state_id().unwrap(), expected_state);
    assert_eq!(fs::read(&vote_path).unwrap(), expected_image);
    assert_eq!(fs::read(&vote_anchor_path).unwrap(), stopped_anchor);

    let before_repeat = fs::read(&vote_path).unwrap();
    let repeat = finality.acknowledge_signer_stop().unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(repeat).unwrap(),
        FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing)
            if existing == stopped
    ));
    assert_eq!(fs::read(&vote_path).unwrap(), before_repeat);
    assert_eq!(fs::read(&vote_anchor_path).unwrap(), stopped_anchor);
    drop(vote_journal);

    let mut selected_vote =
        fixture.create_anchored(&selected_vote_directory, &selected_vote_anchor_directory);
    let selected_conflict = selected_finality
        .acknowledge_signer_stop_is_externally_durable(selected_halt.state_id())
        .unwrap();
    let selected_stop = match selected_vote
        .stop_after_durable_finality_conflict(selected_conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected selected-sibling signer stop, got {other:?}"),
    };
    let (_, selected_vote_path) =
        keyed_paths(&selected_vote_directory.0, fixture.signer()).unwrap();
    let selected_vote_image = fs::read(&selected_vote_path).unwrap();
    let selected_vote_anchor_path = selected_vote_anchor_directory.vote_anchor(fixture.signer());
    let selected_vote_anchor_image = fs::read(&selected_vote_anchor_path).unwrap();
    let pair_conflict = finality.acknowledge_signer_stop().unwrap();
    assert!(matches!(
        selected_vote.stop_after_durable_finality_conflict(pair_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == selected_halt.height() && incoming_height == halt.height()
    ));
    assert_eq!(
        selected_vote.state_id().unwrap(),
        selected_stop.vote_state_id()
    );
    assert_eq!(fs::read(selected_vote_path).unwrap(), selected_vote_image);
    assert_eq!(
        fs::read(selected_vote_anchor_path).unwrap(),
        selected_vote_anchor_image
    );
    drop(selected_vote);

    let reopened = fixture
        .open_anchored(&vote_directory, &vote_anchor_directory)
        .unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(fs::read(vote_path).unwrap(), expected_image);
}

#[test]
fn recovered_signer_session_replays_latest_completed_round_with_bounded_work() {
    let fixture = Fixture::new(8);
    let directory = TestDirectory::new("completed-round-recovery");
    let parent = fixture.branch();
    let parent_round = parent.begin_round_zero().unwrap();

    let mut finality = fixture.create_finality(&directory);
    let first_transition = fixture.owned_transition();
    let first_artifact_block = first_transition.value().artifact_block();
    let _ = finality.commit_verified(first_transition).unwrap();
    let finality_state = finality.state_id().unwrap();
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
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, child_lineage_state)
        .unwrap();
    let child_coordinate = child.coordinate();
    let child_round_zero = child.begin_round_zero().unwrap();
    let child_round_one = child.begin_round_zero().unwrap().advance_round().unwrap();

    let mut child_artifact_state = ArtifactChainState::new(fixture.definition);
    child_artifact_state
        .apply_block(&first_artifact_block, proof_payload())
        .unwrap();
    let second_payload = proof_payload_for(ZfcAxiom::Union);
    let second_artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(second_payload.clone())
        .unwrap()
        .artifact_id();
    let second_artifact_block = child_artifact_state
        .prepare_block(second_artifact_id)
        .unwrap();
    let proposal_value = child_round_zero.value_for_artifact_block(second_artifact_block);
    let proposal_root = proposal_value.proposal_signing_root();
    let mut proposal_bytes = proposal_value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        child_round_zero.position(),
        proposal_root,
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = child_round_zero
        .decode_and_verify_proposal_control(&proposal_bytes, second_payload)
        .unwrap();

    let effect = session.decide_prevote_for_proposal(&proposal).unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_zero, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let prevote_quorum = certificate_bytes(
        fixture.context,
        child_round_zero.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(proposal_root),
        &fixture.signing_key(),
    );
    let effect = session
        .decide_precommit_for_proposal_quorum(&child_round_zero, &proposal, &prevote_quorum)
        .unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_zero, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    session.advance_round(&child_round_one).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_one, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let vote_state = session
        .sign_prepared_vote(acknowledgement)
        .unwrap()
        .state_id();
    let expected_locked = session.locked_value();
    let expected_valid = session.valid_value().cloned();
    assert!(expected_locked.is_some());
    assert!(expected_valid.is_some());

    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(session);
    drop(vote_journal);
    drop(child_round_one);
    drop(child_round_zero);
    drop(child);
    drop(parent_round);
    drop(parent);
    drop(finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mut vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    assert!(matches!(
        vote_journal.issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                required: 1,
                maximum: 0,
            }
        )
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = vote_journal
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(1),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), child_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(1))
    );
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Prevote
    );
    assert_eq!(recovered.session().locked_value(), expected_locked);
    assert_eq!(recovered.session().valid_value(), expected_valid.as_ref());
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn signer_recovery_rejects_mismatched_history_and_foreign_handle_provenance() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("recovery-provenance");
    let missing_directory = TestDirectory::new("recovery-missing");
    let mismatch_directory = TestDirectory::new("recovery-mismatch");
    let equivalent_directory = TestDirectory::new("recovery-equivalent");
    let parent = fixture.branch();
    let parent_round = parent.begin_round_zero().unwrap();

    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let finality_coordinate = finality.head().unwrap().coordinate();
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
    let vote_state = prepared_height.state_id();
    drop(prepared_height);
    drop(session);
    drop(vote_journal);
    drop(parent_round);
    drop(parent);
    drop(finality);

    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let finality_image = fs::read(&finality_path).unwrap();
    let mut equivalent_finality = fixture.create_finality(&equivalent_directory);
    let _ = equivalent_finality
        .commit_verified(fixture.owned_transition_for_round(ZfcAxiom::Pairing, 1))
        .unwrap();
    let equivalent_state = equivalent_finality.state_id().unwrap();
    assert_ne!(equivalent_state, finality_state);
    assert_eq!(
        equivalent_finality.head().unwrap().coordinate(),
        finality_coordinate
    );
    let equivalent_path = equivalent_directory.0.join(crate::JOURNAL_FILE_NAME);
    let equivalent_image = fs::read(&equivalent_path).unwrap();
    assert_ne!(equivalent_image, finality_image);
    drop(equivalent_finality);
    let equivalent_finality = fixture.open_finality(&equivalent_directory, equivalent_state);

    let missing_finality = fixture.create_finality(&missing_directory);
    let missing_state = missing_finality.state_id().unwrap();
    let missing_path = missing_directory.0.join(crate::JOURNAL_FILE_NAME);
    let missing_image = fs::read(&missing_path).unwrap();

    let mut mismatched_finality = fixture.create_finality(&mismatch_directory);
    let _ = mismatched_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap();
    let mismatched_state = mismatched_finality.state_id().unwrap();
    let mismatched_image = fs::read(mismatch_directory.0.join(crate::JOURNAL_FILE_NAME)).unwrap();

    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    let vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        missing_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable {
            height,
        }) if height == ConsensusHeight::new(2)
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(missing_finality.state_id().unwrap(), missing_state);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(&missing_path).unwrap(), missing_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        mismatched_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch {
            height,
        }) if height == ConsensusHeight::new(2)
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(mismatched_finality.state_id().unwrap(), mismatched_state);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(
        fs::read(mismatch_directory.0.join(crate::JOURNAL_FILE_NAME)).unwrap(),
        mismatched_image
    );

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = equivalent_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    drop(vote_journal);
    let mut reopened = fixture.open(&directory, vote_state).unwrap();
    assert!(matches!(
        reopened.issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignSignerRecovery)
    ));
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(&equivalent_path).unwrap(), equivalent_image);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);

    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = equivalent_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(
        recovered.session().position().height(),
        ConsensusHeight::new(2)
    );
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(equivalent_path).unwrap(), equivalent_image);
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
}

#[test]
fn signer_recovery_capability_requires_a_live_exact_anchored_lineage() {
    let fixture = Fixture::new(2);
    let unbound_directory = TestDirectory::new("recovery-unbound");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut unbound = fixture.create(&unbound_directory);
    let (_, unbound_path) = keyed_paths(&unbound_directory.0, fixture.signer()).unwrap();
    let activated = activate_proposal_authoring(&mut unbound);
    let activated_image = fs::read(&unbound_path).unwrap();
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xee; 32]),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch { .. })
    ));
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(activated),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    assert_eq!(unbound.state_id().unwrap(), activated);
    assert_eq!(fs::read(&unbound_path).unwrap(), activated_image);
    let bound = unbound.bind_signing_lineage(&round).unwrap();
    let session = unbound.issue_signing_session(&round, bound).unwrap();
    drop(session);
    let bound_image = fs::read(&unbound_path).unwrap();
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));
    assert_eq!(unbound.state_id().unwrap(), bound);
    assert_eq!(fs::read(&unbound_path).unwrap(), bound_image);

    let pending_directory = TestDirectory::new("recovery-pending");
    let mut pending = fixture.create(&pending_directory);
    let mut session = issue_session(&mut pending, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let pending_vote = prepared(session.prepare_vote(&round, effect).unwrap());
    let prepared_state = pending_vote.state_id();
    drop(session);
    drop(pending);
    let pending = fixture.open(&pending_directory, prepared_state).unwrap();
    let (_, pending_path) = keyed_paths(&pending_directory.0, fixture.signer()).unwrap();
    let pending_image = fs::read(&pending_path).unwrap();
    assert!(matches!(
        pending.acknowledge_signer_recovery_is_externally_durable(prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
    assert_eq!(pending.state_id().unwrap(), prepared_state);
    assert_eq!(fs::read(&pending_path).unwrap(), pending_image);

    let halted_directory = TestDirectory::new("recovery-vote-halt");
    let mut halted = fixture.create(&halted_directory);
    let _ = halted.bind_signing_lineage(&round).unwrap();
    let prepared = prepared(halted.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let _ = halted.sign_prepared_vote(prepared).unwrap();
    let halt = match halted
        .prepare_vote(fixture.proposal_prevote_intent())
        .unwrap()
    {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal halt, got {other:?}"),
    };
    let (_, halted_path) = keyed_paths(&halted_directory.0, fixture.signer()).unwrap();
    let halted_image = fs::read(&halted_path).unwrap();
    assert!(matches!(
        halted.acknowledge_signer_recovery_is_externally_durable(halt.state_id()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
    assert_eq!(halted.state_id().unwrap(), halt.state_id());
    assert_eq!(halted.halt().unwrap(), Some(halt));
    assert_eq!(fs::read(halted_path).unwrap(), halted_image);
}

#[test]
fn initial_lineage_recovery_reproduces_exact_configured_virtual_genesis() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("recovery-initial-lineage");
    let mismatch_directory = TestDirectory::new("recovery-initial-mismatch");
    let finality = fixture.create_finality(&directory);
    let finality_state = finality.state_id().unwrap();
    let mismatched_context = ConsensusContextV0::new(
        fixture.context.chain_id(),
        ConsensusGenesisId::from_bytes([0x43; 32]),
        fixture.context.protocol_version(),
    );
    let mismatched_finality = FixedValidatorFinalityJournalV0::create(
        &mismatch_directory.0,
        fixture.definition,
        mismatched_context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
    )
    .unwrap();
    let mismatched_state = mismatched_finality.state_id().unwrap();
    let branch = fixture.branch();
    let expected_coordinate = branch.coordinate();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut vote_journal);
    let vote_state = vote_journal.bind_signing_lineage(&round).unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let mismatched_path = mismatch_directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let mismatched_image = fs::read(&mismatched_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(round);
    drop(branch);
    drop(finality);
    drop(mismatched_finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mismatched_finality = FixedValidatorFinalityJournalV0::open_verified(
        &mismatch_directory.0,
        fixture.definition,
        mismatched_context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        mismatched_state,
    )
    .unwrap();
    let mut vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        mismatched_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch {
            height,
        }) if height == ConsensusHeight::new(1)
    ));
    assert_eq!(mismatched_finality.state_id().unwrap(), mismatched_state);
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = vote_journal
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), expected_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(0))
    );
    assert_eq!(finality.state_id().unwrap(), finality_state);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
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
    let phase = session.phase();
    let locked = session.locked_value();
    let valid = session.valid_value().cloned();
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
    let nil_precommit_quorum = certificate_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    assert!(matches!(
        session.advance_round_for_nil_precommit_quorum(&round, &nil_precommit_quorum),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    let higher_round_quorum = certificate_bytes(
        fixture.context,
        round_one.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round,
            &higher_round_quorum,
            round_one.position().round(),
        ),
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
    assert_eq!(session.phase(), phase);
    assert_eq!(session.locked_value(), locked);
    assert_eq!(session.valid_value(), valid.as_ref());
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
fn replay_rejects_proposal_conflict_while_vote_preparation_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("proposal-conflict-during-pending-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round, lineage).unwrap();

    let (retained_block, retained_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let retained = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: retained_block,
                    canonical_artifact_bytes: retained_payload,
                },
            )
            .unwrap(),
    );
    let retained = session
        .acknowledge_prepared_proposal_is_externally_durable(retained, retained.state_id())
        .unwrap();
    let _ = session.sign_prepared_proposal(retained).unwrap();

    let vote_effect = session.decide_prevote_without_proposal().unwrap();
    let pending_vote = prepared(session.prepare_vote(&round, vote_effect).unwrap());
    let pending_state = pending_vote.state_id();
    let entry = session.journal.core.record_sequence;

    let (conflicting_block, conflicting_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let conflicting_state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let conflicting = conflicting_state
        .prepare_proposal_intent(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: conflicting_block,
                canonical_artifact_bytes: conflicting_payload,
            },
            fixture.signer(),
        )
        .unwrap();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_proposal(conflicting.clone()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Prevote,
        }) if position == round.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        PROPOSAL_CONFLICT_HALT_RECORD,
        conflicting.canonical_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_vote_conflict_while_proposal_preparation_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("vote-conflict-during-pending-proposal");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, lineage).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();
    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let precommit = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(precommit).unwrap();
    session.advance_round(&round_one).unwrap();

    let (proposal_block, proposal_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let pending_proposal = prepared_proposal(
        session
            .prepare_proposal(
                &round_one,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: proposal_block,
                    canonical_artifact_bytes: proposal_payload,
                },
            )
            .unwrap(),
    );
    let pending_state = pending_proposal.state_id();
    let entry = session.journal.core.record_sequence;
    let conflicting_vote = fixture.proposal_prevote_intent();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_vote(conflicting_vote.clone()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                position,
            }
        ) if position == round_one.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        CONFLICT_HALT_RECORD,
        conflicting_vote.canonical_state_and_vote_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_proposal_conflict_for_older_slot_while_later_proposal_is_pending() {
    let fixture = Fixture::new(6);
    let directory = TestDirectory::new("older-proposal-conflict-during-later-proposal");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, lineage).unwrap();

    let (retained_block, retained_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let retained = prepared_proposal(
        session
            .prepare_proposal(
                &round_zero,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: retained_block,
                    canonical_artifact_bytes: retained_payload,
                },
            )
            .unwrap(),
    );
    let retained = session
        .acknowledge_prepared_proposal_is_externally_durable(retained, retained.state_id())
        .unwrap();
    let _ = session.sign_prepared_proposal(retained).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();
    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let precommit = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(precommit).unwrap();
    session.advance_round(&round_one).unwrap();

    let (later_block, later_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let pending = prepared_proposal(
        session
            .prepare_proposal(
                &round_one,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: later_block,
                    canonical_artifact_bytes: later_payload.clone(),
                },
            )
            .unwrap(),
    );
    let pending_state = pending.state_id();
    let entry = session.journal.core.record_sequence;

    let conflicting_state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let conflicting = conflicting_state
        .prepare_proposal_intent(
            &round_zero,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: later_block,
                canonical_artifact_bytes: later_payload,
            },
            fixture.signer(),
        )
        .unwrap();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_proposal(conflicting.clone()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                position,
            }
        ) if position == round_one.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        PROPOSAL_CONFLICT_HALT_RECORD,
        conflicting.canonical_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_vote_conflict_for_older_slot_while_later_vote_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("older-vote-conflict-during-later-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round, lineage).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();

    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let pending = prepared(session.prepare_vote(&round, precommit_effect).unwrap());
    let pending_state = pending.state_id();
    let entry = session.journal.core.record_sequence;
    let conflicting_vote = fixture.proposal_prevote_intent();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_vote(conflicting_vote.clone()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        CONFLICT_HALT_RECORD,
        conflicting_vote.canonical_state_and_vote_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt {
            entry: actual,
        }) if actual == entry
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
    let _ = activate_proposal_authoring(&mut journal);
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
fn every_higher_round_checkpoint_append_fault_poisons_and_reopens_only_exact_prefix() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round_zero.parent_coordinate(),
        round_zero.position().height(),
        fixture.signer(),
    );
    let lineage_body =
        signing_lineage_record(round_zero.position().height(), lineage_id, 0).unwrap();
    let lineage_state = step_state_id(
        genesis,
        u32::try_from(lineage_body.len()).unwrap().to_be_bytes(),
        &lineage_body,
    );
    let mut lineage_image = prefix;
    let _ = append_test_record(&mut lineage_image, genesis, &lineage_body);
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let transition = state
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint = transition.canonical_checkpoint_bytes().to_vec();
    let body = tagged_record(HIGHER_ROUND_CHECKPOINT_RECORD, &checkpoint, 0).unwrap();
    let checkpoint_state = step_state_id(
        lineage_state,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = lineage_image.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::from_images(lineage_image.clone(), lineage_image.clone());
        let mut core = fixture.replay_scripted(io, lineage_state).unwrap();
        core.file.inject_fault(fault.clone());
        assert!(
            matches!(
                core.append_higher_round_checkpoint(&checkpoint),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(
            core.latest_current_lineage_state.is_none(),
            "fault {fault:?}"
        );
        assert_eq!(core.state_id, lineage_state, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));

        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor, lineage_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == lineage_state && actual == checkpoint_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, checkpoint_state).unwrap();
            assert!(matches!(
                reopened.latest_current_lineage_state,
                Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
                    if state_id == checkpoint_state
            ));
        } else {
            let old_anchor = ScriptedIo::from_images(durable.clone(), durable.clone());
            let reopened = fixture.replay_scripted(old_anchor, lineage_state).unwrap();
            assert!(
                reopened.latest_current_lineage_state.is_none(),
                "fault {fault:?}"
            );
            assert_eq!(reopened.file.volatile.get_ref(), &lineage_image);
            let proposed = ScriptedIo::from_images(durable.clone(), durable);
            assert!(
                matches!(
                    fixture.replay_scripted(proposed, checkpoint_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == checkpoint_state && actual == lineage_state
                ),
                "fault {fault:?}"
            );
        }
    }
}

fn assert_every_finality_stop_append_fault(
    fixture: &Fixture,
    finality: &FixedValidatorFinalityJournalV0,
    halt: FixedValidatorFinalityHaltV0,
    expected_tag: u8,
) {
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let proposed = FixedValidatorFinalityConflictSignerStopV0 {
        kind: halt.kind(),
        finality_state_id: halt.state_id(),
        height: halt.height(),
        first_ancestry: halt.first_ancestry(),
        first_envelope_id: halt.first_envelope_id(),
        second_ancestry: halt.second_ancestry(),
        second_envelope_id: halt.second_envelope_id(),
        vote_state_id: genesis,
    };
    let body = finality_conflict_stop_record(proposed, 0).unwrap();
    assert_eq!(body[0], expected_tag);
    let stopped_state = step_state_id(
        genesis,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = prefix.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        let conflict = finality
            .acknowledge_signer_stop_is_externally_durable(halt.state_id())
            .unwrap();
        assert!(
            matches!(
                core.stop_after_durable_finality_conflict(conflict),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(core.finality_conflict_stop.is_none(), "fault {fault:?}");
        assert_eq!(core.state_id, genesis, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));

        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let stale = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(stale, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == genesis && actual == stopped_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, stopped_state).unwrap();
            let stop = reopened
                .finality_conflict_stop
                .expect("the exact durable stop replays");
            assert_eq!(stop.finality_state_id(), halt.state_id());
            assert_eq!(stop.vote_state_id(), stopped_state);
        } else {
            let partial = ScriptedIo::from_images(durable.clone(), durable.clone());
            let reopened = fixture.replay_scripted(partial, genesis).unwrap();
            assert!(reopened.finality_conflict_stop.is_none(), "fault {fault:?}");
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
            let proposed = ScriptedIo::from_images(durable.clone(), durable);
            assert!(
                matches!(
                    fixture.replay_scripted(proposed, stopped_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == stopped_state && actual == genesis
                ),
                "fault {fault:?}"
            );
        }
    }
}

#[test]
fn every_finality_stop_append_fault_poisons_and_reopens_only_from_exact_anchor() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-fault-source");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };
    assert_every_finality_stop_append_fault(
        &fixture,
        &finality,
        halt,
        FINALITY_CONFLICT_STOP_RECORD,
    );
}

#[cfg(unix)]
#[test]
fn every_preselection_stop_append_fault_replays_only_the_exact_tag_0b_state() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("preselection-stop-fault-source");
    let finality_anchor_directory = TestDirectory::new("preselection-stop-fault-anchor");
    let mut anchored_finality =
        fixture.create_anchored_finality(&finality_directory, &finality_anchor_directory);
    let halt = anchored_finality
        .commit_verified_preselection_conflict(
            fixture.owned_transition_for_round(ZfcAxiom::Union, 2),
            fixture.owned_transition_for_round(ZfcAxiom::Pairing, 2),
        )
        .unwrap();
    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    drop(anchored_finality);
    let finality = fixture.open_finality(&finality_directory, halt.state_id());
    assert_every_finality_stop_append_fault(
        &fixture,
        &finality,
        halt,
        PRESELECTION_CONFLICT_STOP_RECORD,
    );
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
