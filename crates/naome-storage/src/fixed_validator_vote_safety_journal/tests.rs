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

mod codec_replay;
mod conflict_stop;
mod faults;
mod height_handoff;
mod proposal_authoring;
mod recovery;
mod round_progression;
mod signing_session;
