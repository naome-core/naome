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
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])
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
        let payload = proof_payload();
        let artifact_state = ArtifactChainState::new(self.definition);
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = artifact_state.prepare_block(artifact_id).unwrap();
        let branch = self.branch();
        let round = branch.begin_round_zero().unwrap();
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
    let session = dropped_journal.issue_signing_session(&round).unwrap();
    assert_eq!(session.position(), round.position());
    drop(session);
    assert!(matches!(
        dropped_journal.issue_signing_session(&round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let forgotten_directory = TestDirectory::new("session-forget");
    let mut forgotten_journal = fixture.create(&forgotten_directory);
    let session = forgotten_journal.issue_signing_session(&round).unwrap();
    std::mem::forget(session);
    assert!(matches!(
        forgotten_journal.issue_signing_session(&round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));
}

#[test]
fn session_requires_exact_external_prepare_acknowledgement_before_signing() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-anchor-ack");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
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
    let mut first_session = first_journal.issue_signing_session(&round).unwrap();
    let mut second_session = second_journal.issue_signing_session(&round).unwrap();

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
    let mut session = journal.issue_signing_session(&round).unwrap();
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
    let mut session = journal.issue_signing_session(&round_zero).unwrap();

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
fn session_advances_only_its_owned_lineage_to_a_verified_child_height() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-child-height");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let transition = fixture.owned_transition();
    let expected_ancestry = transition.value().ancestry_id();
    let mut journal = fixture.create(&directory);
    let mut session = journal.issue_signing_session(&round).unwrap();

    let child = session
        .advance_height_with_verified_transition(transition)
        .unwrap();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(session.position().height(), ConsensusHeight::new(2));
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
}

#[test]
fn completed_replay_issues_one_exact_session_but_pending_replay_issues_none() {
    let fixture = Fixture::new(3);
    let completed_directory = TestDirectory::new("session-completed-replay");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&completed_directory);
    let completed_state = {
        let mut session = journal.issue_signing_session(&round).unwrap();
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
    let resumed = reopened.issue_signing_session(&round).unwrap();
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    drop(resumed);
    assert!(matches!(
        reopened.issue_signing_session(&round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let pending_directory = TestDirectory::new("session-pending-replay");
    let mut pending_journal = fixture.create(&pending_directory);
    let pending_state = {
        let mut session = pending_journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        prepared(session.prepare_vote(&round, effect).unwrap()).state_id()
    };
    drop(pending_journal);
    let mut pending_reopen = fixture.open(&pending_directory, pending_state).unwrap();
    assert!(matches!(
        pending_reopen.issue_signing_session(&round),
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
        reopened.issue_signing_session(&round),
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
