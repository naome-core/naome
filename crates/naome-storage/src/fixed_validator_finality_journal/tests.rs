use std::env;
use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag,
};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, CONSENSUS_KEY_BYTES, ConsensusContextV0,
    ConsensusGenesisId, ConsensusKey, ConsensusProtocolVersion, ConsensusRound, ConsensusValueV0,
    OwnedVerifiedFixedConsensusTransitionV0, ProposalSigningRoot, VerifiedProducerAuthorizationV0,
};
use naome_foundation::{FOUNDATION_ID, FreeVariable, ZfcAxiom};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
use crate::fault_io::{Fault, ScriptedIo, all_append_faults};
use crate::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactChainJournal,
    ArtifactPayloadStoreLimits, CandidateBranchReconstructionError,
    CandidateBranchReconstructionLimits, CanonicalArtifactPayloadStore,
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
                "naome-fixed-finality-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("temporary directory failed: {error}"),
            }
        }
    }

    fn journal(&self) -> PathBuf {
        self.0.join(JOURNAL_FILE_NAME)
    }

    fn finality_anchor(&self) -> PathBuf {
        self.0.join("fixed-validator-finality.anchor")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn signing_key(index: u16) -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    seed[2] = 0xa5;
    SigningKey::from_bytes(&seed)
}

fn consensus_key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}

fn proof_payload(axiom: ZfcAxiom) -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn artifact_id(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn dependency_payloads(root_axiom: ZfcAxiom) -> ([Vec<u8>; 2], [ArtifactId; 2]) {
    let mut dag = ArtifactDag::new();
    let root = proof_payload(root_axiom);
    let root_record = dag.apply_canonical_artifact_bytes(root.clone()).unwrap();
    let root_id = root_record.artifact_id();
    let root_proof_id = root_record.as_proof().unwrap().proof_id();
    let child = ProofCertificate::new(vec![
        ProofStep::ProofReference {
            proof_id: root_proof_id,
        },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(1),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form()
    .certificate()
    .clone();
    let child = ArtifactPayload::Proof(child).to_canonical_bytes();
    let child_id = dag
        .apply_canonical_artifact_bytes(child.clone())
        .unwrap()
        .artifact_id();
    ([root, child], [root_id, child_id])
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
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

fn certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = 2;
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    body[85] = 1;
    body[86..].copy_from_slice(root.as_bytes());
    let key = consensus_key(signer);
    let mut transcript = b"naome:consensus-precommit-signing:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn envelope_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let root = value.proposal_signing_root();
    let authorization = authorization_bytes(value.context(), position, root, proposer);
    let certificate = certificate_bytes(value.context(), position, root, proposer);
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization);
    bytes.extend_from_slice(&certificate);
    bytes
}

struct Fixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    proposer: SigningKey,
    entries: [ActiveAgreementEntry; 1],
    limit: FixedValidatorFinalityReplayLimitV0,
}

impl Fixture {
    fn new() -> Self {
        let definition = ArtifactChainDefinition::new([0x31; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x42; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let proposer = signing_key(1);
        let entries = [ActiveAgreementEntry::new(
            consensus_key(&proposer),
            AgreementWeight::new(1),
        )];
        Self {
            definition,
            context,
            proposer,
            entries,
            limit: FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        }
    }

    fn create(&self, directory: &TestDirectory) -> FixedValidatorFinalityJournalV0 {
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
        )
        .unwrap()
    }

    fn open(
        &self,
        directory: &TestDirectory,
        expected: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorFinalityJournalV0, FixedValidatorFinalityJournalErrorV0> {
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
            expected,
        )
    }

    #[cfg(unix)]
    fn create_anchored(
        &self,
        journal_directory: &TestDirectory,
        anchor_directory: &TestDirectory,
    ) -> FixedValidatorAnchoredFinalityJournalV0 {
        FixedValidatorAnchoredFinalityJournalV0::create(
            &journal_directory.0,
            &anchor_directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn open_anchored(
        &self,
        journal_directory: &TestDirectory,
        anchor_directory: &TestDirectory,
    ) -> Result<FixedValidatorAnchoredFinalityJournalV0, FixedValidatorAnchoredFinalityJournalErrorV0>
    {
        FixedValidatorAnchoredFinalityJournalV0::open(
            &journal_directory.0,
            &anchor_directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
        )
    }

    fn transition(
        &self,
        branch: &FixedConsensusBranchV0,
        selected: &mut ArtifactChainState,
        axiom: ZfcAxiom,
        round: u64,
    ) -> OwnedVerifiedFixedConsensusTransitionV0 {
        let payload = proof_payload(axiom);
        let block = selected.prepare_block(artifact_id(&payload)).unwrap();
        let mut cursor = branch.begin_round_zero().unwrap();
        for _ in 0..round {
            cursor = cursor.advance_round().unwrap();
        }
        let value = cursor.value_for_artifact_block(block);
        let bytes = envelope_bytes(value, cursor.position(), &self.proposer);
        cursor
            .decode_and_verify(&bytes, payload)
            .unwrap()
            .into_owned()
    }
}

fn create_candidate_store(
    directory: &TestDirectory,
    definition: ArtifactChainDefinition,
) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        &directory.0,
        definition,
        ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
    )
    .unwrap()
}

fn create_payload_store(directory: &TestDirectory) -> CanonicalArtifactPayloadStore {
    CanonicalArtifactPayloadStore::create(
        &directory.0,
        ArtifactPayloadStoreLimits::new(16, 1024 * 1024).unwrap(),
    )
    .unwrap()
}

fn retain_transition_inputs(
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    parent: &FixedConsensusBranchV0,
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
) {
    let block = transition.value().artifact_block();
    let _ = candidates.insert(&block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            parent.artifact_snapshot(),
            &block,
            transition.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
}

fn candidate_image(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.0.join("artifact-block-candidate-store.log")).unwrap()
}

fn payload_image(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.0.join("artifact-payload-store.log")).unwrap()
}

fn flip_byte(path: PathBuf, offset: u64) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0_u8; 1];
    io::Read::read_exact(&mut file, &mut byte).unwrap();
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn finalizes_two_heights_and_reopens_exact_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("two-heights");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let expected_head = second.value().ancestry_id();
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(reopened.head().unwrap().ancestry_id(), expected_head);
}

#[cfg(unix)]
#[test]
fn anchored_finality_advances_before_publication_and_reopens_exactly() {
    let fixture = Fixture::new();
    let journal_directory = TestDirectory::new("anchored-finality-journal");
    let anchor_directory = TestDirectory::new("anchored-finality-anchor");
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    assert_eq!(journal.journal.core.record_sequence, 0);
    let genesis_anchor = fs::read(anchor_directory.finality_anchor()).unwrap();
    assert_eq!(genesis_anchor.len(), 221);
    assert_eq!(&genesis_anchor[149..157], &0_u64.to_be_bytes());
    assert_eq!(
        &genesis_anchor[157..189],
        journal.state_id().unwrap().as_bytes()
    );

    let mut selected = ArtifactChainState::new(fixture.definition);
    let parent = journal.head().unwrap().clone();
    let first = fixture.transition(&parent, &mut selected, ZfcAxiom::Pairing, 0);
    let duplicate = fixture.transition(&parent, &mut selected, ZfcAxiom::Pairing, 0);
    let expected_head = first.value().artifact_block().id();
    let expected_state = match journal.commit_verified(first).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Finalized { state_id, .. } => state_id,
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { .. }
        | FixedValidatorFinalityCommitOutcomeV0::Halted(_) => {
            panic!("the first direct child must finalize")
        }
    };
    assert_eq!(journal.journal.core.record_sequence, 1);
    let committed_anchor = fs::read(anchor_directory.finality_anchor()).unwrap();
    assert_ne!(committed_anchor, genesis_anchor);
    assert_eq!(&committed_anchor[149..157], &1_u64.to_be_bytes());
    assert_eq!(&committed_anchor[157..189], expected_state.as_bytes());

    assert!(matches!(
        journal.commit_verified(duplicate).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { state_id, .. }
            if state_id == expected_state
    ));
    assert_eq!(journal.journal.core.record_sequence, 1);
    assert_eq!(
        fs::read(anchor_directory.finality_anchor()).unwrap(),
        committed_anchor
    );

    drop(journal);
    let reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 1);
    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(
        reopened.head().unwrap().artifact_snapshot().head_block_id(),
        expected_head
    );
}

#[cfg(unix)]
#[test]
fn anchored_finality_classifies_old_ahead_and_divergent_anchor_images() {
    let fixture = Fixture::new();

    let behind_journal = TestDirectory::new("anchor-behind-journal");
    let behind_anchor = TestDirectory::new("anchor-behind-anchor");
    let mut journal = fixture.create_anchored(&behind_journal, &behind_anchor);
    let genesis_anchor = fs::read(behind_anchor.finality_anchor()).unwrap();
    let genesis_journal = fs::read(behind_journal.journal()).unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    let current_anchor = fs::read(behind_anchor.finality_anchor()).unwrap();
    let current_journal = fs::read(behind_journal.journal()).unwrap();
    drop(journal);
    fs::write(behind_anchor.finality_anchor(), &genesis_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&behind_journal, &behind_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                anchored_sequence: 0,
                journal_sequence: 1,
            }
        ))
    ));
    assert_eq!(fs::read(behind_journal.journal()).unwrap(), current_journal);

    fs::write(behind_anchor.finality_anchor(), &current_anchor).unwrap();
    fs::write(behind_journal.journal(), &genesis_journal).unwrap();
    assert!(matches!(
        fixture.open_anchored(&behind_journal, &behind_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorAhead {
                anchored_sequence: 1,
                journal_sequence: 0,
            }
        ))
    ));

    let left_journal = TestDirectory::new("anchor-divergent-left-journal");
    let left_anchor = TestDirectory::new("anchor-divergent-left-anchor");
    let right_journal = TestDirectory::new("anchor-divergent-right-journal");
    let right_anchor = TestDirectory::new("anchor-divergent-right-anchor");
    let mut left = fixture.create_anchored(&left_journal, &left_anchor);
    let mut right = fixture.create_anchored(&right_journal, &right_anchor);
    let mut left_selected = ArtifactChainState::new(fixture.definition);
    let mut right_selected = ArtifactChainState::new(fixture.definition);
    let left_transition = fixture.transition(
        left.head().unwrap(),
        &mut left_selected,
        ZfcAxiom::Pairing,
        0,
    );
    let right_transition = fixture.transition(
        right.head().unwrap(),
        &mut right_selected,
        ZfcAxiom::Union,
        0,
    );
    let _ = left.commit_verified(left_transition).unwrap();
    let _ = right.commit_verified(right_transition).unwrap();
    let divergent_anchor = fs::read(right_anchor.finality_anchor()).unwrap();
    drop(left);
    drop(right);
    fs::write(left_anchor.finality_anchor(), divergent_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&left_journal, &left_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorStateMismatch { sequence: 1 }
        ))
    ));
}

#[test]
fn candidate_backed_finality_installs_one_exact_direct_child_without_mutating_sources() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-success-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-success-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-success-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();

    let second = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round(),
    );
    let block = second.value().artifact_block();
    let target = block.id();
    let envelope = second.canonical_envelope_bytes().to_vec();
    let artifact_bytes = second.canonical_artifact_bytes().to_vec();
    let expected_position = second.position();
    let expected_ancestry = second.value().ancestry_id();
    let expected_envelope_id = second.envelope_id();
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &second,
    );

    let old_state = journal.state_id().unwrap();
    let old_finality = fs::read(finality_directory.journal()).unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let body = canonical_record_body(FINALIZE_RECORD, &second, 1).unwrap();
    let body_length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(old_state, body_length, &body);

    let outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        target,
        &envelope,
        ConsensusRound::new(fixture.limit.max_round()),
    )
    .unwrap();

    assert_eq!(outcome.target(), target);
    assert_eq!(outcome.position(), expected_position);
    assert_eq!(outcome.ancestry_id(), expected_ancestry);
    assert_eq!(outcome.envelope_id(), expected_envelope_id);
    assert_eq!(outcome.state_id(), expected_state);
    assert_eq!(journal.state_id().unwrap(), expected_state);
    assert_eq!(journal.finalized_len().unwrap(), 2);
    assert_eq!(
        journal.head().unwrap().artifact_snapshot().head_block_id(),
        target
    );
    let record = journal
        .finality_record(expected_position.height())
        .unwrap()
        .unwrap();
    assert_eq!(record.position(), expected_position);
    assert_eq!(record.canonical_envelope_bytes(), envelope);
    assert_eq!(record.canonical_artifact_bytes(), artifact_bytes);

    let mut expected_finality = old_finality;
    expected_finality.extend_from_slice(&body_length);
    expected_finality.extend_from_slice(&body);
    expected_finality.extend_from_slice(expected_state.as_bytes());
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        expected_finality
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
    assert_eq!(candidates.get(target).unwrap(), Some(block));
    let retained_payload = payloads.get(block.artifact_id()).unwrap().unwrap();
    assert_eq!(retained_payload.canonical_artifact_bytes(), artifact_bytes);

    drop(journal);
    assert!(matches!(
        fixture.open(&finality_directory, old_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    let reopened = fixture.open(&finality_directory, expected_state).unwrap();
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(
        reopened.head().unwrap().artifact_snapshot().head_block_id(),
        target
    );
}

#[cfg(unix)]
#[test]
fn candidate_backed_anchored_finality_keeps_the_safe_product_path_composable() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("anchored-candidate-finality");
    let anchor_directory = TestDirectory::new("anchored-candidate-anchor");
    let candidate_directory = TestDirectory::new("anchored-candidate-store");
    let payload_directory = TestDirectory::new("anchored-candidate-payloads");
    let mut journal = fixture.create_anchored(&finality_directory, &anchor_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let target = transition.value().artifact_block().id();
    let envelope = transition.canonical_envelope_bytes().to_vec();
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &transition,
    );
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let outcome = commit_candidate_backed_anchored_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        target,
        &envelope,
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(outcome.target(), target);
    assert_eq!(journal.journal.core.record_sequence, 1);
    assert_eq!(journal.state_id().unwrap(), outcome.state_id());
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);

    drop(journal);
    let reopened = fixture
        .open_anchored(&finality_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 1);
    assert_eq!(
        SelectedArtifactHistory::selected_head_block_id(&reopened).unwrap(),
        target
    );
}

#[test]
fn candidate_backed_finality_rejects_missing_misdirected_and_unbounded_inputs_without_writes() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-reject-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-reject-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-reject-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let block = transition.value().artifact_block();
    let target = block.id();
    let envelope = transition.canonical_envelope_bytes().to_vec();
    let finality_before = fs::read(finality_directory.journal()).unwrap();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateUnavailable { target: actual })
            if actual == target
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );

    let _ = candidates.insert(&block).unwrap();
    let candidate_only = candidate_image(&candidate_directory);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })
            if artifact_id == block.artifact_id()
    ));
    assert_eq!(candidate_image(&candidate_directory), candidate_only);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );

    let _ = payloads
        .validate_and_insert_branch_payload(
            journal.head().unwrap().artifact_snapshot(),
            &block,
            transition.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let wrong_target = ArtifactBlockId::from_bytes([0x99; 32]);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            wrong_target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::EnvelopeTargetMismatch {
            expected,
            actual,
        }) if expected == wrong_target && actual == target
    ));

    let mut trailing = envelope.clone();
    trailing.push(0);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &trailing,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(_))
    ));

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::RoundLimitExceeded { round, maximum }
        )) if round == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
    ));

    let mut attacker_round = envelope.clone();
    let round_offset =
        ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH + 77;
    attacker_round[round_offset..round_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &attacker_round,
            ConsensusRound::new(fixture.limit.max_round()),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::RoundLimitExceeded { round, maximum }
        )) if round == ConsensusRound::new(u64::MAX)
            && maximum == ConsensusRound::new(fixture.limit.max_round())
    ));

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(fixture.limit.max_round() + 1),
        ),
        Err(CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
            requested,
            journal,
        }) if requested == fixture.limit.max_round() + 1
            && journal == fixture.limit.max_round()
    ));

    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_requires_one_independent_certificate_per_height() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-sequential-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-sequential-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-sequential-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first_for_child =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let child = first_for_child.into_branch();
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    selected
        .apply_block(&first_block, first.canonical_artifact_bytes().to_vec())
        .unwrap();
    let second = fixture.transition(&child, &mut selected, ZfcAxiom::Union, 0);
    let second_block = second.value().artifact_block();

    let _ = candidates.insert(&first_block).unwrap();
    let _ = candidates.insert(&second_block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            journal.head().unwrap().artifact_snapshot(),
            &first_block,
            first.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            child.artifact_snapshot(),
            &second_block,
            second.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let genesis_finality = fs::read(finality_directory.journal()).unwrap();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            second_block.id(),
            second.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch { expected, actual }
        )) if expected == ConsensusHeight::new(1) && actual == ConsensusHeight::new(2)
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        genesis_finality
    );

    let first_outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        first_block.id(),
        first.canonical_envelope_bytes(),
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(first_outcome.position().height(), ConsensusHeight::new(1));
    let second_outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        second_block.id(),
        second.canonical_envelope_bytes(),
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(second_outcome.position().height(), ConsensusHeight::new(2));
    assert_eq!(journal.finalized_len().unwrap(), 2);
    assert_eq!(
        journal.head().unwrap().artifact_snapshot().head_block_id(),
        second_block.id()
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_reauthenticates_evidence_and_artifact_parent() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-verify-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-verify-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-verify-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &transition,
    );
    let block = transition.value().artifact_block();
    let target = block.id();
    let envelope = transition.canonical_envelope_bytes();
    let finality_before = fs::read(finality_directory.journal()).unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let mut invalid_authorization = envelope.to_vec();
    let signature_offset =
        ConsensusValueV0::BYTE_LENGTH + AUTHORIZATION_BODY_BYTES + CONSENSUS_KEY_BYTES;
    invalid_authorization[signature_offset] ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &invalid_authorization,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ProducerAuthorization(_)
            )
        ))
    ));

    let mut wrong_role = envelope.to_vec();
    let certificate_offset =
        ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
    wrong_role[certificate_offset] = 1;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &wrong_role,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::PrecommitCertificate(_)
            )
        ))
    ));

    let mut wrong_certificate_height = envelope.to_vec();
    wrong_certificate_height[certificate_offset + 69..certificate_offset + 77]
        .copy_from_slice(&2_u64.to_be_bytes());
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &wrong_certificate_height,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::CertificateHeightMismatch {
                expected,
                actual,
            }
        )) if expected == ConsensusHeight::new(1) && actual == ConsensusHeight::new(2)
    ));

    let mut foreign_context = envelope.to_vec();
    foreign_context[0] ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &foreign_context,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ChainIdMismatch { .. }
            )
        ))
    ));

    let wrong_parent = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xa7; 32]),
        block.previous_artifact_set_root(),
        block.resulting_artifact_set_root(),
        block.artifact_id(),
    );
    let round = journal.head().unwrap().begin_round_zero().unwrap();
    let wrong_parent_value = round.value_for_artifact_block(wrong_parent);
    let wrong_parent_envelope =
        envelope_bytes(wrong_parent_value, round.position(), &fixture.proposer);
    let _ = candidates.insert(&wrong_parent).unwrap();
    let candidate_with_wrong_parent = candidate_image(&candidate_directory);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            wrong_parent.id(),
            &wrong_parent_envelope,
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ArtifactValidation(_)
            )
        ))
    ));

    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
    assert_eq!(
        candidate_image(&candidate_directory),
        candidate_with_wrong_parent
    );
    assert_ne!(candidate_with_wrong_parent, candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_rejects_foreign_candidate_store_before_source_reads() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-foreign-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-foreign-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-foreign-payloads");
    let mut journal = fixture.create(&finality_directory);
    let foreign_definition = ArtifactChainDefinition::new([0x91; 32]);
    let mut candidates = create_candidate_store(&candidate_directory, foreign_definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let finality_before = fs::read(finality_directory.journal()).unwrap();
    candidates.poison_after_injected_ambiguous_commit();
    payloads.poison_after_injected_ambiguous_commit();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            transition.value().artifact_block().id(),
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateChainMismatch {
            expected,
            actual,
        }) if expected == fixture.definition.id() && actual == foreign_definition.id()
    ));
    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
}

#[test]
fn candidate_backed_finality_rejects_stale_and_halted_journals_before_selection() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-stale-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-stale-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-stale-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let stale = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &stale,
    );
    let selected_transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let conflicting_transition = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let _ = journal.commit_verified(selected_transition).unwrap();
    let finality_before_stale = fs::read(finality_directory.journal()).unwrap();
    let stale_target = stale.value().artifact_block().id();
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            stale_target,
            stale.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch { expected, actual }
        )) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(1)
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before_stale
    );
    assert_eq!(journal.finalized_len().unwrap(), 1);
    assert!(journal.halt().unwrap().is_none());

    assert!(matches!(
        journal.commit_verified(conflicting_transition).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    let halted_image = fs::read(finality_directory.journal()).unwrap();
    candidates.poison_after_injected_ambiguous_commit();
    payloads.poison_after_injected_ambiguous_commit();
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            stale_target,
            stale.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::FinalityJournal(
            FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. }
        ))
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        halted_image
    );
}

#[test]
fn candidate_backed_finality_store_integrity_failures_poison_only_the_owning_source() {
    let fixture = Fixture::new();
    let mut selected = ArtifactChainState::new(fixture.definition);

    let candidate_finality_directory =
        TestDirectory::new("candidate-backed-corrupt-candidate-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-corrupt-candidate-store");
    let candidate_payload_directory =
        TestDirectory::new("candidate-backed-corrupt-candidate-payloads");
    let mut candidate_journal = fixture.create(&candidate_finality_directory);
    let mut corrupt_candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut healthy_payloads = create_payload_store(&candidate_payload_directory);
    let transition = fixture.transition(
        candidate_journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        0,
    );
    retain_transition_inputs(
        &mut corrupt_candidates,
        &mut healthy_payloads,
        candidate_journal.head().unwrap(),
        &transition,
    );
    let block = transition.value().artifact_block();
    let target = block.id();
    let candidate_finality_before = fs::read(candidate_finality_directory.journal()).unwrap();
    let candidate_payload_before = payload_image(&candidate_payload_directory);
    let candidate_path = candidate_directory
        .0
        .join("artifact-block-candidate-store.log");
    let candidate_body_offset = b"naome:artifact-block-candidate-store:v0\0".len() as u64
        + ArtifactChainId::BYTE_LENGTH as u64;
    flip_byte(candidate_path, candidate_body_offset);
    let corrupted_candidate_image = candidate_image(&candidate_directory);

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut candidate_journal,
            &mut corrupt_candidates,
            &mut healthy_payloads,
            target,
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateStore(_))
    ));
    assert!(matches!(
        corrupt_candidates.get(target),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert!(healthy_payloads.get(block.artifact_id()).unwrap().is_some());
    assert_eq!(
        fs::read(candidate_finality_directory.journal()).unwrap(),
        candidate_finality_before
    );
    assert_eq!(
        candidate_image(&candidate_directory),
        corrupted_candidate_image
    );
    assert_eq!(
        payload_image(&candidate_payload_directory),
        candidate_payload_before
    );

    let payload_finality_directory =
        TestDirectory::new("candidate-backed-corrupt-payload-finality");
    let payload_candidate_directory =
        TestDirectory::new("candidate-backed-corrupt-payload-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-corrupt-payload-store");
    let mut payload_journal = fixture.create(&payload_finality_directory);
    let mut healthy_candidates =
        create_candidate_store(&payload_candidate_directory, fixture.definition);
    let mut corrupt_payloads = create_payload_store(&payload_directory);
    retain_transition_inputs(
        &mut healthy_candidates,
        &mut corrupt_payloads,
        payload_journal.head().unwrap(),
        &transition,
    );
    let payload_finality_before = fs::read(payload_finality_directory.journal()).unwrap();
    let payload_candidate_before = candidate_image(&payload_candidate_directory);
    let payload_path = payload_directory.0.join("artifact-payload-store.log");
    let payload_body_offset = b"naome:artifact-payload-store:v1\0".len() as u64
        + FOUNDATION_ID.len() as u64
        + 4
        + ArtifactId::BYTE_LENGTH as u64;
    flip_byte(payload_path, payload_body_offset);
    let corrupted_payload_image = payload_image(&payload_directory);

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut payload_journal,
            &mut healthy_candidates,
            &mut corrupt_payloads,
            target,
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadStore(_))
    ));
    assert_eq!(healthy_candidates.get(target).unwrap(), Some(block));
    assert!(matches!(
        corrupt_payloads.get(block.artifact_id()),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
    assert_eq!(
        fs::read(payload_finality_directory.journal()).unwrap(),
        payload_finality_before
    );
    assert_eq!(
        candidate_image(&payload_candidate_directory),
        payload_candidate_before
    );
    assert_eq!(payload_image(&payload_directory), corrupted_payload_image);
}

#[test]
fn signer_handoff_requires_retained_finality_and_exact_current_anchor() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("signer-handoff-anchor");
    let mut journal = fixture.create(&directory);
    let genesis_state = journal.state_id().unwrap();
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(0),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable {
            height,
        }) if height == ConsensusHeight::new(0)
    ));
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable {
            height,
        }) if height == ConsensusHeight::new(1)
    ));

    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_position = first.position();
    let first_ancestry = first.value().ancestry_id();
    let first_envelope = first.envelope_id();
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    let first_state = journal.state_id().unwrap();

    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == first_state && acknowledged == genesis_state
    ));
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            first_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), first_position);
    assert_eq!(durable.transition.value().ancestry_id(), first_ancestry);
    assert_eq!(durable.transition.envelope_id(), first_envelope);
    drop(durable);

    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    let second_state = journal.state_id().unwrap();
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            first_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == second_state && acknowledged == first_state
    ));
    let historical = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            second_state,
        )
        .unwrap();
    assert_eq!(historical.transition.value().ancestry_id(), first_ancestry);
}

#[test]
fn reopened_finality_history_reconstructs_current_and_historical_candidate_anchors_read_only() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("candidate-recovery");
    let mut journal = fixture.create(&directory);
    let genesis = fixture.definition.id().virtual_genesis_block_id();
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let mut historical_branch = selected.clone();

    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let second_block = second.value().artifact_block();
    let second_payload = second.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(second).unwrap();
    selected.apply_block(&second_block, second_payload).unwrap();

    let (historical_payloads, historical_artifact_ids) = dependency_payloads(ZfcAxiom::PowerSet);
    let premature_dependency = historical_branch
        .prepare_block(historical_artifact_ids[1])
        .unwrap();
    let historical_root = historical_branch
        .prepare_block(historical_artifact_ids[0])
        .unwrap();
    historical_branch
        .apply_block(&historical_root, historical_payloads[0].clone())
        .unwrap();
    let historical_target = historical_branch
        .prepare_block(historical_artifact_ids[1])
        .unwrap();
    historical_branch
        .apply_block(&historical_target, historical_payloads[1].clone())
        .unwrap();
    let historical_target_root = historical_branch.artifact_dag().artifact_set_root();

    let current_payload = proof_payload(ZfcAxiom::Choice);
    let current_target = selected
        .prepare_block(artifact_id(&current_payload))
        .unwrap();
    let current_successor = selected
        .branch_snapshot()
        .validate_child(&current_target, current_payload.clone())
        .unwrap();

    let expected_state = journal.state_id().unwrap();
    let expected_head = journal.artifact_head_block_id().unwrap();
    let expected_root = journal.artifact_set_root().unwrap();
    let journal_image = fs::read(directory.journal()).unwrap();
    drop(journal);

    let reopened = fixture.open(&directory, expected_state).unwrap();
    assert_eq!(
        reopened.artifact_chain_id().unwrap(),
        fixture.definition.id()
    );
    assert_eq!(reopened.artifact_head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(reopened.core.snapshot_index.len(), 3);
    assert_eq!(reopened.core.snapshot_index.get(&genesis), Some(&0));
    assert_eq!(
        reopened.core.snapshot_index.get(&first_block.id()),
        Some(&1)
    );
    assert_eq!(
        reopened.core.snapshot_index.get(&second_block.id()),
        Some(&2)
    );
    assert!(
        reopened
            .artifact_branch_snapshot_at(genesis)
            .unwrap()
            .unwrap()
            .is_virtual_genesis()
    );
    let historical_snapshot = reopened
        .artifact_branch_snapshot_at(first_block.id())
        .unwrap()
        .unwrap();
    let current_snapshot = reopened
        .artifact_branch_snapshot_at(second_block.id())
        .unwrap()
        .unwrap();
    assert_eq!(current_snapshot.head_block_id(), expected_head);
    assert!(
        reopened
            .artifact_branch_snapshot_at(ArtifactBlockId::from_bytes([0xee; 32]))
            .unwrap()
            .is_none()
    );
    assert!(
        historical_snapshot
            .validate_child(&premature_dependency, historical_payloads[1].clone())
            .is_err(),
        "the historical snapshot must not resolve a dependency absent from that branch"
    );

    let candidate_limits = ArtifactBlockCandidateStoreLimits::new(4).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.0, fixture.definition, candidate_limits)
            .unwrap();
    for block in [historical_root, historical_target, current_target] {
        let _ = candidates.insert(&block).unwrap();
    }
    let payload_byte_limit = historical_payloads
        .iter()
        .map(|payload| u64::try_from(payload.len()).unwrap())
        .sum::<u64>()
        + u64::try_from(current_payload.len()).unwrap();
    let payload_limits = ArtifactPayloadStoreLimits::new(3, payload_byte_limit).unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(&directory.0, payload_limits).unwrap();
    let historical_root_outcome = payloads
        .validate_and_insert_branch_payload(
            &historical_snapshot,
            &historical_root,
            historical_payloads[0].clone(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            historical_root_outcome.successor(),
            &historical_target,
            historical_payloads[1].clone(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(&current_snapshot, &current_target, current_payload)
        .unwrap();
    let payload_image = fs::read(directory.0.join("artifact-payload-store.log")).unwrap();

    let historical = reopened
        .reconstruct_candidate_branch(
            historical_target.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(historical.anchor_block_id(), first_block.id());
    assert_eq!(historical.block_count(), 2);
    assert_eq!(
        historical.snapshot().artifact_set_root(),
        historical_target_root
    );

    let current = reopened
        .reconstruct_candidate_branch(
            current_target.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(1).unwrap(),
        )
        .unwrap();
    assert_eq!(current.anchor_block_id(), second_block.id());
    assert_eq!(current.block_count(), 1);
    assert_eq!(
        current.snapshot().artifact_set_root(),
        current_successor.artifact_set_root()
    );

    let unknown_parent = ArtifactBlockId::from_bytes([0xdd; 32]);
    let unknown_anchor = ArtifactBlock::new(
        unknown_parent,
        current_target.previous_artifact_set_root(),
        current_target.resulting_artifact_set_root(),
        current_target.artifact_id(),
    );
    let _ = candidates.insert(&unknown_anchor).unwrap();
    let candidate_image = fs::read(directory.0.join("artifact-block-candidate-store.log")).unwrap();
    assert!(matches!(
        reopened.reconstruct_candidate_branch(
            unknown_anchor.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        ),
        Err(CandidateBranchReconstructionError::CandidateNotRetained { block_id })
            if block_id == unknown_parent
    ));

    let mismatch_directory = TestDirectory::new("candidate-recovery-mismatch");
    let mismatch_definition = ArtifactChainDefinition::new([0x99; 32]);
    let mut mismatch_candidates = ArtifactBlockCandidateStore::create(
        &mismatch_directory.0,
        mismatch_definition,
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();
    let mut mismatch_payloads = CanonicalArtifactPayloadStore::create(
        &mismatch_directory.0,
        ArtifactPayloadStoreLimits::new(1, 1).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        reopened.reconstruct_candidate_branch(
            ArtifactBlockId::from_bytes([0xcc; 32]),
            &mut mismatch_candidates,
            &mut mismatch_payloads,
            CandidateBranchReconstructionLimits::new(1).unwrap(),
        ),
        Err(CandidateBranchReconstructionError::ChainIdMismatch {
            selected: actual_selected,
            candidates: actual_candidates,
        }) if actual_selected == fixture.definition.id()
            && actual_candidates == mismatch_definition.id()
    ));

    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(reopened.artifact_head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(fs::read(directory.journal()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.0.join("artifact-block-candidate-store.log")).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.0.join("artifact-payload-store.log")).unwrap(),
        payload_image
    );
}

#[test]
fn state_id_goldens_cover_genesis_and_two_steps() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("goldens");
    let mut journal = fixture.create(&directory);
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "9beeb687529f3dbd5e91b8ccc9aeca3ef8321b1c7a10601be4e5eb22d0f1fe53"
    );
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let block = first.value().artifact_block();
    let payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "f56cb626eb72a336f4cc19ef5cf7b84b2fc70252de39ed653302e3f64d683c5d"
    );
    selected.apply_block(&block, payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "63764e2271be86b357c4dcd56f997674950e99d7a3dc3a85d56e5ea105195940"
    );
}

#[test]
fn same_value_later_round_is_idempotent_without_write() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("same-value");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_envelope_id = first.envelope_id();
    let first_envelope = first.canonical_envelope_bytes().to_vec();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let variant = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let _ = journal.commit_verified(first).unwrap();
    let image = fs::read(directory.journal()).unwrap();
    let state = journal.state_id().unwrap();
    assert!(matches!(
        journal.commit_verified(variant).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
            retained_envelope_id,
            state_id,
            ..
        } if retained_envelope_id == first_envelope_id && state_id == state
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), image);
    let retained = journal
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(retained.envelope_id(), first_envelope_id);
    assert_eq!(retained.canonical_envelope_bytes(), first_envelope);
    assert_eq!(retained.canonical_artifact_bytes(), first_payload);
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(ConsensusHeight::new(1), state)
        .unwrap();
    assert_eq!(durable.transition.position().round().value(), 0);
    assert_eq!(durable.transition.envelope_id(), first_envelope_id);
}

#[test]
fn conflicting_valid_sibling_durably_halts_and_denies_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("halt");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let conflict = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let denied_commit =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let reopened_denied_commit =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 2);
    let _ = journal.commit_verified(first).unwrap();
    let pre_halt_image = fs::read(directory.journal()).unwrap();
    let halt = match journal.commit_verified(conflict).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert!(matches!(
        journal.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_chain_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_head_block_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_set_root(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_branch_snapshot_at(fixture.definition.id().virtual_genesis_block_id()),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.parent_for_height(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finality_record(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finalized_len(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            journal.state_id().unwrap(),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.commit_verified(denied_commit),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let state = journal.state_id().unwrap();
    let halt_image = fs::read(directory.journal()).unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert!(matches!(
        reopened.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_chain_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_head_block_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_set_root(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_branch_snapshot_at(fixture.definition.id().virtual_genesis_block_id()),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.parent_for_height(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.finality_record(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.finalized_len(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            reopened.state_id().unwrap(),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let mut reopened = reopened;
    assert!(matches!(
        reopened.commit_verified(reopened_denied_commit),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    drop(reopened);

    let mut incomplete_after_halt = halt_image.clone();
    incomplete_after_halt.push(0);
    fs::write(directory.journal(), &incomplete_after_halt).unwrap();
    let recovered_halt = fixture.open(&directory, state).unwrap();
    assert_eq!(recovered_halt.halt().unwrap(), Some(halt));
    drop(recovered_halt);
    assert_eq!(fs::read(directory.journal()).unwrap(), halt_image);

    let mut complete_after_halt = halt_image.clone();
    complete_after_halt.extend_from_slice(&pre_halt_image[JOURNAL_PREFIX_BYTES..]);
    fs::write(directory.journal(), &complete_after_halt).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::RecordAfterHalt { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), complete_after_halt);

    fs::write(directory.journal(), &pre_halt_image).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn trusted_anchor_controls_incomplete_tail_recovery_and_suffix_rollback() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("anchor");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(first).unwrap();
    let committed = fs::read(directory.journal()).unwrap();
    let first_state = journal.state_id().unwrap();
    drop(journal);

    let cut = committed.len() - 7;
    fs::write(directory.journal(), &committed[..cut]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), &committed[..cut]);
    let recovered = fixture.open(&directory, genesis).unwrap();
    drop(recovered);
    assert_eq!(
        fs::read(directory.journal()).unwrap().len(),
        JOURNAL_PREFIX_BYTES
    );

    fs::write(directory.journal(), &committed).unwrap();
    assert!(matches!(
        fixture.open(&directory, genesis),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed);
    fs::write(directory.journal(), &committed[..JOURNAL_PREFIX_BYTES]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn mutation_duplicate_and_reorder_fail_closed() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("tamper");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let image = fs::read(directory.journal()).unwrap();
    let first_len = 4
        + u32::from_be_bytes(
            image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
                .try_into()
                .unwrap(),
        ) as usize
        + 32;
    let first = &image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + first_len];
    let second = &image[JOURNAL_PREFIX_BYTES + first_len..];
    for altered in [
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + 5] ^= 1;
            bytes
        },
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + first_len - 1] ^= 1;
            bytes
        },
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            first.to_vec(),
            first.to_vec(),
            second.to_vec(),
        ]
        .concat(),
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            second.to_vec(),
            first.to_vec(),
        ]
        .concat(),
    ] {
        fs::write(directory.journal(), &altered).unwrap();
        assert!(fixture.open(&directory, state).is_err());
        assert_eq!(fs::read(directory.journal()).unwrap(), altered);
    }
}

#[test]
fn recomputed_state_ids_cannot_authorize_invalid_tags_or_artifact_semantics() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("semantic-tamper");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    drop(journal);

    let image = fs::read(directory.journal()).unwrap();
    let body_length_bytes: [u8; 4] = image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
        .try_into()
        .unwrap();
    let body_length = u32::from_be_bytes(body_length_bytes) as usize;
    let body_start = JOURNAL_PREFIX_BYTES + 4;
    let body_end = body_start + body_length;

    let mut invalid_tag = image.clone();
    invalid_tag[body_start] = 3;
    let tag_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_tag[body_start..body_end],
    );
    invalid_tag[body_end..body_end + 32].copy_from_slice(tag_state.as_bytes());
    fs::write(directory.journal(), &invalid_tag).unwrap();
    assert!(matches!(
        fixture.open(&directory, tag_state),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_tag);

    let mut invalid_payload = image;
    invalid_payload[body_end - 1] ^= 1;
    let payload_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_payload[body_start..body_end],
    );
    invalid_payload[body_end..body_end + 32].copy_from_slice(payload_state.as_bytes());
    fs::write(directory.journal(), &invalid_payload).unwrap();
    assert!(matches!(
        fixture.open(&directory, payload_state),
        Err(FixedValidatorFinalityJournalErrorV0::Replay { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_payload);
}

#[test]
fn every_incomplete_first_entry_cut_obeys_the_trusted_anchor() {
    let fixture = Fixture::new();
    let source = TestDirectory::new("all-cuts-source");
    let mut journal = fixture.create(&source);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    let committed = fs::read(source.journal()).unwrap();
    let finalized = journal.state_id().unwrap();
    drop(journal);

    for cut in JOURNAL_PREFIX_BYTES + 1..committed.len() {
        let directory = TestDirectory::new("all-cuts");
        fs::write(directory.journal(), &committed[..cut]).unwrap();
        assert!(
            matches!(
                fixture.open(&directory, finalized),
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ),
            "cut={cut}"
        );
        assert_eq!(
            fs::read(directory.journal()).unwrap(),
            &committed[..cut],
            "cut={cut}"
        );
        let recovered = fixture.open(&directory, genesis).unwrap();
        assert_eq!(recovered.finalized_len().unwrap(), 0, "cut={cut}");
        drop(recovered);
        assert_eq!(
            fs::read(directory.journal()).unwrap().len(),
            JOURNAL_PREFIX_BYTES,
            "cut={cut}"
        );
    }
}

#[test]
fn max_round_is_header_bound_and_shared_namespace_rejects_old_format() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("namespace");
    let old = ArtifactChainJournal::create(&directory.0, fixture.definition).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            fixture.limit,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Locked)
    ));
    drop(old);
    assert!(matches!(
        fixture.open(
            &directory,
            FixedValidatorFinalityJournalStateIdV0::from_bytes([0; 32]),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidHeader)
            | Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));

    fs::remove_file(directory.journal()).unwrap();
    let journal = fixture.create(&directory);
    let state = journal.state_id().unwrap();
    drop(journal);
    let other_limit = FixedValidatorFinalityReplayLimitV0::new(9).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            other_limit,
            state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));
}

#[test]
fn round_limit_accepts_maximum_and_rejects_max_plus_one_before_io_and_replay() {
    assert_eq!(
        FixedValidatorFinalityReplayLimitV0::new(0),
        Err(FixedValidatorFinalityReplayLimitErrorV0)
    );
    let fixture = Fixture::new();
    let directory = TestDirectory::new("round-limit");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let at_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        fixture.limit.max_round(),
    );
    let at_limit_position = at_limit.position();
    let at_limit_ancestry = at_limit.value().ancestry_id();
    let at_limit_envelope = at_limit.envelope_id();
    let at_limit_envelope_bytes = at_limit.canonical_envelope_bytes().to_vec();
    let at_limit_payload_bytes = at_limit.canonical_artifact_bytes().to_vec();
    let above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    let replay_above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    assert!(matches!(
        journal.commit_verified(at_limit).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let committed_state = journal.state_id().unwrap();
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            committed_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), at_limit_position);
    assert_eq!(durable.transition.value().ancestry_id(), at_limit_ancestry);
    assert_eq!(durable.transition.envelope_id(), at_limit_envelope);
    assert_eq!(
        durable.transition.canonical_envelope_bytes(),
        at_limit_envelope_bytes
    );
    assert_eq!(
        durable.transition.canonical_artifact_bytes(),
        at_limit_payload_bytes
    );
    drop(durable);
    let committed_image = fs::read(directory.journal()).unwrap();
    assert!(matches!(
        journal.commit_verified(above_limit),
        Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
            round,
            maximum,
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed_image);
    drop(journal);

    let reopened = fixture.open(&directory, committed_state).unwrap();
    let durable = reopened
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            committed_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), at_limit_position);
    assert_eq!(durable.transition.value().ancestry_id(), at_limit_ancestry);
    assert_eq!(durable.transition.envelope_id(), at_limit_envelope);
    assert_eq!(
        durable.transition.canonical_envelope_bytes(),
        at_limit_envelope_bytes
    );
    assert_eq!(
        durable.transition.canonical_artifact_bytes(),
        at_limit_payload_bytes
    );
    drop(durable);
    drop(reopened);

    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);
    let body = canonical_record_body(FINALIZE_RECORD, &replay_above_limit, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let state = step_state_id(genesis, body_length_bytes, &body);
    let mut image = prefix.clone();
    image.extend_from_slice(&body_length_bytes);
    image.extend_from_slice(&body);
    image.extend_from_slice(state.as_bytes());
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(image.clone(), image),
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            state,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ReplayRoundLimitExceeded {
            round,
            maximum,
            ..
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
}

#[test]
fn every_candidate_backed_append_fault_poisons_only_finality_and_reopens_exactly() {
    let fixture = Fixture::new();
    let candidate_directory = TestDirectory::new("candidate-backed-fault-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-fault-payloads");
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis_branch =
        fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        genesis_branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis_id = genesis_state_id(&prefix);
    let genesis_block_id = fixture.definition.id().virtual_genesis_block_id();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let probe = fixture.transition(&genesis_branch, &mut selected, ZfcAxiom::Pairing, 0);
    let proposed_block_id = probe.value().artifact_block().id();
    let canonical_envelope = probe.canonical_envelope_bytes().to_vec();
    retain_transition_inputs(&mut candidates, &mut payloads, &genesis_branch, &probe);
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let body = canonical_record_body(FINALIZE_RECORD, &probe, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let proposed_state = step_state_id(genesis_id, body_length_bytes, &body);

    for fault in all_append_faults(
        RECORD_LENGTH_BYTES as usize + body.len(),
        STATE_ID_BYTES as usize,
    ) {
        let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let branches = vec![branch];
        let snapshot_index = genesis_snapshot_index(&branches).unwrap();
        let mut core = FixedValidatorFinalityJournalCore::empty(
            io,
            fixture.context,
            fixture.limit,
            branches,
            snapshot_index,
            genesis_id,
        );
        assert!(
            matches!(
                commit_candidate_backed_finality_core_v0(
                    &mut core,
                    &mut candidates,
                    &mut payloads,
                    proposed_block_id,
                    &canonical_envelope,
                    ConsensusRound::new(0),
                ),
                Err(CandidateBackedFinalityErrorV0::FinalityJournal(
                    FixedValidatorFinalityJournalErrorV0::Commit {
                        envelope_id,
                        proposed_state_id,
                        ..
                    }
                )) if envelope_id == probe.envelope_id()
                    && proposed_state_id == proposed_state
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert_eq!(core.state_id, genesis_id, "fault={fault:?}");
        assert_eq!(core.records.len(), 0, "fault={fault:?}");
        assert_eq!(core.branches.len(), 1, "fault={fault:?}");
        assert_eq!(core.snapshot_index.len(), 1, "fault={fault:?}");
        assert_eq!(
            core.snapshot_index.get(&genesis_block_id),
            Some(&0),
            "fault={fault:?}"
        );
        assert!(
            matches!(
                core.ensure_operational(),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );
        assert!(
            matches!(
                core.reconstruct_selected_transition(ConsensusHeight::new(1)),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );
        assert_eq!(
            candidate_image(&candidate_directory),
            candidate_before,
            "fault={fault:?}"
        );
        assert_eq!(
            payload_image(&payload_directory),
            payload_before,
            "fault={fault:?}"
        );
        assert_eq!(
            candidates.get(proposed_block_id).unwrap(),
            Some(probe.value().artifact_block()),
            "fault={fault:?}"
        );
        assert!(
            payloads
                .get(probe.value().artifact_block().artifact_id())
                .unwrap()
                .is_some(),
            "fault={fault:?}"
        );

        let durable = core.file.durable.clone();
        let durable_commit = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let old_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable.clone()),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            genesis_id,
            None,
        );
        if durable_commit {
            assert!(matches!(
                old_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        } else {
            let old_anchor = old_anchor.unwrap();
            assert_eq!(old_anchor.state_id, genesis_id);
            assert_eq!(old_anchor.snapshot_index.len(), 1);
            assert_eq!(old_anchor.snapshot_index.get(&genesis_block_id), Some(&0));
        }

        let new_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            proposed_state,
            None,
        );
        if durable_commit {
            let new_anchor = new_anchor.unwrap();
            assert_eq!(new_anchor.state_id, proposed_state);
            assert_eq!(new_anchor.snapshot_index.len(), 2);
            assert_eq!(new_anchor.snapshot_index.get(&genesis_block_id), Some(&0));
            assert_eq!(new_anchor.snapshot_index.get(&proposed_block_id), Some(&1));
            assert!(
                new_anchor
                    .reconstruct_selected_transition(ConsensusHeight::new(1))
                    .is_ok()
            );
        } else {
            assert!(matches!(
                new_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        }
    }
}

#[test]
fn replay_recovery_and_stabilization_io_fail_closed() {
    let fixture = Fixture::new();
    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);

    let mut incomplete = prefix.clone();
    incomplete.push(0);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            recovery_io,
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![branch.clone()],
            genesis,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Recovery { .. })
    ));

    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix.clone());
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            stabilize_io,
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            genesis,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Stabilize { .. })
    ));
}
