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
    ConsensusGenesisId, ConsensusKey, ConsensusPosition, ConsensusProtocolVersion, ConsensusRound,
    ConsensusValueV0, FixedConsensusPrecommitBatchSealErrorV0,
    OwnedVerifiedFixedConsensusTransitionV0, PrecommitCertificateVerifyError, ProposalSigningRoot,
    QuorumCertificateBuildError, VerifiedFixedConsensusProposalV0, VerifiedProducerAuthorizationV0,
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

#[cfg(unix)]
mod recovery_bundle_export;

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

    #[cfg(unix)]
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

fn signed_precommit_bytes(
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
    let mut bytes = body.to_vec();
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

    fn preselection_conflict_pair(
        &self,
        branch: &FixedConsensusBranchV0,
        round: u64,
    ) -> (
        OwnedVerifiedFixedConsensusTransitionV0,
        OwnedVerifiedFixedConsensusTransitionV0,
    ) {
        let mut first_selected = ArtifactChainState::new(self.definition);
        let first = self.transition(branch, &mut first_selected, ZfcAxiom::Pairing, round);
        let mut second_selected = ArtifactChainState::new(self.definition);
        let second = self.transition(branch, &mut second_selected, ZfcAxiom::Union, round);
        (first, second)
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

#[cfg(unix)]
fn single_entry_image(
    prefix: &[u8],
    previous: FixedValidatorFinalityJournalStateIdV0,
    body: &[u8],
) -> (Vec<u8>, FixedValidatorFinalityJournalStateIdV0) {
    let body_length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let state = step_state_id(previous, body_length, body);
    let mut image = prefix.to_vec();
    image.extend_from_slice(&body_length);
    image.extend_from_slice(body);
    image.extend_from_slice(state.as_bytes());
    (image, state)
}

mod candidate_commit;
mod faults;
mod preselection_conflict;
mod recovery;
mod replay;
