use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    AppendPhase, ArtifactChainJournal, ArtifactChainJournalError, ENTRY_FIXED_BYTES,
    ENTRY_MAX_BODY_BYTES, ENTRY_MIN_BODY_BYTES, JOURNAL_FILE_NAME, JOURNAL_HEADER,
    JOURNAL_PREFIX_BYTES, JournalCore,
};
use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId,
    ArtifactChainDefinition, ArtifactChainId, ArtifactChainState, ArtifactDag,
    ArtifactSetMembership, ArtifactSetRoot,
};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_ledger::{AcceptedArtifactRecord, LedgerError};
use naome_proof::{
    ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId, ArtifactPayload, ArtifactPayloadError,
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, DefinedFormula, DefinitionCertificate,
    ProofCertificate, ProofCertificateError, ProofId, ProofStep,
};

mod admission;
mod branch_snapshots;
mod candidate_branch_import;
mod candidate_branch_reconstruction;
mod candidate_branch_recovery_bundle;
mod candidate_validation;
mod faults;
mod replay;

const CHAIN_BYTE: u8 = 0x11;
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);
type JournalEntryFixture = (ArtifactBlock, Vec<u8>, ArtifactId);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-artifact-chain-storage-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.path.join(JOURNAL_FILE_NAME)
    }

    fn write_image(&self, bytes: &[u8]) {
        fs::write(self.journal_path(), bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn chain_definition(byte: u8) -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([byte; 32])
}

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    let certificate = certificate(steps)
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    canonical_bytes(vec![ProofStep::ZfcAxiom(axiom)])
}

fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn relation_definition_bytes() -> Vec<u8> {
    let variable = FreeVariable::new(0);
    ArtifactPayload::Definition(
        DefinitionCertificate::relation(1, DefinedFormula::equal(variable, variable)).unwrap(),
    )
    .to_canonical_bytes()
}

fn dependency_chain_with_len(length: usize) -> (Vec<Vec<u8>>, Vec<ArtifactId>) {
    assert!(length > 0);
    let mut dag = ArtifactDag::new();
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let root_record = dag.apply_canonical_artifact_bytes(root.clone()).unwrap();
    let mut previous_proof_id = root_record.as_proof().unwrap().proof_id();
    let mut payloads = Vec::with_capacity(length);
    let mut artifact_ids = Vec::with_capacity(length);
    payloads.push(root);
    artifact_ids.push(root_record.artifact_id());
    for index in 1..length {
        let payload = referenced_generalization(
            previous_proof_id,
            FreeVariable::new(u32::try_from(index).unwrap()),
        );
        let record = dag.apply_canonical_artifact_bytes(payload.clone()).unwrap();
        previous_proof_id = record.as_proof().unwrap().proof_id();
        payloads.push(payload);
        artifact_ids.push(record.artifact_id());
    }
    (payloads, artifact_ids)
}

fn independent_axioms() -> (Vec<Vec<u8>>, Vec<ArtifactId>) {
    let payloads = vec![axiom_bytes(ZfcAxiom::Pairing), axiom_bytes(ZfcAxiom::Union)];
    let artifact_ids = payloads
        .iter()
        .map(|payload| {
            ArtifactDag::new()
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id()
        })
        .collect();
    (payloads, artifact_ids)
}

fn artifact_bytes(payload: &[u8]) -> Vec<u8> {
    payload.to_vec()
}

fn prepared_block(state: &ArtifactChainState, artifact_id: ArtifactId) -> ArtifactBlock {
    state.prepare_block(artifact_id).unwrap()
}

fn one_block(definition: ArtifactChainDefinition, artifact_id: ArtifactId) -> ArtifactBlock {
    let state = ArtifactChainState::new(definition);
    prepared_block(&state, artifact_id)
}

fn two_block_chain(definition: ArtifactChainDefinition) -> [JournalEntryFixture; 2] {
    let (payloads, artifact_ids) = dependency_chain_with_len(2);
    let mut state = ArtifactChainState::new(definition);
    let first = prepared_block(&state, artifact_ids[0]);
    state
        .apply_block(&first, artifact_bytes(&payloads[0]))
        .unwrap();
    let second = prepared_block(&state, artifact_ids[1]);
    [
        (first, payloads[0].clone(), artifact_ids[0]),
        (second, payloads[1].clone(), artifact_ids[1]),
    ]
}

fn over_formula_node_budget_bytes() -> Vec<u8> {
    let variable = FreeVariable::new(1);
    let mut half_limit = Formula::equal(variable, variable);
    for _ in 0..14 {
        half_limit = Formula::implies(half_limit.clone(), half_limit);
    }
    let half_limit = Formula::negate(half_limit);
    let (half_bytes, half_nodes) = half_limit
        .encode_canonical_with_node_limit(CERTIFICATE_MAX_FORMULA_NODES)
        .unwrap();
    let leaf_bytes = Formula::equal(variable, variable)
        .encode_canonical()
        .unwrap();
    assert_eq!(half_nodes, CERTIFICATE_MAX_FORMULA_NODES / 2);

    let formulas = [&half_bytes[..], &half_bytes[..], &leaf_bytes[..]];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u32::try_from(formulas.len()).unwrap().to_be_bytes());
    for formula in formulas {
        bytes.push(0x04);
        bytes.extend_from_slice(&u32::try_from(formula.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(formula);
    }
    assert!(bytes.len() < CERTIFICATE_MAX_BYTES);
    let mut artifact = Vec::with_capacity(bytes.len() + 1);
    artifact.push(0x00);
    artifact.extend(bytes);
    assert!(artifact.len() <= ARTIFACT_PAYLOAD_MAX_BYTES);
    artifact
}

fn journal_prefix(id: ArtifactChainId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(JOURNAL_PREFIX_BYTES);
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(id.as_bytes());
    prefix
}

fn entry(block: &ArtifactBlock, payload: &[u8]) -> Vec<u8> {
    let block_bytes = block.to_canonical_bytes();
    assert_eq!(block_bytes.len(), ARTIFACT_BLOCK_BYTES);
    let body_length = block_bytes.len() + payload.len();
    let body_length_bytes = u32::try_from(body_length).unwrap().to_be_bytes();
    let mut body = Vec::with_capacity(body_length);
    body.extend_from_slice(&block_bytes);
    body.extend_from_slice(payload);
    let mut encoded = Vec::with_capacity(ENTRY_FIXED_BYTES as usize + body.len());
    encoded.extend_from_slice(&body_length_bytes);
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(block.id().as_bytes());
    encoded
}

fn raw_entry(body: &[u8], footer: ArtifactBlockId) -> Vec<u8> {
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut encoded = Vec::with_capacity(ENTRY_FIXED_BYTES as usize + body.len());
    encoded.extend_from_slice(&body_length_bytes);
    encoded.extend_from_slice(body);
    encoded.extend_from_slice(footer.as_bytes());
    encoded
}

fn journal_image(id: ArtifactChainId, entries: &[JournalEntryFixture]) -> Vec<u8> {
    let mut image = journal_prefix(id);
    for (block, payload, _) in entries {
        image.extend_from_slice(&entry(block, payload));
    }
    image
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct RecordSnapshot {
    bytes: Vec<u8>,
    artifact_id: ArtifactId,
}

fn snapshot(record: &AcceptedArtifactRecord) -> RecordSnapshot {
    RecordSnapshot {
        bytes: record.canonical_artifact_bytes().to_vec(),
        artifact_id: record.artifact_id(),
    }
}
