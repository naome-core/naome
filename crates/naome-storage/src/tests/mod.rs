use std::env;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    AppendPhase, BLOCK_LENGTH_BYTES, ENTRY_FIXED_BYTES, ENTRY_MAX_BODY_BYTES, ENTRY_MIN_BODY_BYTES,
    JOURNAL_FILE_NAME, JOURNAL_HEADER, JOURNAL_PREFIX_BYTES, JournalCore, JournalIo,
    PROOF_BLOCK_MIN_BYTES, ProofChainJournal, ProofChainJournalError,
};
use naome_chain::{
    AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, ProofBlock, ProofBlockApplyError,
    ProofBlockId, ProofChainId, ProofChainState, ProofDag, ProofSetMembership, ProofSetRoot,
    ProofTransitionApplyError,
};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_ledger::{AcceptedProofRecord, LedgerError, ProofBatchError};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, ProofCertificate, ProofCertificateError,
    ProofId, ProofStep,
};

mod admission;
mod faults;
mod replay;

const CHAIN_BYTE: u8 = 0x11;
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);
type JournalEntryFixture = (ProofBlock, Vec<Vec<u8>>, Vec<ProofId>);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-proof-chain-storage-{}-{sequence}",
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

fn chain_id(byte: u8) -> ProofChainId {
    ProofChainId::from_bytes([byte; 32])
}

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    certificate(steps)
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec()
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

fn dependency_chain_with_len(length: usize) -> (Vec<Vec<u8>>, Vec<ProofId>) {
    assert!(length > 0);
    let mut dag = ProofDag::new();
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let root_id = dag
        .apply_canonical_proof_bytes(root.clone())
        .unwrap()
        .proof_id();
    let mut payloads = Vec::with_capacity(length);
    let mut proof_ids = Vec::with_capacity(length);
    payloads.push(root);
    proof_ids.push(root_id);
    for index in 1..length {
        let payload = referenced_generalization(
            *proof_ids.last().unwrap(),
            FreeVariable::new(u32::try_from(index).unwrap()),
        );
        let proof_id = dag
            .apply_canonical_proof_bytes(payload.clone())
            .unwrap()
            .proof_id();
        payloads.push(payload);
        proof_ids.push(proof_id);
    }
    (payloads, proof_ids)
}

fn independent_axioms() -> (Vec<Vec<u8>>, Vec<ProofId>) {
    let payloads = vec![axiom_bytes(ZfcAxiom::Pairing), axiom_bytes(ZfcAxiom::Union)];
    let proof_ids = payloads
        .iter()
        .map(|payload| {
            ProofDag::new()
                .apply_canonical_proof_bytes(payload.clone())
                .unwrap()
                .proof_id()
        })
        .collect();
    (payloads, proof_ids)
}

fn addressed_candidates(
    payloads: &[Vec<u8>],
    proof_ids: &[ProofId],
) -> Vec<AddressedProofCandidate> {
    assert_eq!(payloads.len(), proof_ids.len());
    payloads
        .iter()
        .cloned()
        .zip(proof_ids.iter().copied())
        .map(|(payload, proof_id)| AddressedProofCandidate::new(proof_id, payload))
        .collect()
}

fn prepared_block(state: &ProofChainState, proof_ids: &[ProofId]) -> ProofBlock {
    state.prepare_block(proof_ids.to_vec()).unwrap()
}

fn one_block(id: ProofChainId, _payloads: &[Vec<u8>], proof_ids: &[ProofId]) -> ProofBlock {
    let state = ProofChainState::new(id);
    prepared_block(&state, proof_ids)
}

fn two_block_chain(id: ProofChainId) -> [JournalEntryFixture; 2] {
    let (payloads, proof_ids) = dependency_chain_with_len(2);
    let mut state = ProofChainState::new(id);
    let first_payloads = vec![payloads[0].clone()];
    let first_ids = vec![proof_ids[0]];
    let first = prepared_block(&state, &first_ids);
    state
        .apply_block(&first, addressed_candidates(&first_payloads, &first_ids))
        .unwrap();
    let second_payloads = vec![payloads[1].clone()];
    let second_ids = vec![proof_ids[1]];
    let second = prepared_block(&state, &second_ids);
    [
        (first, first_payloads, first_ids),
        (second, second_payloads, second_ids),
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
    bytes
}

fn journal_prefix(id: ProofChainId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(JOURNAL_PREFIX_BYTES);
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(id.as_bytes());
    prefix
}

fn entry(block: &ProofBlock, payloads: &[Vec<u8>]) -> Vec<u8> {
    assert_eq!(payloads.len(), block.transition().proof_ids().len());
    let block_bytes = block.to_canonical_bytes();
    let body_length = BLOCK_LENGTH_BYTES
        + block_bytes.len()
        + payloads
            .iter()
            .map(|payload| 4 + payload.len())
            .sum::<usize>();
    let body_length_bytes = u32::try_from(body_length).unwrap().to_be_bytes();
    let mut body = Vec::with_capacity(body_length);
    body.extend_from_slice(&u16::try_from(block_bytes.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&block_bytes);
    for payload in payloads {
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        body.extend_from_slice(payload);
    }
    let mut encoded = Vec::with_capacity(ENTRY_FIXED_BYTES as usize + body.len());
    encoded.extend_from_slice(&body_length_bytes);
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(block.id().as_bytes());
    encoded
}

fn raw_entry(body: &[u8], footer: ProofBlockId) -> Vec<u8> {
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut encoded = Vec::with_capacity(ENTRY_FIXED_BYTES as usize + body.len());
    encoded.extend_from_slice(&body_length_bytes);
    encoded.extend_from_slice(body);
    encoded.extend_from_slice(footer.as_bytes());
    encoded
}

fn journal_image(id: ProofChainId, entries: &[JournalEntryFixture]) -> Vec<u8> {
    let mut image = journal_prefix(id);
    for (block, payloads, _) in entries {
        image.extend_from_slice(&entry(block, payloads));
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
    proof_id: ProofId,
    dependencies: Vec<ProofId>,
}

fn snapshot(record: &AcceptedProofRecord) -> RecordSnapshot {
    RecordSnapshot {
        bytes: record.canonical_proof_bytes().to_vec(),
        proof_id: record.proof_id(),
        dependencies: record.direct_dependencies().to_vec(),
    }
}
