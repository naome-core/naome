use std::env;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::{
    AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, ProofBatchError, ProofDag,
    ProofSetMembership,
};
use naome_checker::{CheckError, ProofStateError};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, ProofCertificate, ProofCertificateError,
    ProofId, ProofStep,
};
use sha2::Digest;

use super::{
    AppendPhase, GENESIS_DOMAIN, JOURNAL_FILE_NAME, JOURNAL_HEADER, JournalCore, JournalError,
    JournalIo, ProofDagJournal, TRANSACTION_DOMAIN, TRANSACTION_FIXED_BYTES,
    TRANSACTION_MAX_BODY_BYTES, TRANSACTION_MIN_BODY_BYTES, genesis_digest, transaction_hasher,
};

mod admission;
mod faults;
mod replay;

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("naome-storage-{}-{sequence}", std::process::id()));
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

fn dependency_chain() -> (Vec<Vec<u8>>, Vec<ProofId>) {
    dependency_chain_with_len(3)
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

fn transaction(previous: [u8; 32], payloads: &[Vec<u8>]) -> (Vec<u8>, [u8; 32]) {
    assert!((1..=PROOF_BATCH_MAX_CANDIDATES).contains(&payloads.len()));
    let body_length = 1 + payloads
        .iter()
        .map(|payload| 4 + payload.len())
        .sum::<usize>();
    let mut body = Vec::with_capacity(body_length);
    body.push(payloads.len() as u8);
    for payload in payloads {
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        body.extend_from_slice(payload);
    }
    raw_transaction(previous, &body)
}

fn raw_transaction(previous: [u8; 32], body: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut hasher = transaction_hasher(previous, body_length_bytes);
    hasher.update(body);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = Vec::with_capacity(TRANSACTION_FIXED_BYTES as usize + body.len());
    encoded.extend_from_slice(&body_length_bytes);
    encoded.extend_from_slice(body);
    encoded.extend_from_slice(&digest);
    (encoded, digest)
}

fn journal_image(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut image = JOURNAL_HEADER.to_vec();
    let mut previous = genesis_digest();
    for payload in payloads {
        let (encoded, digest) = transaction(previous, std::slice::from_ref(payload));
        image.extend_from_slice(&encoded);
        previous = digest;
    }
    image
}

fn journal_transaction_image(transactions: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut image = JOURNAL_HEADER.to_vec();
    let mut previous = genesis_digest();
    for payloads in transactions {
        let (encoded, digest) = transaction(previous, payloads);
        image.extend_from_slice(&encoded);
        previous = digest;
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

fn snapshot(record: &naome_ledger::AcceptedProofRecord) -> RecordSnapshot {
    RecordSnapshot {
        bytes: record.canonical_proof_bytes().to_vec(),
        proof_id: record.proof_id(),
        dependencies: record.direct_dependencies().to_vec(),
    }
}
