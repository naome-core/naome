use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::{AddressedProofCandidate, ProofChainId, ProofDag};
use naome_foundation::ZfcAxiom;
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofCertificate, ProofId, ProofStep};
use naome_storage::ProofChainJournal;

use super::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofExchangeWireError, ProofRequest,
    ProofResponse, proof_response,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-proof-exchange-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
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

fn response(bytes: Vec<u8>) -> ProofResponse {
    ProofResponse::from_wire_bytes(bytes).unwrap()
}

#[test]
fn request_and_response_wire_contract_is_exact_and_allocation_preserving() {
    let mut request_bytes = [0_u8; PROOF_REQUEST_BYTES];
    for (index, byte) in request_bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    let request = ProofRequest::new(ProofId::from_bytes(request_bytes));
    assert_eq!(request.to_wire_bytes(), request_bytes);
    assert_eq!(
        ProofRequest::from_wire_bytes(&request_bytes).unwrap(),
        request
    );

    for actual in 0..PROOF_REQUEST_BYTES {
        assert_eq!(
            ProofRequest::from_wire_bytes(&request_bytes[..actual]),
            Err(ProofExchangeWireError::InvalidRequestLength {
                actual,
                expected: PROOF_REQUEST_BYTES,
            })
        );
    }
    let mut extended_request = request_bytes.to_vec();
    extended_request.push(0xff);
    assert_eq!(
        ProofRequest::from_wire_bytes(&extended_request),
        Err(ProofExchangeWireError::InvalidRequestLength {
            actual: PROOF_REQUEST_BYTES + 1,
            expected: PROOF_REQUEST_BYTES,
        })
    );

    let unavailable = response(Vec::new());
    assert!(unavailable.is_unavailable());
    assert!(unavailable.into_wire_bytes().is_empty());

    let proof_bytes = axiom_bytes(ZfcAxiom::Pairing);
    assert_eq!(proof_bytes, [0x00, 0x00, 0x00, 0x01, 0x10, 0x01]);
    let proof_pointer = proof_bytes.as_ptr();
    let found = response(proof_bytes);
    assert!(!found.is_unavailable());
    let round_trip = found.into_wire_bytes();
    assert_eq!(round_trip.as_ptr(), proof_pointer);
    assert_eq!(round_trip, [0x00, 0x00, 0x00, 0x01, 0x10, 0x01]);
}

#[test]
fn response_limit_is_the_certificate_limit_and_precedes_proof_parsing() {
    assert_eq!(PROOF_RESPONSE_MAX_BYTES, CERTIFICATE_MAX_BYTES);

    let maximum = vec![0x5a; PROOF_RESPONSE_MAX_BYTES];
    let pointer = maximum.as_ptr();
    let maximum = ProofResponse::from_wire_bytes(maximum).unwrap();
    let maximum = maximum.into_wire_bytes();
    assert_eq!(maximum.len(), PROOF_RESPONSE_MAX_BYTES);
    assert_eq!(maximum.as_ptr(), pointer);

    assert_eq!(
        ProofResponse::from_wire_bytes(vec![0; PROOF_RESPONSE_MAX_BYTES + 1]).unwrap_err(),
        ProofExchangeWireError::ResponseTooLong {
            actual: PROOF_RESPONSE_MAX_BYTES + 1,
            maximum: PROOF_RESPONSE_MAX_BYTES,
        }
    );
}

#[test]
fn serving_borrows_exact_retained_bytes_and_missing_is_only_local() {
    let directory = TestDirectory::new();
    let mut journal =
        ProofChainJournal::create(directory.path(), ProofChainId::from_bytes([0x31; 32])).unwrap();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let mut identity = ProofDag::new();
    let pairing_id = identity
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap();
    let pairing_id = pairing_id.proof_id();
    let block = journal.prepare_block(vec![pairing_id]).unwrap();
    let record = journal
        .apply_block(
            &block,
            vec![AddressedProofCandidate::new(pairing_id, pairing.clone())],
        )
        .unwrap();
    let retained_pointer = record.canonical_proof_bytes().as_ptr();

    let served = proof_response(&journal, ProofRequest::new(pairing_id))
        .unwrap()
        .unwrap();
    assert_eq!(served, pairing);
    assert_eq!(served.as_ptr(), retained_pointer);

    let unknown = ProofId::from_bytes([0xa5; 32]);
    assert!(
        proof_response(&journal, ProofRequest::new(unknown))
            .unwrap()
            .is_none()
    );
}
