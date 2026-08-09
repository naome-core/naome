use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use naome_checker::CheckError;
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofCertificate, ProofId, ProofStep};
use naome_storage::{JournalError, ProofDagJournal};

use super::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofExchangeWireError, ProofRequest,
    ProofResponse, ProofResponseOutcome, admit_proof_response, proof_response,
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

    fn journal_bytes(&self) -> Vec<u8> {
        fs::read(self.path.join("proof-dag.journal")).unwrap()
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
    let mut journal = ProofDagJournal::create(directory.path()).unwrap();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let record = journal
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap();
    let pairing_id = record.proof_id();
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

#[test]
fn unavailable_changes_nothing_even_when_the_requested_proof_is_local() {
    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(directory.path()).unwrap();
    let record = journal
        .apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Pairing))
        .unwrap();
    let request = ProofRequest::new(record.proof_id());
    let before_file = directory.journal_bytes();
    let before_root = journal.proof_set_root().unwrap();
    let before_len = journal.len().unwrap();

    assert_eq!(
        admit_proof_response(&mut journal, request, response(Vec::new())).unwrap(),
        ProofResponseOutcome::Unavailable
    );
    assert_eq!(directory.journal_bytes(), before_file);
    assert_eq!(journal.proof_set_root().unwrap(), before_root);
    assert_eq!(journal.len().unwrap(), before_len);
    assert!(journal.proof(request.proof_id()).unwrap().is_some());
}

#[test]
fn wrong_address_never_unlocks_the_valid_response_body() {
    let source_directory = TestDirectory::new();
    let mut source = ProofDagJournal::create(source_directory.path()).unwrap();
    let union = axiom_bytes(ZfcAxiom::Union);
    let union_id = source
        .apply_canonical_proof_bytes(union.clone())
        .unwrap()
        .proof_id();
    let child = referenced_generalization(union_id, FreeVariable::new(31));

    let target_directory = TestDirectory::new();
    let mut target = ProofDagJournal::create(target_directory.path()).unwrap();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = target
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap()
        .proof_id();
    let wrong_id = ProofId::from_bytes([0xd4; 32]);
    assert_ne!(wrong_id, union_id);

    let before_file = target_directory.journal_bytes();
    let before_root = target.proof_set_root().unwrap();
    let before_len = target.len().unwrap();
    let error = admit_proof_response(
        &mut target,
        ProofRequest::new(wrong_id),
        response(union.clone()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        JournalError::Admission {
            source: LedgerError::ProofIdMismatch { expected, actual },
        } if expected == wrong_id && actual == union_id
    ));
    assert_eq!(target_directory.journal_bytes(), before_file);
    assert_eq!(target.proof_set_root().unwrap(), before_root);
    assert_eq!(target.len().unwrap(), before_len);
    assert!(target.proof(pairing_id).unwrap().is_some());
    assert!(target.proof(union_id).unwrap().is_none());

    assert!(matches!(
        target.apply_canonical_proof_bytes(child.clone()),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. },
            },
        }) if proof_id == union_id
    ));
    assert_eq!(target.proof_set_root().unwrap(), before_root);

    assert_eq!(
        admit_proof_response(
            &mut target,
            ProofRequest::new(union_id),
            response(union.clone()),
        )
        .unwrap(),
        ProofResponseOutcome::Accepted
    );
    target.apply_canonical_proof_bytes(child.clone()).unwrap();

    let control_directory = TestDirectory::new();
    let mut control = ProofDagJournal::create(control_directory.path()).unwrap();
    control.apply_canonical_proof_bytes(pairing).unwrap();
    control.apply_canonical_proof_bytes(union).unwrap();
    control.apply_canonical_proof_bytes(child).unwrap();
    assert_eq!(
        target_directory.journal_bytes(),
        control_directory.journal_bytes()
    );
    assert_eq!(
        target.proof_set_root().unwrap(),
        control.proof_set_root().unwrap()
    );
}

#[test]
fn missing_dependency_is_not_fetched_or_retained_and_retry_is_exact() {
    let source_directory = TestDirectory::new();
    let mut source = ProofDagJournal::create(source_directory.path()).unwrap();
    let parent = axiom_bytes(ZfcAxiom::Pairing);
    let parent_id = source
        .apply_canonical_proof_bytes(parent.clone())
        .unwrap()
        .proof_id();
    let child = referenced_generalization(parent_id, FreeVariable::new(42));
    let child_id = source
        .apply_canonical_proof_bytes(child.clone())
        .unwrap()
        .proof_id();

    let target_directory = TestDirectory::new();
    let mut target = ProofDagJournal::create(target_directory.path()).unwrap();
    let empty_file = target_directory.journal_bytes();
    let empty_root = target.proof_set_root().unwrap();

    for _ in 0..2 {
        assert!(matches!(
            admit_proof_response(
                &mut target,
                ProofRequest::new(child_id),
                response(child.clone()),
            ),
            Err(JournalError::Admission {
                source: LedgerError::Check {
                    source: CheckError::UnknownProofReference { proof_id, .. },
                },
            }) if proof_id == parent_id
        ));
        assert_eq!(target_directory.journal_bytes(), empty_file);
        assert_eq!(target.proof_set_root().unwrap(), empty_root);
        assert!(target.is_empty().unwrap());
    }

    assert_eq!(
        admit_proof_response(
            &mut target,
            ProofRequest::new(parent_id),
            response(parent.clone()),
        )
        .unwrap(),
        ProofResponseOutcome::Accepted
    );
    assert_eq!(
        admit_proof_response(
            &mut target,
            ProofRequest::new(child_id),
            response(child.clone()),
        )
        .unwrap(),
        ProofResponseOutcome::Accepted
    );

    let expected_root = target.proof_set_root().unwrap();
    drop(target);
    let reopened = ProofDagJournal::open_verified(target_directory.path(), expected_root).unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
    assert!(reopened.proof(parent_id).unwrap().is_some());
    assert!(reopened.proof(child_id).unwrap().is_some());
}
