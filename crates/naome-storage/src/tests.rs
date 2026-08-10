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

#[test]
fn journal_header_and_transaction_are_exact_golden_bytes() {
    assert_eq!(JOURNAL_HEADER.len(), 36);
    assert_eq!(GENESIS_DOMAIN.len(), 44);
    assert_eq!(TRANSACTION_DOMAIN.len(), 28);
    assert_eq!(TRANSACTION_MIN_BODY_BYTES, 6);
    assert_eq!(TRANSACTION_MAX_BODY_BYTES, 33_554_465);
    assert_eq!(
        genesis_digest().as_slice(),
        hex_bytes("7127edbfaed6d7b39d6a9ef69b3e3412a5ade11c0c13b2622b0ca33f11523764")
    );

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    assert_eq!(pairing, hex_bytes("000000011001"));
    let (pairing_transaction, digest) =
        transaction(genesis_digest(), std::slice::from_ref(&pairing));
    assert_eq!(
        digest.as_slice(),
        hex_bytes("a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f")
    );
    assert_eq!(
        pairing_transaction,
        hex_bytes(
            "0000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f"
        )
    );
    assert_eq!(
        journal_image(std::slice::from_ref(&pairing)),
        hex_bytes(
            "6e616f6d653a70726f6f662d6461672d7472616e73616374696f6e2d6a6f75726e616c000000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f"
        )
    );

    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap();
    drop(journal);
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        journal_image(&[pairing])
    );
}

#[test]
fn create_open_and_exclusive_lock_preserve_one_empty_journal() {
    let directory = TestDirectory::new();
    let journal = ProofDagJournal::create(&directory.path).unwrap();
    assert!(journal.is_empty().unwrap());
    assert_eq!(journal.len().unwrap(), 0);
    let empty_root = journal.proof_set_root().unwrap();
    let unknown = ProofId::from_bytes([0x55; 32]);
    assert_eq!(
        journal
            .proof_set_proof(unknown)
            .unwrap()
            .verify(empty_root, unknown),
        Ok(ProofSetMembership::Absent)
    );

    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.is_empty().unwrap());
    assert_eq!(reopened.proof_set_root().unwrap(), empty_root);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(reopened);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Create { .. })
    ));
}

#[test]
fn reopen_replays_dependency_chain_exactly() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root = snapshot(
        journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap(),
    );
    let child_bytes = referenced_generalization(root.proof_id, FreeVariable::new(0));
    let child = snapshot(
        journal
            .apply_canonical_proof_bytes(child_bytes.clone())
            .unwrap(),
    );
    let grandchild_bytes = referenced_generalization(child.proof_id, FreeVariable::new(1));
    let grandchild = snapshot(
        journal
            .apply_canonical_proof_bytes(grandchild_bytes.clone())
            .unwrap(),
    );
    assert_eq!(child.dependencies, [root.proof_id]);
    assert_eq!(grandchild.dependencies, [child.proof_id]);
    let expected_root = journal.proof_set_root().unwrap();
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(reopened.len().unwrap(), 3);
    assert_eq!(
        snapshot(reopened.proof(root.proof_id).unwrap().unwrap()),
        root
    );
    assert_eq!(
        snapshot(reopened.proof(child.proof_id).unwrap().unwrap()),
        child
    );
    assert_eq!(
        snapshot(reopened.proof(grandchild.proof_id).unwrap().unwrap()),
        grandchild
    );
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for proof_id in [root.proof_id, child.proof_id, grandchild.proof_id] {
        assert_eq!(
            reopened
                .proof_set_proof(proof_id)
                .unwrap()
                .verify(expected_root, proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn maximum_rooted_batch_is_one_transaction_and_replays_the_complete_closure() {
    let directory = TestDirectory::new();
    let (payloads, proof_ids) = dependency_chain_with_len(PROOF_BATCH_MAX_CANDIDATES);
    let requested_root = *proof_ids.last().unwrap();
    let expected_image = journal_transaction_image(std::slice::from_ref(&payloads));
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();

    let root = journal
        .apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &proof_ids),
        )
        .unwrap();
    assert_eq!(root.proof_id(), requested_root);
    assert_eq!(journal.len().unwrap(), payloads.len());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), expected_image);
    let expected_root = journal.proof_set_root().unwrap();
    for proof_id in &proof_ids {
        assert!(journal.proof(*proof_id).unwrap().is_some());
    }
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(reopened.len().unwrap(), payloads.len());
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for proof_id in proof_ids {
        assert!(reopened.proof(proof_id).unwrap().is_some());
    }
}

#[test]
fn late_address_mismatch_in_rooted_batch_consumes_no_journal_io_or_fault() {
    let (payloads, proof_ids) = dependency_chain();
    let requested_root = *proof_ids.last().unwrap();
    let wrong_id = ProofId::from_bytes([0xa7; 32]);
    let mut wrong_ids = proof_ids.clone();
    wrong_ids[1] = wrong_id;
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
    let volatile_before = core.file.volatile.get_ref().clone();
    let committed_end_before = core.committed_end;
    let chain_digest_before = core.chain_digest;

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &wrong_ids),
        ),
        Err(JournalError::BatchAdmission { source })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 1,
                    expected: Some(expected),
                    source: LedgerError::ProofIdMismatch { actual, .. },
                } if *expected == wrong_id && *actual == proof_ids[1]
            )
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault, Some(fault));
    assert_eq!(core.file.volatile.get_ref(), &volatile_before);
    assert_eq!(core.file.durable, JOURNAL_HEADER);
    assert_eq!(core.committed_end, committed_end_before);
    assert_eq!(core.chain_digest, chain_digest_before);
    assert!(core.ensure_healthy().is_ok());
    assert!(core.dag.is_empty());

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &proof_ids),
        ),
        Err(JournalError::Commit {
            root_proof_id,
            proof_count: 3,
            ..
        }) if root_proof_id == requested_root
    ));
    assert!(core.file.fault.is_none());
    assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
}

#[test]
fn oversized_rooted_batch_fails_before_secondary_allocation_or_journal_io() {
    let requested_root = ProofId::from_bytes([0xf0; 32]);
    let candidates = (0..=PROOF_BATCH_MAX_CANDIDATES)
        .map(|index| {
            let expected = if index == PROOF_BATCH_MAX_CANDIDATES {
                requested_root
            } else {
                ProofId::from_bytes([u8::try_from(index).unwrap(); 32])
            };
            AddressedProofCandidate::new(expected, Vec::new())
        })
        .collect();
    let mut core = JournalCore::empty(ScriptedIo::new(Some(Fault::Seek)));

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(requested_root, candidates),
        Err(JournalError::BatchAdmission { source })
            if matches!(
                source.as_ref(),
                ProofBatchError::TooManyCandidates {
                    actual,
                    maximum: PROOF_BATCH_MAX_CANDIDATES,
                } if *actual == PROOF_BATCH_MAX_CANDIDATES + 1
            )
    ));
    assert_eq!(core.file.fault, Some(Fault::Seek));
    assert!(core.file.trace.is_empty());
    assert!(core.dag.is_empty());
    assert!(core.ensure_healthy().is_ok());
}

#[test]
fn verified_open_checks_the_exact_replayed_set_after_all_format_checks() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap();
    let prefix_root = journal.proof_set_root().unwrap();
    let prefix_len = fs::metadata(directory.journal_path()).unwrap().len();
    let _ = journal
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap();
    let complete_root = journal.proof_set_root().unwrap();
    drop(journal);

    let verified = ProofDagJournal::open_verified(&directory.path, complete_root).unwrap();
    assert_eq!(verified.len().unwrap(), 2);
    drop(verified);

    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == prefix_root && actual == complete_root
    ));

    let mut corrupt = journal_image(&[root_bytes.clone(), union_bytes]);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    directory.write_image(&corrupt);
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::TransactionDigestMismatch { .. })
    ));

    directory.write_image(&journal_image(&[root_bytes]));
    fs::OpenOptions::new()
        .write(true)
        .open(directory.journal_path())
        .unwrap()
        .set_len(prefix_len)
        .unwrap();
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, complete_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == complete_root && actual == prefix_root
    ));
}

#[test]
fn physical_journal_order_does_not_change_the_proof_set_root() {
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);

    let mut first = ProofDagJournal::create(&first_directory.path).unwrap();
    let _ = first.apply_canonical_proof_bytes(pairing.clone()).unwrap();
    let _ = first.apply_canonical_proof_bytes(union.clone()).unwrap();
    let first_root = first.proof_set_root().unwrap();
    drop(first);

    let mut second = ProofDagJournal::create(&second_directory.path).unwrap();
    let _ = second.apply_canonical_proof_bytes(union).unwrap();
    let _ = second.apply_canonical_proof_bytes(pairing).unwrap();
    let second_root = second.proof_set_root().unwrap();
    drop(second);

    assert_eq!(first_root, second_root);
    assert_ne!(
        fs::read(first_directory.journal_path()).unwrap(),
        fs::read(second_directory.journal_path()).unwrap()
    );
}

#[test]
fn rejected_admissions_write_nothing_and_leave_the_journal_healthy() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut union_control = ProofDag::new();
    let union_id = union_control
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap()
        .proof_id();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root_id = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let committed_len = fs::metadata(directory.journal_path()).unwrap().len();
    let committed_root = journal.proof_set_root().unwrap();
    let committed_image = fs::read(directory.journal_path()).unwrap();

    assert_ne!(root_id, union_id);
    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(union_bytes.clone(), root_id),
        Err(JournalError::Admission {
            source: LedgerError::ProofIdMismatch {
                expected,
                actual,
            },
        }) if expected == root_id && actual == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(union_id).unwrap().is_none());

    let locked_child = referenced_generalization(union_id, FreeVariable::new(1));
    assert!(matches!(
        journal.apply_canonical_proof_bytes(locked_child.clone()),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    assert!(matches!(
        journal.apply_canonical_proof_bytes(root_bytes),
        Err(JournalError::Admission {
            source: LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            }
        })
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    let missing_id = ProofId::from_bytes([0x55; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    assert!(matches!(
        journal.apply_canonical_proof_bytes(missing),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == missing_id
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(root_id).unwrap().is_some());

    let child = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = journal
        .apply_canonical_proof_bytes(child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(child_id).unwrap().is_some());

    let accepted_union = journal
        .apply_canonical_proof_bytes_with_expected_id(union_bytes, union_id)
        .unwrap();
    assert_eq!(accepted_union.proof_id(), union_id);
    let locked_child_id = journal
        .apply_canonical_proof_bytes(locked_child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(locked_child_id).unwrap().is_some());

    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(root_id).unwrap().is_some());
    assert!(reopened.proof(union_id).unwrap().is_some());
    assert!(reopened.proof(locked_child_id).unwrap().is_some());
}

#[test]
fn formula_node_limit_rejection_is_atomic_and_complete_replay_fails_closed() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let next_bytes = axiom_bytes(ZfcAxiom::Union);
    let over_budget = over_formula_node_budget_bytes();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root_id = journal
        .apply_canonical_proof_bytes(root_bytes)
        .unwrap()
        .proof_id();
    let committed_image = fs::read(directory.journal_path()).unwrap();
    let committed_root = journal.proof_set_root().unwrap();

    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(
            over_budget.clone(),
            ProofId::from_bytes([0x51; 32]),
        ),
        Err(JournalError::Admission {
            source: LedgerError::Decode {
                source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
            },
        }) if maximum == CERTIFICATE_MAX_FORMULA_NODES
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(root_id).unwrap().is_some());

    let next_id = journal
        .apply_canonical_proof_bytes(next_bytes)
        .unwrap()
        .proof_id();
    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(root_id).unwrap().is_some());
    assert!(reopened.proof(next_id).unwrap().is_some());
    drop(reopened);

    let replay_directory = TestDirectory::new();
    let complete_over_budget_image = journal_image(std::slice::from_ref(&over_budget));
    replay_directory.write_image(&complete_over_budget_image);
    assert!(matches!(
        ProofDagJournal::open(&replay_directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Decode {
                        source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                    },
                    ..
                } if *maximum == CERTIFICATE_MAX_FORMULA_NODES
            )
    ));
    assert_eq!(
        fs::read(replay_directory.journal_path()).unwrap(),
        complete_over_budget_image
    );
}

#[test]
fn every_incomplete_final_transaction_recovers_only_the_committed_prefix() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let full = journal_image(&[root_bytes.clone(), union_bytes.clone()]);
    let prefix = journal_image(std::slice::from_ref(&root_bytes));
    let (root_id, prefix_root) = {
        let directory = TestDirectory::new();
        let mut journal = ProofDagJournal::create(&directory.path).unwrap();
        let root_id = journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        (root_id, journal.proof_set_root().unwrap())
    };

    for cut in prefix.len()..full.len() {
        let directory = TestDirectory::new();
        directory.write_image(&full[..cut]);
        let mut recovered = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(recovered.len().unwrap(), 1, "cut={cut}");
        assert!(recovered.proof(root_id).unwrap().is_some(), "cut={cut}");
        assert_eq!(
            recovered.proof_set_root().unwrap(),
            prefix_root,
            "cut={cut}"
        );
        assert_eq!(
            fs::metadata(directory.journal_path()).unwrap().len(),
            prefix.len() as u64,
            "cut={cut}"
        );

        let child_bytes = referenced_generalization(root_id, FreeVariable::new(3));
        let child_id = recovered
            .apply_canonical_proof_bytes(child_bytes)
            .unwrap()
            .proof_id();
        drop(recovered);
        let reopened = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(reopened.len().unwrap(), 2, "cut={cut}");
        assert!(reopened.proof(child_id).unwrap().is_some(), "cut={cut}");
    }

    let directory = TestDirectory::new();
    directory.write_image(&full);
    assert_eq!(
        ProofDagJournal::open(&directory.path)
            .unwrap()
            .len()
            .unwrap(),
        2
    );
}

#[test]
fn complete_corruption_deletion_and_reordering_fail_closed() {
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let infinity = axiom_bytes(ZfcAxiom::Infinity);
    let (root_transaction, root_digest) =
        transaction(genesis_digest(), std::slice::from_ref(&root));
    let (union_transaction, union_digest) = transaction(root_digest, std::slice::from_ref(&union));
    let (infinity_transaction, _) = transaction(union_digest, std::slice::from_ref(&infinity));

    for index in 9..union_transaction.len() {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&root_transaction);
        let union_start = image.len();
        image.extend_from_slice(&union_transaction);
        image.extend_from_slice(&infinity_transaction);
        image[union_start + index] ^= 0x01;
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::TransactionDigestMismatch { transaction: 1, .. })
        ));
    }

    for transactions in [
        vec![root_transaction.clone(), infinity_transaction.clone()],
        vec![
            root_transaction.clone(),
            infinity_transaction.clone(),
            union_transaction.clone(),
        ],
        vec![
            root_transaction.clone(),
            union_transaction.clone(),
            union_transaction.clone(),
            infinity_transaction.clone(),
        ],
    ] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        for transaction in transactions {
            image.extend_from_slice(&transaction);
        }
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::TransactionDigestMismatch { .. })
        ));
    }

    let directory = TestDirectory::new();
    let mut bad_header = journal_image(&[root]);
    bad_header[0] ^= 1;
    directory.write_image(&bad_header);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::InvalidHeader)
    ));
}

#[test]
fn transaction_lengths_are_preflighted_before_payload_allocation() {
    for actual in [
        0,
        TRANSACTION_MIN_BODY_BYTES - 1,
        TRANSACTION_MAX_BODY_BYTES + 1,
        u32::MAX,
    ] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&actual.to_be_bytes());
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidTransactionLength {
                transaction: 0,
                actual: found,
                ..
            }) if found == actual
        ));
    }

    let directory = TestDirectory::new();
    let mut short_maximum = JOURNAL_HEADER.to_vec();
    short_maximum.extend_from_slice(&TRANSACTION_MAX_BODY_BYTES.to_be_bytes());
    directory.write_image(&short_maximum);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert!(recovered.is_empty().unwrap());
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        JOURNAL_HEADER.len() as u64
    );
}

#[test]
fn transaction_inner_shape_is_preflighted_without_payload_overread() {
    let cases = [
        (vec![0, 0, 0, 0, 1, 0], "zero proof count", 0_u8, None),
        (
            vec![(PROOF_BATCH_MAX_CANDIDATES + 1) as u8, 0, 0, 0, 1, 0],
            "over-limit proof count",
            (PROOF_BATCH_MAX_CANDIDATES + 1) as u8,
            None,
        ),
        (vec![1, 0, 0, 0, 0, 0], "zero proof length", 1, Some(0)),
        (
            {
                let mut body = vec![1];
                body.extend_from_slice(&(CERTIFICATE_MAX_BYTES as u32 + 1).to_be_bytes());
                body.push(0);
                body
            },
            "over-limit proof length",
            1,
            Some(CERTIFICATE_MAX_BYTES as u32 + 1),
        ),
    ];

    for (body, name, proof_count, proof_length) in cases {
        let directory = TestDirectory::new();
        let (encoded, _) = raw_transaction(genesis_digest(), &body);
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&encoded);
        directory.write_image(&image);
        let error = match ProofDagJournal::open(&directory.path) {
            Err(error) => error,
            Ok(_) => panic!("case={name}: malformed transaction opened"),
        };
        if let Some(expected_length) = proof_length {
            assert!(
                matches!(
                    &error,
                    JournalError::InvalidTransactionProofLength {
                        transaction: 0,
                        proof: 0,
                        actual,
                        ..
                    } if *actual == expected_length
                ),
                "case={name}: {error:?}"
            );
        } else {
            assert!(
                matches!(
                    &error,
                    JournalError::InvalidTransactionProofCount {
                        transaction: 0,
                        actual,
                        ..
                    } if *actual == proof_count
                ),
                "case={name}: {error:?}"
            );
        }
    }

    for body in [
        vec![1, 0, 0, 0, 2, 0],
        vec![1, 0, 0, 0, 1, 0, 0],
        vec![2, 0, 0, 0, 1, 0],
    ] {
        let directory = TestDirectory::new();
        let (encoded, _) = raw_transaction(genesis_digest(), &body);
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&encoded);
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidTransactionBody { transaction: 0, .. })
        ));
    }
}

#[test]
fn digest_valid_batch_replay_enforces_dependency_order_and_root_reachability() {
    let (payloads, _) = dependency_chain();
    let reversed = payloads.iter().cloned().rev().collect::<Vec<_>>();
    let directory = TestDirectory::new();
    let reversed_image = journal_transaction_image(&[reversed]);
    directory.write_image(&reversed_image);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Check {
                        source: CheckError::UnknownProofReference { .. },
                    },
                    ..
                }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), reversed_image);

    let unrelated = axiom_bytes(ZfcAxiom::Union);
    let closure_with_unrelated = vec![payloads[0].clone(), unrelated, payloads[1].clone()];
    let directory = TestDirectory::new();
    let unrelated_image = journal_transaction_image(&[closure_with_unrelated]);
    directory.write_image(&unrelated_image);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::UnreachableCandidate { index: 1, .. }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), unrelated_image);
}

#[test]
fn every_batch_payload_and_footer_mutation_fails_the_transaction_digest() {
    let (payloads, _) = dependency_chain();
    let full = journal_transaction_image(std::slice::from_ref(&payloads));
    let transaction_start = JOURNAL_HEADER.len();
    let mut cursor = transaction_start + 4 + 1;
    let mut mutation_offsets = Vec::new();
    for payload in &payloads {
        cursor += 4;
        mutation_offsets.extend(cursor..cursor + payload.len());
        cursor += payload.len();
    }
    mutation_offsets.extend(full.len() - 32..full.len());

    for offset in mutation_offsets {
        let directory = TestDirectory::new();
        let mut mutated = full.clone();
        mutated[offset] ^= 0x01;
        directory.write_image(&mutated);
        assert!(
            matches!(
                ProofDagJournal::open(&directory.path),
                Err(JournalError::TransactionDigestMismatch { transaction: 0, .. })
            ),
            "offset={offset}"
        );
    }
}

#[test]
fn committed_transactions_are_strictly_revalidated_in_physical_order() {
    let malformed = vec![0x00];
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[malformed]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Decode { .. },
                    ..
                }
            )
    ));

    let noncanonical = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
    ])
    .to_canonical_bytes();
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[noncanonical]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::NonCanonicalProof,
                    ..
                }
            )
    ));

    let missing_id = ProofId::from_bytes([0x77; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[missing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Check {
                        source: CheckError::UnknownProofReference { proof_id, .. }
                    },
                    ..
                } if *proof_id == missing_id
            )
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing.clone(), pairing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 1, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::State {
                        source: ProofStateError::DuplicateProof { .. }
                    },
                    ..
                }
            )
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = {
        let mut dag = ProofDag::new();
        dag.apply_canonical_proof_bytes(pairing.clone())
            .unwrap()
            .proof_id()
    };
    let alias = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: pairing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing, alias]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 1, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::State {
                        source: ProofStateError::DuplicateDerivation { .. }
                    },
                    ..
                }
            )
    ));
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fault {
    Seek,
    Write { phase: AppendPhase, after: usize },
    SyncBefore { phase: AppendPhase },
    SyncAfter { phase: AppendPhase },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Trace {
    Write(AppendPhase, usize),
    Sync(AppendPhase),
}

struct ScriptedIo {
    volatile: Cursor<Vec<u8>>,
    durable: Vec<u8>,
    fault: Option<Fault>,
    plain_sync_failure: bool,
    body_written: usize,
    commit_written: usize,
    trace: Vec<Trace>,
}

impl ScriptedIo {
    fn new(fault: Option<Fault>) -> Self {
        Self {
            volatile: Cursor::new(JOURNAL_HEADER.to_vec()),
            durable: JOURNAL_HEADER.to_vec(),
            fault,
            plain_sync_failure: false,
            body_written: 0,
            commit_written: 0,
            trace: Vec::new(),
        }
    }

    fn from_images(visible: Vec<u8>, durable: Vec<u8>) -> Self {
        Self {
            volatile: Cursor::new(visible),
            durable,
            fault: None,
            plain_sync_failure: false,
            body_written: 0,
            commit_written: 0,
            trace: Vec::new(),
        }
    }

    fn phase_written(&mut self, phase: AppendPhase) -> &mut usize {
        match phase {
            AppendPhase::Body => &mut self.body_written,
            AppendPhase::Commit => &mut self.commit_written,
        }
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.volatile.read(buffer)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.volatile.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for ScriptedIo {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.fault == Some(Fault::Seek) {
            self.fault = None;
            return Err(io::Error::other("injected append seek failure"));
        }
        self.volatile.seek(position)
    }
}

impl JournalIo for ScriptedIo {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.volatile.get_mut().truncate(size as usize);
        if self.volatile.position() > size {
            self.volatile.set_position(size);
        }
        Ok(())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        if self.plain_sync_failure {
            self.plain_sync_failure = false;
            return Err(io::Error::other("injected stabilization failure"));
        }
        self.durable = self.volatile.get_ref().clone();
        Ok(())
    }

    fn append_write_all(&mut self, phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.trace.push(Trace::Write(phase, bytes.len()));
        let fault = self.fault.clone();
        if let Some(Fault::Write {
            phase: fault_phase,
            after,
        }) = fault
            && fault_phase == phase
        {
            let written_before = *self.phase_written(phase);
            if after <= written_before + bytes.len() {
                let allowed = after.saturating_sub(written_before);
                self.volatile.write_all(&bytes[..allowed])?;
                *self.phase_written(phase) += allowed;
                self.fault = None;
                return Err(io::Error::other("injected append write failure"));
            }
        }

        self.volatile.write_all(bytes)?;
        *self.phase_written(phase) += bytes.len();
        Ok(())
    }

    fn append_sync_all(&mut self, phase: AppendPhase) -> io::Result<()> {
        self.trace.push(Trace::Sync(phase));
        match self.fault.clone() {
            Some(Fault::SyncBefore { phase: fault_phase }) if fault_phase == phase => {
                self.fault = None;
                Err(io::Error::other("injected pre-sync failure"))
            }
            Some(Fault::SyncAfter { phase: fault_phase }) if fault_phase == phase => {
                self.durable = self.volatile.get_ref().clone();
                self.fault = None;
                Err(io::Error::other("injected post-sync failure"))
            }
            _ => {
                self.durable = self.volatile.get_ref().clone();
                Ok(())
            }
        }
    }
}

#[test]
fn expected_proof_id_mismatch_consumes_no_journal_io_or_fault() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut control = ProofDag::new();
    let actual = control
        .apply_canonical_proof_bytes(payload.clone())
        .unwrap()
        .proof_id();
    let expected = ProofId::from_bytes([0x95; 32]);
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
    let volatile_before = core.file.volatile.get_ref().clone();
    let position_before = core.file.volatile.position();
    let committed_end_before = core.committed_end;
    let chain_digest_before = core.chain_digest;

    assert!(matches!(
        core.apply_canonical_proof_bytes_with_expected_id(payload.clone(), expected),
        Err(JournalError::Admission {
            source: LedgerError::ProofIdMismatch {
                expected: mismatch_expected,
                actual: mismatch_actual,
            },
        }) if mismatch_expected == expected && mismatch_actual == actual
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault, Some(fault));
    assert_eq!(core.file.volatile.get_ref(), &volatile_before);
    assert_eq!(core.file.volatile.position(), position_before);
    assert_eq!(core.file.durable, JOURNAL_HEADER);
    assert_eq!(core.committed_end, committed_end_before);
    assert_eq!(core.chain_digest, chain_digest_before);
    assert!(core.ensure_healthy().is_ok());
    assert!(core.dag.is_empty());

    assert!(matches!(
        core.apply_canonical_proof_bytes_with_expected_id(payload, actual),
        Err(JournalError::Commit { root_proof_id, .. }) if root_proof_id == actual
    ));
    assert!(core.file.fault.is_none());
    assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
}

#[test]
fn batch_append_barriers_are_ordered_and_every_ambiguous_failure_is_all_or_none() {
    let (payloads, proof_ids) = dependency_chain();
    let root_id = *proof_ids.last().unwrap();
    let body_write_bytes = 4
        + 1
        + payloads
            .iter()
            .map(|payload| 4 + payload.len())
            .sum::<usize>();
    let mut faults = vec![Fault::Seek];
    faults.extend((0..=body_write_bytes).map(|after| Fault::Write {
        phase: AppendPhase::Body,
        after,
    }));
    faults.extend([
        Fault::SyncBefore {
            phase: AppendPhase::Body,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Body,
        },
    ]);
    faults.extend((0..=32).map(|after| Fault::Write {
        phase: AppendPhase::Commit,
        after,
    }));
    faults.extend([
        Fault::SyncBefore {
            phase: AppendPhase::Commit,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Commit,
        },
    ]);

    for fault in faults {
        let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
        assert!(
            matches!(
                core.apply_rooted_canonical_proof_batch(
                    root_id,
                    addressed_candidates(&payloads, &proof_ids),
                ),
                Err(JournalError::Commit {
                    root_proof_id,
                    proof_count: 3,
                    ..
                }) if root_proof_id == root_id
            ),
            "fault={fault:?}"
        );
        assert!(
            core.file.fault.is_none(),
            "fault was not consumed: {fault:?}"
        );
        assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
        assert!(matches!(
            core.apply_rooted_canonical_proof_batch(
                root_id,
                addressed_candidates(&payloads, &proof_ids),
            ),
            Err(JournalError::Poisoned)
        ));

        let durable = core.file.durable.clone();
        let visible = core.file.volatile.get_ref().clone();
        let durable_contains_proof = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let visible_contains_proof = matches!(
            fault,
            Fault::Write {
                phase: AppendPhase::Commit,
                after: 32..
            } | Fault::SyncBefore {
                phase: AppendPhase::Commit
            } | Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );

        for (name, image, expected_present) in [
            ("durable", durable.clone(), durable_contains_proof),
            ("visible", visible, visible_contains_proof),
        ] {
            let mut replayed =
                JournalCore::replay(ScriptedIo::from_images(image, durable.clone())).unwrap();
            assert_eq!(
                replayed.dag.len(),
                usize::from(expected_present) * payloads.len(),
                "fault={fault:?} image={name}"
            );
            for proof_id in &proof_ids {
                assert_eq!(
                    replayed.dag.proof(*proof_id).is_some(),
                    expected_present,
                    "fault={fault:?} image={name} proof_id={proof_id:?}"
                );
            }
            let expected_image = if expected_present {
                journal_transaction_image(std::slice::from_ref(&payloads))
            } else {
                JOURNAL_HEADER.to_vec()
            };
            assert_eq!(
                replayed.file.durable, expected_image,
                "fault={fault:?} image={name} was not stabilized"
            );

            let retry = replayed.apply_rooted_canonical_proof_batch(
                root_id,
                addressed_candidates(&payloads, &proof_ids),
            );
            if expected_present {
                assert!(matches!(
                    retry,
                    Err(JournalError::BatchAdmission { source })
                        if matches!(
                            source.as_ref(),
                            ProofBatchError::Candidate {
                                index: 0,
                                source: LedgerError::State {
                                    source: ProofStateError::DuplicateProof { .. }
                                },
                                ..
                            }
                        )
                ));
            } else {
                assert!(retry.is_ok(), "fault={fault:?} image={name}");
            }
        }
    }

    let mut success = JournalCore::empty(ScriptedIo::new(None));
    success
        .apply_rooted_canonical_proof_batch(root_id, addressed_candidates(&payloads, &proof_ids))
        .unwrap();
    let mut expected_trace = vec![
        Trace::Write(AppendPhase::Body, 4),
        Trace::Write(AppendPhase::Body, 1),
    ];
    for payload in &payloads {
        expected_trace.push(Trace::Write(AppendPhase::Body, 4));
        expected_trace.push(Trace::Write(AppendPhase::Body, payload.len()));
    }
    expected_trace.extend([
        Trace::Sync(AppendPhase::Body),
        Trace::Write(AppendPhase::Commit, 32),
        Trace::Sync(AppendPhase::Commit),
    ]);
    assert_eq!(success.file.trace, expected_trace);
    assert_eq!(success.file.durable, journal_transaction_image(&[payloads]));
}

#[test]
fn replay_stabilization_failure_returns_no_handle() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let visible = journal_image(&[payload]);
    let mut file = ScriptedIo::from_images(visible, JOURNAL_HEADER.to_vec());
    file.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(file),
        Err(JournalError::Stabilize { .. })
    ));
}

#[test]
fn incomplete_header_and_existing_garbage_never_auto_initialize() {
    for prefix_len in 0..JOURNAL_HEADER.len() {
        let directory = TestDirectory::new();
        directory.write_image(&JOURNAL_HEADER[..prefix_len]);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidHeader)
        ));
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            JOURNAL_HEADER[..prefix_len]
        );
    }

    let directory = TestDirectory::new();
    directory.write_image(b"not a journal");
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Create { .. })
    ));
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        b"not a journal"
    );
}

#[test]
fn complete_footer_mutation_is_never_recovered_as_a_torn_tail() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let mut image = journal_image(&[pairing]);
    let footer_start = image.len() - 32;
    for index in footer_start..image.len() {
        let directory = TestDirectory::new();
        let mut corrupted = image.clone();
        corrupted[index] ^= 0x80;
        directory.write_image(&corrupted);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::TransactionDigestMismatch { transaction: 0, .. })
        ));
    }
    image.truncate(footer_start + 31);
    let directory = TestDirectory::new();
    directory.write_image(&image);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert!(recovered.is_empty().unwrap());
}

#[test]
fn in_range_length_damage_is_explicitly_treated_as_an_incomplete_suffix() {
    let directory = TestDirectory::new();
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let infinity = axiom_bytes(ZfcAxiom::Infinity);
    let prefix = journal_image(std::slice::from_ref(&root));
    let mut image = journal_image(&[root, union, infinity]);
    image[prefix.len()..prefix.len() + 4].copy_from_slice(&100_u32.to_be_bytes());
    directory.write_image(&image);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(recovered.len().unwrap(), 1);
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        prefix.len() as u64
    );
}

#[test]
fn poisoned_public_handle_hides_state_and_keeps_its_lock() {
    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let proof_id = journal
        .apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Pairing))
        .unwrap();
    let proof_id = proof_id.proof_id();
    journal.core.poisoned = true;

    assert!(matches!(
        journal.proof(proof_id),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(journal.len(), Err(JournalError::Poisoned)));
    assert!(matches!(journal.is_empty(), Err(JournalError::Poisoned)));
    assert!(matches!(
        journal.proof_set_root(),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.proof_set_proof(proof_id),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Union)),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(
            axiom_bytes(ZfcAxiom::Union),
            ProofId::from_bytes([0x96; 32]),
        ),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Locked)
    ));

    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(proof_id).unwrap().is_some());
}
