use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::ArtifactDag;
use naome_checker::CheckError;
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{
    ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate,
    ProofCertificate, ProofStep,
};

use super::*;
use crate::fault_io::{Fault, ScriptedIo, Trace, all_append_faults};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-payload-store-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn store_path(&self) -> PathBuf {
        self.path.join(STORE_FILE_NAME)
    }

    fn write_image(&self, bytes: &[u8]) {
        fs::write(self.store_path(), bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn limits(max_entries: usize, max_total_payload_bytes: u64) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(max_entries, max_total_payload_bytes).unwrap()
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

fn relation_definition_bytes() -> Vec<u8> {
    let variable = FreeVariable::new(0);
    ArtifactPayload::Definition(
        DefinitionCertificate::relation(1, DefinedFormula::equal(variable, variable)).unwrap(),
    )
    .to_canonical_bytes()
}

fn admitted(dag: &mut ArtifactDag, bytes: Vec<u8>) -> ArtifactId {
    dag.apply_canonical_artifact_bytes(bytes)
        .unwrap()
        .artifact_id()
}

fn store_prefix() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORE_PREFIX_BYTES as usize);
    bytes.extend_from_slice(STORE_HEADER);
    bytes.extend_from_slice(FOUNDATION_ID.as_bytes());
    bytes
}

fn encoded_entry(artifact_id: ArtifactId, payload: &[u8]) -> Vec<u8> {
    let payload_len = u32::try_from(payload.len()).unwrap();
    let payload_length_bytes = payload_len.to_be_bytes();
    let digest = entry_digest(payload_length_bytes, artifact_id, payload);
    let mut bytes = Vec::with_capacity((ENTRY_FIXED_BYTES + u64::from(payload_len)) as usize);
    bytes.extend_from_slice(&payload_length_bytes);
    bytes.extend_from_slice(artifact_id.as_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&digest);
    bytes
}

fn store_image(entries: &[(ArtifactId, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = store_prefix();
    for (artifact_id, payload) in entries {
        bytes.extend_from_slice(&encoded_entry(*artifact_id, payload));
    }
    bytes
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

#[test]
fn positive_limits_are_explicit_and_exact_duplicate_precedes_capacity() {
    assert_eq!(
        ArtifactPayloadStoreLimits::new(0, 0),
        Err(ArtifactPayloadStoreLimitsError::ZeroMaxEntries)
    );
    assert_eq!(
        ArtifactPayloadStoreLimits::new(0, 1),
        Err(ArtifactPayloadStoreLimitsError::ZeroMaxEntries)
    );
    assert_eq!(
        ArtifactPayloadStoreLimits::new(1, 0),
        Err(ArtifactPayloadStoreLimitsError::ZeroMaxTotalPayloadBytes)
    );

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let policy = limits(1, pairing.len() as u64);
    assert_eq!(policy.max_entries(), 1);
    assert_eq!(policy.max_total_payload_bytes(), pairing.len() as u64);

    let mut pairing_dag = ArtifactDag::new();
    let pairing_id = admitted(&mut pairing_dag, pairing.clone());
    let pairing_record = pairing_dag.artifact(pairing_id).unwrap();
    let mut union_dag = ArtifactDag::new();
    let union_id = admitted(&mut union_dag, union);
    let union_record = union_dag.artifact(union_id).unwrap();
    let directory = TestDirectory::new("limits");
    let mut store = CanonicalArtifactPayloadStore::create(&directory.path, policy).unwrap();
    assert!(
        store
            .get(ArtifactId::from_bytes([0xff; ArtifactId::BYTE_LENGTH]))
            .unwrap()
            .is_none()
    );

    assert_eq!(
        store.insert(pairing_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let committed = fs::read(directory.store_path()).unwrap();
    assert_eq!(
        store.insert(pairing_record).unwrap(),
        ArtifactPayloadInsertOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    assert_eq!(store.len().unwrap(), 1);
    assert_eq!(store.total_payload_bytes().unwrap(), pairing.len() as u64);
    assert!(matches!(
        store.insert(union_record),
        Err(CanonicalArtifactPayloadStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    drop(store);
    let reopened = CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)).unwrap();
    assert_eq!(reopened.limits(), limits(2, 1_000));
    assert_eq!(reopened.len().unwrap(), 1);
    drop(reopened);

    let directory = TestDirectory::new("payload-byte-limit");
    let mut store =
        CanonicalArtifactPayloadStore::create(&directory.path, limits(2, pairing.len() as u64))
            .unwrap();
    assert_eq!(
        store.insert(pairing_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert!(matches!(
        store.insert(union_record),
        Err(CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
            maximum,
            ..
        }) if maximum == pairing.len() as u64
    ));
}

#[test]
fn proof_and_definition_payloads_archive_and_reload_with_exact_tags() {
    let proof_payload = axiom_bytes(ZfcAxiom::Pairing);
    let definition_payload = relation_definition_bytes();
    let mut dag = ArtifactDag::new();
    let proof_artifact_id = admitted(&mut dag, proof_payload.clone());
    let definition_artifact_id = admitted(&mut dag, definition_payload.clone());
    let total = (proof_payload.len() + definition_payload.len()) as u64;
    let directory = TestDirectory::new("mixed-artifacts");
    let mut store =
        CanonicalArtifactPayloadStore::create(&directory.path, limits(2, total)).unwrap();

    assert_eq!(
        store
            .insert(dag.artifact(proof_artifact_id).unwrap())
            .unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(
        store
            .insert(dag.artifact(definition_artifact_id).unwrap())
            .unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(
        store
            .get(proof_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        proof_payload
    );
    assert_eq!(
        store
            .get(definition_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        definition_payload
    );
}

#[test]
fn existing_identity_conflict_precedes_full_store_limits_without_replacement() {
    let canonical = axiom_bytes(ZfcAxiom::Pairing);
    let mut dag = ArtifactDag::new();
    let artifact_id = admitted(&mut dag, canonical);
    let record = dag.artifact(artifact_id).unwrap();
    let conflicting = vec![0xff];
    let image = store_image(&[(artifact_id, conflicting.clone())]);
    let directory = TestDirectory::new("conflict");
    directory.write_image(&image);
    let mut store = CanonicalArtifactPayloadStore::open(&directory.path, limits(1, 1)).unwrap();

    assert!(matches!(
        store.insert(record),
        Err(CanonicalArtifactPayloadStoreError::PayloadConflict { artifact_id: actual })
            if actual == artifact_id
    ));
    assert_eq!(store.len().unwrap(), 1);
    assert_eq!(
        store.total_payload_bytes().unwrap(),
        conflicting.len() as u64
    );
    assert_eq!(fs::read(directory.store_path()).unwrap(), image);
}

#[test]
fn exact_format_golden_binds_foundation_address_payload_and_digest() {
    let variable = FreeVariable::new(42);
    let payload = canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]);
    let mut dag = ArtifactDag::new();
    let artifact_id = admitted(&mut dag, payload.clone());
    let record = dag.artifact(artifact_id).unwrap();
    let directory = TestDirectory::new("golden");
    let mut store =
        CanonicalArtifactPayloadStore::create(&directory.path, limits(1, payload.len() as u64))
            .unwrap();
    assert_eq!(
        store.insert(record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    drop(store);

    assert_eq!(
        fs::read(directory.store_path()).unwrap(),
        hex_bytes(
            "6e616f6d653a61727469666163742d7061796c6f61642d73746f72653a763100\
             6e616f6d653a7a6663\
             00000013\
             c0de06fa90f5d8ba27cf4d97779d2614a3eb819695ac8ac13751df9e1b062798\
             00000000020600000000210000000000000000\
             af6f242f1cfec001cc3b2632e883b5f353812d2175df739c0ff9543f94382108"
                .replace([' ', '\n'], "")
                .as_str(),
        )
    );
}

#[test]
fn complete_header_entry_and_duplicate_corruption_fail_without_recovery() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut dag = ArtifactDag::new();
    let artifact_id = admitted(&mut dag, payload.clone());
    let valid = store_image(&[(artifact_id, payload.clone())]);
    let entry_offset = STORE_PREFIX_BYTES as usize;
    let artifact_id_offset = entry_offset + PAYLOAD_LENGTH_BYTES as usize;
    let payload_offset = artifact_id_offset + ARTIFACT_ID_BYTES as usize;
    let footer_offset = payload_offset + payload.len();

    let directory = TestDirectory::new("wrong-magic");
    let mut wrong_magic = valid.clone();
    wrong_magic[0] ^= 1;
    directory.write_image(&wrong_magic);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)),
        Err(CanonicalArtifactPayloadStoreError::InvalidHeader)
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), wrong_magic);

    let directory = TestDirectory::new("wrong-foundation");
    let mut wrong_foundation = valid.clone();
    wrong_foundation[STORE_HEADER.len()] ^= 1;
    directory.write_image(&wrong_foundation);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)),
        Err(CanonicalArtifactPayloadStoreError::FoundationIdMismatch)
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), wrong_foundation);

    let directory = TestDirectory::new("zero-length");
    let mut zero_length = valid.clone();
    zero_length[entry_offset..entry_offset + 4].copy_from_slice(&0_u32.to_be_bytes());
    directory.write_image(&zero_length);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)),
        Err(CanonicalArtifactPayloadStoreError::InvalidPayloadLength {
            entry: 0,
            actual: 0,
            ..
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), zero_length);

    let directory = TestDirectory::new("oversized-length");
    let mut oversized_length = store_prefix();
    oversized_length.extend_from_slice(
        &u32::try_from(ARTIFACT_PAYLOAD_MAX_BYTES + 1)
            .unwrap()
            .to_be_bytes(),
    );
    directory.write_image(&oversized_length);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(2, u64::MAX)),
        Err(CanonicalArtifactPayloadStoreError::InvalidPayloadLength {
            entry: 0,
            actual,
            maximum,
            ..
        }) if actual == ARTIFACT_PAYLOAD_MAX_BYTES as u32 + 1
            && maximum == ARTIFACT_PAYLOAD_MAX_BYTES as u32
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), oversized_length);

    for (label, offset) in [
        ("artifact-id", artifact_id_offset),
        ("payload", payload_offset),
        ("footer", footer_offset),
    ] {
        let directory = TestDirectory::new(label);
        let mut corrupt = valid.clone();
        corrupt[offset] ^= 1;
        directory.write_image(&corrupt);
        assert!(matches!(
            CanonicalArtifactPayloadStore::open(&directory.path, limits(1, 1)),
            Err(CanonicalArtifactPayloadStoreError::EntryDigestMismatch { entry: 0, .. })
        ));
        assert_eq!(fs::read(directory.store_path()).unwrap(), corrupt);
    }

    let directory = TestDirectory::new("duplicate");
    let mut duplicate = valid.clone();
    duplicate.extend_from_slice(&valid[entry_offset..]);
    directory.write_image(&duplicate);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(1, payload.len() as u64)),
        Err(CanonicalArtifactPayloadStoreError::DuplicateArtifactId {
            entry: 1,
            artifact_id: actual,
            ..
        }) if actual == artifact_id
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), duplicate);
}

#[test]
fn every_incomplete_entry_cut_recovers_only_the_committed_prefix() {
    let first_payload = axiom_bytes(ZfcAxiom::Pairing);
    let second_payload = axiom_bytes(ZfcAxiom::Union);
    let mut first_dag = ArtifactDag::new();
    let first_id = admitted(&mut first_dag, first_payload.clone());
    let mut second_dag = ArtifactDag::new();
    let second_id = admitted(&mut second_dag, second_payload.clone());
    let prefix = store_prefix();
    let first = store_image(&[(first_id, first_payload.clone())]);
    let complete = store_image(&[
        (first_id, first_payload.clone()),
        (second_id, second_payload.clone()),
    ]);

    for cut in prefix.len() + 1..first.len() {
        let directory = TestDirectory::new("first-cut");
        directory.write_image(&first[..cut]);
        let store = CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)).unwrap();
        assert!(store.is_empty().unwrap(), "cut={cut}");
        drop(store);
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            prefix,
            "cut={cut}"
        );
    }

    for cut in first.len() + 1..complete.len() {
        let directory = TestDirectory::new("second-cut");
        directory.write_image(&complete[..cut]);
        let store = CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)).unwrap();
        assert_eq!(store.len().unwrap(), 1, "cut={cut}");
        assert!(store.contains(first_id).unwrap(), "cut={cut}");
        assert!(!store.contains(second_id).unwrap(), "cut={cut}");
        drop(store);
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            first,
            "cut={cut}"
        );
    }

    let directory = TestDirectory::new("invalid-four-byte-tail");
    let mut invalid = prefix.clone();
    invalid.extend_from_slice(&0_u32.to_be_bytes());
    directory.write_image(&invalid);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)),
        Err(CanonicalArtifactPayloadStoreError::InvalidPayloadLength {
            entry: 0,
            actual: 0,
            ..
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), invalid);

    let second_entry = encoded_entry(second_id, &second_payload);
    let mut incomplete = first.clone();
    incomplete.extend_from_slice(&second_entry[..PAYLOAD_LENGTH_BYTES as usize + 1]);
    let directory = TestDirectory::new("tail-does-not-consume-capacity");
    directory.write_image(&incomplete);
    let store =
        CanonicalArtifactPayloadStore::open(&directory.path, limits(1, first_payload.len() as u64))
            .unwrap();
    assert_eq!(store.len().unwrap(), 1);
    drop(store);
    assert_eq!(fs::read(directory.store_path()).unwrap(), first);

    let mut over_limit_with_tail = first.clone();
    over_limit_with_tail.extend_from_slice(&second_entry[..3]);
    let directory = TestDirectory::new("committed-capacity-precedes-tail-recovery");
    directory.write_image(&over_limit_with_tail);
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(
            &directory.path,
            limits(1, first_payload.len() as u64 - 1),
        ),
        Err(CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded { .. })
    ));
    assert_eq!(
        fs::read(directory.store_path()).unwrap(),
        over_limit_with_tail
    );
}

#[test]
fn replay_accepts_unique_entries_in_any_order_but_enforces_local_limits() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let mut pairing_dag = ArtifactDag::new();
    let pairing_id = admitted(&mut pairing_dag, pairing.clone());
    let mut union_dag = ArtifactDag::new();
    let union_id = admitted(&mut union_dag, union.clone());
    let reversed = store_image(&[(union_id, union.clone()), (pairing_id, pairing.clone())]);
    let directory = TestDirectory::new("order-independent");
    directory.write_image(&reversed);
    let mut store = CanonicalArtifactPayloadStore::open(&directory.path, limits(2, 1_000)).unwrap();
    assert_eq!(store.len().unwrap(), 2);
    assert_eq!(
        store
            .get(pairing_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        pairing
    );
    assert_eq!(
        store
            .get(union_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        union
    );
    drop(store);

    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, limits(1, 1_000)),
        Err(CanonicalArtifactPayloadStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1
        })
    ));
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(
            &directory.path,
            limits(2, (pairing.len() + union.len() - 1) as u64),
        ),
        Err(CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded { .. })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), reversed);
}

#[test]
fn exclusive_lock_is_independent_of_store_creation_and_released_on_drop() {
    let directory = TestDirectory::new("lock");
    let policy = limits(1, 100);
    let store = CanonicalArtifactPayloadStore::create(&directory.path, policy).unwrap();
    assert!(matches!(
        CanonicalArtifactPayloadStore::create(&directory.path, policy),
        Err(CanonicalArtifactPayloadStoreError::Locked)
    ));
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(&directory.path, policy),
        Err(CanonicalArtifactPayloadStoreError::Locked)
    ));
    drop(store);
    assert!(matches!(
        CanonicalArtifactPayloadStore::create(&directory.path, policy),
        Err(CanonicalArtifactPayloadStoreError::Create { .. })
    ));
    let reopened = CanonicalArtifactPayloadStore::open(&directory.path, policy).unwrap();
    assert!(reopened.is_empty().unwrap());
}

#[test]
fn loaded_payload_requires_context_revalidation_and_is_owned() {
    let dependency_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut source = ArtifactDag::new();
    let dependency_artifact_id = admitted(&mut source, dependency_bytes.clone());
    let dependency_proof_id = source
        .artifact(dependency_artifact_id)
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let child_bytes = canonical_bytes(vec![
        ProofStep::ProofReference {
            proof_id: dependency_proof_id,
        },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ]);
    let child_artifact_id = admitted(&mut source, child_bytes.clone());
    let child_record = source.artifact(child_artifact_id).unwrap();
    let directory = TestDirectory::new("context-revalidation");
    let mut store =
        CanonicalArtifactPayloadStore::create(&directory.path, limits(1, 1_000)).unwrap();
    assert_eq!(
        store.insert(child_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );

    let loaded = store.get(child_artifact_id).unwrap().unwrap();
    assert_eq!(loaded.artifact_id(), child_artifact_id);
    assert_eq!(loaded.canonical_artifact_bytes(), child_bytes);
    let mut fresh = ArtifactDag::new();
    assert_eq!(
        fresh.apply_canonical_artifact_bytes_with_expected_id(
            loaded.canonical_artifact_bytes().to_vec(),
            child_artifact_id,
        ),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: dependency_proof_id,
            }
        })
    );

    fresh
        .apply_canonical_artifact_bytes_with_expected_id(dependency_bytes, dependency_artifact_id)
        .unwrap();
    fresh
        .apply_canonical_artifact_bytes_with_expected_id(
            loaded.canonical_artifact_bytes().to_vec(),
            child_artifact_id,
        )
        .unwrap();

    let mut mutated = loaded.into_canonical_artifact_bytes().into_vec();
    mutated[0] ^= 1;
    assert_ne!(mutated, child_bytes);
    assert_eq!(
        store
            .get(child_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        child_bytes
    );
}

#[test]
fn archive_does_not_impose_global_derivation_or_dependency_state() {
    let variable = FreeVariable::new(7);
    let theorem = Formula::for_all(variable, Formula::equal(variable, variable));
    let consequent = ZfcAxiom::Pairing.formula();
    let inline_bytes = canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
        ProofStep::Simplification {
            antecedent: theorem.clone().into(),
            consequent: consequent.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
    ]);
    let mut inline_context = ArtifactDag::new();
    let inline_id = admitted(&mut inline_context, inline_bytes);

    let dependency_bytes = canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]);
    let mut cited_context = ArtifactDag::new();
    let dependency_artifact_id = admitted(&mut cited_context, dependency_bytes);
    let dependency_proof_id = cited_context
        .artifact(dependency_artifact_id)
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let cited_bytes = canonical_bytes(vec![
        ProofStep::ProofReference {
            proof_id: dependency_proof_id,
        },
        ProofStep::Simplification {
            antecedent: theorem.into(),
            consequent: consequent.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]);
    let cited_id = admitted(&mut cited_context, cited_bytes);
    let inline_record = inline_context.artifact(inline_id).unwrap();
    let cited_record = cited_context.artifact(cited_id).unwrap();
    let inline_proof = inline_record.as_proof().unwrap();
    let cited_proof = cited_record.as_proof().unwrap();
    assert_eq!(inline_proof.statement_id(), cited_proof.statement_id());
    assert_eq!(inline_proof.derivation_id(), cited_proof.derivation_id());
    assert_ne!(inline_id, cited_id);

    let directory = TestDirectory::new("context-neutral");
    let total = inline_record.canonical_artifact_bytes().len()
        + cited_record.canonical_artifact_bytes().len();
    let mut store =
        CanonicalArtifactPayloadStore::create(&directory.path, limits(2, total as u64)).unwrap();
    assert_eq!(
        store.insert(inline_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(
        store.insert(cited_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(store.len().unwrap(), 2);
    assert!(store.get(inline_id).unwrap().is_some());
    assert!(store.get(cited_id).unwrap().is_some());
}

#[test]
fn changed_indexed_bytes_fail_closed_and_poison_every_followup() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut dag = ArtifactDag::new();
    let artifact_id = admitted(&mut dag, payload.clone());
    let record = dag.artifact(artifact_id).unwrap();
    let length_offset = STORE_PREFIX_BYTES;
    let artifact_id_offset = length_offset + PAYLOAD_LENGTH_BYTES;
    let payload_offset = STORE_PREFIX_BYTES + PAYLOAD_LENGTH_BYTES + ARTIFACT_ID_BYTES;
    let footer_offset = payload_offset + payload.len() as u64;
    for (index, (label, offset)) in [
        ("length", length_offset),
        ("artifact-id", artifact_id_offset),
        ("payload", payload_offset),
        ("footer", footer_offset),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = TestDirectory::new(label);
        let policy = limits(1, 1_000);
        let mut store = CanonicalArtifactPayloadStore::create(&directory.path, policy).unwrap();
        assert_eq!(
            store.insert(record).unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.store_path())
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        file.sync_all().unwrap();

        let error = if index % 2 == 0 {
            store.get(artifact_id).unwrap_err()
        } else {
            store.insert(record).unwrap_err()
        };
        assert!(matches!(
            error,
            CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id: actual }
                if actual == artifact_id
        ));
        assert!(matches!(
            store.contains(artifact_id),
            Err(CanonicalArtifactPayloadStoreError::Poisoned)
        ));
        assert!(matches!(
            store.insert(record),
            Err(CanonicalArtifactPayloadStoreError::Poisoned)
        ));
        assert_eq!(store.limits(), policy);
    }

    let directory = TestDirectory::new("truncated-after-open");
    let policy = limits(1, 1_000);
    let mut store = CanonicalArtifactPayloadStore::create(&directory.path, policy).unwrap();
    assert_eq!(
        store.insert(record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let committed_len = fs::metadata(directory.store_path()).unwrap().len();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.store_path())
        .unwrap();
    file.set_len(committed_len - 1).unwrap();
    file.sync_all().unwrap();

    assert!(matches!(
        store.get(artifact_id),
        Err(CanonicalArtifactPayloadStoreError::Read { .. })
    ));
    assert_eq!(store.limits(), policy);
    assert!(matches!(
        store.len(),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
}

fn scripted_io(fault: Option<Fault>) -> ScriptedIo {
    ScriptedIo::new(store_prefix(), fault)
}

#[test]
fn append_barriers_are_ordered_and_every_ambiguous_failure_reopens_old_or_new() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut dag = ArtifactDag::new();
    let artifact_id = admitted(&mut dag, payload.clone());
    let record = dag.artifact(artifact_id).unwrap();
    let policy = limits(1, payload.len() as u64);

    let mut success = ArtifactPayloadStoreCore::empty(scripted_io(None), policy);
    assert_eq!(
        success.insert(record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(
        success.file.trace,
        [
            Trace::Write(AppendPhase::Body, PAYLOAD_LENGTH_BYTES as usize),
            Trace::Write(AppendPhase::Body, ARTIFACT_ID_BYTES as usize),
            Trace::Write(AppendPhase::Body, payload.len()),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, DIGEST_BYTES as usize),
            Trace::Sync(AppendPhase::Commit),
        ]
    );

    let body_bytes = PAYLOAD_LENGTH_BYTES as usize + ARTIFACT_ID_BYTES as usize + payload.len();
    let faults = all_append_faults(body_bytes, DIGEST_BYTES as usize);

    for fault in faults {
        let mut core = ArtifactPayloadStoreCore::empty(scripted_io(Some(fault.clone())), policy);
        assert!(
            matches!(
                core.insert(record),
                Err(CanonicalArtifactPayloadStoreError::Commit {
                    artifact_id: actual,
                    payload_bytes,
                    ..
                }) if actual == artifact_id && payload_bytes == payload.len()
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert!(core.index.is_empty(), "fault={fault:?}");
        assert_eq!(core.total_payload_bytes, 0, "fault={fault:?}");
        assert_eq!(core.committed_end, STORE_PREFIX_BYTES, "fault={fault:?}");
        assert!(matches!(
            core.insert(record),
            Err(CanonicalArtifactPayloadStoreError::Poisoned)
        ));

        let durable = core.file.durable.clone();
        let mut reopened = ArtifactPayloadStoreCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            policy,
        )
        .unwrap();
        assert!(reopened.index.len() <= 1, "fault={fault:?}");
        if reopened.index.is_empty() {
            assert_eq!(reopened.total_payload_bytes, 0, "fault={fault:?}");
        } else {
            assert_eq!(reopened.total_payload_bytes, payload.len() as u64);
            assert_eq!(
                reopened
                    .get(artifact_id)
                    .unwrap()
                    .unwrap()
                    .canonical_artifact_bytes(),
                payload
            );
        }
    }
}

#[test]
fn replay_recovery_and_stabilization_failures_return_no_handle() {
    let mut incomplete = store_prefix();
    incomplete.push(0xff);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        ArtifactPayloadStoreCore::replay(recovery_io, limits(1, 1)),
        Err(CanonicalArtifactPayloadStoreError::Recovery {
            offset: STORE_PREFIX_BYTES,
            ..
        })
    ));

    let mut incomplete = store_prefix();
    incomplete.push(0xff);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.plain_sync_failure = true;
    assert!(matches!(
        ArtifactPayloadStoreCore::replay(recovery_io, limits(1, 1)),
        Err(CanonicalArtifactPayloadStoreError::Recovery {
            offset: STORE_PREFIX_BYTES,
            ..
        })
    ));

    let prefix = store_prefix();
    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix);
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        ArtifactPayloadStoreCore::replay(stabilize_io, limits(1, 1)),
        Err(CanonicalArtifactPayloadStoreError::Stabilize { .. })
    ));
}
