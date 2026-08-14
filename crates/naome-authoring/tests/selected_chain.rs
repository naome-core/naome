use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_authoring::{
    CompileError, CompiledProof, SelectedChainCompileError, compile, compile_against_selected_chain,
};
use naome_chain::{AddressedProofCandidate, ProofChainDefinition, ProofDag};
use naome_checker::CheckError;
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use naome_storage::{
    CanonicalProofPayloadStore, ProofBlockCandidateInsertOutcome, ProofBlockCandidateStore,
    ProofBlockCandidateStoreLimits, ProofChainJournal, ProofPayloadInsertOutcome,
    ProofPayloadStoreLimits,
};

const SELF_EQUALITY: &str = r#"
foundation "naome:zfc";
theorem equality_is_reflexive {
  statement (forall x (equal x x));
  proof {
    step reflexive = (equality-reflexivity x);
    step universally_reflexive = (generalization reflexive x);
    result universally_reflexive;
  }
}
"#;

const NESTED_SELF_EQUALITY: &str = r#"
foundation "naome:zfc";
theorem nested_equality_is_reflexive {
  statement (forall y (forall x (equal x x)));
  proof {
    step reflexive = (equality-reflexivity x);
    step for_every_x = (generalization reflexive x);
    step for_every_y = (generalization for_every_x y);
    result for_every_y;
  }
}
"#;

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-selected-authoring-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn read(&self, file_name: &str) -> Vec<u8> {
        fs::read(self.path.join(file_name)).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn reference_source(proof_id: ProofId) -> String {
    let mut encoded = String::with_capacity(ProofId::BYTE_LENGTH * 2);
    for byte in proof_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    format!(
        "foundation \"naome:zfc\"; theorem cited {{ statement (forall y (forall x (equal x x))); proof {{ step selected = (proof-reference {encoded}); step extended = (generalization selected y); result extended; }} }}"
    )
}

fn assert_unknown_reference(
    result: Result<CompiledProof, SelectedChainCompileError>,
    expected: ProofId,
) {
    assert!(matches!(
        result,
        Err(SelectedChainCompileError::Compilation {
            source: CompileError::Check {
                source: CheckError::UnknownProofReference { step: 0, proof_id }
            }
        }) if proof_id == expected
    ));
}

#[test]
fn only_exact_journal_selection_authorizes_reference_compilation_without_mutation() {
    let directory = TestDirectory::new();
    let definition = ProofChainDefinition::new([0x11; 32]);
    let dependency = compile(SELF_EQUALITY).unwrap();
    let dependency_id = dependency.proof_id();
    let dependency_bytes = dependency.canonical_proof_bytes().to_vec();
    let source = reference_source(dependency_id);
    let monolithic = compile(NESTED_SELF_EQUALITY).unwrap();

    let mut journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let candidate = journal.prepare_block(vec![dependency_id]).unwrap();
    let candidate_bytes = u64::try_from(candidate.to_canonical_bytes().len()).unwrap();
    let mut candidate_store = ProofBlockCandidateStore::create(
        &directory.path,
        definition,
        ProofBlockCandidateStoreLimits::new(1, candidate_bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(
        candidate_store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );

    let payload_bytes = u64::try_from(dependency_bytes.len()).unwrap();
    let mut archive = CanonicalProofPayloadStore::create(
        &directory.path,
        ProofPayloadStoreLimits::new(1, payload_bytes).unwrap(),
    )
    .unwrap();
    let mut independently_checked = ProofDag::new();
    let record = independently_checked
        .apply_canonical_proof_bytes_with_expected_id(dependency_bytes, dependency_id)
        .unwrap();
    assert_eq!(
        archive.insert(record).unwrap(),
        ProofPayloadInsertOutcome::Inserted
    );

    let empty_journal_image = directory.read("proof-chain.journal");
    let candidate_image = directory.read("proof-block-candidate-store.log");
    let archive_image = directory.read("proof-payload-store.log");
    let empty_head = journal.head_block_id().unwrap();
    let empty_root = journal.proof_set_root().unwrap();

    // Structurally stored and independently checked artifacts remain only
    // candidates. The adapter has no candidate/archive/network fallback.
    assert_unknown_reference(
        compile_against_selected_chain(&source, &journal),
        dependency_id,
    );
    assert_eq!(journal.head_block_id().unwrap(), empty_head);
    assert_eq!(journal.proof_set_root().unwrap(), empty_root);
    assert!(journal.is_empty().unwrap());
    assert_eq!(directory.read("proof-chain.journal"), empty_journal_image);
    assert_eq!(
        directory.read("proof-block-candidate-store.log"),
        candidate_image
    );
    assert_eq!(directory.read("proof-payload-store.log"), archive_image);

    let selected_block = candidate_store.get(candidate.id()).unwrap().unwrap();
    let selected_payload = archive.get(dependency_id).unwrap().unwrap();
    journal
        .apply_block(
            &selected_block,
            vec![AddressedProofCandidate::new(
                dependency_id,
                selected_payload.into_canonical_proof_bytes().into_vec(),
            )],
        )
        .unwrap();

    let selected_journal_image = directory.read("proof-chain.journal");
    let selected_head = journal.head_block_id().unwrap();
    let selected_root = journal.proof_set_root().unwrap();
    let compiled = compile_against_selected_chain(&source, &journal).unwrap();
    assert_eq!(compiled.statement_id(), monolithic.statement_id());
    assert_eq!(compiled.derivation_id(), monolithic.derivation_id());
    assert_ne!(compiled.derivation_id(), dependency.derivation_id());
    assert_ne!(compiled.proof_id(), dependency_id);
    assert_ne!(compiled.proof_id(), monolithic.proof_id());
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    assert!(matches!(
        certificate.steps(),
        [
            ProofStep::ProofReference { proof_id },
            ProofStep::Generalization { premise: 0, .. }
        ] if *proof_id == dependency_id
    ));
    assert_eq!(journal.head_block_id().unwrap(), selected_head);
    assert_eq!(journal.proof_set_root().unwrap(), selected_root);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(
        directory.read("proof-chain.journal"),
        selected_journal_image
    );
    assert_eq!(
        directory.read("proof-block-candidate-store.log"),
        candidate_image
    );
    assert_eq!(directory.read("proof-payload-store.log"), archive_image);

    // Exact ProofId selection admits no statement, derivation, or proof alias.
    let wrong_id = ProofId::from_bytes([0xff; ProofId::BYTE_LENGTH]);
    let wrong_source = reference_source(wrong_id);
    assert_unknown_reference(
        compile_against_selected_chain(&wrong_source, &journal),
        wrong_id,
    );
    assert_eq!(journal.head_block_id().unwrap(), selected_head);
    assert_eq!(journal.proof_set_root().unwrap(), selected_root);
    assert_eq!(
        directory.read("proof-chain.journal"),
        selected_journal_image
    );

    drop(journal);
    let reopened =
        ProofChainJournal::open_verified(&directory.path, definition, selected_head).unwrap();
    let replayed = compile_against_selected_chain(&source, &reopened).unwrap();
    assert_eq!(replayed, compiled);
    assert_eq!(reopened.head_block_id().unwrap(), selected_head);
    assert_eq!(reopened.proof_set_root().unwrap(), selected_root);
    assert_eq!(reopened.len().unwrap(), 1);
    assert_eq!(
        directory.read("proof-chain.journal"),
        selected_journal_image
    );
    assert_eq!(
        directory.read("proof-block-candidate-store.log"),
        candidate_image
    );
    assert_eq!(directory.read("proof-payload-store.log"), archive_image);
}
