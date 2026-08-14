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
use naome_proof::{DerivationId, ProofCertificate, ProofId, ProofStep, StatementId};
use naome_storage::{
    CanonicalProofPayloadStore, ProofBlockCandidateInsertOutcome, ProofBlockCandidateStore,
    ProofBlockCandidateStoreLimits, ProofChainJournal, ProofPayloadInsertOutcome,
    ProofPayloadStoreLimits,
};

const SELF_EQUALITY: &str = r#"
foundation = "naome:zfc"
statement = forall(x, equal(x, x))
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    return p1
"#;

const NESTED_SELF_EQUALITY: &str = r#"
foundation = "naome:zfc"
statement = forall(y, forall(x, equal(x, x)))
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    p2 = generalization(p1, y)
    return p2
"#;

const LONG_SELECTED_DEPENDENCY_PROOF: &str = r#"
foundation = "naome:zfc"
statement = forall(a, forall(set,
    implies(member(a, set), member(a, set))
))

proof:
    p0 = cite("c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73")
    p1 = cite("6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720")
    p2 = cite("dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285")
    p3 = cite("e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71")
    p4 = cite("7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d")

    p5 = simplification(
        forall(x, equal(x, x)),
        forall(y, equal(y, y)),
    )
    p6 = modus_ponens(p0, p5)
    p7 = modus_ponens(p1, p6)

    p8 = universal_instantiation(x, a, equal(x, x))
    p9 = modus_ponens(p7, p8)

    p10 = universal_instantiation(
        x,
        a,
        implies(equal(x, x), equal(x, x)),
    )
    p11 = modus_ponens(p2, p10)
    p12 = modus_ponens(p9, p11)

    p13 = simplification(
        equal(a, a),
        forall(x, forall(y,
            implies(
                forall(z, iff(member(z, x), member(z, y))),
                equal(x, y),
            ),
        )),
    )
    p14 = modus_ponens(p12, p13)
    p15 = modus_ponens(p4, p14)

    p16 = universal_instantiation(
        x,
        a,
        forall(y, forall(s,
            implies(
                equal(x, y),
                implies(member(x, s), member(y, s)),
            ),
        )),
    )
    p17 = modus_ponens(p3, p16)

    p18 = universal_instantiation(
        y,
        a,
        forall(s,
            implies(
                equal(a, y),
                implies(member(a, s), member(y, s)),
            ),
        ),
    )
    p19 = modus_ponens(p17, p18)

    p20 = universal_instantiation(
        s,
        set,
        implies(
            equal(a, a),
            implies(member(a, s), member(a, s)),
        ),
    )
    p21 = modus_ponens(p19, p20)

    p22 = modus_ponens(p15, p21)
    p23 = generalization(p22, set)
    p24 = generalization(p23, a)
    return p24
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
        "foundation = \"naome:zfc\" statement = forall(y, forall(x, equal(x, x))) proof: p0 = cite(\"{encoded}\") p1 = generalization(p0, y) return p1"
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

fn hex32(encoded: &str) -> [u8; 32] {
    assert_eq!(encoded.len(), 64);
    let mut bytes = [0_u8; 32];
    for (pair, byte) in encoded.as_bytes().chunks_exact(2).zip(&mut bytes) {
        let high = char::from(pair[0]).to_digit(16).unwrap();
        let low = char::from(pair[1]).to_digit(16).unwrap();
        *byte = u8::try_from((high << 4) | low).unwrap();
    }
    bytes
}

#[test]
fn long_agent_style_proof_uses_only_selected_exact_dependencies_without_mutation() {
    let directory = TestDirectory::new();
    let definition = ProofChainDefinition::new([0x21; 32]);
    let mut journal = ProofChainJournal::create(&directory.path, definition).unwrap();

    for source in [
        include_str!("../../../examples/self-equality.nao"),
        include_str!("../../../examples/quantifier-instantiation.nao"),
        include_str!("../../../examples/implication-identity.nao"),
        include_str!("../../../examples/equality-substitution.nao"),
        include_str!("../../../examples/extensionality.nao"),
    ] {
        let dependency = compile(source).unwrap();
        let block = journal.prepare_block(vec![dependency.proof_id()]).unwrap();
        journal
            .apply_block(
                &block,
                vec![AddressedProofCandidate::new(
                    dependency.proof_id(),
                    dependency.canonical_proof_bytes().to_vec(),
                )],
            )
            .unwrap();
    }

    let journal_image = directory.read("proof-chain.journal");
    let head = journal.head_block_id().unwrap();
    let root = journal.proof_set_root().unwrap();
    let len = journal.len().unwrap();

    let compiled =
        compile_against_selected_chain(LONG_SELECTED_DEPENDENCY_PROOF, &journal).unwrap();
    assert_eq!(
        compiled.statement_id(),
        StatementId::from_bytes(hex32(
            "82ee04b9082115a985aa3a669bccab902c6108da31cfba242dcb533334656dba"
        ))
    );
    assert_eq!(
        compiled.derivation_id(),
        DerivationId::from_bytes(hex32(
            "65664aa8ff799d4d82f7cf1dd88aa768fdb7e97f9f4b7c010e10e3813e2ad322"
        ))
    );
    assert_eq!(
        compiled.proof_id(),
        ProofId::from_bytes(hex32(
            "bc81051d252a5012e65369702e205541f3e3d660c7edd11cfb134859951ec10a"
        ))
    );
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    assert_eq!(certificate.steps().len(), 25);
    assert_eq!(
        certificate
            .steps()
            .iter()
            .filter(|step| matches!(step, ProofStep::ProofReference { .. }))
            .count(),
        5
    );
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.proof_set_root().unwrap(), root);
    assert_eq!(journal.len().unwrap(), len);
    assert_eq!(directory.read("proof-chain.journal"), journal_image);
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
