//! Actual mathematical inputs for AB-03 through AB-05, not MVP settlement evidence.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_authoring::{CompiledProof, compile, compile_against_selected_chain};
use naome_chain::ArtifactChainDefinition;
use naome_checker::{
    ArtifactState, CheckError, CheckedProof, check_normal_form_with_state,
    normalize_and_check_with_state,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_storage::ArtifactChainJournal;

const HELPER_H: &str = include_str!("../../../examples/research-mvp/helper-h.nao");
const SOLUTION_A: &str = include_str!("../../../examples/research-mvp/solution-a.nao");
const SOLUTION_B: &str = include_str!("../../../examples/research-mvp/solution-b.nao");
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "naome-research-mvp-fixtures-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create fixture directory: {error}"),
            }
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn check_exact_bytes(bytes: &[u8], state: &ArtifactState) -> CheckedProof {
    let original = ProofCertificate::from_canonical_bytes(bytes).unwrap();
    assert_eq!(original.to_canonical_bytes(), bytes);
    let normalized = normalize_and_check_with_state(original, state).unwrap();
    // No source-only or unreachable material may silently vanish from these
    // original certificates. The exact submitted bytes already are normal form.
    assert_eq!(normalized.normal_form().canonical_bytes(), bytes);
    let strict = check_normal_form_with_state(
        normalized
            .into_normal_form()
            .with_matching_canonical_bytes(bytes.into())
            .unwrap(),
        state,
    )
    .unwrap();
    assert_eq!(strict.normal_form().canonical_bytes(), bytes);
    strict
}

fn selected_source(source: &str) -> (Directory, ArtifactChainJournal, CompiledProof) {
    let directory = Directory::new();
    let mut journal =
        ArtifactChainJournal::create(&directory.0, ArtifactChainDefinition::new([0x41; 32]))
            .unwrap();
    let helper = compile(source).unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(helper.canonical_proof_bytes()).unwrap();
    let block = journal
        .prepare_block(ArtifactId::from_proof_id(helper.proof_id()))
        .unwrap();
    journal
        .apply_block(
            &block,
            ArtifactPayload::Proof(certificate).to_canonical_bytes(),
        )
        .unwrap();
    (directory, journal, helper)
}

#[test]
fn research_mvp_roots_use_real_helper_and_have_distinct_exact_targets() {
    let (_directory, journal, helper) = selected_source(HELPER_H);
    let a = compile_against_selected_chain(SOLUTION_A, &journal).unwrap();
    let b = compile_against_selected_chain(SOLUTION_B, &journal).unwrap();
    let state = journal.artifact_state().unwrap();
    let checked_h = check_exact_bytes(helper.canonical_proof_bytes(), &ArtifactState::new());
    let checked_a = check_exact_bytes(a.canonical_proof_bytes(), state);
    let checked_b = check_exact_bytes(b.canonical_proof_bytes(), state);
    let x = FreeVariable::new(0);
    let h = Formula::for_all(x, Formula::equal(x, x));
    let target_a = Formula::for_all(FreeVariable::new(1), h.clone());
    let core_b = Formula::implies(h.clone(), h.clone());
    let question_b = Formula::negate(core_b.clone());
    assert_eq!(checked_h.conclusion(), &h); // C is exactly this known helper.
    assert_eq!(checked_a.conclusion(), &target_a);
    assert_eq!(checked_b.conclusion(), &core_b); // R3: negative B is REFUTED.
    assert_ne!(checked_b.conclusion(), &question_b);
    assert_ne!(helper.statement_id(), a.statement_id());
    assert_ne!(helper.statement_id(), b.statement_id());
    assert_ne!(a.statement_id(), b.statement_id());
    for checked in [&checked_a, &checked_b] {
        assert_eq!(
            checked.direct_artifact_dependencies().as_ref(),
            &[ArtifactId::from_proof_id(helper.proof_id())]
        );
        assert!(checked.normal_form().certificate().steps().iter().any(|step| {
            matches!(step, ProofStep::ProofReference { proof_id } if *proof_id == helper.proof_id())
        }));
        assert!(checked.normal_form().canonical_bytes().len() <= 64 * 1024);
        assert!(checked.normal_form().certificate().steps().len() <= 4_096);
    }
    assert!(checked_h.direct_artifact_dependencies().is_empty());
    assert!(helper.canonical_proof_bytes().len() + a.canonical_proof_bytes().len() <= 256 * 1024);
    assert_eq!(journal.len().unwrap(), 1); // Authoring never publishes its roots.
}

#[test]
fn research_mvp_b_rechecks_from_exported_helper_bytes_without_original_store() {
    let (directory, journal, helper) = selected_source(HELPER_H);
    let b = compile_against_selected_chain(SOLUTION_B, &journal).unwrap();
    let helper_bytes = helper.canonical_proof_bytes().to_vec();
    let b_bytes = b.canonical_proof_bytes().to_vec();
    drop(journal);
    drop(directory);

    // This is an independent mathematical resolver, not a simulated network.
    let mut independent = ArtifactState::new();
    let missing = normalize_and_check_with_state(
        ProofCertificate::from_canonical_bytes(&b_bytes).unwrap(),
        &independent,
    );
    assert!(
        matches!(missing, Err(CheckError::UnknownProofReference { proof_id, .. }) if proof_id == helper.proof_id())
    );
    let checked_h = check_exact_bytes(&helper_bytes, &independent);
    assert_eq!(checked_h.proof_id(), helper.proof_id());
    independent.register_proof(checked_h).unwrap();
    let checked_b = check_exact_bytes(&b_bytes, &independent);
    assert_eq!(checked_b.proof_id(), b.proof_id());
    assert_eq!(checked_b.statement_id(), b.statement_id());
    assert_eq!(checked_b.derivation_id(), b.derivation_id());

    for bytes in [&helper_bytes, &b_bytes] {
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProofCertificate::from_canonical_bytes(&trailing).is_err());
        assert!(ProofCertificate::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn research_mvp_original_duplicate_and_replaced_b_are_both_actually_valid() {
    let duplicate_source = include_str!("../../../examples/research-mvp/helper-h-duplicate.nao");
    let original_source = include_str!("../../../examples/research-mvp/solution-b-original.nao");
    let (_old_dir, old, helper) = selected_source(HELPER_H);
    let (_staged_dir, staged, duplicate) = selected_source(duplicate_source);
    assert_eq!(helper.statement_id(), duplicate.statement_id());
    assert_ne!(helper.proof_id(), duplicate.proof_id());
    let checked_h = check_exact_bytes(helper.canonical_proof_bytes(), &ArtifactState::new());
    let checked_duplicate =
        check_exact_bytes(duplicate.canonical_proof_bytes(), &ArtifactState::new());
    assert_eq!(checked_h.conclusion(), checked_duplicate.conclusion());
    let original = compile_against_selected_chain(original_source, &staged).unwrap();
    let replaced = compile_against_selected_chain(SOLUTION_B, &old).unwrap();
    let checked_original = check_exact_bytes(
        original.canonical_proof_bytes(),
        staged.artifact_state().unwrap(),
    );
    let checked_replaced = check_exact_bytes(
        replaced.canonical_proof_bytes(),
        old.artifact_state().unwrap(),
    );
    assert_eq!(checked_original.conclusion(), checked_replaced.conclusion());
    assert_eq!(original.statement_id(), replaced.statement_id());
    assert_ne!(original.proof_id(), replaced.proof_id());
    assert_eq!(
        checked_original.direct_artifact_dependencies().as_ref(),
        &[ArtifactId::from_proof_id(duplicate.proof_id())]
    );
    assert_eq!(
        checked_replaced.direct_artifact_dependencies().as_ref(),
        &[ArtifactId::from_proof_id(helper.proof_id())]
    );
    // Demonstrate that the concrete final fixture is precisely the permitted
    // reference rewrite. This is not the MVP parent-selection implementation.
    let steps = ProofCertificate::from_canonical_bytes(original.canonical_proof_bytes())
        .unwrap()
        .steps()
        .iter()
        .map(|step| match step {
            ProofStep::ProofReference { proof_id } if *proof_id == duplicate.proof_id() => {
                ProofStep::ProofReference {
                    proof_id: helper.proof_id(),
                }
            }
            other => other.clone(),
        })
        .collect();
    let rewritten = normalize_and_check_with_state(
        ProofCertificate::new(steps).unwrap(),
        old.artifact_state().unwrap(),
    )
    .unwrap();
    assert_eq!(
        rewritten.normal_form().canonical_bytes(),
        replaced.canonical_proof_bytes()
    );
}
