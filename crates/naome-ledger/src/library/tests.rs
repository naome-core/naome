use super::verification::strict_check;
use super::*;
use crate::profile::{Limits, TimingKind};
use naome_checker::normalize_and_check_with_state;
use naome_foundation::FreeVariable;

type Node = (ProofId, Vec<u8>);

fn author(value: u8) -> AccountId {
    AccountId::from_bytes([value; 32])
}
fn x() -> FreeVariable {
    FreeVariable::new(0)
}
fn h_formula() -> Formula {
    Formula::for_all(x(), Formula::equal(x(), x()))
}
fn checked(steps: Vec<ProofStep>, state: &mut ArtifactState) -> Node {
    let proof =
        normalize_and_check_with_state(ProofCertificate::new(steps).unwrap(), state).unwrap();
    let node = (
        proof.proof_id(),
        proof.normal_form().canonical_bytes().to_vec(),
    );
    state.register_proof(proof).unwrap();
    node
}
fn h(state: &mut ArtifactState) -> Node {
    checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x() },
            ProofStep::Generalization {
                premise: 0,
                variable: x(),
            },
        ],
        state,
    )
}
fn generalize(reference: ProofId, state: &mut ArtifactState) -> Node {
    checked(
        vec![
            ProofStep::ProofReference {
                proof_id: reference,
            },
            ProofStep::Generalization {
                premise: 0,
                variable: x(),
            },
        ],
        state,
    )
}
fn b(reference: ProofId, state: &mut ArtifactState) -> Node {
    checked(
        vec![
            ProofStep::ProofReference {
                proof_id: reference,
            },
            ProofStep::Simplification {
                antecedent: h_formula().into(),
                consequent: h_formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ],
        state,
    )
}
fn question(source: &str) -> CompiledQuestion {
    CompiledQuestion::compile(source, &Profile::lab()).unwrap()
}
fn qa() -> CompiledQuestion {
    question(include_str!(
        "../../../../examples/research-mvp/question-a.nao"
    ))
}
fn qb() -> CompiledQuestion {
    question(include_str!(
        "../../../../examples/research-mvp/question-b.nao"
    ))
}
fn qc() -> CompiledQuestion {
    question(include_str!(
        "../../../../examples/research-mvp/question-c.nao"
    ))
}
fn publish_a() -> (ProofLibrary, Node, Node) {
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let root = generalize(helper.0, &mut state);
    let package = ProofPackage::new(
        author(1),
        root.0,
        vec![root.clone(), helper.clone()],
        &Profile::lab(),
    )
    .unwrap();
    let mut library = ProofLibrary::new();
    let normalized = library.normalize(&package, &qa(), &Profile::lab()).unwrap();
    assert_eq!(normalized.outcome(), ProofOutcome::Proved);
    assert!(normalized.citations().is_empty());
    assert_eq!(normalized.new_proofs().len(), 2);
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 10,
                operation_index: 2,
            },
        )
        .unwrap();
    (library, helper, root)
}

#[test]
fn real_a_group_then_b_refutation_preserves_h_attribution_and_known_c() {
    let (mut library, helper, _) = publish_a();
    let mut state = library.dag.artifact_state().clone();
    let root = b(helper.0, &mut state);
    let package = ProofPackage::new(author(2), root.0, vec![root], &Profile::lab()).unwrap();
    let normalized = library.normalize(&package, &qb(), &Profile::lab()).unwrap();
    assert_eq!(normalized.outcome(), ProofOutcome::Refuted);
    assert_eq!(normalized.citations(), &[helper.0]);
    assert_eq!(normalized.work().checker_calls, 4); // H+B, independently twice.
    assert_eq!(normalized.original_hash(), package.original_hash());
    assert_eq!(library.known_target(&qc()).unwrap().proof_id(), helper.0);
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 20,
                operation_index: 0,
            },
        )
        .unwrap();
    assert_eq!(library.len(), 3);
    assert_eq!(library.lookup(helper.0).unwrap().author(), author(1));
    assert_eq!(library.lookup(helper.0).unwrap().recipient(), author(1));
    assert_eq!(library.lookup(helper.0).unwrap().coordinate().height, 10);
    assert_eq!(
        library.lookup(normalized.root()).unwrap().author(),
        author(2)
    );
    let before = library.encode().unwrap();
    assert!(
        library
            .publish(
                &normalized,
                AdmissionCoordinate {
                    height: 21,
                    operation_index: 0
                }
            )
            .is_err()
    );
    assert_eq!(library.encode().unwrap(), before);
}

#[test]
fn duplicate_helper_substitution_prunes_its_only_dependency_and_recomputes_root() {
    let (library, helper, old_a) = publish_a();
    let mut state = ArtifactState::new();
    // K has A's statement but a different inlined certificate.
    let k = checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x() },
            ProofStep::Generalization {
                premise: 0,
                variable: x(),
            },
            ProofStep::Generalization {
                premise: 1,
                variable: x(),
            },
        ],
        &mut state,
    );
    let duplicate = checked(
        vec![
            ProofStep::ProofReference { proof_id: k.0 },
            ProofStep::UniversalInstantiation {
                variable: x(),
                replacement: x(),
                body: h_formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ],
        &mut state,
    );
    let root = b(duplicate.0, &mut state);
    let package = ProofPackage::new(
        author(2),
        root.0,
        vec![root.clone(), duplicate.clone(), k.clone()],
        &Profile::lab(),
    )
    .unwrap();
    let normalized = library.normalize(&package, &qb(), &Profile::lab()).unwrap();
    assert_eq!(
        normalized.substitutions().get(&duplicate.0),
        Some(&helper.0)
    );
    assert_eq!(normalized.substitutions().get(&k.0), Some(&old_a.0));
    assert_eq!(normalized.citations(), &[helper.0]);
    assert_eq!(normalized.new_proofs().len(), 1);
    assert_ne!(normalized.root(), root.0);
    let expected = b(helper.0, &mut library.dag.artifact_state().clone());
    assert_eq!(normalized.root(), expected.0);
    assert_eq!(normalized.new_proofs()[0].canonical_bytes(), expected.1);
    assert!(ProofPackage::decode(normalized.final_bytes(), &Profile::lab()).is_ok());
}

#[test]
fn different_new_certificates_of_same_statement_include_root_collision() {
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let duplicate = checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x() },
            ProofStep::Simplification {
                antecedent: Formula::equal(x(), x()).into(),
                consequent: Formula::equal(x(), x()).into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: x(),
            },
        ],
        &mut state,
    );
    let package = ProofPackage::new(
        author(1),
        helper.0,
        vec![helper.clone(), duplicate],
        &Profile::lab(),
    )
    .unwrap();
    let library = ProofLibrary::new();
    assert_eq!(
        library
            .normalize(&package, &qc(), &Profile::lab())
            .unwrap_err(),
        ResearchError::Invalid("different new certificates of one exact statement")
    );
    assert!(library.is_empty());
    let coalesced = ProofPackage::new(
        author(1),
        helper.0,
        vec![helper.clone(), helper],
        &Profile::lab(),
    )
    .unwrap();
    assert_eq!(coalesced.certificates().len(), 1);
    assert!(
        library
            .normalize(&coalesced, &qc(), &Profile::lab())
            .is_ok()
    );
}

#[test]
fn invalid_unused_original_and_noncanonical_original_are_not_repaired() {
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let invalid = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: x() },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: x(),
        },
    ])
    .unwrap()
    .to_canonical_bytes();
    let package = ProofPackage::new(
        author(1),
        helper.0,
        vec![helper.clone(), (ProofId::from_bytes([7; 32]), invalid)],
        &Profile::lab(),
    )
    .unwrap();
    let library = ProofLibrary::new();
    let before = library.root();
    assert!(library.normalize(&package, &qc(), &Profile::lab()).is_err());
    let certificate = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(99),
        },
        ProofStep::EqualityReflexivity { variable: x() },
        ProofStep::Generalization {
            premise: 1,
            variable: x(),
        },
    ])
    .unwrap();
    let package = ProofPackage::new(
        author(1),
        helper.0,
        vec![(helper.0, certificate.to_canonical_bytes())],
        &Profile::lab(),
    )
    .unwrap();
    assert_eq!(
        library
            .normalize(&package, &qc(), &Profile::lab())
            .unwrap_err(),
        ResearchError::Invalid("certificate is not strict root normal form")
    );
    assert_eq!(library.root(), before);
}

#[test]
fn cycles_unknown_dependencies_wrong_target_and_known_roots_fail() {
    let one = ProofId::from_bytes([1; 32]);
    let two = ProofId::from_bytes([2; 32]);
    let reference = |id| {
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: id }])
            .unwrap()
            .to_canonical_bytes()
    };
    assert!(
        ProofPackage::new(
            author(1),
            one,
            vec![(one, reference(two)), (two, reference(one))],
            &Profile::lab()
        )
        .is_err()
    );
    let missing =
        ProofPackage::new(author(1), one, vec![(one, reference(two))], &Profile::lab()).unwrap();
    assert!(
        ProofLibrary::new()
            .normalize(&missing, &qc(), &Profile::lab())
            .is_err()
    );
    let (library, helper, _) = publish_a();
    let known = ProofPackage::new(author(2), helper.0, vec![helper], &Profile::lab()).unwrap();
    assert_eq!(
        library
            .normalize(&known, &qc(), &Profile::lab())
            .unwrap_err(),
        ResearchError::Invalid("root target already selected")
    );
    assert_eq!(
        ProofLibrary::new()
            .normalize(&known, &qa(), &Profile::lab())
            .unwrap_err(),
        ResearchError::Invalid("root does not prove an approved target")
    );
}

#[test]
fn canonical_package_order_and_bounds_are_enforced() {
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let root = generalize(helper.0, &mut state);
    let package = ProofPackage::new(
        author(1),
        root.0,
        vec![root.clone(), helper.clone()],
        &Profile::lab(),
    )
    .unwrap();
    let bytes = package.encode().unwrap();
    assert_eq!(
        ProofPackage::decode(&bytes, &Profile::lab()).unwrap(),
        package
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ProofPackage::decode(&trailing, &Profile::lab()).is_err());
    assert!(ProofPackage::decode(&bytes[..bytes.len() - 1], &Profile::lab()).is_err());
    let mut reversed = package.clone();
    reversed.nodes.reverse();
    assert!(ProofPackage::decode(&reversed.encode().unwrap(), &Profile::lab()).is_err());
    let limits = Limits {
        checker_calls_per_record: 1,
        ..Limits::default()
    };
    let small = Profile::with_limits(TimingKind::Lab, limits).unwrap();
    assert!(
        ProofLibrary::new()
            .normalize(&package, &qa(), &small)
            .is_err()
    );
    let limits = Limits {
        package_bytes: bytes.len() as u64 - 1,
        certificate_bytes: bytes.len() as u64 - 1,
        ..Limits::default()
    };
    let small = Profile::with_limits(TimingKind::Lab, limits).unwrap();
    assert!(ProofPackage::decode(&bytes, &small).is_err());
}

#[test]
fn stale_library_parent_prevents_whole_publication_without_mutation() {
    let mut library = ProofLibrary::new();
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let root = generalize(helper.0, &mut state);
    let package = ProofPackage::new(
        author(1),
        root.0,
        vec![helper.clone(), root],
        &Profile::lab(),
    )
    .unwrap();
    let stale = library.normalize(&package, &qa(), &Profile::lab()).unwrap();
    let first = ProofPackage::new(author(2), helper.0, vec![helper], &Profile::lab()).unwrap();
    let first = library.normalize(&first, &qc(), &Profile::lab()).unwrap();
    library
        .publish(
            &first,
            AdmissionCoordinate {
                height: 1,
                operation_index: 0,
            },
        )
        .unwrap();
    let before = library.encode().unwrap();
    assert!(
        library
            .publish(
                &stale,
                AdmissionCoordinate {
                    height: 2,
                    operation_index: 0
                }
            )
            .is_err()
    );
    assert_eq!(library.encode().unwrap(), before);
}

#[test]
fn older_ancestors_are_checked_but_only_first_boundary_proof_is_cited() {
    let (library, helper, old_a) = publish_a();
    let mut state = library.dag.artifact_state().clone();
    let root = generalize(old_a.0, &mut state);
    let task =
        question("foundation = \"naome:zfc\" statement = forall(z,forall(y,forall(x,equal(x,x))))");
    let package = ProofPackage::new(author(2), root.0, vec![root], &Profile::lab()).unwrap();
    let normalized = library.normalize(&package, &task, &Profile::lab()).unwrap();
    assert_eq!(normalized.citations(), &[old_a.0]);
    assert!(!normalized.citations().contains(&helper.0));
    assert_eq!(normalized.work().checker_calls, 6); // H, old A, new root twice.
    for constrained in [
        Limits {
            dependency_proofs: 1,
            citation_proofs: 1,
            ..Limits::default()
        },
        Limits {
            dependency_depth: 1,
            ..Limits::default()
        },
        Limits {
            dependency_bytes: 1,
            ..Limits::default()
        },
    ] {
        let profile = Profile::with_limits(TimingKind::Lab, constrained).unwrap();
        assert!(matches!(
            library.normalize(&package, &task, &profile),
            Err(ResearchError::Limit(_))
        ));
    }
}

#[test]
fn repeated_boundary_paths_count_once_and_new_helpers_are_not_citations() {
    let mut library = ProofLibrary::new();
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let package =
        ProofPackage::new(author(1), helper.0, vec![helper.clone()], &Profile::lab()).unwrap();
    let normalized = library.normalize(&package, &qc(), &Profile::lab()).unwrap();
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 1,
                operation_index: 0,
            },
        )
        .unwrap();
    let u = generalize(helper.0, &mut state);
    let u_formula = Formula::for_all(x(), h_formula());
    let root = checked(
        vec![
            ProofStep::ProofReference { proof_id: u.0 },
            ProofStep::Simplification {
                antecedent: u_formula.into(),
                consequent: h_formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ProofReference { proof_id: helper.0 },
            ProofStep::ModusPonens {
                premise: 3,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 4,
                variable: x(),
            },
        ],
        &mut state,
    );
    let task =
        question("foundation = \"naome:zfc\" statement = forall(z,forall(y,forall(x,equal(x,x))))");
    let package = ProofPackage::new(author(2), root.0, vec![u, root], &Profile::lab()).unwrap();
    let normalized = library.normalize(&package, &task, &Profile::lab()).unwrap();
    assert_eq!(normalized.citations(), &[helper.0]);
    assert_eq!(normalized.new_proofs().len(), 2);
}

#[test]
fn claimed_identity_is_checked_and_package_hash_binds_author_and_root() {
    let mut state = ArtifactState::new();
    let helper = h(&mut state);
    let first =
        ProofPackage::new(author(1), helper.0, vec![helper.clone()], &Profile::lab()).unwrap();
    let second =
        ProofPackage::new(author(2), helper.0, vec![helper.clone()], &Profile::lab()).unwrap();
    assert_ne!(first.original_hash(), second.original_hash());
    let wrong = ProofId::from_bytes([99; 32]);
    let forged =
        ProofPackage::new(author(1), wrong, vec![(wrong, helper.1)], &Profile::lab()).unwrap();
    assert_eq!(
        ProofLibrary::new()
            .normalize(&forged, &qc(), &Profile::lab())
            .unwrap_err(),
        ResearchError::Invalid("claimed proof ID mismatch")
    );
}

#[test]
fn parent_selection_orders_height_operation_then_raw_proof_id() {
    let (base, helper, _) = publish_a();
    let mut state = ArtifactState::new();
    let duplicate = checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x() },
            ProofStep::Simplification {
                antecedent: Formula::equal(x(), x()).into(),
                consequent: Formula::equal(x(), x()).into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: x(),
            },
        ],
        &mut state,
    );
    for (coordinate, expected) in [
        (
            AdmissionCoordinate {
                height: 11,
                operation_index: 0,
            },
            helper.0,
        ),
        (
            AdmissionCoordinate {
                height: 10,
                operation_index: 1,
            },
            duplicate.0,
        ),
        (
            AdmissionCoordinate {
                height: 10,
                operation_index: 2,
            },
            helper.0.min(duplicate.0),
        ),
    ] {
        let mut library = base.clone();
        // Deliberately exercise multiple eligible parent candidates internally.
        // The public fresh-library publication API prohibits this situation and
        // this fixture introduces no legacy-import authority path.
        let checked = strict_check(
            &duplicate.1,
            library.dag.artifact_state(),
            &Profile::lab(),
            &mut VerificationWork::default(),
        )
        .unwrap();
        let older = LibraryProof {
            proof: record(&checked, author(8)),
            coordinate,
        };
        library
            .dag
            .admit_checked_proof(checked, duplicate.0)
            .unwrap();
        Arc::make_mut(&mut library.statements)
            .entry(older.conclusion.encode_canonical().unwrap())
            .or_default()
            .insert((coordinate, older.proof_id));
        Arc::make_mut(&mut library.records).insert(older.proof_id, Arc::new(older));
        library.cached_root = OnceLock::new();
        let mut original_state = ArtifactState::new();
        let submitted_h = h(&mut original_state);
        let submitted_root = b(submitted_h.0, &mut original_state);
        let original = ProofPackage::new(
            author(2),
            submitted_root.0,
            vec![submitted_h.clone(), submitted_root],
            &Profile::lab(),
        )
        .unwrap();
        let normalized = library
            .normalize(&original, &qb(), &Profile::lab())
            .unwrap();
        assert_eq!(
            normalized.substitutions().get(&submitted_h.0),
            Some(&expected)
        );
        assert_eq!(normalized.citations(), &[expected]);
        assert_eq!(
            library.lookup(expected).unwrap().author(),
            if expected == helper.0 {
                author(1)
            } else {
                author(8)
            }
        );
    }
}

#[test]
fn same_derivation_original_alias_is_verified_then_removed_before_publication() {
    let (mut library, helper, _) = publish_a();
    let mut original_state = library.dag.artifact_state().clone();
    let alias = normalize_and_check_with_state(
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: helper.0 }]).unwrap(),
        &original_state,
    )
    .unwrap();
    let alias_node = (
        alias.proof_id(),
        alias.normal_form().canonical_bytes().to_vec(),
    );
    assert_ne!(alias_node.0, helper.0);
    original_state
        .register_proof_for_verification(alias)
        .unwrap();
    let root = b(alias_node.0, &mut original_state);
    let package = ProofPackage::new(
        author(2),
        root.0,
        vec![alias_node.clone(), root],
        &Profile::lab(),
    )
    .unwrap();
    let normalized = library.normalize(&package, &qb(), &Profile::lab()).unwrap();
    assert_eq!(
        normalized.substitutions().get(&alias_node.0),
        Some(&helper.0)
    );
    assert_eq!(normalized.citations(), &[helper.0]);
    assert_eq!(normalized.new_proofs().len(), 1);
    assert!(
        !normalized
            .publication_dag
            .artifact_state()
            .contains_proof(alias_node.0)
    );
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 20,
                operation_index: 0,
            },
        )
        .unwrap();
    assert!(library.lookup(alias_node.0).is_none());
    assert!(!library.dag.artifact_state().contains_proof(alias_node.0));
    assert_eq!(library.lookup(helper.0).unwrap().author(), author(1));
}

#[test]
fn streamed_library_root_matches_full_canonical_encoding() {
    for library in [ProofLibrary::new(), publish_a().0] {
        let expected = hash(
            b"naome:state:proof-library:v1\0",
            &[&library.encode().unwrap()],
        );
        assert_eq!(library.root(), expected);
        assert_eq!(library.clone().root(), expected);
        assert_eq!(library.root(), expected);
    }
}

mod qualification;

mod depth_boundary;

fn assert_dag_exactly_matches_publication(library: &ProofLibrary) {
    use crate::{ArtifactDag, ArtifactSetMembership};
    use naome_proof::{ArtifactId, ArtifactPayload};
    let mut independent = ArtifactDag::new();
    let mut remaining: BTreeSet<_> = library.proofs().map(|p| p.proof_id()).collect();
    while !remaining.is_empty() {
        let id = *remaining
            .iter()
            .find(|id| {
                library
                    .lookup(**id)
                    .unwrap()
                    .dependencies()
                    .iter()
                    .all(|dep| independent.artifact_state().contains_proof(*dep))
            })
            .expect("acyclic publication");
        let proof = library.lookup(id).unwrap();
        let artifact_id = ArtifactId::from_proof_id(id);
        let record = library
            .artifact_dag()
            .artifact(artifact_id)
            .unwrap()
            .as_proof()
            .unwrap();
        assert_eq!(record.canonical_proof_bytes(), proof.canonical_bytes());
        assert_eq!(record.statement_id(), proof.statement_id());
        assert_eq!(
            record
                .direct_proof_dependencies()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            proof.dependencies().iter().copied().collect()
        );
        assert!(record.direct_definition_dependencies().is_empty());
        let bytes = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(proof.canonical_bytes()).unwrap(),
        )
        .to_canonical_bytes();
        independent
            .apply_canonical_artifact_bytes_with_expected_id(bytes, artifact_id)
            .unwrap();
        assert_eq!(
            library
                .artifact_dag()
                .artifact_set_proof(artifact_id)
                .verify(library.artifact_dag().artifact_set_root(), artifact_id)
                .unwrap(),
            ArtifactSetMembership::Present
        );
        remaining.remove(&id);
    }
    assert_eq!(library.len(), library.artifact_dag().len());
    assert_eq!(
        library.artifact_dag().artifact_set_root(),
        independent.artifact_set_root()
    );
}

#[test]
fn artifact_dag_is_exactly_the_atomic_published_library_component() {
    let empty = ProofLibrary::new();
    assert_dag_exactly_matches_publication(&empty);
    let (mut library, helper, _) = publish_a();
    assert_dag_exactly_matches_publication(&library);
    let mut scratch = library.dag.artifact_state().clone();
    let root = b(helper.0, &mut scratch);
    let package = ProofPackage::new(author(2), root.0, vec![root], &Profile::lab()).unwrap();
    let before = library.encode().unwrap();
    let before_dag = library.artifact_dag().artifact_set_root();
    let normalized = library.normalize(&package, &qb(), &Profile::lab()).unwrap();
    assert_eq!(normalized.work().checker_calls, 4); // No unmetered duplicate DAG check.
    assert_eq!(library.encode().unwrap(), before);
    assert_eq!(library.artifact_dag().artifact_set_root(), before_dag);
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 20,
                operation_index: 0,
            },
        )
        .unwrap();
    assert_dag_exactly_matches_publication(&library);
    let before = library.encode().unwrap();
    let before_dag = library.artifact_dag().artifact_set_root();
    assert!(
        library
            .publish(
                &normalized,
                AdmissionCoordinate {
                    height: 21,
                    operation_index: 0
                }
            )
            .is_err()
    );
    assert_eq!(library.encode().unwrap(), before);
    assert_eq!(library.artifact_dag().artifact_set_root(), before_dag);
    assert_dag_exactly_matches_publication(&library);
    // The original parent stays an immutable, isolated component.
    assert_dag_exactly_matches_publication(&empty);
}
