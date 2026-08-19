use std::error::Error as _;

use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_checker::{
    ArtifactState, CheckedProof, check_definition_with_state, normalize_and_check,
    normalize_and_check_with_state,
};
use naome_economy::{FloorQualifiedArtifactBaseFee, NaoAtoms};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate, DefinitionId,
    ProofCertificate, ProofFormula, ProofId, ProofStep,
};

use super::{
    CheckedProofTargetSplitError, SelectedProofTargetSplitError,
    project_checked_proof_target_split, project_selected_proof_target_split,
};

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).expect("the test proof is structurally valid")
}

fn proof_formula(formula: DefinedFormula) -> ProofFormula {
    ProofFormula::from_defined(formula).expect("the test formula is canonically representable")
}

fn observed_artifact(byte: u8) -> ArtifactId {
    ArtifactId::from_bytes([byte; 32])
}

fn qualified_fee(atoms: u128) -> FloorQualifiedArtifactBaseFee {
    FloorQualifiedArtifactBaseFee::try_from_fee_atoms(NaoAtoms::new(atoms)).unwrap()
}

fn checked_proof_artifact_bytes(proof: &CheckedProof) -> Vec<u8> {
    ArtifactPayload::Proof(proof.normal_form().certificate().clone()).to_canonical_bytes()
}

fn apply_selected_artifact(
    chain: &mut ArtifactChainState,
    artifact_id: ArtifactId,
    canonical_artifact_bytes: &[u8],
) {
    let block = chain.prepare_block(artifact_id).unwrap();
    chain
        .apply_block(&block, canonical_artifact_bytes.to_vec())
        .unwrap();
}

struct SelectedMixedProofFixture {
    chain: ArtifactChainState,
    proof: CheckedProof,
    proof_bytes: Vec<u8>,
    proof_artifact_id: ArtifactId,
    targets: [ArtifactId; 2],
    transitive_target: ArtifactId,
}

fn selected_mixed_proof_fixture() -> SelectedMixedProofFixture {
    let variable = FreeVariable::new(13);
    let mut chain = ArtifactChainState::new(ArtifactChainDefinition::new([0x63; 32]));
    let base = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .unwrap();
    let base_id = base.proof_id();
    let base_artifact_id = ArtifactId::from_proof_id(base_id);
    let base_bytes = checked_proof_artifact_bytes(&base);
    let base_conclusion = base.conclusion().clone();
    apply_selected_artifact(&mut chain, base_artifact_id, &base_bytes);

    let source = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id: base_id },
            ProofStep::Simplification {
                antecedent: base_conclusion.into(),
                consequent: ZfcAxiom::Extensionality.formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]),
        chain.artifact_state(),
    )
    .unwrap();
    let source_id = source.proof_id();
    let source_artifact_id = ArtifactId::from_proof_id(source_id);
    let source_bytes = checked_proof_artifact_bytes(&source);
    let theorem = source.conclusion().clone();

    let definition = DefinitionCertificate::relation(
        1,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    let definition_bytes = ArtifactPayload::Definition(definition.clone()).to_canonical_bytes();
    apply_selected_artifact(&mut chain, source_artifact_id, &source_bytes);
    let checked_definition =
        check_definition_with_state(definition, chain.artifact_state()).unwrap();
    let definition_id = checked_definition.definition_id();
    let definition_artifact_id = ArtifactId::from_definition_id(definition_id);
    apply_selected_artifact(&mut chain, definition_artifact_id, &definition_bytes);

    let defined = DefinedFormula::defined_relation(definition_id, [variable]);
    let proof = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference {
                proof_id: source_id,
            },
            ProofStep::Simplification {
                antecedent: theorem.into(),
                consequent: proof_formula(defined),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::Generalization {
                premise: 2,
                variable,
            },
        ]),
        chain.artifact_state(),
    )
    .unwrap();
    let proof_artifact_id = ArtifactId::from_proof_id(proof.proof_id());
    let proof_bytes = checked_proof_artifact_bytes(&proof);

    let mut targets = [source_artifact_id, definition_artifact_id];
    targets.sort_unstable();
    SelectedMixedProofFixture {
        chain,
        proof,
        proof_bytes,
        proof_artifact_id,
        targets,
        transitive_target: base_artifact_id,
    }
}

fn selected_definition_chain() -> (ArtifactChainState, ArtifactId) {
    let definition = DefinitionCertificate::relation(
        1,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    let definition_id = definition.definition_id();
    let definition_artifact_id = ArtifactId::from_definition_id(definition_id);
    let definition_bytes = ArtifactPayload::Definition(definition).to_canonical_bytes();
    let mut chain = ArtifactChainState::new(ArtifactChainDefinition::new([0x64; 32]));
    apply_selected_artifact(&mut chain, definition_artifact_id, &definition_bytes);
    (chain, definition_artifact_id)
}

fn select_relation(state: &mut ArtifactState, body: DefinedFormula) -> DefinitionId {
    let checked = check_definition_with_state(
        DefinitionCertificate::relation(1, body).expect("the relation definition is valid"),
        state,
    )
    .expect("the relation definition checks");
    let definition_id = checked.definition_id();
    state.register_definition(checked).unwrap();
    definition_id
}

fn select_closed_proof(state: &mut ArtifactState) -> (ProofId, Formula) {
    let variable = FreeVariable::new(7);
    let checked = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .unwrap();
    let proof_id = checked.proof_id();
    let conclusion = checked.conclusion().clone();
    state.register_proof(checked).unwrap();
    (proof_id, conclusion)
}

fn proof_using_every_reference(
    references: &[(ProofId, Formula)],
    conclusion_axiom: ZfcAxiom,
) -> ProofCertificate {
    let mut steps = references
        .iter()
        .map(|(proof_id, _)| ProofStep::ProofReference {
            proof_id: *proof_id,
        })
        .collect::<Vec<_>>();
    let conclusion = conclusion_axiom.formula();
    steps.push(ProofStep::ZfcAxiom(conclusion_axiom));
    let mut conclusion_step = u32::try_from(steps.len() - 1).unwrap();

    for (reference_step, (_, premise)) in references.iter().enumerate().rev() {
        let implication_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::Simplification {
            antecedent: conclusion.clone().into(),
            consequent: premise.clone().into(),
        });
        let conditional_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: conclusion_step,
            implication: implication_step,
        });
        conclusion_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: u32::try_from(reference_step).unwrap(),
            implication: conditional_step,
        });
    }

    certificate(steps)
}

fn four_reference_checked_proof() -> (CheckedProof, [ArtifactId; 4]) {
    let mut state = ArtifactState::new();
    let references = [
        ZfcAxiom::Pairing,
        ZfcAxiom::Infinity,
        ZfcAxiom::Choice,
        ZfcAxiom::Extensionality,
    ]
    .into_iter()
    .map(|axiom| {
        let checked = normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(axiom)])).unwrap();
        let proof_id = checked.proof_id();
        state.register_proof(checked).unwrap();
        (proof_id, axiom.formula())
    })
    .collect::<Vec<_>>();
    let checked = normalize_and_check_with_state(
        proof_using_every_reference(&references, ZfcAxiom::Foundation),
        &state,
    )
    .unwrap();
    let mut targets = references
        .iter()
        .map(|(proof_id, _)| ArtifactId::from_proof_id(*proof_id))
        .collect::<Vec<_>>();
    targets.sort_unstable();
    let targets: [ArtifactId; 4] = targets.try_into().unwrap();
    (checked, targets)
}

fn mixed_checked_proof() -> (CheckedProof, [ArtifactId; 2]) {
    let variable = FreeVariable::new(13);
    let mut state = ArtifactState::new();
    let (proof_id, theorem) = select_closed_proof(&mut state);
    let definition_id = select_relation(
        &mut state,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    );
    let defined = DefinedFormula::defined_relation(definition_id, [variable]);
    let implication = ProofStep::Simplification {
        antecedent: theorem.into(),
        consequent: proof_formula(defined),
    };
    let proof_reference = ProofStep::ProofReference { proof_id };
    let checked = normalize_and_check_with_state(
        certificate(vec![
            proof_reference,
            implication,
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::Generalization {
                premise: 2,
                variable,
            },
        ]),
        &state,
    )
    .unwrap();
    let mut targets = [
        ArtifactId::from_proof_id(proof_id),
        ArtifactId::from_definition_id(definition_id),
    ];
    targets.sort_unstable();
    (checked, targets)
}

fn repeated_reference_checked_proof() -> (CheckedProof, ArtifactId) {
    let mut state = ArtifactState::new();
    let (proof_id, theorem) = select_closed_proof(&mut state);
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id },
            ProofStep::ProofReference { proof_id },
            ProofStep::Simplification {
                antecedent: theorem.clone().into(),
                consequent: theorem.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 3,
            },
        ]),
        &state,
    )
    .unwrap();
    (checked, ArtifactId::from_proof_id(proof_id))
}

fn transitive_reference_checked_proof() -> (CheckedProof, ArtifactId, ArtifactId) {
    let mut state = ArtifactState::new();
    let (base_id, theorem) = select_closed_proof(&mut state);
    let intermediate = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id: base_id },
            ProofStep::Simplification {
                antecedent: theorem.into(),
                consequent: ZfcAxiom::Extensionality.formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]),
        &state,
    )
    .unwrap();
    let intermediate_id = intermediate.proof_id();
    state.register_proof(intermediate).unwrap();
    let checked = normalize_and_check_with_state(
        certificate(vec![ProofStep::ProofReference {
            proof_id: intermediate_id,
        }]),
        &state,
    )
    .unwrap();
    (
        checked,
        ArtifactId::from_proof_id(base_id),
        ArtifactId::from_proof_id(intermediate_id),
    )
}

#[test]
fn complete_mixed_targets_are_sorted_and_coupled_to_exact_split() {
    let (proof, targets) = mixed_checked_proof();
    let projected =
        project_checked_proof_target_split(&proof, qualified_fee(13), &[targets[1], targets[0]])
            .unwrap();

    assert_eq!(
        projected.checked_proof_artifact_id(),
        ArtifactId::from_proof_id(proof.proof_id())
    );
    assert_eq!(projected.targets(), targets);
    assert_eq!(projected.citation_pool(), NaoAtoms::new(5));
    assert_eq!(projected.per_target_share(), NaoAtoms::new(2));
    assert_eq!(projected.unassigned_remainder(), NaoAtoms::new(1));
}

#[test]
fn empty_and_proper_subset_lists_remain_external_caller_choices() {
    let (proof, targets) = mixed_checked_proof();

    let empty = project_checked_proof_target_split(&proof, qualified_fee(13), &[]).unwrap();
    assert!(empty.targets().is_empty());
    assert_eq!(empty.citation_pool(), NaoAtoms::new(5));
    assert_eq!(empty.per_target_share(), NaoAtoms::ZERO);
    assert_eq!(empty.unassigned_remainder(), NaoAtoms::new(5));

    let subset =
        project_checked_proof_target_split(&proof, qualified_fee(13), &[targets[1]]).unwrap();
    assert_eq!(subset.targets(), &[targets[1]]);
    assert_eq!(subset.per_target_share(), NaoAtoms::new(5));
    assert_eq!(subset.unassigned_remainder(), NaoAtoms::ZERO);
}

#[test]
fn strict_application_enables_the_same_identity_bound_split_as_the_checked_proof() {
    let SelectedMixedProofFixture {
        mut chain,
        proof,
        proof_bytes,
        proof_artifact_id,
        targets,
        ..
    } = selected_mixed_proof_fixture();
    let block = chain.prepare_block(proof_artifact_id).unwrap();
    let head_before = chain.head_block_id();
    let root_before = chain.artifact_dag().artifact_set_root();
    let len_before = chain.artifact_dag().len();

    chain.validate_block(&block, proof_bytes.clone()).unwrap();
    assert_eq!(chain.head_block_id(), head_before);
    assert_eq!(chain.artifact_dag().artifact_set_root(), root_before);
    assert_eq!(chain.artifact_dag().len(), len_before);
    assert_eq!(
        project_selected_proof_target_split(
            &chain,
            proof_artifact_id,
            qualified_fee(13),
            &[targets[0], targets[0]],
        ),
        Err(SelectedProofTargetSplitError::UnknownArtifact {
            artifact_id: proof_artifact_id,
        })
    );

    chain.apply_block(&block, proof_bytes).unwrap();
    let selected_head = chain.head_block_id();
    let selected_root = chain.artifact_dag().artifact_set_root();
    let selected_len = chain.artifact_dag().len();
    let checked =
        project_checked_proof_target_split(&proof, qualified_fee(13), &[targets[1], targets[0]])
            .unwrap();
    let selected = project_selected_proof_target_split(
        &chain,
        proof_artifact_id,
        qualified_fee(13),
        &[targets[1], targets[0]],
    )
    .unwrap();

    assert_eq!(selected, checked);
    assert_eq!(selected.checked_proof_artifact_id(), proof_artifact_id);
    assert_eq!(selected.targets(), targets);
    assert_eq!(selected.citation_pool(), NaoAtoms::new(5));
    assert_eq!(selected.per_target_share(), NaoAtoms::new(2));
    assert_eq!(selected.unassigned_remainder(), NaoAtoms::new(1));
    assert_eq!(chain.head_block_id(), selected_head);
    assert_eq!(chain.artifact_dag().artifact_set_root(), selected_root);
    assert_eq!(chain.artifact_dag().len(), selected_len);
}

#[test]
fn selected_empty_and_proper_subset_lists_remain_external_caller_choices() {
    let SelectedMixedProofFixture {
        mut chain,
        proof_bytes,
        proof_artifact_id,
        targets,
        ..
    } = selected_mixed_proof_fixture();
    apply_selected_artifact(&mut chain, proof_artifact_id, &proof_bytes);

    let empty =
        project_selected_proof_target_split(&chain, proof_artifact_id, qualified_fee(13), &[])
            .unwrap();
    assert!(empty.targets().is_empty());
    assert_eq!(empty.per_target_share(), NaoAtoms::ZERO);
    assert_eq!(empty.unassigned_remainder(), NaoAtoms::new(5));

    let subset = project_selected_proof_target_split(
        &chain,
        proof_artifact_id,
        qualified_fee(13),
        &[targets[1]],
    )
    .unwrap();
    assert_eq!(subset.targets(), &[targets[1]]);
    assert_eq!(subset.per_target_share(), NaoAtoms::new(5));
    assert_eq!(subset.unassigned_remainder(), NaoAtoms::ZERO);
}

#[test]
fn selected_source_errors_precede_every_target_check() {
    let (chain, definition_artifact_id) = selected_definition_chain();
    let unknown = observed_artifact(0xfa);
    let malformed = [observed_artifact(0x01); 2];

    assert_eq!(
        project_selected_proof_target_split(&chain, unknown, qualified_fee(5), &malformed,),
        Err(SelectedProofTargetSplitError::UnknownArtifact {
            artifact_id: unknown,
        })
    );
    assert_eq!(
        project_selected_proof_target_split(
            &chain,
            definition_artifact_id,
            qualified_fee(5),
            &malformed,
        ),
        Err(SelectedProofTargetSplitError::NotProof {
            artifact_id: definition_artifact_id,
        })
    );
}

#[test]
fn selected_proof_reuses_nested_target_precedence_and_excludes_transitive_ancestors() {
    let SelectedMixedProofFixture {
        mut chain,
        proof_bytes,
        proof_artifact_id,
        targets,
        transitive_target,
        ..
    } = selected_mixed_proof_fixture();
    apply_selected_artifact(&mut chain, proof_artifact_id, &proof_bytes);

    assert_eq!(
        project_selected_proof_target_split(
            &chain,
            proof_artifact_id,
            qualified_fee(5),
            &[targets[1], targets[1]],
        ),
        Err(SelectedProofTargetSplitError::TargetSplit(
            CheckedProofTargetSplitError::DuplicateTarget {
                artifact_id: targets[1],
            },
        ))
    );
    assert_eq!(
        project_selected_proof_target_split(
            &chain,
            proof_artifact_id,
            qualified_fee(5),
            &[transitive_target],
        ),
        Err(SelectedProofTargetSplitError::TargetSplit(
            CheckedProofTargetSplitError::NonDirectTarget {
                artifact_id: transitive_target,
            },
        ))
    );
}

#[test]
fn excessive_length_precedes_duplicates_and_non_direct_targets() {
    let variable = FreeVariable::new(17);
    let proof = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .unwrap();
    let repeated_non_direct = [observed_artifact(0xff); 2];

    assert_eq!(
        project_checked_proof_target_split(&proof, qualified_fee(5), &repeated_non_direct),
        Err(CheckedProofTargetSplitError::TooManyTargets {
            actual: 2,
            maximum: 0,
        })
    );
}

#[test]
fn lowest_duplicate_precedes_non_direct_and_is_order_invariant() {
    let (proof, _) = four_reference_checked_proof();
    let low = observed_artifact(0x01);
    let high = observed_artifact(0xfe);
    let expected = Err(CheckedProofTargetSplitError::DuplicateTarget { artifact_id: low });

    for targets in [[high, low, high, low], [low, high, low, high]] {
        assert_eq!(
            project_checked_proof_target_split(&proof, qualified_fee(5), &targets),
            expected
        );
    }
}

#[test]
fn lowest_non_direct_target_is_order_invariant() {
    let (proof, direct) = four_reference_checked_proof();
    let low = observed_artifact(0x01);
    let high = observed_artifact(0xfe);
    assert!(!direct.contains(&low));
    assert!(!direct.contains(&high));
    let expected = Err(CheckedProofTargetSplitError::NonDirectTarget { artifact_id: low });

    for targets in [[high, direct[0], low], [low, direct[0], high]] {
        assert_eq!(
            project_checked_proof_target_split(&proof, qualified_fee(5), &targets),
            expected
        );
    }
}

#[test]
fn repeated_direct_references_collapse_before_the_count_is_derived() {
    let (proof, target) = repeated_reference_checked_proof();
    assert_eq!(proof.direct_artifact_dependencies().as_ref(), &[target]);

    let projected =
        project_checked_proof_target_split(&proof, qualified_fee(9), &[target]).unwrap();
    assert_eq!(projected.targets(), &[target]);
    assert_eq!(projected.citation_pool(), NaoAtoms::new(3));
    assert_eq!(projected.per_target_share(), NaoAtoms::new(3));
    assert_eq!(projected.unassigned_remainder(), NaoAtoms::ZERO);
}

#[test]
fn transitive_target_is_not_direct() {
    let (proof, transitive, direct) = transitive_reference_checked_proof();
    assert_eq!(proof.direct_artifact_dependencies().as_ref(), &[direct]);
    assert_eq!(
        project_checked_proof_target_split(&proof, qualified_fee(5), &[transitive]),
        Err(CheckedProofTargetSplitError::NonDirectTarget {
            artifact_id: transitive,
        })
    );
}

#[test]
fn maximum_fee_conserves_the_complete_full_width_citation_pool() {
    let (proof, targets) = mixed_checked_proof();
    let projected =
        project_checked_proof_target_split(&proof, qualified_fee(u128::MAX), &targets).unwrap();
    assert_eq!(u128::MAX % 5, 0);
    let expected_pool = 2 * (u128::MAX / 5);
    let target_count = targets.len() as u128;
    let assigned = projected
        .per_target_share()
        .atoms()
        .checked_mul(target_count)
        .unwrap();
    let conserved = assigned
        .checked_add(projected.unassigned_remainder().atoms())
        .unwrap();

    assert_eq!(projected.citation_pool(), NaoAtoms::new(expected_pool));
    assert_eq!(
        projected.per_target_share(),
        NaoAtoms::new(expected_pool / target_count)
    );
    assert_eq!(
        projected.unassigned_remainder(),
        NaoAtoms::new(expected_pool % target_count)
    );
    assert_eq!(conserved, expected_pool);
}

#[test]
fn errors_have_exact_display_and_implement_standard_error() {
    let too_many = CheckedProofTargetSplitError::TooManyTargets {
        actual: 1,
        maximum: 0,
    };
    let duplicate = CheckedProofTargetSplitError::DuplicateTarget {
        artifact_id: observed_artifact(0x12),
    };
    let non_direct = CheckedProofTargetSplitError::NonDirectTarget {
        artifact_id: observed_artifact(0x34),
    };
    let unknown = SelectedProofTargetSplitError::UnknownArtifact {
        artifact_id: observed_artifact(0x56),
    };
    let not_proof = SelectedProofTargetSplitError::NotProof {
        artifact_id: observed_artifact(0x78),
    };
    let nested = SelectedProofTargetSplitError::TargetSplit(non_direct);

    assert_eq!(
        too_many.to_string(),
        "checked-proof citation target slice has 1 entries; the limit is 0"
    );
    assert_eq!(
        duplicate.to_string(),
        format!(
            "checked-proof citation target slice repeats artifact {:?}",
            observed_artifact(0x12)
        )
    );
    assert_eq!(
        non_direct.to_string(),
        format!(
            "artifact {:?} is not a direct dependency of the checked proof",
            observed_artifact(0x34)
        )
    );
    assert_eq!(
        unknown.to_string(),
        format!(
            "artifact {:?} is not selected in the supplied artifact chain",
            observed_artifact(0x56)
        )
    );
    assert_eq!(
        not_proof.to_string(),
        format!(
            "selected artifact {:?} is not a proof",
            observed_artifact(0x78)
        )
    );
    assert_eq!(nested.to_string(), non_direct.to_string());
    assert!(too_many.source().is_none());
    assert!(duplicate.source().is_none());
    assert!(non_direct.source().is_none());
    assert!(unknown.source().is_none());
    assert!(not_proof.source().is_none());
    assert_eq!(nested.source().unwrap().to_string(), non_direct.to_string());
}
