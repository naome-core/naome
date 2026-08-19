use std::error::Error as _;

use naome_checker::{
    ArtifactState, CheckedProof, check_definition_with_state, normalize_and_check,
    normalize_and_check_with_state,
};
use naome_economy::{FloorQualifiedArtifactBaseFee, NaoAtoms};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_proof::{
    ArtifactId, DefinedFormula, DefinitionCertificate, DefinitionId, ProofCertificate,
    ProofFormula, ProofId, ProofStep,
};

use super::{CheckedProofTargetSplitError, project_checked_proof_target_split};

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
    assert!(too_many.source().is_none());
    assert!(duplicate.source().is_none());
    assert!(non_direct.source().is_none());
}
