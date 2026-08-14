use naome_checker::{CheckError, ProofStateError};
use naome_foundation::{Formula, FreeVariable, LogicError, ZfcAxiom};
use naome_ledger::{AddressedProofCandidate, LedgerError, ProofBatchError};
use naome_proof::{ProofCertificate, ProofId, ProofStep};

use super::{
    PROOF_BATCH_MAX_CANDIDATES, PROOF_BLOCK_MAX_BYTES, PROOF_TRANSITION_MAX_BYTES, ProofBlock,
    ProofBlockApplyError, ProofBlockId, ProofChainDefinition, ProofChainState, ProofDag,
    ProofSetMembership, ProofSetProof, ProofSetRoot, ProofTransition, ProofTransitionApplyError,
    ProofTransitionError,
};

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

fn identity_bytes(variable: FreeVariable) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn identity_detour_bytes(variable: FreeVariable) -> Vec<u8> {
    let equality = Formula::equal(variable, variable);
    canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
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
            variable,
        },
    ])
}

fn proof_citing_both_identities(
    direct: ProofId,
    detour: ProofId,
    variable: FreeVariable,
) -> Vec<u8> {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::for_all(variable, equality);
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id: direct },
        ProofStep::ProofReference { proof_id: detour },
        ProofStep::Simplification {
            antecedent: identity.clone(),
            consequent: identity,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 3,
        },
    ])
}

fn addressed_chain(count: usize) -> (Vec<ProofId>, Vec<Vec<u8>>) {
    assert!(count > 0);
    let mut scratch = ProofDag::new();
    let mut proof_ids = Vec::with_capacity(count);
    let mut payloads = Vec::with_capacity(count);

    let first = axiom_bytes(ZfcAxiom::Pairing);
    let mut previous = scratch
        .apply_canonical_proof_bytes(first.clone())
        .unwrap()
        .proof_id();
    proof_ids.push(previous);
    payloads.push(first);

    for index in 1..count {
        let bytes =
            referenced_generalization(previous, FreeVariable::new(u32::try_from(index).unwrap()));
        previous = scratch
            .apply_canonical_proof_bytes(bytes.clone())
            .unwrap()
            .proof_id();
        proof_ids.push(previous);
        payloads.push(bytes);
    }

    (proof_ids, payloads)
}

fn addressed_candidates(
    proof_ids: &[ProofId],
    payloads: &[Vec<u8>],
) -> Vec<AddressedProofCandidate> {
    proof_ids
        .iter()
        .copied()
        .zip(payloads)
        .map(|(proof_id, bytes)| AddressedProofCandidate::new(proof_id, bytes.clone()))
        .collect()
}

fn proof_id_for(bytes: &[u8]) -> ProofId {
    ProofDag::new()
        .apply_canonical_proof_bytes(bytes.to_vec())
        .unwrap()
        .proof_id()
}

fn proof_chain(byte: u8) -> ProofChainState {
    ProofChainState::new(ProofChainDefinition::new([byte; 32]))
}

fn assert_transition_error_parity(
    dag: &mut ProofDag,
    transition: &ProofTransition,
    candidates: impl Fn() -> Vec<AddressedProofCandidate>,
) -> ProofTransitionApplyError {
    let validation = dag.validate_proof_transition(transition, candidates());
    let application = dag
        .apply_proof_transition(transition, candidates())
        .map(|_| ());
    assert_eq!(validation, application);
    validation.unwrap_err()
}

#[test]
fn direct_child_validation_is_repeatable_non_mutating_and_becomes_stale() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let pairing_id = proof_id_for(&pairing);
    let union_id = proof_id_for(&union);
    let candidate =
        |proof_id, bytes: &Vec<u8>| vec![AddressedProofCandidate::new(proof_id, bytes.clone())];
    let mut selected = proof_chain(0x61);
    let anchor = selected.head_block_id();
    let empty_root = selected.proof_dag().proof_set_root();
    let pairing_witness = selected.proof_dag().proof_set_proof(pairing_id);
    let pairing_block = selected.prepare_block(vec![pairing_id]).unwrap();
    let union_block = selected.prepare_block(vec![union_id]).unwrap();

    assert_eq!(
        selected.validate_block(&pairing_block, candidate(pairing_id, &pairing)),
        Ok(())
    );
    assert_eq!(
        selected.validate_block(&pairing_block, candidate(pairing_id, &pairing)),
        Ok(())
    );
    assert_eq!(
        selected.validate_block(&union_block, candidate(union_id, &union)),
        Ok(())
    );
    assert_eq!(selected.head_block_id(), anchor);
    assert_eq!(selected.proof_dag().proof_set_root(), empty_root);
    assert_eq!(selected.proof_dag().len(), 0);
    assert_eq!(
        selected.proof_dag().proof_set_proof(pairing_id),
        pairing_witness
    );
    assert!(selected.proof_dag().proof(pairing_id).is_none());
    assert!(selected.proof_dag().proof(union_id).is_none());

    selected
        .apply_block(&pairing_block, candidate(pairing_id, &pairing))
        .unwrap();
    let stale = ProofBlockApplyError::ParentBlockIdMismatch {
        expected: pairing_block.id(),
        actual: anchor,
    };
    assert_eq!(
        selected.validate_block(&union_block, candidate(union_id, &union)),
        Err(stale)
    );
}

#[test]
fn direct_child_validation_preserves_application_errors_and_maximum_block() {
    let (proof_ids, payloads) = addressed_chain(PROOF_BATCH_MAX_CANDIDATES);
    let state = proof_chain(0x62);
    let block = state.prepare_block(proof_ids.clone()).unwrap();
    assert_eq!(block.to_canonical_bytes().len(), PROOF_BLOCK_MAX_BYTES);
    assert_eq!(
        state.validate_block(&block, addressed_candidates(&proof_ids, &payloads)),
        Ok(())
    );
    assert_eq!(state.proof_dag().len(), 0);
    assert_eq!(state.head_block_id(), block.parent_block_id());

    let malformed = vec![AddressedProofCandidate::new(proof_ids[0], vec![0])];
    let one_id_block = state.prepare_block(vec![proof_ids[0]]).unwrap();
    let validation_error = state.validate_block(&one_id_block, malformed).unwrap_err();
    let mut application_state = proof_chain(0x62);
    let application_error = application_state
        .apply_block(
            &one_id_block,
            vec![AddressedProofCandidate::new(proof_ids[0], vec![0])],
        )
        .unwrap_err();
    assert_eq!(validation_error, application_error);

    let foreign_parent = ProofBlock::new(
        ProofBlockId::from_bytes([0x99; 32]),
        block.transition().clone(),
    );
    assert!(matches!(
        state.validate_block(
            &foreign_parent,
            vec![AddressedProofCandidate::new(proof_ids[0], vec![0])]
        ),
        Err(ProofBlockApplyError::ParentBlockIdMismatch { .. })
    ));
}

#[test]
fn transition_validation_preserves_every_preflight_error_precedence() {
    let (proof_ids, _) = addressed_chain(2);
    let mut dag = ProofDag::new();
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    let malformed = || {
        proof_ids
            .iter()
            .copied()
            .map(|proof_id| AddressedProofCandidate::new(proof_id, vec![0]))
            .collect::<Vec<_>>()
    };

    let wrong_previous = ProofTransition::new(
        ProofSetRoot::from_bytes([0x91; 32]),
        transition.resulting_proof_set_root(),
        proof_ids.clone(),
    )
    .unwrap();
    assert!(matches!(
        assert_transition_error_parity(&mut dag, &wrong_previous, malformed),
        ProofTransitionApplyError::PreviousProofSetRootMismatch { .. }
    ));

    assert_eq!(
        assert_transition_error_parity(&mut dag, &transition, || {
            vec![AddressedProofCandidate::new(proof_ids[0], vec![0])]
        }),
        ProofTransitionApplyError::CandidateCountMismatch {
            expected: 2,
            actual: 1,
        }
    );

    let wrong_id = ProofId::from_bytes([0x92; 32]);
    assert_eq!(
        assert_transition_error_parity(&mut dag, &transition, || {
            vec![
                AddressedProofCandidate::new(wrong_id, vec![0]),
                AddressedProofCandidate::new(proof_ids[1], vec![0]),
            ]
        }),
        ProofTransitionApplyError::CandidateProofIdMismatch {
            index: 0,
            expected: proof_ids[0],
            actual: wrong_id,
        }
    );

    let wrong_result = ProofTransition::new(
        transition.previous_proof_set_root(),
        ProofSetRoot::from_bytes([0x93; 32]),
        proof_ids.clone(),
    )
    .unwrap();
    assert!(matches!(
        assert_transition_error_parity(&mut dag, &wrong_result, malformed),
        ProofTransitionApplyError::ResultingProofSetRootMismatch { .. }
    ));
    assert!(dag.is_empty());
}

#[test]
fn independent_nodes_have_no_implicit_linear_order() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let unknown = ProofId::from_bytes([0x55; 32]);
    let mut first = ProofDag::new();

    assert!(first.is_empty());
    assert!(first.proof(unknown).is_none());
    let pairing_id = first
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap()
        .proof_id();
    let union_id = first
        .apply_canonical_proof_bytes(union.clone())
        .unwrap()
        .proof_id();
    assert_eq!(first.len(), 2);
    assert!(
        first
            .proof(pairing_id)
            .unwrap()
            .direct_dependencies()
            .is_empty()
    );
    assert!(
        first
            .proof(union_id)
            .unwrap()
            .direct_dependencies()
            .is_empty()
    );

    let mut reversed = ProofDag::new();
    let _ = reversed.apply_canonical_proof_bytes(union).unwrap();
    let _ = reversed.apply_canonical_proof_bytes(pairing).unwrap();
    assert_eq!(reversed.proof(pairing_id), first.proof(pairing_id));
    assert_eq!(reversed.proof(union_id), first.proof(union_id));
    assert_eq!(reversed.proof_set_root(), first.proof_set_root());
    assert_eq!(
        first
            .proof_set_proof(pairing_id)
            .verify(first.proof_set_root(), pairing_id),
        Ok(ProofSetMembership::Present)
    );
    assert_eq!(
        first
            .proof_set_proof(unknown)
            .verify(first.proof_set_root(), unknown),
        Ok(ProofSetMembership::Absent)
    );
}

#[test]
fn dependencies_must_precede_admission_and_replay_directly() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut original = ProofDag::new();
    let root_id = original
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let child_bytes = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = original
        .apply_canonical_proof_bytes(child_bytes.clone())
        .unwrap()
        .proof_id();
    let grandchild_bytes = referenced_generalization(child_id, FreeVariable::new(1));
    let grandchild_id = original
        .apply_canonical_proof_bytes(grandchild_bytes.clone())
        .unwrap()
        .proof_id();

    assert_eq!(
        original.proof(child_id).unwrap().direct_dependencies(),
        [root_id]
    );
    assert_eq!(
        original.proof(grandchild_id).unwrap().direct_dependencies(),
        [child_id]
    );
    assert!(
        !original
            .proof(grandchild_id)
            .unwrap()
            .direct_dependencies()
            .contains(&root_id)
    );

    let source_root = original.proof_set_root();
    let root_witness_bytes = original.proof_set_proof(root_id).to_canonical_bytes();
    let root_witness = ProofSetProof::from_canonical_bytes(&root_witness_bytes).unwrap();
    assert_eq!(
        root_witness.verify(source_root, root_id),
        Ok(ProofSetMembership::Present)
    );

    let mut replay = ProofDag::new();
    assert_eq!(
        replay.apply_canonical_proof_bytes(child_bytes.clone()),
        Err(LedgerError::Check {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: root_id,
            },
        })
    );
    assert!(replay.is_empty());
    assert_eq!(replay.proof_set_root(), ProofDag::new().proof_set_root());

    let _ = replay.apply_canonical_proof_bytes(root_bytes).unwrap();
    let _ = replay.apply_canonical_proof_bytes(child_bytes).unwrap();
    let _ = replay
        .apply_canonical_proof_bytes(grandchild_bytes)
        .unwrap();
    assert_eq!(replay.proof(root_id), original.proof(root_id));
    assert_eq!(replay.proof(child_id), original.proof(child_id));
    assert_eq!(replay.proof(grandchild_id), original.proof(grandchild_id));
    assert_eq!(replay.proof_set_root(), original.proof_set_root());
}

#[test]
fn expected_proof_id_mismatch_cannot_change_or_unlock_the_dag() {
    let pairing_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut control = ProofDag::new();
    let pairing_id = control
        .apply_canonical_proof_bytes(pairing_bytes.clone())
        .unwrap()
        .proof_id();
    let union_id = control
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap()
        .proof_id();
    let child_bytes = referenced_generalization(union_id, FreeVariable::new(2));
    let child_id = control
        .apply_canonical_proof_bytes(child_bytes.clone())
        .unwrap()
        .proof_id();

    let mut exercised = ProofDag::new();
    let _ = exercised
        .apply_canonical_proof_bytes(pairing_bytes)
        .unwrap();
    let root_before = exercised.proof_set_root();
    let pairing_before = exercised
        .proof(pairing_id)
        .unwrap()
        .canonical_proof_bytes()
        .to_vec();
    let absent_before = exercised.proof_set_proof(union_id).to_canonical_bytes();

    let mismatch =
        exercised.apply_canonical_proof_bytes_with_expected_id(union_bytes.clone(), pairing_id);
    assert_eq!(
        mismatch,
        Err(LedgerError::ProofIdMismatch {
            expected: pairing_id,
            actual: union_id,
        })
    );
    assert_eq!(exercised.len(), 1);
    assert_eq!(exercised.proof_set_root(), root_before);
    assert_eq!(
        exercised.proof(pairing_id).unwrap().canonical_proof_bytes(),
        pairing_before
    );
    assert!(exercised.proof(union_id).is_none());
    assert_eq!(
        exercised.proof_set_proof(union_id).to_canonical_bytes(),
        absent_before
    );

    assert_eq!(
        exercised.apply_canonical_proof_bytes(child_bytes.clone()),
        Err(LedgerError::Check {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: union_id,
            },
        })
    );
    assert_eq!(exercised.proof_set_root(), root_before);
    assert!(exercised.proof(child_id).is_none());

    let admitted = exercised
        .apply_canonical_proof_bytes_with_expected_id(union_bytes, union_id)
        .unwrap();
    assert_eq!(admitted.proof_id(), union_id);
    let child = exercised
        .apply_canonical_proof_bytes_with_expected_id(child_bytes, child_id)
        .unwrap();
    assert_eq!(child.proof_id(), child_id);
    assert_eq!(exercised.proof_set_root(), control.proof_set_root());
    assert_eq!(exercised.proof(pairing_id), control.proof(pairing_id));
    assert_eq!(exercised.proof(union_id), control.proof(union_id));
    assert_eq!(exercised.proof(child_id), control.proof(child_id));
}

#[test]
fn duplicate_artifacts_and_reference_aliases_never_overwrite_records() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut dag = ProofDag::new();
    let root = dag.apply_canonical_proof_bytes(root_bytes.clone()).unwrap();
    let root_id = root.proof_id();
    let derivation_id = root.derivation_id();
    let proof_set_root = dag.proof_set_root();

    assert_eq!(
        dag.apply_canonical_proof_bytes(root_bytes),
        Err(LedgerError::State {
            source: ProofStateError::DuplicateProof { proof_id: root_id },
        })
    );
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.proof_set_root(), proof_set_root);

    let alias = canonical_bytes(vec![ProofStep::ProofReference { proof_id: root_id }]);
    assert_eq!(
        dag.apply_canonical_proof_bytes(alias),
        Err(LedgerError::State {
            source: ProofStateError::DuplicateDerivation { derivation_id },
        })
    );
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.proof_set_root(), proof_set_root);
    assert_eq!(dag.proof(root_id).unwrap().proof_id(), root_id);
}

#[test]
fn genuine_alternative_derivations_of_one_statement_are_retained() {
    let variable = FreeVariable::new(7);
    let mut dag = ProofDag::new();
    let direct_id = dag
        .apply_canonical_proof_bytes(identity_bytes(variable))
        .unwrap()
        .proof_id();
    let detour_id = dag
        .apply_canonical_proof_bytes(identity_detour_bytes(variable))
        .unwrap()
        .proof_id();
    let direct = dag.proof(direct_id).unwrap();
    let detour = dag.proof(detour_id).unwrap();

    assert_eq!(direct.statement_id(), detour.statement_id());
    assert_ne!(direct.derivation_id(), detour.derivation_id());
    assert_ne!(direct.proof_id(), detour.proof_id());

    let dependent_id = dag
        .apply_canonical_proof_bytes(proof_citing_both_identities(direct_id, detour_id, variable))
        .unwrap()
        .proof_id();
    assert_eq!(
        dag.proof(dependent_id).unwrap().direct_dependencies(),
        [direct_id, detour_id]
    );
    assert_eq!(dag.len(), 3);
    for proof_id in [direct_id, detour_id, dependent_id] {
        assert_eq!(
            dag.proof_set_proof(proof_id)
                .verify(dag.proof_set_root(), proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn unrelated_prior_nodes_do_not_change_an_accepted_record() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut minimal = ProofDag::new();
    let root_id = minimal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let child_bytes = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = minimal
        .apply_canonical_proof_bytes(child_bytes.clone())
        .unwrap()
        .proof_id();

    let mut extended = ProofDag::new();
    let _ = extended.apply_canonical_proof_bytes(root_bytes).unwrap();
    let _ = extended
        .apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Union))
        .unwrap();
    let _ = extended.apply_canonical_proof_bytes(child_bytes).unwrap();

    assert_eq!(minimal.proof(child_id), extended.proof(child_id));
}

#[test]
fn failed_boundaries_leave_the_retained_dag_unchanged() {
    let mut dag = ProofDag::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let root_id = dag
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let committed_root = dag.proof_set_root();
    let assert_root_unchanged = |dag: &ProofDag| {
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.proof_set_root(), committed_root);
        assert_eq!(
            dag.proof(root_id).unwrap().canonical_proof_bytes(),
            root_bytes
        );
    };

    assert!(matches!(
        dag.apply_canonical_proof_bytes(vec![0]),
        Err(LedgerError::Decode { .. })
    ));
    assert_root_unchanged(&dag);

    let noncanonical = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
    ])
    .to_canonical_bytes();
    assert_eq!(
        dag.apply_canonical_proof_bytes(noncanonical),
        Err(LedgerError::NonCanonicalProof)
    );
    assert_root_unchanged(&dag);

    let invalid = canonical_bytes(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]);
    assert_eq!(
        dag.apply_canonical_proof_bytes(invalid),
        Err(LedgerError::Check {
            source: CheckError::Logic {
                step: 2,
                source: LogicError::ModusPonensMismatch,
            },
        })
    );
    assert_root_unchanged(&dag);

    let missing = ProofId::from_bytes([0x77; 32]);
    assert_eq!(
        dag.apply_canonical_proof_bytes(referenced_generalization(missing, FreeVariable::new(1),)),
        Err(LedgerError::Check {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: missing,
            },
        })
    );
    assert_root_unchanged(&dag);

    let child = dag
        .apply_canonical_proof_bytes(referenced_generalization(root_id, FreeVariable::new(2)))
        .unwrap();
    assert_eq!(child.direct_dependencies(), [root_id]);
    assert_eq!(dag.len(), 2);
}

#[test]
fn rooted_batch_failures_preserve_dag_root_records_and_witnesses() {
    let selected_bytes = axiom_bytes(ZfcAxiom::Extensionality);
    let parent_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let unrelated_bytes = axiom_bytes(ZfcAxiom::Union);

    let mut control = ProofDag::new();
    let selected_id = control
        .apply_canonical_proof_bytes(selected_bytes.clone())
        .unwrap()
        .proof_id();
    let parent_id = control
        .apply_canonical_proof_bytes(parent_bytes.clone())
        .unwrap()
        .proof_id();
    let root_bytes = referenced_generalization(parent_id, FreeVariable::new(0));
    let root_id = control
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();

    let mut scratch = ProofDag::new();
    let unrelated_id = scratch
        .apply_canonical_proof_bytes(unrelated_bytes.clone())
        .unwrap()
        .proof_id();

    let mut dag = ProofDag::new();
    let _ = dag
        .apply_canonical_proof_bytes(selected_bytes.clone())
        .unwrap();
    let committed_root = dag.proof_set_root();
    let selected_record = dag
        .proof(selected_id)
        .unwrap()
        .canonical_proof_bytes()
        .to_vec();
    let selected_witness = dag.proof_set_proof(selected_id).to_canonical_bytes();
    let parent_witness = dag.proof_set_proof(parent_id).to_canonical_bytes();
    let root_witness = dag.proof_set_proof(root_id).to_canonical_bytes();
    let unrelated_witness = dag.proof_set_proof(unrelated_id).to_canonical_bytes();
    let assert_unchanged = |dag: &ProofDag| {
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.proof_set_root(), committed_root);
        assert_eq!(
            dag.proof(selected_id).unwrap().canonical_proof_bytes(),
            selected_record
        );
        assert!(dag.proof(parent_id).is_none());
        assert!(dag.proof(root_id).is_none());
        assert!(dag.proof(unrelated_id).is_none());
        assert_eq!(
            dag.proof_set_proof(selected_id).to_canonical_bytes(),
            selected_witness
        );
        assert_eq!(
            dag.proof_set_proof(parent_id).to_canonical_bytes(),
            parent_witness
        );
        assert_eq!(
            dag.proof_set_proof(root_id).to_canonical_bytes(),
            root_witness
        );
        assert_eq!(
            dag.proof_set_proof(unrelated_id).to_canonical_bytes(),
            unrelated_witness
        );
    };

    let wrong_root = ProofId::from_bytes([0x88; 32]);
    assert_eq!(
        dag.apply_rooted_canonical_proof_batch(
            wrong_root,
            vec![
                AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                AddressedProofCandidate::new(wrong_root, root_bytes.clone()),
            ],
        ),
        Err(ProofBatchError::Candidate {
            index: 1,
            expected: Some(wrong_root),
            source: LedgerError::ProofIdMismatch {
                expected: wrong_root,
                actual: root_id,
            },
        })
    );
    assert_unchanged(&dag);

    assert_eq!(
        dag.apply_rooted_canonical_proof_batch(
            root_id,
            vec![
                AddressedProofCandidate::new(unrelated_id, unrelated_bytes),
                AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                AddressedProofCandidate::new(root_id, root_bytes.clone()),
            ],
        ),
        Err(ProofBatchError::UnreachableCandidate {
            index: 0,
            proof_id: unrelated_id,
        })
    );
    assert_unchanged(&dag);

    let accepted_root = dag
        .apply_rooted_canonical_proof_batch(
            root_id,
            vec![
                AddressedProofCandidate::new(parent_id, parent_bytes),
                AddressedProofCandidate::new(root_id, root_bytes),
            ],
        )
        .unwrap()
        .proof_id();
    assert_eq!(accepted_root, root_id);
    assert_eq!(dag.len(), 3);
    assert_eq!(dag.proof_set_root(), control.proof_set_root());
    for proof_id in [selected_id, parent_id, root_id] {
        assert_eq!(dag.proof(proof_id), control.proof(proof_id));
        assert_eq!(
            dag.proof_set_proof(proof_id)
                .verify(dag.proof_set_root(), proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn prepared_transition_projects_and_applies_one_exact_rooted_closure() {
    let selected_bytes = axiom_bytes(ZfcAxiom::Extensionality);
    let mut dag = ProofDag::new();
    let selected_id = dag
        .apply_canonical_proof_bytes(selected_bytes.clone())
        .unwrap()
        .proof_id();
    let previous_root = dag.proof_set_root();
    let selected_witness = dag.proof_set_proof(selected_id).to_canonical_bytes();
    let (proof_ids, payloads) = addressed_chain(3);

    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    assert_eq!(transition.previous_proof_set_root(), previous_root);
    assert_eq!(transition.proof_ids(), proof_ids);
    assert_eq!(transition.root_proof_id(), *proof_ids.last().unwrap());
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.proof_set_root(), previous_root);
    assert_eq!(
        dag.proof_set_proof(selected_id).to_canonical_bytes(),
        selected_witness
    );

    let root_id = transition.root_proof_id();
    let accepted = dag
        .apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
    assert_eq!(accepted.proof_id(), root_id);
    assert_eq!(dag.len(), 4);
    assert_eq!(dag.proof_set_root(), transition.resulting_proof_set_root());
    for proof_id in proof_ids.iter().copied().chain([selected_id]) {
        assert_eq!(
            dag.proof_set_proof(proof_id)
                .verify(dag.proof_set_root(), proof_id),
            Ok(ProofSetMembership::Present)
        );
    }

    let actual_replay_root = dag.proof_set_root();
    assert!(matches!(
        dag.apply_proof_transition(&transition, Vec::new()),
        Err(ProofTransitionApplyError::PreviousProofSetRootMismatch {
            expected,
            actual,
        }) if expected == previous_root && actual == actual_replay_root
    ));

    let mut control = ProofDag::new();
    let _ = control.apply_canonical_proof_bytes(selected_bytes).unwrap();
    let _ = control
        .apply_rooted_canonical_proof_batch(root_id, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
    assert_eq!(control.proof_set_root(), dag.proof_set_root());
}

#[test]
fn singleton_transition_projects_and_applies_from_the_empty_state() {
    let (proof_ids, payloads) = addressed_chain(1);
    let mut dag = ProofDag::new();
    let previous_root = dag.proof_set_root();
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();

    assert_eq!(transition.previous_proof_set_root(), previous_root);
    assert_ne!(transition.resulting_proof_set_root(), previous_root);
    assert!(dag.is_empty());
    assert_eq!(dag.proof_set_root(), previous_root);

    let accepted = dag
        .apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
    assert_eq!(accepted.proof_id(), proof_ids[0]);
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.proof_set_root(), transition.resulting_proof_set_root());
}

#[test]
fn transition_binding_errors_precede_payload_work_and_preserve_witnesses() {
    let selected_bytes = axiom_bytes(ZfcAxiom::Extensionality);
    let mut dag = ProofDag::new();
    let selected_id = dag
        .apply_canonical_proof_bytes(selected_bytes.clone())
        .unwrap()
        .proof_id();
    let (proof_ids, payloads) = addressed_chain(2);
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    let committed_root = dag.proof_set_root();
    let selected_witness = dag.proof_set_proof(selected_id).to_canonical_bytes();
    let absent_witness = dag.proof_set_proof(proof_ids[0]).to_canonical_bytes();
    let assert_unchanged = |dag: &ProofDag| {
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.proof_set_root(), committed_root);
        assert_eq!(
            dag.proof(selected_id).unwrap().canonical_proof_bytes(),
            selected_bytes
        );
        assert_eq!(
            dag.proof_set_proof(selected_id).to_canonical_bytes(),
            selected_witness
        );
        assert_eq!(
            dag.proof_set_proof(proof_ids[0]).to_canonical_bytes(),
            absent_witness
        );
    };

    let wrong_id = ProofId::from_bytes([0x92; 32]);

    let wrong_previous = ProofTransition::new(
        ProofSetRoot::from_bytes([0x91; 32]),
        transition.resulting_proof_set_root(),
        proof_ids.clone(),
    )
    .unwrap();
    assert!(matches!(
        dag.apply_proof_transition(
            &wrong_previous,
            vec![
                AddressedProofCandidate::new(wrong_id, vec![0]),
                AddressedProofCandidate::new(proof_ids[1], vec![0]),
            ],
        ),
        Err(ProofTransitionApplyError::PreviousProofSetRootMismatch { .. })
    ));
    assert_unchanged(&dag);

    assert_eq!(
        dag.apply_proof_transition(
            &transition,
            vec![AddressedProofCandidate::new(wrong_id, vec![0])],
        ),
        Err(ProofTransitionApplyError::CandidateCountMismatch {
            expected: 2,
            actual: 1,
        })
    );
    assert_unchanged(&dag);

    assert_eq!(
        dag.apply_proof_transition(
            &transition,
            vec![
                AddressedProofCandidate::new(wrong_id, vec![0]),
                AddressedProofCandidate::new(proof_ids[1], vec![0]),
            ],
        ),
        Err(ProofTransitionApplyError::CandidateProofIdMismatch {
            index: 0,
            expected: proof_ids[0],
            actual: wrong_id,
        })
    );
    assert_unchanged(&dag);

    let wrong_result = ProofTransition::new(
        committed_root,
        ProofSetRoot::from_bytes([0x93; 32]),
        proof_ids.clone(),
    )
    .unwrap();
    assert_eq!(
        dag.apply_proof_transition(
            &wrong_result,
            vec![
                AddressedProofCandidate::new(wrong_id, vec![0]),
                AddressedProofCandidate::new(proof_ids[1], vec![0]),
            ],
        ),
        Err(ProofTransitionApplyError::CandidateProofIdMismatch {
            index: 0,
            expected: proof_ids[0],
            actual: wrong_id,
        })
    );
    assert_unchanged(&dag);
    assert!(matches!(
        dag.apply_proof_transition(
            &wrong_result,
            vec![
                AddressedProofCandidate::new(proof_ids[0], vec![0]),
                AddressedProofCandidate::new(proof_ids[1], vec![0]),
            ],
        ),
        Err(ProofTransitionApplyError::ResultingProofSetRootMismatch { .. })
    ));
    assert_unchanged(&dag);

    let root_id = transition.root_proof_id();
    assert_eq!(
        dag.apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads),)
            .unwrap()
            .proof_id(),
        root_id
    );
}

#[test]
fn transition_correlates_every_candidate_before_reading_any_payload() {
    let (proof_ids, payloads) = addressed_chain(PROOF_BATCH_MAX_CANDIDATES);
    let mut dag = ProofDag::new();
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    let original_root = dag.proof_set_root();
    let original_witnesses = proof_ids
        .iter()
        .map(|proof_id| dag.proof_set_proof(*proof_id).to_canonical_bytes())
        .collect::<Vec<_>>();

    let malformed_candidates = || {
        proof_ids
            .iter()
            .copied()
            .map(|proof_id| AddressedProofCandidate::new(proof_id, vec![0]))
            .collect::<Vec<_>>()
    };
    let mut too_few = malformed_candidates();
    too_few.pop();
    assert_eq!(
        dag.apply_proof_transition(&transition, too_few),
        Err(ProofTransitionApplyError::CandidateCountMismatch {
            expected: PROOF_BATCH_MAX_CANDIDATES,
            actual: PROOF_BATCH_MAX_CANDIDATES - 1,
        })
    );
    let mut too_many = malformed_candidates();
    too_many.push(AddressedProofCandidate::new(
        ProofId::from_bytes([0xa5; 32]),
        vec![0],
    ));
    assert_eq!(
        dag.apply_proof_transition(&transition, too_many),
        Err(ProofTransitionApplyError::CandidateCountMismatch {
            expected: PROOF_BATCH_MAX_CANDIDATES,
            actual: PROOF_BATCH_MAX_CANDIDATES + 1,
        })
    );
    assert!(dag.is_empty());
    assert_eq!(dag.proof_set_root(), original_root);

    for mismatch_index in 0..proof_ids.len() {
        let mut candidates = malformed_candidates();
        let mut wrong_bytes = *proof_ids[mismatch_index].as_bytes();
        wrong_bytes[0] ^= 1;
        let wrong_id = ProofId::from_bytes(wrong_bytes);
        candidates[mismatch_index] = AddressedProofCandidate::new(wrong_id, vec![0]);

        assert_eq!(
            dag.apply_proof_transition(&transition, candidates),
            Err(ProofTransitionApplyError::CandidateProofIdMismatch {
                index: mismatch_index,
                expected: proof_ids[mismatch_index],
                actual: wrong_id,
            })
        );
        assert!(dag.is_empty());
        assert_eq!(dag.proof_set_root(), original_root);
        for (proof_id, witness) in proof_ids.iter().zip(&original_witnesses) {
            assert_eq!(
                dag.proof_set_proof(*proof_id).to_canonical_bytes(),
                *witness
            );
        }
    }

    let mut permuted = malformed_candidates();
    permuted.reverse();
    assert_eq!(
        dag.apply_proof_transition(&transition, permuted),
        Err(ProofTransitionApplyError::CandidateProofIdMismatch {
            index: 0,
            expected: proof_ids[0],
            actual: *proof_ids.last().unwrap(),
        })
    );
    assert!(dag.is_empty());
    assert_eq!(dag.proof_set_root(), original_root);

    let _ = dag
        .apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
}

#[test]
fn transition_delegates_strict_rooted_batch_failures_without_a_prefix() {
    let (proof_ids, payloads) = addressed_chain(3);
    let mut dag = ProofDag::new();
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    let empty_root = dag.proof_set_root();
    let witnesses = proof_ids
        .iter()
        .map(|proof_id| dag.proof_set_proof(*proof_id).to_canonical_bytes())
        .collect::<Vec<_>>();
    let assert_empty = |dag: &ProofDag| {
        assert!(dag.is_empty());
        assert_eq!(dag.proof_set_root(), empty_root);
        for (proof_id, witness) in proof_ids.iter().zip(&witnesses) {
            assert!(dag.proof(*proof_id).is_none());
            assert_eq!(
                dag.proof_set_proof(*proof_id).to_canonical_bytes(),
                *witness
            );
        }
    };

    let mut malformed = addressed_candidates(&proof_ids, &payloads);
    malformed[0] = AddressedProofCandidate::new(proof_ids[0], vec![0]);
    assert!(matches!(
        dag.apply_proof_transition(&transition, malformed),
        Err(ProofTransitionApplyError::Batch {
            source: ProofBatchError::Candidate { index: 0, .. },
        })
    ));
    assert_empty(&dag);

    let mut swapped = addressed_candidates(&proof_ids, &payloads);
    swapped[0] = AddressedProofCandidate::new(proof_ids[0], axiom_bytes(ZfcAxiom::Union));
    assert!(matches!(
        dag.apply_proof_transition(&transition, swapped),
        Err(ProofTransitionApplyError::Batch {
            source: ProofBatchError::Candidate {
                index: 0,
                source: LedgerError::ProofIdMismatch { .. },
                ..
            },
        })
    ));
    assert_empty(&dag);

    let unrelated_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut scratch = ProofDag::new();
    let unrelated_id = scratch
        .apply_canonical_proof_bytes(unrelated_bytes.clone())
        .unwrap()
        .proof_id();
    let mut unrelated_ids = vec![unrelated_id];
    unrelated_ids.extend_from_slice(&proof_ids);
    let unrelated_transition = dag.prepare_proof_transition(unrelated_ids.clone()).unwrap();
    let mut unrelated_candidates =
        vec![AddressedProofCandidate::new(unrelated_id, unrelated_bytes)];
    unrelated_candidates.extend(addressed_candidates(&proof_ids, &payloads));
    assert_eq!(
        dag.apply_proof_transition(&unrelated_transition, unrelated_candidates),
        Err(ProofTransitionApplyError::Batch {
            source: ProofBatchError::UnreachableCandidate {
                index: 0,
                proof_id: unrelated_id,
            },
        })
    );
    assert_empty(&dag);

    assert_eq!(
        dag.apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads),)
            .unwrap()
            .proof_id(),
        transition.root_proof_id()
    );
}

#[test]
fn transition_preserves_dependency_order_for_rooted_admission() {
    let (proof_ids, payloads) = addressed_chain(3);
    let mut reversed_ids = proof_ids.clone();
    reversed_ids.reverse();
    let mut reversed_payloads = payloads.clone();
    reversed_payloads.reverse();
    let mut dag = ProofDag::new();
    let reversed = dag.prepare_proof_transition(reversed_ids.clone()).unwrap();
    let original_root = dag.proof_set_root();

    assert_eq!(
        dag.apply_proof_transition(
            &reversed,
            addressed_candidates(&reversed_ids, &reversed_payloads),
        ),
        Err(ProofTransitionApplyError::Batch {
            source: ProofBatchError::Candidate {
                index: 0,
                expected: Some(reversed_ids[0]),
                source: LedgerError::Check {
                    source: CheckError::UnknownProofReference {
                        step: 0,
                        proof_id: proof_ids[1],
                    },
                },
            },
        })
    );
    assert!(dag.is_empty());
    assert_eq!(dag.proof_set_root(), original_root);

    let canonical = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    let accepted = dag
        .apply_proof_transition(&canonical, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
    assert_eq!(accepted.proof_id(), canonical.root_proof_id());
}

#[test]
fn transition_limits_and_existing_selection_are_exact() {
    let (proof_ids, payloads) = addressed_chain(PROOF_BATCH_MAX_CANDIDATES);
    let mut dag = ProofDag::new();
    let transition = dag.prepare_proof_transition(proof_ids.clone()).unwrap();
    assert_eq!(
        transition.to_canonical_bytes().len(),
        PROOF_TRANSITION_MAX_BYTES
    );
    let _ = dag
        .apply_proof_transition(&transition, addressed_candidates(&proof_ids, &payloads))
        .unwrap();
    assert_eq!(dag.len(), PROOF_BATCH_MAX_CANDIDATES);

    assert_eq!(
        dag.prepare_proof_transition(Vec::new()),
        Err(ProofTransitionError::Empty)
    );
    let mut excess = proof_ids.clone();
    let mut excess_bytes = *proof_ids[0].as_bytes();
    excess_bytes[0] ^= 1;
    excess.push(ProofId::from_bytes(excess_bytes));
    assert_eq!(
        dag.prepare_proof_transition(excess),
        Err(ProofTransitionError::TooManyProofs {
            actual: PROOF_BATCH_MAX_CANDIDATES + 1,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        })
    );
    assert_eq!(
        dag.prepare_proof_transition(vec![proof_ids[0], proof_ids[0]]),
        Err(ProofTransitionError::DuplicateProofId {
            first_index: 0,
            duplicate_index: 1,
            proof_id: proof_ids[0],
        })
    );

    assert_eq!(
        dag.prepare_proof_transition(vec![proof_ids[0]]),
        Err(ProofTransitionError::AlreadySelectedProofId {
            index: 0,
            proof_id: proof_ids[0],
        })
    );

    let wrong_result = ProofTransition::new(
        dag.proof_set_root(),
        ProofSetRoot::from_bytes([0x94; 32]),
        vec![proof_ids[0]],
    )
    .unwrap();
    assert!(matches!(
        dag.apply_proof_transition(
            &wrong_result,
            vec![AddressedProofCandidate::new(
                proof_ids[0],
                payloads[0].clone(),
            )],
        ),
        Err(ProofTransitionApplyError::ResultingProofSetRootMismatch { .. })
    ));
    assert_eq!(dag.len(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(dag.proof_set_root(), transition.resulting_proof_set_root());

    let duplicate_transition = ProofTransition::new(
        dag.proof_set_root(),
        dag.proof_set_root(),
        vec![proof_ids[0]],
    )
    .unwrap();
    assert!(matches!(
        dag.apply_proof_transition(
            &duplicate_transition,
            vec![AddressedProofCandidate::new(
                proof_ids[0],
                payloads[0].clone(),
            )],
        ),
        Err(ProofTransitionApplyError::Batch {
            source: ProofBatchError::Candidate {
                index: 0,
                source: LedgerError::State {
                    source: ProofStateError::DuplicateProof { .. },
                },
                ..
            },
        })
    ));
}

#[test]
fn block_preparation_binds_the_current_head_without_mutating_chain_state() {
    let chain = proof_chain(0x11);
    let initial_head = chain.head_block_id();
    let initial_root = chain.proof_dag().proof_set_root();
    let (proof_ids, _) = addressed_chain(3);
    let initial_witness = chain
        .proof_dag()
        .proof_set_proof(proof_ids[0])
        .to_canonical_bytes();

    let block = chain.prepare_block(proof_ids.clone()).unwrap();

    assert_eq!(block.parent_block_id(), initial_head);
    assert_eq!(block.transition().proof_ids(), proof_ids);
    assert_eq!(block.transition().previous_proof_set_root(), initial_root);
    assert_ne!(block.transition().resulting_proof_set_root(), initial_root);
    assert_eq!(chain.head_block_id(), initial_head);
    assert!(chain.proof_dag().is_empty());
    assert_eq!(chain.proof_dag().proof_set_root(), initial_root);
    assert_eq!(
        chain
            .proof_dag()
            .proof_set_proof(proof_ids[0])
            .to_canonical_bytes(),
        initial_witness
    );
}

#[test]
fn two_blocks_apply_in_order_and_the_second_resolves_the_first() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut scratch = ProofDag::new();
    let root_id = scratch
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let child_bytes = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = scratch
        .apply_canonical_proof_bytes(child_bytes.clone())
        .unwrap()
        .proof_id();

    let mut chain = proof_chain(0x12);
    let first = chain.prepare_block(vec![root_id]).unwrap();
    let first_id = first.id();
    assert_eq!(
        chain
            .apply_block(
                &first,
                vec![AddressedProofCandidate::new(root_id, root_bytes)],
            )
            .unwrap()
            .proof_id(),
        root_id
    );
    assert_eq!(chain.head_block_id(), first_id);
    assert_eq!(
        chain.proof_dag().proof_set_root(),
        first.transition().resulting_proof_set_root()
    );

    let second = chain.prepare_block(vec![child_id]).unwrap();
    assert_eq!(second.parent_block_id(), first_id);
    assert_eq!(
        chain
            .apply_block(
                &second,
                vec![AddressedProofCandidate::new(child_id, child_bytes)],
            )
            .unwrap()
            .proof_id(),
        child_id
    );
    assert_eq!(chain.head_block_id(), second.id());
    assert_eq!(chain.proof_dag().len(), 2);
    assert!(chain.proof_state().contains_proof(root_id));
    assert!(chain.proof_state().contains_proof(child_id));
    assert_eq!(
        chain
            .proof_dag()
            .proof(child_id)
            .unwrap()
            .direct_dependencies(),
        [root_id]
    );
    assert_eq!(
        chain.proof_dag().proof_set_root(),
        second.transition().resulting_proof_set_root()
    );
}

#[test]
fn replay_sibling_and_foreign_chain_fail_at_the_parent_before_payload_work() {
    let pairing_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = proof_id_for(&pairing_bytes);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let union_id = proof_id_for(&union_bytes);
    let mut chain = proof_chain(0x13);
    let replay = chain.prepare_block(vec![pairing_id]).unwrap();
    let sibling = chain.prepare_block(vec![union_id]).unwrap();
    let genesis = chain.head_block_id();

    let _ = chain
        .apply_block(
            &replay,
            vec![AddressedProofCandidate::new(pairing_id, pairing_bytes)],
        )
        .unwrap();
    let selected_head = chain.head_block_id();
    let selected_root = chain.proof_dag().proof_set_root();
    let selected_witness = chain
        .proof_dag()
        .proof_set_proof(pairing_id)
        .to_canonical_bytes();

    for stale in [&replay, &sibling] {
        assert_eq!(
            chain.apply_block(stale, Vec::new()),
            Err(ProofBlockApplyError::ParentBlockIdMismatch {
                expected: selected_head,
                actual: genesis,
            })
        );
        assert_eq!(chain.head_block_id(), selected_head);
        assert_eq!(chain.proof_dag().len(), 1);
        assert_eq!(chain.proof_dag().proof_set_root(), selected_root);
        assert_eq!(
            chain
                .proof_dag()
                .proof_set_proof(pairing_id)
                .to_canonical_bytes(),
            selected_witness
        );
    }

    let mut foreign = proof_chain(0x14);
    let foreign_head = foreign.head_block_id();
    let foreign_root = foreign.proof_dag().proof_set_root();
    assert_eq!(
        foreign.apply_block(
            &sibling,
            vec![AddressedProofCandidate::new(union_id, union_bytes)],
        ),
        Err(ProofBlockApplyError::ParentBlockIdMismatch {
            expected: foreign_head,
            actual: genesis,
        })
    );
    assert_eq!(foreign.head_block_id(), foreign_head);
    assert!(foreign.proof_dag().is_empty());
    assert_eq!(foreign.proof_dag().proof_set_root(), foreign_root);
}

#[test]
fn parent_mismatch_precedes_a_stale_transition_and_malformed_candidates() {
    let mut chain = proof_chain(0x15);
    let expected_parent = chain.head_block_id();
    let actual_parent = ProofBlockId::from_bytes([0xa1; 32]);
    let proof_id = ProofId::from_bytes([0xa2; 32]);
    let stale = ProofTransition::new(
        ProofSetRoot::from_bytes([0xa3; 32]),
        ProofSetRoot::from_bytes([0xa4; 32]),
        vec![proof_id],
    )
    .unwrap();
    let block = ProofBlock::new(actual_parent, stale);
    let initial_root = chain.proof_dag().proof_set_root();

    assert_eq!(
        chain.apply_block(
            &block,
            vec![AddressedProofCandidate::new(proof_id, vec![0])],
        ),
        Err(ProofBlockApplyError::ParentBlockIdMismatch {
            expected: expected_parent,
            actual: actual_parent,
        })
    );
    assert_eq!(chain.head_block_id(), expected_parent);
    assert!(chain.proof_dag().is_empty());
    assert_eq!(chain.proof_dag().proof_set_root(), initial_root);
}

#[test]
fn nested_batch_failure_preserves_head_dag_and_witnesses_then_retry() {
    let selected_bytes = axiom_bytes(ZfcAxiom::Extensionality);
    let selected_id = proof_id_for(&selected_bytes);
    let mut chain = proof_chain(0x16);
    let selected_block = chain.prepare_block(vec![selected_id]).unwrap();
    let _ = chain
        .apply_block(
            &selected_block,
            vec![AddressedProofCandidate::new(
                selected_id,
                selected_bytes.clone(),
            )],
        )
        .unwrap();

    let (proof_ids, payloads) = addressed_chain(2);
    let block = chain.prepare_block(proof_ids.clone()).unwrap();
    let committed_head = chain.head_block_id();
    let committed_root = chain.proof_dag().proof_set_root();
    let selected_witness = chain
        .proof_dag()
        .proof_set_proof(selected_id)
        .to_canonical_bytes();
    let absent_witness = chain
        .proof_dag()
        .proof_set_proof(proof_ids[0])
        .to_canonical_bytes();
    let assert_unchanged = |chain: &ProofChainState| {
        assert_eq!(chain.head_block_id(), committed_head);
        assert_eq!(chain.proof_dag().len(), 1);
        assert_eq!(chain.proof_dag().proof_set_root(), committed_root);
        assert_eq!(
            chain
                .proof_dag()
                .proof(selected_id)
                .unwrap()
                .canonical_proof_bytes(),
            selected_bytes
        );
        assert_eq!(
            chain
                .proof_dag()
                .proof_set_proof(selected_id)
                .to_canonical_bytes(),
            selected_witness
        );
        assert_eq!(
            chain
                .proof_dag()
                .proof_set_proof(proof_ids[0])
                .to_canonical_bytes(),
            absent_witness
        );
    };

    let mut malformed = addressed_candidates(&proof_ids, &payloads);
    malformed[0] = AddressedProofCandidate::new(proof_ids[0], vec![0]);
    assert!(matches!(
        chain.apply_block(&block, malformed),
        Err(ProofBlockApplyError::Transition {
            source: ProofTransitionApplyError::Batch {
                source: ProofBatchError::Candidate { index: 0, .. },
            },
        })
    ));
    assert_unchanged(&chain);

    assert_eq!(
        chain
            .apply_block(&block, addressed_candidates(&proof_ids, &payloads))
            .unwrap()
            .proof_id(),
        block.transition().root_proof_id()
    );
    assert_eq!(chain.head_block_id(), block.id());
    assert_eq!(chain.proof_dag().len(), 3);
    assert_eq!(
        chain.proof_dag().proof_set_root(),
        block.transition().resulting_proof_set_root()
    );
}

#[test]
fn maximum_eight_proof_block_applies_one_complete_rooted_transaction() {
    let (proof_ids, payloads) = addressed_chain(PROOF_BATCH_MAX_CANDIDATES);
    let mut chain = proof_chain(0x17);
    let block = chain.prepare_block(proof_ids.clone()).unwrap();
    assert_eq!(block.to_canonical_bytes().len(), PROOF_BLOCK_MAX_BYTES);

    assert_eq!(
        chain
            .apply_block(&block, addressed_candidates(&proof_ids, &payloads))
            .unwrap()
            .proof_id(),
        *proof_ids.last().unwrap()
    );
    assert_eq!(chain.head_block_id(), block.id());
    assert_eq!(chain.proof_dag().len(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(
        chain.proof_dag().proof_set_root(),
        block.transition().resulting_proof_set_root()
    );
    for proof_id in proof_ids {
        assert_eq!(
            chain
                .proof_dag()
                .proof_set_proof(proof_id)
                .verify(chain.proof_dag().proof_set_root(), proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn equal_final_proof_sets_from_different_histories_have_distinct_heads() {
    let pairing_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = proof_id_for(&pairing_bytes);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let union_id = proof_id_for(&union_bytes);
    let definition = ProofChainDefinition::new([0x18; 32]);
    let mut first = ProofChainState::new(definition);
    let mut second = ProofChainState::new(definition);
    assert_eq!(first.head_block_id(), second.head_block_id());

    let first_pairing = first.prepare_block(vec![pairing_id]).unwrap();
    let _ = first
        .apply_block(
            &first_pairing,
            vec![AddressedProofCandidate::new(
                pairing_id,
                pairing_bytes.clone(),
            )],
        )
        .unwrap();
    let first_union = first.prepare_block(vec![union_id]).unwrap();
    let _ = first
        .apply_block(
            &first_union,
            vec![AddressedProofCandidate::new(union_id, union_bytes.clone())],
        )
        .unwrap();

    let second_union = second.prepare_block(vec![union_id]).unwrap();
    let _ = second
        .apply_block(
            &second_union,
            vec![AddressedProofCandidate::new(union_id, union_bytes)],
        )
        .unwrap();
    let second_pairing = second.prepare_block(vec![pairing_id]).unwrap();
    let _ = second
        .apply_block(
            &second_pairing,
            vec![AddressedProofCandidate::new(pairing_id, pairing_bytes)],
        )
        .unwrap();

    assert_eq!(first.proof_dag().len(), 2);
    assert_eq!(second.proof_dag().len(), 2);
    assert_eq!(
        first.proof_dag().proof_set_root(),
        second.proof_dag().proof_set_root()
    );
    assert_ne!(first.head_block_id(), second.head_block_id());
    assert_ne!(first_pairing.id(), second_union.id());
    assert_ne!(first_union.id(), second_pairing.id());
}
