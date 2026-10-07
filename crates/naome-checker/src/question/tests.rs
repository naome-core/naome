use super::*;
use crate::normalize_and_check;
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_proof::DefinitionId;

fn var(id: u32) -> FreeVariable {
    FreeVariable::new(id)
}
fn equal() -> Formula {
    Formula::for_all(var(0), Formula::equal(var(0), var(0)))
}
fn unresolved() -> Formula {
    Formula::for_all(var(0), Formula::member(var(0), var(0)))
}
fn register(state: &mut ArtifactState, steps: Vec<ProofStep>) -> (ProofId, Formula) {
    let proof = normalize_and_check(ProofCertificate::new(steps).unwrap()).unwrap();
    let id = proof.proof_id();
    let formula = proof.conclusion().clone();
    state.register_proof(proof).unwrap();
    (id, formula)
}
fn equality(state: &mut ArtifactState) -> (ProofId, Formula) {
    register(
        state,
        vec![
            ProofStep::EqualityReflexivity { variable: var(0) },
            ProofStep::Generalization {
                premise: 0,
                variable: var(0),
            },
        ],
    )
}
fn indexed(entries: &[RegisteredQuestion<'_>]) -> QuestionRegistry {
    let mut registry = QuestionRegistry::new();
    for entry in entries {
        registry.insert(*entry).unwrap();
    }
    registry
}

fn decision(
    target: &Formula,
    state: &ArtifactState,
    registry: &[RegisteredQuestion<'_>],
    policy: &ApprovalPolicy,
) -> ApprovalDecision {
    let registry = indexed(registry);
    assess_question(
        &AssessmentQuestion::new(
            FOUNDATION_ID,
            target,
            b"complete test question source",
            &[],
            None,
        )
        .unwrap(),
        &KnowledgeSnapshot::new([9; 32], state, &registry),
        policy,
    )
}

#[test]
fn snapshot_dependent_exact_answers_are_read_only_and_reproducible() {
    let policy = ApprovalPolicy::default();
    let mut state = ArtifactState::new();
    let question = equal();
    let before = decision(&question, &state, &[], &policy);
    assert!(before.approved());
    let (witness, _) = equality(&mut state);
    let registered: Vec<_> = state.proof_conclusions().map(|(id, _, _, _)| id).collect();
    let after = decision(&question, &state, &[], &policy);
    assert_eq!(after.reason, Some(RejectionReason::KnownProof));
    assert_eq!(after.witness, Some(witness));
    assert_ne!(before.snapshot, after.snapshot);
    assert_eq!(after, decision(&question, &state, &[], &policy));
    assert_eq!(
        registered,
        state
            .proof_conclusions()
            .map(|(id, _, _, _)| id)
            .collect::<Vec<_>>()
    );
    let (_, negative) = register(&mut state, vec![ProofStep::ZfcAxiom(ZfcAxiom::Infinity)]);
    let bytes = negative.encode_canonical().unwrap();
    assert_eq!(bytes[0], 0x02);
    // This fixture's axiom is exactly the single negation of its target.
    let refuted = Formula::decode_canonical(&bytes[1..]).unwrap();
    let rejected = decision(&refuted, &state, &[], &policy);
    assert_eq!(rejected.reason, Some(RejectionReason::KnownRefutation));
}

#[test]
fn canonical_duplicates_and_self_record_exemption_cannot_hide_other_records() {
    let first = equal();
    let renamed = Formula::for_all(var(42), Formula::equal(var(42), var(42)));
    assert_eq!(first, renamed);
    let state = ArtifactState::new();
    let registry = [
        RegisteredQuestion::new([1; 32], &first).unwrap(),
        RegisteredQuestion::new([2; 32], &renamed).unwrap(),
    ];
    let policy = ApprovalPolicy::default();
    assert_eq!(
        decision(&renamed, &state, &registry, &policy).reason,
        Some(RejectionReason::ExactDuplicate)
    );
    let input = AssessmentQuestion::new(
        FOUNDATION_ID,
        &renamed,
        b"renamed complete input",
        &[],
        Some([2; 32]),
    )
    .unwrap();
    let full_registry = indexed(&registry);
    let snapshot = KnowledgeSnapshot::new([4; 32], &state, &full_registry);
    let result = assess_question(&input, &snapshot, &policy);
    assert_eq!(result.reason, Some(RejectionReason::ExactDuplicate));
    assert_eq!(result.related_record, Some([1; 32]));
    let self_registry = indexed(&registry[1..]);
    let only_self = KnowledgeSnapshot::new([4; 32], &state, &self_registry);
    assert!(assess_question(&input, &only_self, &policy).approved());
    let unknown_record = AssessmentQuestion::new(
        FOUNDATION_ID,
        &renamed,
        b"renamed complete input",
        &[],
        Some([8; 32]),
    )
    .unwrap();
    assert_eq!(
        assess_question(&unknown_record, &only_self, &policy).reason,
        Some(RejectionReason::InvalidRegistry)
    );
}

#[test]
fn unanswered_equivalence_requires_both_actual_checked_implications() {
    let a = unresolved();
    let b = Formula::for_all(var(17), a.clone());
    let registry = [RegisteredQuestion::new([1; 32], &b).unwrap()];
    let policy = ApprovalPolicy::default();
    let mut state = ArtifactState::new();
    assert!(decision(&a, &state, &registry, &policy).approved());
    let (forward, _) = register(
        &mut state,
        vec![ProofStep::VacuousUniversal {
            formula: a.clone().into(),
        }],
    );
    assert!(
        decision(&a, &state, &registry, &policy).approved(),
        "one direction cannot establish equivalence"
    );
    let invalid = ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id: forward },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ])
    .unwrap();
    assert!(normalize_and_check_with_state(invalid, &state).is_err());
    assert!(
        decision(&a, &state, &registry, &policy).approved(),
        "failed evidence cannot enter checked state"
    );
    let _ = register(
        &mut state,
        vec![ProofStep::UniversalInstantiation {
            variable: var(17),
            replacement: var(18),
            body: a.clone().into(),
        }],
    );
    let result = decision(&a, &state, &registry, &policy);
    assert_eq!(result.reason, Some(RejectionReason::ProvenEquivalent));
    assert_eq!(result.rule, "Q05_CHECKED_MUTUAL_IMPLICATIONS");
    assert!(result.witness.is_some() && result.supporting_witness.is_some());
}

#[test]
fn checked_implication_transfer_requires_its_proven_premise() {
    let a = equal();
    let b = Formula::implies(unresolved(), a.clone());
    let mut state = ArtifactState::new();
    let _ = register(
        &mut state,
        vec![ProofStep::Simplification {
            antecedent: a.clone().into(),
            consequent: unresolved().into(),
        }],
    );
    let policy = ApprovalPolicy::default();
    assert!(decision(&b, &state, &[], &policy).approved());
    let _ = equality(&mut state);
    let result = decision(&b, &state, &[], &policy);
    assert_eq!(result.reason, Some(RejectionReason::KnownProof));
    assert_eq!(result.rule, "Q04_CHECKED_TRANSFER");
    assert!(result.witness.is_some() && result.supporting_witness.is_some());
    assert!(
        decision(&Formula::implies(a, unresolved()), &state, &[], &policy).approved(),
        "reversing implication is not a transfer"
    );
}

fn general_identity(state: &mut ArtifactState) -> Formula {
    let atom = Formula::member(var(0), var(1));
    let self_implies = Formula::implies(atom.clone(), atom.clone());
    register(
        state,
        vec![
            ProofStep::Simplification {
                antecedent: atom.clone().into(),
                consequent: self_implies.clone().into(),
            },
            ProofStep::Simplification {
                antecedent: atom.clone().into(),
                consequent: atom.clone().into(),
            },
            ProofStep::Frege {
                first: atom.clone().into(),
                second: self_implies.into(),
                third: atom.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 3,
            },
            ProofStep::Generalization {
                premise: 4,
                variable: var(1),
            },
            ProofStep::Generalization {
                premise: 5,
                variable: var(0),
            },
        ],
    )
    .1
}

#[test]
fn checked_general_result_settles_diagonal_only_through_finite_checker_rules() {
    let mut state = ArtifactState::new();
    let atom = Formula::member(var(10), var(10));
    let diagonal = Formula::for_all(var(10), Formula::implies(atom.clone(), atom));
    let policy = ApprovalPolicy::default();
    assert!(decision(&diagonal, &state, &[], &policy).approved());
    let general = general_identity(&mut state);
    assert_ne!(
        general, diagonal,
        "diagonal is a proper narrowing of two quantified variables"
    );
    let result = decision(&diagonal, &state, &[], &policy);
    assert_eq!(result.reason, Some(RejectionReason::KnownLemmaInstance));
    assert_eq!(result.rule, "Q06_CHECKED_UNIVERSAL_INSTANCE");
    let changed_assumption = Formula::for_all(
        var(0),
        Formula::for_all(
            var(1),
            Formula::implies(
                Formula::member(var(0), var(1)),
                Formula::equal(var(0), var(1)),
            ),
        ),
    );
    assert!(decision(&changed_assumption, &state, &[], &policy).approved());
    let changed_quantifier = Formula::exists(
        var(0),
        Formula::for_all(
            var(1),
            Formula::implies(
                Formula::member(var(0), var(1)),
                Formula::member(var(0), var(1)),
            ),
        ),
    );
    assert!(decision(&changed_quantifier, &state, &[], &policy).approved());
    assert_eq!(
        state.proof_conclusions().count(),
        1,
        "temporary inference never registers a proof"
    );
}

#[test]
fn dependencies_input_context_and_exhausted_work_fail_closed() {
    let mut state = ArtifactState::new();
    let target = unresolved();
    let policy = ApprovalPolicy::default();
    let missing = [ArtifactId::from_definition_id(DefinitionId::from_bytes(
        [55; 32],
    ))];
    let empty_registry = QuestionRegistry::new();
    let snapshot = KnowledgeSnapshot::new([3; 32], &state, &empty_registry);
    let input = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"complete dependency input",
        &missing,
        None,
    )
    .unwrap();
    assert_eq!(
        assess_question(&input, &snapshot, &policy).reason,
        Some(RejectionReason::MissingDependency)
    );
    let foreign =
        AssessmentQuestion::new("other", &target, b"complete dependency input", &[], None).unwrap();
    assert_eq!(
        assess_question(&foreign, &snapshot, &policy).reason,
        Some(RejectionReason::FoundationMismatch)
    );
    let open = Formula::member(var(0), var(1));
    assert_eq!(
        decision(&open, &state, &[], &policy).reason,
        Some(RejectionReason::InvalidTarget)
    );
    let _ = equality(&mut state);
    general_identity(&mut state);
    let mut limited = policy;
    limited.limits.formula_work_bytes = 1;
    assert_eq!(
        decision(&target, &state, &[], &limited).reason,
        Some(RejectionReason::ExecutionLimit)
    );
    limited = policy;
    limited.limits.operations = 1;
    assert_eq!(
        decision(&target, &state, &[], &limited).reason,
        Some(RejectionReason::ExecutionLimit)
    );
    limited = policy;
    limited.limits.formula_nodes = 1;
    assert_eq!(
        decision(&target, &ArtifactState::new(), &[], &limited).reason,
        Some(RejectionReason::InputLimit)
    );
    assert!(matches!(
        RegisteredQuestion::new([1; 32], &open),
        Err(RejectionReason::InvalidRegistry)
    ));
}

#[test]
fn changing_registry_snapshot_or_policy_invalidates_bound_approval() {
    let state = ArtifactState::new();
    let target = unresolved();
    let policy = ApprovalPolicy::default();
    let first = decision(&target, &state, &[], &policy);
    let mut new_policy = policy;
    new_policy.revision += 1;
    let second = decision(&target, &state, &[], &new_policy);
    assert!(first.approved() && second.approved());
    assert!(!first.same_context(&second));
    let registry = [RegisteredQuestion::new([4; 32], &target).unwrap()];
    let third = decision(&target, &state, &registry, &policy);
    assert!(!first.same_context(&third));
    assert_eq!(third.reason, Some(RejectionReason::ExactDuplicate));
    new_policy.rule_set = 2;
    assert_eq!(
        decision(&target, &state, &[], &new_policy).reason,
        Some(RejectionReason::UnsupportedPolicy)
    );
}

#[test]
fn intrinsic_bindings_survive_early_policy_and_work_failures() {
    let state = ArtifactState::new();
    let target = unresolved();
    let other = equal();
    let records_a = [
        RegisteredQuestion::new([1; 32], &target).unwrap(),
        RegisteredQuestion::new([2; 32], &other).unwrap(),
    ];
    let records_b = [
        RegisteredQuestion::new([1; 32], &target).unwrap(),
        RegisteredQuestion::new([3; 32], &other).unwrap(),
    ];
    let registries = [indexed(&records_a), indexed(&records_b)];
    let snapshots = [
        KnowledgeSnapshot::new([5; 32], &state, &registries[0]),
        KnowledgeSnapshot::new([5; 32], &state, &registries[1]),
    ];
    let first = AssessmentQuestion::new(FOUNDATION_ID, &target, b"source A", &[], None).unwrap();
    let second = AssessmentQuestion::new(FOUNDATION_ID, &target, b"source B", &[], None).unwrap();
    let mut policy = ApprovalPolicy {
        rule_set: 99,
        ..ApprovalPolicy::default()
    };
    let a = assess_question(&first, &snapshots[0], &policy);
    let b = assess_question(&second, &snapshots[1], &policy);
    assert_eq!(a.reason, Some(RejectionReason::UnsupportedPolicy));
    assert_eq!(a.question, b.question);
    assert_ne!(a.input, b.input);
    assert_ne!(a.snapshot, b.snapshot);
    policy = ApprovalPolicy::default();
    policy.limits.operations = 1;
    let a = assess_question(&first, &snapshots[0], &policy);
    let b = assess_question(&first, &snapshots[1], &policy);
    assert_eq!(a.reason, Some(RejectionReason::ExecutionLimit));
    assert_ne!(a.snapshot, b.snapshot);
    let refs_a = [ArtifactId::from_bytes([1; 32])];
    let refs_b = [ArtifactId::from_bytes([2; 32])];
    let a = AssessmentQuestion::new(FOUNDATION_ID, &target, b"same source", &refs_a, None).unwrap();
    let b = AssessmentQuestion::new(FOUNDATION_ID, &target, b"same source", &refs_b, None).unwrap();
    assert_ne!(
        assess_question(&a, &snapshots[0], &policy).input,
        assess_question(&b, &snapshots[0], &policy).input
    );
}

#[test]
fn checked_dependency_kind_domains_and_duplicate_reason_are_preserved() {
    let mut state = ArtifactState::new();
    let certificate = naome_proof::DefinitionCertificate::relation(
        1,
        naome_proof::DefinedFormula::equal(var(0), var(0)),
    )
    .unwrap();
    let definition = crate::check_definition_with_state(certificate, &state).unwrap();
    let id = definition.definition_id();
    state.register_definition(definition).unwrap();
    let valid = ArtifactId::from_definition_id(id);
    let wrong_kind = ArtifactId::from_proof_id(ProofId::from_bytes(*id.as_bytes()));
    assert_ne!(
        valid, wrong_kind,
        "typed artifact domains distinguish identical raw digests"
    );
    let target = unresolved();
    let policy = ApprovalPolicy::default();
    let empty_registry = QuestionRegistry::new();
    let snapshot = KnowledgeSnapshot::new([1; 32], &state, &empty_registry);
    let valid_refs = [valid];
    let invalid_refs = [wrong_kind];
    let input = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"same complete source",
        &valid_refs,
        None,
    )
    .unwrap();
    let invalid = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"same complete source",
        &invalid_refs,
        None,
    )
    .unwrap();
    let accepted = assess_question(&input, &snapshot, &policy);
    let rejected = assess_question(&invalid, &snapshot, &policy);
    assert!(accepted.approved());
    assert_eq!(rejected.reason, Some(RejectionReason::MissingDependency));
    assert_ne!(accepted.input, rejected.input);
    let repeated = [valid, valid];
    let duplicate = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"same complete source",
        &repeated,
        None,
    )
    .unwrap();
    assert_eq!(
        assess_question(&duplicate, &snapshot, &policy).reason,
        Some(RejectionReason::DuplicateDependency)
    );
}

#[test]
fn cached_checked_set_fingerprint_is_order_independent_and_rollback_safe() {
    let mut first = ArtifactState::new();
    let empty = first.snapshot_id();
    let _ = equality(&mut first);
    general_identity(&mut first);
    let mut second = ArtifactState::new();
    general_identity(&mut second);
    let _ = equality(&mut second);
    assert_eq!(first.snapshot_id(), second.snapshot_id());
    assert_ne!(empty, first.snapshot_id());
    let before = first.snapshot_id();
    let certificate = || {
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: var(0) },
            ProofStep::Generalization {
                premise: 0,
                variable: var(0),
            },
        ])
        .unwrap()
    };
    let duplicate = normalize_and_check(certificate()).unwrap();
    assert!(first.register_proof(duplicate).is_err());
    assert_eq!(before, first.snapshot_id());
    let mut collision = normalize_and_check(certificate()).unwrap();
    collision.statement_id = StatementId::from_bytes([77; 32]);
    assert!(first.register_proof(collision).is_err());
    assert_eq!(before, first.snapshot_id());
    let mut branch = first.clone();
    let _ = register(&mut branch, vec![ProofStep::ZfcAxiom(ZfcAxiom::Infinity)]);
    assert_eq!(before, first.snapshot_id());
    assert_ne!(before, branch.snapshot_id());
}

#[test]
fn registry_acquisition_checks_bounds_before_recursive_closure() {
    let mut oversized = Formula::member(var(0), var(1));
    for _ in 0..10 {
        oversized = Formula::implies(oversized.clone(), oversized);
    }
    assert!(
        matches!(
            RegisteredQuestion::new([1; 32], &oversized),
            Err(RejectionReason::InputLimit)
        ),
        "oversized open input must reach the input bound before closure inspection"
    );
    let mut deep = Formula::member(var(0), var(1));
    for _ in 0..=naome_foundation::FORMULA_MAX_DEPTH {
        deep = Formula::negate(deep);
    }
    assert!(matches!(
        RegisteredQuestion::new([2; 32], &deep),
        Err(RejectionReason::InputLimit)
    ));
}

fn patterned(index: u32) -> Formula {
    let x = var(0);
    let mut body = Formula::equal(x, x);
    for bit in 0..11 {
        let atom = if index & (1 << bit) == 0 {
            Formula::equal(x, x)
        } else {
            Formula::member(x, x)
        };
        body = Formula::implies(atom, body);
    }
    for _ in 0..4 {
        body = Formula::implies(body.clone(), body);
    }
    Formula::for_all(x, body)
}

fn large_checked_context() -> (ArtifactState, QuestionRegistry) {
    let mut state = ArtifactState::new();
    let mut registry = QuestionRegistry::new();
    let (late_witness, _) = equality(&mut ArtifactState::new());
    let mut index = 0_u32;
    while registry.len() < 1025 {
        assert!(index < 2048, "finite unique validated filler family");
        let formula = patterned(index);
        let proof = normalize_and_check(
            ProofCertificate::new(vec![ProofStep::Simplification {
                antecedent: formula.clone().into(),
                consequent: unresolved().into(),
            }])
            .unwrap(),
        )
        .unwrap();
        let current = index;
        index += 1;
        if proof.proof_id() >= late_witness {
            continue;
        }
        let definition = naome_proof::DefinitionCertificate::relation(
            1,
            naome_proof::DefinedFormula::from_primitive(&Formula::implies(
                Formula::equal(var(0), var(0)),
                formula.clone(),
            ))
            .unwrap(),
        )
        .unwrap();
        let checked = crate::check_definition_with_state(definition, &state).unwrap();
        state.register_definition(checked).unwrap();
        state.register_proof(proof).unwrap();
        let mut record = [0; 32];
        record[..4].copy_from_slice(&current.to_le_bytes());
        registry
            .insert(RegisteredQuestion::new(record, &formula).unwrap())
            .unwrap();
    }
    assert_eq!(state.proof_conclusions().count(), 1025);
    assert_eq!(state.definition_ids().count(), 1025);
    assert_eq!(registry.len(), 1025);
    assert!(
        state
            .proof_conclusions()
            .map(|(_, _, _, length)| length)
            .sum::<usize>()
            > 1024 * 1024
    );
    (state, registry)
}

fn indexed_decision(
    target: &Formula,
    state: &ArtifactState,
    registry: &QuestionRegistry,
    policy: &ApprovalPolicy,
) -> ApprovalDecision {
    let input =
        AssessmentQuestion::new(FOUNDATION_ID, target, b"whole graph target", &[], None).unwrap();
    assess_question(
        &input,
        &KnowledgeSnapshot::new([9; 32], state, registry),
        policy,
    )
}

#[test]
fn complete_large_checked_context_approves_irrelevant_data_and_finds_late_witnesses() {
    let (state, registry) = large_checked_context();
    let policy = ApprovalPolicy::default();
    let unrelated = unresolved();
    assert!(
        indexed_decision(&unrelated, &state, &registry, &policy).approved(),
        "complete indexes exhaust all relevant buckets even beyond every former aggregate cap"
    );

    let mut proved = state.clone();
    let (witness, formula) = equality(&mut proved);
    assert_eq!(
        proved
            .proof_conclusions()
            .position(|(proof, _, _, _)| proof == witness),
        Some(1025),
        "the matching proof lies beyond the former sorted 1024-proof boundary"
    );
    let before = state.snapshot_id();
    let result = indexed_decision(&formula, &proved, &registry, &policy);
    assert_eq!(result.reason, Some(RejectionReason::KnownProof));
    assert_eq!(result.witness, Some(witness));

    let mut refuted = state.clone();
    let (_, negative) = register(&mut refuted, vec![ProofStep::ZfcAxiom(ZfcAxiom::Infinity)]);
    let bytes = negative.encode_canonical().unwrap();
    let target = Formula::decode_canonical(&bytes[1..]).unwrap();
    assert_eq!(
        indexed_decision(&target, &refuted, &registry, &policy).reason,
        Some(RejectionReason::KnownRefutation)
    );

    let mut transferred = state.clone();
    let (_, premise) = equality(&mut transferred);
    let _ = register(
        &mut transferred,
        vec![ProofStep::Simplification {
            antecedent: premise.clone().into(),
            consequent: unrelated.clone().into(),
        }],
    );
    let result = indexed_decision(
        &Formula::implies(unrelated.clone(), premise),
        &transferred,
        &registry,
        &policy,
    );
    assert_eq!(result.reason, Some(RejectionReason::KnownProof));
    assert_eq!(result.rule, "Q04_CHECKED_TRANSFER");

    let mut equivalent = state.clone();
    let related = Formula::for_all(var(17), unrelated.clone());
    let mut changed_registry = registry.clone();
    changed_registry
        .insert(RegisteredQuestion::new([255; 32], &related).unwrap())
        .unwrap();
    let _ = register(
        &mut equivalent,
        vec![ProofStep::VacuousUniversal {
            formula: unrelated.clone().into(),
        }],
    );
    assert!(
        indexed_decision(&unrelated, &equivalent, &changed_registry, &policy).approved(),
        "one direction remains insufficient"
    );
    let _ = register(
        &mut equivalent,
        vec![ProofStep::UniversalInstantiation {
            variable: var(17),
            replacement: var(18),
            body: unrelated.clone().into(),
        }],
    );
    let result = indexed_decision(&unrelated, &equivalent, &changed_registry, &policy);
    assert_eq!(result.reason, Some(RejectionReason::ProvenEquivalent));
    assert_eq!(result.related_record, Some([255; 32]));

    let mut specialized = state.clone();
    general_identity(&mut specialized);
    let atom = Formula::member(var(10), var(10));
    let diagonal = Formula::for_all(var(10), Formula::implies(atom.clone(), atom));
    assert_eq!(
        indexed_decision(&diagonal, &specialized, &registry, &policy).reason,
        Some(RejectionReason::KnownLemmaInstance)
    );

    let mut duplicates = registry.clone();
    duplicates
        .insert(RegisteredQuestion::new([254; 32], &unrelated).unwrap())
        .unwrap();
    let duplicate = indexed_decision(&unrelated, &state, &duplicates, &policy);
    assert_eq!(duplicate.reason, Some(RejectionReason::ExactDuplicate));
    assert_eq!(duplicate.related_record, Some([254; 32]));
    assert_eq!(
        state.snapshot_id(),
        before,
        "all index queries and clone insertions preserve the actual receiver"
    );
    assert_eq!(registry.len(), 1025);
}

#[test]
fn relevant_bucket_exhaustion_rejects_instead_of_approving_a_partial_query() {
    let mut state = ArtifactState::new();
    let target = unresolved();
    for index in 0..32 {
        let _ = register(
            &mut state,
            vec![ProofStep::Simplification {
                antecedent: target.clone().into(),
                consequent: patterned(index).into(),
            }],
        );
    }
    let registry = QuestionRegistry::new();
    let policy = ApprovalPolicy::default();
    assert!(indexed_decision(&target, &state, &registry, &policy).approved());
    let mut limited = policy;
    limited.limits.operations = 20;
    let result = indexed_decision(&target, &state, &registry, &limited);
    assert_eq!(result.reason, Some(RejectionReason::ExecutionLimit));
    assert_eq!(result.rule, "Q08_EXECUTION");
    assert!(!result.approved());
    limited = policy;
    limited.limits.formula_work_bytes = 1024;
    assert_eq!(
        indexed_decision(&target, &state, &registry, &limited).reason,
        Some(RejectionReason::ExecutionLimit)
    );
}

#[test]
fn indexed_universal_witnesses_include_negative_and_vacuous_one_two_step_instances() {
    let mut state = ArtifactState::new();
    let axiom = normalize_and_check(
        ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Infinity)]).unwrap(),
    )
    .unwrap();
    let bytes = axiom.conclusion().encode_canonical().unwrap();
    let target = Formula::decode_canonical(&bytes[1..]).unwrap();
    let _ = register(
        &mut state,
        vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Infinity),
            ProofStep::Generalization {
                premise: 0,
                variable: var(4),
            },
        ],
    );
    let policy = ApprovalPolicy::default();
    assert_eq!(
        decision(&target, &state, &[], &policy).reason,
        Some(RejectionReason::KnownLemmaInstance)
    );

    let mut twice = ArtifactState::new();
    let _ = register(
        &mut twice,
        vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Infinity),
            ProofStep::Generalization {
                premise: 0,
                variable: var(4),
            },
            ProofStep::Generalization {
                premise: 1,
                variable: var(5),
            },
        ],
    );
    assert_eq!(
        decision(&target, &twice, &[], &policy).reason,
        Some(RejectionReason::KnownLemmaInstance)
    );
    let intermediate = Formula::for_all(var(4), target);
    let refuted_intermediate = Formula::negate(intermediate);
    // Negative polarity uses the exact structurally projected conclusion,
    // rather than distributing negation through a binder.
    assert!(decision(&refuted_intermediate, &twice, &[], &policy).approved());
}

#[test]
fn indexed_aliases_registry_content_and_branches_keep_complete_cache_bindings() {
    let mut state = ArtifactState::new();
    let (original, target) = equality(&mut state);
    let policy = ApprovalPolicy::default();
    let before = decision(&target, &state, &[], &policy);
    let alias = normalize_and_check_with_state(
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: original }]).unwrap(),
        &state,
    )
    .unwrap();
    let alias_id = alias.proof_id();
    let mut branch = state.clone();
    branch.register_proof_for_replication(alias).unwrap();
    let after = decision(&target, &branch, &[], &policy);
    assert_eq!(after.witness, Some(original.min(alias_id)));
    assert_ne!(
        before.snapshot, after.snapshot,
        "an alias changes the full snapshot even without a new canonical statement"
    );
    assert_eq!(before, decision(&target, &state, &[], &policy));
    let invalid = normalize_and_check_with_state(
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: original }]).unwrap(),
        &state,
    )
    .unwrap();
    let frozen = branch.snapshot_id();
    assert!(branch.register_proof_for_replication(invalid).is_err());
    assert_eq!(branch.snapshot_id(), frozen);
    assert_eq!(after, decision(&target, &branch, &[], &policy));

    let other = unresolved();
    let first = RegisteredQuestion::new([1; 32], &target).unwrap();
    let second = RegisteredQuestion::new([2; 32], &other).unwrap();
    let mut registry = indexed(&[first, second]);
    let reversed = indexed(&[second, first]);
    assert_eq!(registry.identity(), reversed.identity());
    let old = registry.clone();
    let old_id = registry.identity();
    registry
        .insert(RegisteredQuestion::new([3; 32], &target).unwrap())
        .unwrap();
    assert_ne!(
        registry.identity(),
        old_id,
        "another record binding the same formula still changes complete context"
    );
    assert_eq!(old.identity(), old_id);
    let changed = RegisteredQuestion::new([1; 32], &other).unwrap();
    let frozen = registry.identity();
    assert_eq!(
        registry.insert(changed),
        Err(RejectionReason::InvalidRegistry)
    );
    assert_eq!(registry.identity(), frozen);
}
