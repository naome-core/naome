use super::*;
use crate::{
    ArtifactState, check,
    program::{Engine, Error as ProgramError},
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofStep, program::Command};
use rusqlite::Connection;

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}
fn eq(variable: u32) -> Formula {
    let v = FreeVariable::new(variable);
    Formula::equal(v, v)
}
fn engine(commands: &[Command]) -> Engine {
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine.append_group(commands).unwrap();
    engine
}
fn fail(engine: &mut Engine) -> ProofDiagnostic {
    loop {
        match engine.advance(37, 4096, &ArtifactState::new()) {
            Err(ProgramError::Check(diagnostic)) => return *diagnostic,
            Err(other) => panic!("unexpected failure: {other}"),
            Ok(true) => {}
            Ok(false) => panic!("invalid proof was accepted"),
        }
    }
}

#[test]
fn both_paths_distinguish_implication_shape_from_antecedent_identity() {
    for mismatch in [false, true] {
        let x = FreeVariable::new(0);
        let required = if mismatch { eq(1) } else { eq(0) };
        let steps = certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Simplification {
                antecedent: required.into(),
                consequent: eq(0).into(),
            },
            ProofStep::ModusPonens {
                premise: if mismatch { 0 } else { 1 },
                implication: if mismatch { 1 } else { 0 },
            },
        ]);
        let error = check(&steps).unwrap_err();
        let commands = [
            Command::Reflexivity { variable: 0 },
            Command::Equal {
                left: u32::from(mismatch),
                right: u32::from(mismatch),
            },
            Command::Equal { left: 0, right: 0 },
            Command::Simplification {
                antecedent: 1,
                consequent: 2,
            },
            Command::ModusPonens {
                premise: if mismatch { 0 } else { 3 },
                implication: if mismatch { 3 } else { 0 },
            },
        ];
        let report = fail(&mut engine(&commands));
        assert_eq!(report.failure, error.diagnostic().failure);
        assert_eq!(report.rule, Rule::ModusPonens);
        for role in [OperandRole::Premise, OperandRole::Implication] {
            let a = report.operand(role).unwrap();
            let b = error.diagnostic().operand(role).unwrap();
            assert_eq!(a.proved, Some(true));
            assert_eq!(
                a.formula.as_ref().unwrap().root,
                b.formula.as_ref().unwrap().root
            );
        }
        if mismatch {
            let difference = report.difference.as_ref().unwrap();
            assert!(difference.complete);
            assert_eq!(difference.path, vec![PathSegment::LeftVariable]);
            assert_eq!(
                difference.expected.node,
                FormulaNode::Equal {
                    left: Variable::Free(1),
                    right: Variable::Free(1)
                }
            );
            assert_eq!(
                difference.actual.node,
                FormulaNode::Equal {
                    left: Variable::Free(0),
                    right: Variable::Free(0)
                }
            );
        } else {
            assert_eq!(
                report
                    .operand(OperandRole::Implication)
                    .unwrap()
                    .formula
                    .as_ref()
                    .unwrap()
                    .root_node()
                    .unwrap()
                    .node
                    .kind(),
                NodeKind::Equal
            );
        }
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["failure"]["code"], error.diagnostic().code());
        assert!(json["input"]["digest"].as_str().unwrap().len() == 64);
    }
}

#[test]
fn constructed_formulas_are_never_misreported_as_proved_inputs() {
    let mut engine = engine(&[
        Command::Equal { left: 0, right: 0 },
        Command::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ]);
    let report = fail(&mut engine);
    assert_eq!(
        report.failure,
        Failure::InputNotProved {
            operand: OperandRole::Premise,
            reference: 0
        }
    );
    assert_eq!(
        report.operand(OperandRole::Premise).unwrap().proved,
        Some(false)
    );
    assert!(!engine.status().unwrap().fully_checked);
}

#[test]
fn schema_role_and_freshness_failures_have_the_same_witnesses_in_both_paths() {
    for collision in [true, false] {
        let (source, predicate) = if collision {
            (0, eq(0))
        } else {
            (
                1,
                Formula::equal(FreeVariable::new(0), FreeVariable::new(2)),
            )
        };
        let steps = certificate(vec![ProofStep::Separation(naome_proof::ProofSeparation {
            predicate: predicate.clone().into(),
            element: FreeVariable::new(0),
            source: FreeVariable::new(source),
            result: FreeVariable::new(2),
            parameters: vec![],
        })]);
        let error = check(&steps).unwrap_err();
        let mut engine = engine(&[
            Command::Equal {
                left: 0,
                right: if collision { 0 } else { 2 },
            },
            Command::Separation {
                predicate: 0,
                element: 0,
                source,
                result: 2,
            },
        ]);
        let report = fail(&mut engine);
        assert_eq!(report.failure, error.diagnostic().failure);
        assert_eq!(
            report
                .operand(OperandRole::Predicate)
                .unwrap()
                .formula
                .as_ref()
                .unwrap()
                .root,
            error
                .diagnostic()
                .operand(OperandRole::Predicate)
                .unwrap()
                .formula
                .as_ref()
                .unwrap()
                .root
        );
        assert!(!engine.status().unwrap().fully_checked);
    }
}

#[test]
fn bounded_inspection_preserves_binding_and_rejects_changed_inputs() {
    let steps = certificate(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(7),
    }]);
    let error = check(&steps).unwrap_err();
    assert_eq!(error.diagnostic().failure, Failure::OpenConclusion);
    let root = error
        .diagnostic()
        .operand(OperandRole::Conclusion)
        .unwrap()
        .formula
        .as_ref()
        .unwrap()
        .root;
    let query = FormulaQuery {
        start: None,
        operand: OperandRole::Conclusion,
        root,
        path: vec![],
        maximum_nodes: 4,
    };
    let fragment =
        inspect_certificate(&steps, &ArtifactState::new(), error.diagnostic(), &query).unwrap();
    assert_eq!(
        fragment.root_node().unwrap().node,
        FormulaNode::Equal {
            left: Variable::Free(7),
            right: Variable::Free(7)
        }
    );
    let changed = certificate(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(8),
    }]);
    assert_eq!(
        inspect_certificate(&changed, &ArtifactState::new(), error.diagnostic(), &query),
        Err(InspectionError::InputChanged)
    );
    let mut too_large = query;
    too_large.maximum_nodes = MAX_INSPECTION_NODES + 1;
    assert_eq!(
        inspect_certificate(
            &steps,
            &ArtifactState::new(),
            error.diagnostic(),
            &too_large
        ),
        Err(InspectionError::InvalidQuery)
    );
}

#[test]
fn large_shared_dag_diagnostics_and_queries_do_not_materialize_the_formula_tree() {
    let mut commands = vec![
        Command::Equal { left: 0, right: 0 },
        Command::Reflexivity { variable: 0 },
    ];
    let mut root = 0;
    for _ in 0..300 {
        let next = commands.len() as u64;
        commands.push(Command::Implies {
            antecedent: root,
            consequent: root,
        });
        root = next;
    }
    let implication = commands.len() as u64;
    commands.push(Command::Simplification {
        antecedent: root,
        consequent: root,
    });
    commands.push(Command::ModusPonens {
        premise: 1,
        implication,
    });
    let mut engine = engine(&commands);
    let report = fail(&mut engine);
    let formula = report
        .operand(OperandRole::Antecedent)
        .unwrap()
        .formula
        .as_ref()
        .unwrap();
    assert!(!formula.complete);
    assert!(formula.nodes.len() <= FORMULA_FRAGMENT_NODES);
    let query = FormulaQuery {
        start: None,
        operand: OperandRole::Antecedent,
        root: formula.root,
        path: vec![PathSegment::Antecedent; 200],
        maximum_nodes: 4,
    };
    let error = engine
        .advance_with_inspection(37, 4096, &ArtifactState::new(), &query)
        .unwrap_err();
    let fragment = error.diagnostic().unwrap().inspection.as_ref().unwrap();
    assert_eq!(fragment.nodes.len(), 4);
    assert!(!fragment.complete);
    assert_eq!(fragment.root_node().unwrap().node.kind(), NodeKind::Implies);
    engine.append(&Command::Alias { input: 0 }).unwrap();
    assert!(matches!(
        engine.inspect_formula(&report, &query, &ArtifactState::new()),
        Err(ProgramError::Inspection(InspectionError::InputChanged))
    ));
}

#[test]
fn rolled_back_or_reopened_prefix_requires_replay_before_inspection() {
    let commands = [
        Command::Reflexivity { variable: 0 },
        Command::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ];
    let mut engine = engine(&commands);
    let report = fail(&mut engine);
    let query = FormulaQuery {
        start: None,
        operand: OperandRole::Premise,
        root: report
            .operand(OperandRole::Premise)
            .unwrap()
            .formula
            .as_ref()
            .unwrap()
            .root,
        path: vec![],
        maximum_nodes: 1,
    };
    assert!(matches!(
        engine.inspect_formula(&report, &query, &ArtifactState::new()),
        Err(ProgramError::Inspection(
            InspectionError::ReplayRequired { .. }
        ))
    ));
    let error = engine
        .advance_with_inspection(37, 4096, &ArtifactState::new(), &query)
        .unwrap_err();
    assert!(
        error
            .diagnostic()
            .unwrap()
            .inspection
            .as_ref()
            .unwrap()
            .complete
    );
    assert_eq!(engine.status().unwrap().checked_commands, 0);
}

fn deep_mismatch_commands() -> Vec<Command> {
    let mut commands = vec![
        Command::Reflexivity { variable: 0 },
        Command::Member { element: 0, set: 0 },
    ];
    let (mut actual, mut expected) = (0, 1);
    for _ in 0..300 {
        let next = commands.len() as u64;
        commands.push(Command::Generalization {
            premise: actual,
            variable: 0,
        });
        actual = next;
        let next = commands.len() as u64;
        commands.push(Command::ForAll {
            body: expected,
            variable: 0,
        });
        expected = next;
    }
    let implication = commands.len() as u64;
    commands.push(Command::Simplification {
        antecedent: expected,
        consequent: expected,
    });
    commands.push(Command::ModusPonens {
        premise: actual,
        implication,
    });
    commands
}

#[test]
fn failed_program_diagnostic_stays_within_its_quantum() {
    let mut commands = deep_mismatch_commands();
    let failed = commands.pop().unwrap();
    let mut engine = engine(&commands);
    let context = ArtifactState::new();
    while engine.advance(2048, 4096, &context).unwrap() {}
    let checked_before = engine.status().unwrap().checked_commands;
    engine.append(&failed).unwrap();

    let error = engine.advance(1, 4096, &context).unwrap_err();
    let limited = error.diagnostic().unwrap();
    assert_eq!(limited.failure, Failure::AntecedentMismatch);
    assert!(limited.operand(OperandRole::Premise).is_some());
    assert!(limited.difference.is_none());
    assert_eq!(engine.last_quantum_steps(), 1);
    assert_eq!(engine.status().unwrap().checked_commands, checked_before);

    let error = engine.advance(32, 4096, &context).unwrap_err();
    let full = error.diagnostic().unwrap();
    assert_eq!(full.failure, limited.failure);
    assert_eq!(
        full.difference.as_ref().unwrap().path.len(),
        MAX_INSPECTION_PATH
    );
    assert!((2..=32).contains(&engine.last_quantum_steps()));
    assert_eq!(engine.status().unwrap().checked_commands, checked_before);
}

#[test]
fn deep_program_difference_can_be_inspected_in_bounded_segments() {
    let commands = deep_mismatch_commands();
    let mut engine = engine(&commands);
    let report = fail(&mut engine);
    let difference = report.difference.as_ref().unwrap();
    assert!(!difference.complete);
    assert_eq!(difference.path.len(), MAX_INSPECTION_PATH);
    let mut query = FormulaQuery {
        operand: OperandRole::Antecedent,
        root: report
            .operand(OperandRole::Antecedent)
            .unwrap()
            .formula
            .as_ref()
            .unwrap()
            .root,
        start: None,
        path: difference.path.clone(),
        maximum_nodes: 1,
    };
    let first = engine
        .advance_with_inspection(37, 4096, &ArtifactState::new(), &query)
        .unwrap_err();
    let first = first.diagnostic().unwrap().inspection.as_ref().unwrap();
    assert_eq!(first.root, difference.expected.id);
    assert_eq!(first.scope_depth, Some(256));
    query.start = Some(first.root);
    query.path = vec![PathSegment::Quantified; 44];
    let second = engine
        .advance_with_inspection(37, 4096, &ArtifactState::new(), &query)
        .unwrap_err();
    let second = second.diagnostic().unwrap().inspection.as_ref().unwrap();
    assert_eq!(second.anchor_root, query.root);
    assert_eq!(second.start, query.start);
    assert_eq!(second.scope_depth, None);
    assert!(second.complete);
    assert_eq!(second.root_node().unwrap().node.kind(), NodeKind::Member);
    assert!(engine.status().unwrap().checked_commands <= report.checked_before);
    assert!(!engine.status().unwrap().fully_checked);
}

#[test]
fn target_and_manifest_diagnostics_remain_bound_to_checked_results() {
    let variable = FreeVariable::new(0);
    let proof = certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]);
    let actual = Formula::for_all(variable, eq(0));
    let target = Formula::for_all(variable, Formula::member(variable, variable));
    let context = ArtifactState::new();
    let report = target_mismatch(&proof, &context, &target, &actual).unwrap();
    let mut query = FormulaQuery {
        operand: OperandRole::Conclusion,
        root: report
            .operand(OperandRole::Conclusion)
            .unwrap()
            .formula
            .as_ref()
            .unwrap()
            .root,
        start: None,
        path: vec![PathSegment::Quantified],
        maximum_nodes: 1,
    };
    let fragment = inspect_certificate(&proof, &context, &report, &query).unwrap();
    assert_eq!(fragment.scope_depth, Some(1));
    assert_eq!(
        fragment.root_node().unwrap().node,
        FormulaNode::Equal {
            left: Variable::Bound(0),
            right: Variable::Bound(0)
        }
    );
    let mut stale = report.clone();
    stale.schema_version += 1;
    assert_eq!(
        inspect_certificate(&proof, &context, &stale, &query),
        Err(InspectionError::UnsupportedDiagnostic)
    );
    let mut engine = engine(&[
        Command::Reflexivity { variable: 0 },
        Command::Generalization {
            premise: 0,
            variable: 0,
        },
        Command::Seal { proof: 1 },
    ]);
    while engine.advance(37, 4096, &context).unwrap() {}
    while !engine.prepare_export(37).unwrap() {}
    let checked = engine.checked().unwrap();
    let error = checked.check_target(&target).unwrap_err();
    let report = error.diagnostic().unwrap();
    assert_eq!(report.failure, Failure::TargetMismatch);
    assert_eq!(
        report.target_root,
        Some(formula::tree_fragment(target.view(), 1, 0).root)
    );
    assert_eq!(checked.inspect_formula(report, &query).unwrap(), fragment);
    query.operand = OperandRole::Target;
    query.root = report.target_root.unwrap();
    assert!(matches!(
        checked.inspect_formula(report, &query),
        Err(ProgramError::Inspection(InspectionError::TargetRequired))
    ));
    let mut manifest = checked.manifest().clone();
    manifest.commands += 1;
    assert!(matches!(
        checked
            .check_manifest(&manifest)
            .unwrap_err()
            .diagnostic()
            .unwrap()
            .failure,
        Failure::ManifestMismatch {
            field: ClaimField::Commands,
            ..
        }
    ));
    checked.check_manifest(checked.manifest()).unwrap();
}

#[test]
fn tree_continuation_preserves_exact_variables_and_rejects_foreign_addresses() {
    let formula = Formula::implies(eq(7), Formula::negate(eq(8)));
    let root = formula::tree_fragment(formula.view(), 1, 0).root;
    let mut query = FormulaQuery {
        operand: OperandRole::Formula,
        root,
        start: None,
        path: vec![PathSegment::Consequent],
        maximum_nodes: 1,
    };
    let first = inspect_formula_value(&formula, &query).unwrap();
    let FormulaNode::Not { body } = first.root_node().unwrap().node else {
        panic!("negated operand")
    };
    query.start = Some(body);
    query.path.clear();
    let second = inspect_formula_value(&formula, &query).unwrap();
    assert_eq!(
        second.root_node().unwrap().node,
        FormulaNode::Equal {
            left: Variable::Free(8),
            right: Variable::Free(8)
        }
    );
    assert_eq!(second.scope_depth, None);
    query.start = Some(Digest([0; 32]));
    assert_eq!(
        inspect_formula_value(&formula, &query),
        Err(InspectionError::UnknownFormula)
    );
}

#[test]
fn diagnostic_failure_codes_keep_typed_witnesses() {
    let failure = Failure::FormulaWorkLimit {
        actual: 42,
        maximum: 11,
    };
    let encoded = serde_json::to_value(&failure).unwrap();
    assert_eq!(encoded["code"], 0x0025_000fu32);
    assert_eq!(encoded["actual"], 42);
    assert_eq!(encoded["maximum"], 11);
    let context = serde_json::to_value(Failure::ContextLimit).unwrap();
    assert_eq!(context["code"], 0x0025_0010u32);
    assert_eq!(context.as_object().unwrap().len(), 1);
}

#[test]
fn nested_formula_and_expansion_failures_have_numeric_codes_and_witnesses() {
    let failure = Failure::Expansion {
        reason: ExpansionFailure::Formula {
            reason: FormulaFailure::DanglingBoundVariable {
                index: 3,
                binder_depth: 2,
            },
        },
    };
    let json = serde_json::to_value(&failure).unwrap();
    assert_eq!(json["code"], 0x0025_000d_u32);
    assert_eq!(json["reason"]["code"], 0x0029_0007_u32);
    assert_eq!(json["reason"]["reason"]["code"], 0x0028_0007_u32);
    assert_eq!(json["reason"]["reason"]["index"], 3);
    assert_eq!(json["reason"]["reason"]["binder_depth"], 2);
    assert!(json["reason"].get("kind").is_none());
}

#[test]
fn diagnostic_unit_values_have_registered_numeric_codes() {
    assert_eq!(
        serde_json::to_value(InputFormat::Program).unwrap(),
        0x002d_0002_u32
    );
    assert_eq!(
        serde_json::to_value(Outcome::MissingDependency).unwrap(),
        0x002e_0002_u32
    );
    assert_eq!(
        serde_json::to_value(Rule::ModusPonens).unwrap(),
        0x002f_0015_u32
    );
    assert_eq!(
        serde_json::to_value(OperandRole::Implication).unwrap(),
        0x0030_0002_u32
    );
    assert_eq!(
        serde_json::to_value(ClaimField::Commands).unwrap(),
        0x0031_0001_u32
    );
    assert_eq!(
        serde_json::to_value(NodeKind::ForAll).unwrap(),
        0x0035_0005_u32
    );
    assert_eq!(
        serde_json::to_value(PathSegment::Consequent).unwrap(),
        0x0037_0003_u32
    );
    assert_eq!(
        serde_json::to_value(VariableNamespace::Source).unwrap(),
        0x0038_0002_u32
    );
    let codes: Vec<_> = outcome_codes().map(|(_, _, code)| code).collect();
    let unique: std::collections::BTreeSet<_> = codes.iter().copied().collect();
    assert_eq!(codes.len(), unique.len());
    assert!(!unique.contains(&0));
}

#[test]
fn inspection_and_formula_values_preserve_numeric_types_and_witnesses() {
    let mismatch = Failure::ManifestMismatch {
        field: ClaimField::Commands,
        expected: ClaimValue::Count(2),
        actual: ClaimValue::Count(3),
    };
    let value = serde_json::to_value(mismatch).unwrap();
    assert_eq!(value["field"], 0x0031_0001_u32);
    assert_eq!(value["expected"]["code"], 0x0032_0001_u32);
    assert_eq!(value["expected"]["value"], 2);
    assert_eq!(value["actual"]["value"], 3);
    let inspection = InspectionError::ReplayRequired {
        checked_before: 3,
        required_before: 9,
    };
    let value = serde_json::to_value(inspection).unwrap();
    assert_eq!(value["code"], 0x0033_0006_u32);
    assert_eq!(value["required_before"], 9);
    let node = FormulaNode::Equal {
        left: Variable::Free(4),
        right: Variable::Bound(2),
    };
    let value = serde_json::to_value(node).unwrap();
    assert_eq!(value["code"], 0x0036_0001_u32);
    assert_eq!(value["left"]["code"], 0x0034_0001_u32);
    assert_eq!(value["left"]["identifier"], 4);
    assert_eq!(value["right"]["code"], 0x0034_0002_u32);
    assert_eq!(value["right"]["identifier"], 2);
    assert!(value.get("kind").is_none());
}
