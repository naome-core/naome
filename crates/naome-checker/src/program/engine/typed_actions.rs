use super::*;
use crate::diagnostics::Failure;
use naome_foundation::Logic;

fn drain(engine: &mut Engine) {
    while engine.advance(64, 32768, &ArtifactState::new()).unwrap() {}
}

#[test]
fn native_projection_fuses_an_instantiation_at_its_only_later_use() {
    use naome_proof::{
        ProofCertificate, ProofStep,
        program::{Projection, StepResult},
    };

    let [x, y] = [0, 1].map(FreeVariable::new);
    let steps = vec![
        ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: Formula::equal(x, x).into(),
        },
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 1,
            variable: x,
        },
        ProofStep::ModusPonens {
            premise: 2,
            implication: 0,
        },
        ProofStep::Generalization {
            premise: 3,
            variable: y,
        },
    ];
    let projection = Projection::from_inference_steps(&steps).unwrap();
    assert!(matches!(
        projection.commands()[2],
        Command::Instantiate {
            premise: 1,
            replacement: 1
        }
    ));
    assert_eq!(projection.results()[0], StepResult::InstantiationAxiom(2));
    let certificate = crate::check_normal_form_with_state(
        ProofCertificate::new(steps)
            .unwrap()
            .into_unchecked_normal_form(),
        &ArtifactState::new(),
    )
    .unwrap();
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine.append_group(projection.commands()).unwrap();
    drain(&mut engine);
    while !engine.prepare_export(64).unwrap() {}
    let program = engine.checked().unwrap();
    assert_eq!(
        program.manifest().statement_id(),
        certificate.statement_id()
    );
    assert_eq!(program.conclusion(), Some(certificate.conclusion()));
}

#[test]
fn typed_instantiation_preserves_nested_binders_sharing_and_replay() {
    let path = std::env::temp_dir().join(format!(
        "naome-typed-instantiation-{}.sqlite3",
        std::process::id()
    ));
    let mut engine = Engine::open(Connection::open(&path).unwrap()).unwrap();
    engine
        .append_group(&[
            Command::Equal { left: 0, right: 0 },
            Command::Equal { left: 1, right: 1 },
            Command::Simplification {
                antecedent: 0,
                consequent: 1,
            },
            Command::Generalization {
                premise: 2,
                variable: 1,
            },
            Command::Generalization {
                premise: 3,
                variable: 0,
            },
        ])
        .unwrap();
    assert!(engine.checked_fact(4).is_err());
    drain(&mut engine);
    assert!(engine.checked_fact(0).is_err());
    let (fact, shape) = engine.checked_fact(4).unwrap();
    assert_eq!(shape, crate::program::FactShape::Universal);
    let mut other = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    assert!(other.instantiate(&fact, FreeVariable::new(1)).is_err());
    assert_eq!(other.status().unwrap().commands, 0);
    let (nonuniversal, _) = engine.checked_fact(2).unwrap();
    assert!(
        engine
            .instantiate(&nonuniversal, FreeVariable::new(1))
            .is_err()
    );
    assert_eq!(engine.status().unwrap().commands, 5);

    let result = engine.instantiate(&fact, FreeVariable::new(1)).unwrap();
    assert_eq!(result, 5);
    assert!(engine.checked_fact(result).is_err());
    engine.advance(4, 32768, &ArtifactState::new()).unwrap();
    assert_eq!(engine.status().unwrap().committed_commands, 5);
    drop(engine);
    let mut engine = Engine::open(Connection::open(&path).unwrap()).unwrap();
    assert!(engine.checked_fact(4).is_err());
    assert!(engine.instantiate(&fact, FreeVariable::new(1)).is_err());
    drain(&mut engine);
    let v = FreeVariable::new;
    let a = Formula::equal(v(0), v(0));
    let b = Formula::equal(v(1), v(1));
    let body = Formula::for_all(v(1), Logic::simplification(a, b));
    let expected = Logic::universal_instantiation(v(0), v(1), body);
    let (_, consequent) = expected.implication_parts().unwrap();
    assert_eq!(
        engine.result_formula(result).unwrap(),
        Some(consequent.clone())
    );
    assert!(
        !consequent.is_closed(),
        "the free replacement must escape the inner binder"
    );
    engine
        .append_group(&[
            Command::Generalization {
                premise: result,
                variable: 1,
            },
            Command::Seal { proof: 6 },
        ])
        .unwrap();
    drain(&mut engine);
    while !engine.prepare_export(64).unwrap() {}
    let checked = engine.checked().unwrap();
    assert_eq!(
        checked.instantiation_digest(result).unwrap(),
        format::formula_hash(&expected)
    );
    assert_eq!(
        checked.conclusion(),
        Some(&Formula::for_all(v(1), consequent))
    );

    // A second engine reconstructs trust from the canonical input group.
    let mut replay = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    let chunk = checked.input_chunk(0, 32, format::CHUNK_BYTES).unwrap();
    replay.append_group(&chunk.records).unwrap();
    drain(&mut replay);
    while !replay.prepare_export(64).unwrap() {}
    assert_eq!(replay.checked().unwrap().manifest(), checked.manifest());
    drop(checked);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn raw_instantiation_rejects_future_unproved_and_nonuniversal_inputs() {
    for (premise, failure) in [
        (
            2,
            Failure::ReferenceNotEarlier {
                operand: crate::diagnostics::OperandRole::Premise,
                reference: 2,
            },
        ),
        (
            0,
            Failure::InputNotProved {
                operand: crate::diagnostics::OperandRole::Premise,
                reference: 0,
            },
        ),
        (
            1,
            Failure::ExpectedUniversal {
                operand: crate::diagnostics::OperandRole::Premise,
            },
        ),
    ] {
        let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
        engine
            .append_group(&[
                Command::Equal { left: 0, right: 0 },
                Command::Reflexivity { variable: 0 },
                Command::Instantiate {
                    premise,
                    replacement: 1,
                },
            ])
            .unwrap();
        let error = loop {
            match engine.advance(1, 32768, &ArtifactState::new()) {
                Ok(true) => (),
                other => break other.unwrap_err(),
            }
        };
        assert_eq!(error.diagnostic().unwrap().failure, failure);
        assert_eq!(engine.status().unwrap().checked_commands, 2);
    }
}

#[test]
fn graph_nodes_keep_relative_scope_until_a_binder_closes_them() {
    let atom = Command::Graph {
        node: Node::Equal(Variable::Bound(0), Variable::Bound(0)),
    };
    let mut open = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    open.append(&atom).unwrap();
    drain(&mut open);
    open.append(&Command::Simplification {
        antecedent: 0,
        consequent: 0,
    })
    .unwrap();
    let error = open.advance(64, 32768, &ArtifactState::new()).unwrap_err();
    assert!(error.to_string().contains("dangling bound variables"));
    assert_eq!(open.status().unwrap().checked_commands, 1);

    let mut scoped = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    scoped
        .append_group(&[
            atom,
            Command::Graph {
                node: Node::ForAll(0),
            },
            Command::Simplification {
                antecedent: 1,
                consequent: 1,
            },
            Command::Seal { proof: 2 },
        ])
        .unwrap();
    drain(&mut scoped);
    assert!(scoped.checked_fact(1).is_err());
    let atom = Formula::equal(FreeVariable::new(0), FreeVariable::new(0));
    let quantifier = Formula::for_all(FreeVariable::new(0), atom);
    assert_eq!(
        scoped.result_formula(2).unwrap(),
        Some(Logic::simplification(quantifier.clone(), quantifier))
    );
}

#[test]
fn scope_rejects_future_facts_and_invalid_applications() {
    use naome_proof::program::ScopedAction;
    let prefix = [
        Command::Equal { left: 0, right: 0 },
        Command::Implies {
            antecedent: 0,
            consequent: 0,
        },
        Command::ForAll {
            variable: 0,
            body: 1,
        },
        Command::Member { element: 1, set: 1 },
    ];
    for (action, expected) in [
        (
            ScopedAction::Conjoin { left: 0, right: 2 },
            "outside the earlier deduction scope",
        ),
        (
            ScopedAction::Instantiate {
                universal: 1,
                replacement: 1,
                premises: vec![],
            },
            "requires a universal fact",
        ),
        (
            ScopedAction::Instantiate {
                universal: 0,
                replacement: 1,
                premises: vec![1],
            },
            "antecedent mismatch",
        ),
    ] {
        let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
        engine.append_group(&prefix).unwrap();
        drain(&mut engine);
        engine
            .append(&Command::Deduce {
                assumptions: vec![2, 3],
                actions: vec![action],
                result: 2,
            })
            .unwrap();
        let error = loop {
            match engine.advance(1, 32768, &ArtifactState::new()) {
                Ok(true) => (),
                other => break other.unwrap_err(),
            }
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(engine.status().unwrap().checked_commands, 4);
        assert!(engine.checked_fact(4).is_err());
    }
}

#[test]
fn deduction_returns_only_the_discharged_fact_after_its_quantum() {
    use naome_proof::program::ScopedAction;
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::Equal { left: 0, right: 0 },
            Command::Equal { left: 1, right: 1 },
            Command::Deduce {
                assumptions: vec![0, 1],
                actions: vec![ScopedAction::Conjoin { left: 0, right: 1 }],
                result: 2,
            },
        ])
        .unwrap();
    let mut units = 0;
    while engine.advance(1, 32768, &ArtifactState::new()).unwrap() {
        assert_eq!(engine.last_quantum_steps(), 1);
        units += 1;
    }
    assert!(
        units > 50,
        "the joined proof must execute its checked Hilbert steps"
    );
    assert!(engine.checked_fact(0).is_err());
    assert!(engine.checked_fact(1).is_err());
    assert!(engine.checked_fact(2).is_ok());
    assert!(engine.checked_fact(3).is_err());
    let a = Formula::equal(FreeVariable::new(0), FreeVariable::new(0));
    let b = Formula::equal(FreeVariable::new(1), FreeVariable::new(1));
    let expected = Formula::implies(
        a.clone(),
        Formula::implies(b.clone(), Formula::conjunction(a, b)),
    );
    assert_eq!(engine.result_formula(2).unwrap(), Some(expected));
}

#[test]
fn deduction_preparation_yields_and_charges_the_rejected_action() {
    use naome_proof::program::ScopedAction;

    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append(&Command::Equal { left: 0, right: 0 })
        .unwrap();
    drain(&mut engine);
    let mut actions = vec![ScopedAction::Conjoin { left: 0, right: 0 }; 31];
    actions.push(ScopedAction::Conjoin { left: 0, right: 32 });
    engine
        .append(&Command::Deduce {
            assumptions: vec![0],
            actions,
            result: 32,
        })
        .unwrap();
    let context = ArtifactState::new();

    for _ in 0..32 {
        assert!(engine.advance(1, 32768, &context).unwrap());
        assert_eq!(engine.last_quantum_steps(), 1);
        assert_eq!(engine.status().unwrap().checked_commands, 1);
    }
    let error = engine.advance(1, 32768, &context).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the earlier deduction scope")
    );
    assert_eq!(engine.last_quantum_steps(), 1);
    assert_eq!(engine.status().unwrap().checked_commands, 1);
    assert!(engine.checked_fact(1).is_err());
}
