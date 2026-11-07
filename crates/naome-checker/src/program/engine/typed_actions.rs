use super::*;
use crate::diagnostics::Failure;
use naome_foundation::Logic;

fn drain(engine: &mut Engine) {
    while engine.advance(64, 32768, &ArtifactState::new()).unwrap() {}
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
    assert_eq!(result, 6);
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
    assert_eq!(engine.result_formula(5).unwrap(), Some(expected));
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
            Command::Seal { proof: 7 },
        ])
        .unwrap();
    drain(&mut engine);
    while !engine.prepare_export(64).unwrap() {}
    let checked = engine.checked().unwrap();
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
                Command::InstantiationFor {
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
