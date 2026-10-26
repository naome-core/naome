use super::*;
use naome_foundation::FreeVariable;
use naome_proof::{
    DefinedFormula, DefinitionCertificate, ProofCertificate, ProofSeparation, ProofStep,
};

#[test]
fn definition_instantiation_obeys_single_step_pause_and_capture_safe_semantics() {
    let formal = FreeVariable::new(0);
    let binder = FreeVariable::new(1);
    let mut body = DefinedFormula::for_all(
        binder,
        DefinedFormula::implies(
            DefinedFormula::equal(formal, binder),
            DefinedFormula::member(formal, binder),
        ),
    );
    let argument = FreeVariable::new(1);
    let fresh = FreeVariable::new(99);
    let mut expected = Formula::for_all(
        fresh,
        Formula::implies(
            Formula::equal(argument, fresh),
            Formula::member(argument, fresh),
        ),
    );
    for _ in 0..96 {
        body = DefinedFormula::negate(body);
        expected = Formula::negate(expected);
    }
    let certificate = DefinitionCertificate::relation(1, body).unwrap();
    let id = certificate.definition_id();
    let mut context = ArtifactState::new();
    context
        .register_definition(crate::check_definition_with_state(certificate, &context).unwrap())
        .unwrap();
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::DefinedRelation {
                definition_id: *id.as_bytes(),
                arguments: vec![1],
            },
            Command::Separation {
                predicate: 0,
                element: 1,
                source: 2,
                result: 3,
            },
            Command::Seal { proof: 1 },
        ])
        .unwrap();
    let mut quanta = 0;
    while engine.status().unwrap().checked_commands == 0 {
        let before = engine.status().unwrap();
        assert!(!engine.advance(0, 4096, &context).unwrap());
        assert_eq!(engine.status().unwrap().formula_nodes, before.formula_nodes);
        assert_eq!(engine.status().unwrap().checked_commands, 0);
        engine.advance(1, 4096, &context).unwrap();
        let after = engine.status().unwrap();
        assert!(
            after.formula_nodes <= before.formula_nodes + 1,
            "one quantum must not import the entire definition"
        );
        assert_eq!(engine.last_quantum_steps(), 1);
        engine.suspend_cache().unwrap();
        assert_eq!(
            engine
                .connection
                .pragma_query_value(None, "cache_size", |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        quanta += 1;
        assert!(quanta < 1024);
    }
    assert!(quanta > 96);
    while engine.advance(128, 4096, &context).unwrap() {}
    while !engine.prepare_export(128).unwrap() {}
    let mut checked = engine.checked().unwrap();
    let oracle = crate::normalize_and_check(
        ProofCertificate::new(vec![ProofStep::Separation(ProofSeparation {
            predicate: expected.into(),
            element: argument,
            source: FreeVariable::new(2),
            result: FreeVariable::new(3),
            parameters: Vec::new(),
        })])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(checked.conclusion(), Some(oracle.conclusion()));
    assert_eq!(checked.manifest().statement_id(), oracle.statement_id());
    let manifest = checked.manifest().clone();
    checked.suspend_cache().unwrap();
    assert_eq!(checked.manifest(), &manifest);
    checked.restrict_cache(4096).unwrap();
    assert_eq!(checked.conclusion(), Some(oracle.conclusion()));
}

#[test]
fn restarting_a_partial_definition_replays_input_and_requires_the_selected_definition() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "naome-definition-quantum-{}-{}.sqlite3",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let formal = FreeVariable::new(0);
    let mut body = DefinedFormula::equal(formal, formal);
    let mut primitive = Formula::equal(formal, formal);
    for _ in 0..96 {
        body = DefinedFormula::negate(body);
        primitive = Formula::negate(primitive);
    }
    let certificate = DefinitionCertificate::relation(1, body).unwrap();
    let id = certificate.definition_id();
    let mut context = ArtifactState::new();
    context
        .register_definition(crate::check_definition_with_state(certificate, &context).unwrap())
        .unwrap();
    let mut engine = Engine::open(Connection::open(&path).unwrap()).unwrap();
    engine
        .append_group(&[
            Command::DefinedRelation {
                definition_id: *id.as_bytes(),
                arguments: vec![0],
            },
            Command::Separation {
                predicate: 0,
                element: 0,
                source: 1,
                result: 2,
            },
            Command::Seal { proof: 1 },
        ])
        .unwrap();
    engine.advance(128, 4096, &context).unwrap();
    assert_eq!(engine.status().unwrap().checked_commands, 0);
    assert!(engine.status().unwrap().formula_nodes > 0);
    drop(engine);
    let mut missing = Engine::open(Connection::open(&path).unwrap()).unwrap();
    assert_eq!(missing.status().unwrap().checked_commands, 0);
    assert!(
        matches!(missing.advance(1, 4096, &ArtifactState::new()), Err(Error::Check(error))
        if matches!(error.failure, crate::diagnostics::Failure::Expansion {
            reason: crate::diagnostics::ExpansionFailure::UnknownDefinition { .. }
        }))
    );
    drop(missing);
    let mut replay = Engine::open(Connection::open(&path).unwrap()).unwrap();
    while replay.advance(17, 4096, &context).unwrap() {}
    while !replay.prepare_export(17).unwrap() {}
    let checked = replay.checked().unwrap();
    let oracle = crate::normalize_and_check(
        ProofCertificate::new(vec![ProofStep::Separation(ProofSeparation {
            predicate: primitive.into(),
            element: formal,
            source: FreeVariable::new(1),
            result: FreeVariable::new(2),
            parameters: Vec::new(),
        })])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(checked.conclusion(), Some(oracle.conclusion()));
    assert_eq!(checked.manifest().statement_id(), oracle.statement_id());
    drop(checked);
    std::fs::remove_file(path).unwrap();
}
