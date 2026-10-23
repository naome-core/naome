#[path = "support/finite_model.rs"]
mod finite_model;

use finite_model::{Named, Primitive, generate, worlds};
use naome_checker::{ArtifactState, check_definition_with_state};
use naome_foundation::{Formula, FreeVariable, Logic};
use naome_proof::{DefinedFormula, DefinitionCertificate, DefinitionKind};

#[test]
fn generated_binding_and_simultaneous_substitution_match_named_variable_semantics() {
    for seed in 0..256 {
        let named = generate(seed, 4);
        let formula = named.lower();
        let from = (seed % 4) as usize;
        let to = ((seed + 1) % 4) as usize;
        let decoded = Primitive::from_formula(&formula);
        let substituted = Primitive::from_formula(
            &formula
                .clone()
                .substitute_free(FreeVariable::new(from as u32), FreeVariable::new(to as u32)),
        );
        let renamed = Primitive::from_formula(
            &formula
                .clone()
                .map_free_variables(|variable| FreeVariable::new(variable.identifier() ^ 1)),
        );
        let quantified = Primitive::from_formula(&Formula::for_all(
            FreeVariable::new(from as u32),
            formula.clone(),
        ));
        let expected_quantified = Named::All(from as u8, Box::new(named.clone()));
        worlds(|model, free| {
            assert_eq!(
                decoded.evaluate(model, free),
                named.evaluate(model, free),
                "lowering seed {seed}"
            );
            let mut replacement = free;
            replacement[from] = free[to];
            assert_eq!(
                substituted.evaluate(model, free),
                named.evaluate(model, replacement),
                "substitution seed {seed}"
            );
            let swapped = std::array::from_fn(|index| free[index ^ 1]);
            assert_eq!(
                renamed.evaluate(model, free),
                named.evaluate(model, swapped),
                "simultaneous mapping seed {seed}"
            );
            assert_eq!(
                quantified.evaluate(model, free),
                expected_quantified.evaluate(model, free),
                "binding seed {seed}"
            );
        });
        if let Named::All(variable, body) = &named {
            let opened = Primitive::from_formula(
                &formula.open_outer_universal(FreeVariable::new(7)).unwrap(),
            );
            worlds(|model, free| {
                let mut expected = free;
                expected[*variable as usize] = free[7];
                assert_eq!(
                    opened.evaluate(model, free),
                    body.evaluate(model, expected),
                    "opening seed {seed}"
                );
            });
        }
    }
}

#[test]
fn generated_logical_axiom_instances_hold_in_independent_finite_structures() {
    for seed in 0..64 {
        let a = generate(seed * 3, 3).lower();
        let b = generate(seed * 3 + 1, 3).lower();
        let c = generate(seed * 3 + 2, 3).lower();
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        for axiom in [
            Logic::simplification(a.clone(), b.clone()),
            Logic::frege(a.clone(), b.clone(), c),
            Logic::classical_contraposition(a.clone(), b.clone()),
            Logic::universal_distribution(x, a.clone(), b),
            Logic::vacuous_universal(a.clone()),
            Logic::universal_instantiation(x, y, a.clone()),
            Logic::equality_reflexivity(x),
            Logic::equality_substitution(x, y, a),
        ] {
            let semantics = Primitive::from_formula(&axiom);
            worlds(|model, free| {
                assert!(
                    semantics.evaluate(model, free),
                    "invalid logical instance at seed {seed}: {}",
                    axiom.to_source()
                )
            });
        }
    }
}

#[test]
fn selected_definition_expansion_matches_independent_parameter_semantics_under_binders() {
    for seed in 0..64 {
        // Both formal arguments occur freely, while generated inner quantifiers
        // may shadow either name. Extra names are closed inside the definition.
        let body = Named::Implies(
            Box::new(Named::Member(0, 1)),
            Box::new(Named::All(
                2,
                Box::new(Named::All(3, Box::new(generate(seed, 4)))),
            )),
        );
        let primitive = body.lower();
        let certificate = DefinitionCertificate::new(
            DefinitionKind::Relation { arity: 2 },
            DefinedFormula::from_primitive(&primitive).unwrap(),
        )
        .unwrap();
        let mut state = ArtifactState::new();
        let checked = check_definition_with_state(certificate, &state).unwrap();
        let id = checked.definition_id();
        state.register_definition(checked).unwrap();
        let x = FreeVariable::new(7);
        let y = FreeVariable::new(6);
        for arguments in [[x, y], [y, x], [x, x]] {
            let compact = DefinedFormula::for_all(
                x,
                DefinedFormula::for_all(y, DefinedFormula::defined_relation(id, arguments)),
            );
            let expanded = compact.expand_with(&state).unwrap();
            assert!(expanded.is_closed());
            let actual = Primitive::from_formula(&expanded);
            worlds(|model, free| {
                let expected = (0..model.domain).all(|outer| {
                    (0..model.domain).all(|inner| {
                        let argument = |variable| if variable == x { outer } else { inner };
                        let mut parameters = free;
                        parameters[0] = argument(arguments[0]);
                        parameters[1] = argument(arguments[1]);
                        body.evaluate(model, parameters)
                    })
                });
                assert_eq!(
                    actual.evaluate(model, free),
                    expected,
                    "definition expansion seed {seed}, arguments {arguments:?}"
                );
            });
        }
    }
}

#[test]
fn the_oracle_distinguishes_capture_from_free_substitution() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let body = Formula::for_all(x, Formula::member(x, y));
    let correct = Primitive::from_formula(&body.substitute_free(y, x));
    let captured = Primitive::from_formula(&Formula::for_all(x, Formula::member(x, x)));
    let mut distinguishes = false;
    worlds(|model, free| {
        distinguishes |= correct.evaluate(model, free) != captured.evaluate(model, free)
    });
    assert!(
        distinguishes,
        "the model distribution must expose a capture defect"
    );
}
