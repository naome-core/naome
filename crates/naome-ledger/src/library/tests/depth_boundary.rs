use super::*;

#[test]
fn default_older_depth_32_is_checked_and_33_rejects_before_checker() {
    let profile = Profile::lab();
    assert_eq!(profile.limits().dependency_depth, 32);
    let mut library = ProofLibrary::new();
    let mut context = ArtifactState::new();
    let mut previous: Option<(ProofId, Formula)> = None;
    for index in 0..34usize {
        // Fixed-depth, distinct closed tautologies avoid coupling dependency
        // depth to the question's independently bounded formula depth.
        let left = FreeVariable::new((index / 8) as u32);
        let right = FreeVariable::new((index % 8) as u32);
        let antecedent = Formula::equal(left, left);
        let consequent = Formula::equal(right, right);
        let mut formula = Formula::implies(
            antecedent.clone(),
            Formula::implies(consequent.clone(), antecedent.clone()),
        );
        let mut steps = vec![ProofStep::Simplification {
            antecedent: antecedent.into(),
            consequent: consequent.into(),
        }];
        for variable in 0..8 {
            let variable = FreeVariable::new(variable);
            steps.push(ProofStep::Generalization {
                premise: (steps.len() - 1) as u32,
                variable,
            });
            formula = Formula::for_all(variable, formula);
        }
        if let Some((id, older_formula)) = &previous {
            let root = (steps.len() - 1) as u32;
            let older = steps.len() as u32;
            steps.push(ProofStep::ProofReference { proof_id: *id });
            let axiom = steps.len() as u32;
            steps.push(ProofStep::Simplification {
                antecedent: formula.clone().into(),
                consequent: older_formula.clone().into(),
            });
            let implication = steps.len() as u32;
            steps.push(ProofStep::ModusPonens {
                premise: root,
                implication: axiom,
            });
            steps.push(ProofStep::ModusPonens {
                premise: older,
                implication,
            });
        }
        let node = checked(steps, &mut context);
        let task = CompiledQuestion::compile(
            &format!(
                "foundation = \"naome:zfc\"\nstatement = {}",
                formula.to_source()
            ),
            &profile,
        )
        .unwrap();
        let package = ProofPackage::new(author(1), node.0, vec![node.clone()], &profile).unwrap();
        let mut work = VerificationWork::default();
        let result = library.normalize_with_work(&package, &task, &profile, &mut work);
        if index == 33 {
            let before = library.root();
            assert!(matches!(
                result,
                Err(LedgerError::Limit("older dependency depth"))
            ));
            assert_eq!(work, VerificationWork::default());
            assert_eq!(library.root(), before);
            assert_eq!(library.len(), 33);
            break;
        }
        let normalized = result.unwrap();
        if index == 32 {
            assert_eq!(work.checker_calls, 2 * 33);
            assert_eq!(normalized.citations(), &[previous.as_ref().unwrap().0]);
        }
        library
            .publish(
                &normalized,
                AdmissionCoordinate {
                    height: index as u64 + 1,
                    operation_index: 0,
                },
            )
            .unwrap();
        previous = Some((node.0, formula));
    }
}
