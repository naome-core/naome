use std::collections::{BTreeMap, btree_map::Entry};

use naome_foundation::{Formula, FreeVariable, Replacement, Separation};

use crate::{ProofCertificateV0, ProofStepV0, codec};

pub(super) fn normalize(certificate: ProofCertificateV0) -> ProofCertificateV0 {
    let mut source = certificate.steps.into_iter().map(Some).collect::<Vec<_>>();
    let mut normalized_indices = vec![None; source.len()];
    let mut normalized_steps = Vec::new();
    let mut interned_steps = BTreeMap::new();
    let mut variables = VariableNormalizer::default();
    let mut traversal = vec![Visit::Enter(source.len() - 1)];

    while let Some(visit) = traversal.pop() {
        let position = match visit {
            Visit::Enter(position) | Visit::Exit(position) => position,
        };
        if normalized_indices[position].is_some() {
            continue;
        }

        match visit {
            Visit::Enter(_) => {
                traversal.push(Visit::Exit(position));
                let references = source[position]
                    .as_ref()
                    .expect("an unvisited proof step remains available")
                    .local_references();
                if let Some(reference) = references[1] {
                    traversal.push(Visit::Enter(reference as usize));
                }
                if let Some(reference) = references[0] {
                    traversal.push(Visit::Enter(reference as usize));
                }
            }
            Visit::Exit(_) => {
                let step = source[position]
                    .take()
                    .expect("an exiting proof step has not been consumed");
                let step = normalize_step(step, &normalized_indices, &mut variables);
                let mut key = Vec::new();
                codec::encode_step(&step, &mut key)
                    .expect("a certificate step remains canonically encodable");

                let normalized = match interned_steps.entry(key) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let index = u32::try_from(normalized_steps.len())
                            .expect("the source certificate bounds normalized step indices");
                        entry.insert(index);
                        normalized_steps.push(step);
                        index
                    }
                };
                normalized_indices[position] = Some(normalized);
            }
        }
    }

    // Mapping fixed-width identifiers cannot enlarge a step; reachability and
    // interning only remove steps, so every source certificate limit remains.
    ProofCertificateV0 {
        steps: normalized_steps,
    }
}

#[derive(Clone, Copy)]
enum Visit {
    Enter(usize),
    Exit(usize),
}

fn normalize_step(
    step: ProofStepV0,
    normalized_indices: &[Option<u32>],
    variables: &mut VariableNormalizer,
) -> ProofStepV0 {
    match step {
        ProofStepV0::Simplification {
            antecedent,
            consequent,
        } => ProofStepV0::Simplification {
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStepV0::Frege {
            first,
            second,
            third,
        } => ProofStepV0::Frege {
            first: variables.formula(first),
            second: variables.formula(second),
            third: variables.formula(third),
        },
        ProofStepV0::ClassicalContraposition {
            antecedent,
            consequent,
        } => ProofStepV0::ClassicalContraposition {
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStepV0::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => ProofStepV0::UniversalDistribution {
            variable: variables.variable(variable),
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStepV0::VacuousUniversal { formula } => ProofStepV0::VacuousUniversal {
            formula: variables.formula(formula),
        },
        ProofStepV0::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => ProofStepV0::UniversalInstantiation {
            variable: variables.variable(variable),
            replacement: variables.variable(replacement),
            body: variables.formula(body),
        },
        ProofStepV0::EqualityReflexivity { variable } => ProofStepV0::EqualityReflexivity {
            variable: variables.variable(variable),
        },
        ProofStepV0::EqualitySubstitution { from, to, body } => ProofStepV0::EqualitySubstitution {
            from: variables.variable(from),
            to: variables.variable(to),
            body: variables.formula(body),
        },
        ProofStepV0::ZfcAxiom(axiom) => ProofStepV0::ZfcAxiom(axiom),
        ProofStepV0::Separation(instance) => {
            let Separation {
                predicate,
                element,
                source,
                result,
                parameters,
            } = instance;
            ProofStepV0::Separation(Separation {
                predicate: variables.formula(predicate),
                element: variables.variable(element),
                source: variables.variable(source),
                result: variables.variable(result),
                parameters: variables.variables(parameters),
            })
        }
        ProofStepV0::Replacement(instance) => {
            let Replacement {
                predicate,
                input,
                output,
                uniqueness_witness,
                source,
                result,
                parameters,
            } = instance;
            ProofStepV0::Replacement(Replacement {
                predicate: variables.formula(predicate),
                input: variables.variable(input),
                output: variables.variable(output),
                uniqueness_witness: variables.variable(uniqueness_witness),
                source: variables.variable(source),
                result: variables.variable(result),
                parameters: variables.variables(parameters),
            })
        }
        ProofStepV0::ProofReference { proof_id } => ProofStepV0::ProofReference { proof_id },
        ProofStepV0::ModusPonens {
            premise,
            implication,
        } => ProofStepV0::ModusPonens {
            premise: normalized_reference(premise, normalized_indices),
            implication: normalized_reference(implication, normalized_indices),
        },
        ProofStepV0::Generalization { premise, variable } => ProofStepV0::Generalization {
            premise: normalized_reference(premise, normalized_indices),
            variable: variables.variable(variable),
        },
    }
}

fn normalized_reference(reference: u32, normalized_indices: &[Option<u32>]) -> u32 {
    normalized_indices[reference as usize]
        .expect("dependency-first traversal normalizes every referenced step first")
}

#[derive(Default)]
struct VariableNormalizer {
    normalized: BTreeMap<FreeVariable, FreeVariable>,
    next_identifier: u32,
}

impl VariableNormalizer {
    fn formula(&mut self, formula: Formula) -> Formula {
        formula.map_free_variables(|variable| self.variable(variable))
    }

    fn variables(&mut self, variables: Vec<FreeVariable>) -> Vec<FreeVariable> {
        variables
            .into_iter()
            .map(|variable| self.variable(variable))
            .collect()
    }

    fn variable(&mut self, variable: FreeVariable) -> FreeVariable {
        match self.normalized.entry(variable) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let normalized = FreeVariable::new(self.next_identifier);
                self.next_identifier = self
                    .next_identifier
                    .checked_add(1)
                    .expect("the certificate byte limit bounds distinct free variables");
                entry.insert(normalized);
                normalized
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

    use crate::{CERTIFICATE_V0_MAX_STEPS, ProofCertificateV0, ProofId, ProofStepV0};

    #[test]
    fn topological_order_and_free_variable_names_do_not_change_the_normal_form() {
        let first = identity_proof(FreeVariable::new(7), false).into_unchecked_normal_form();
        let reordered = identity_proof(FreeVariable::new(42), true).into_unchecked_normal_form();

        assert_eq!(
            first.certificate().to_canonical_bytes(),
            reordered.certificate().to_canonical_bytes()
        );
        assert_eq!(
            first.certificate().steps(),
            identity_proof(FreeVariable::new(0), false).steps()
        );
    }

    #[test]
    fn normal_form_golden_prunes_renames_deduplicates_and_remaps_references() {
        let first = [
            0x00, 0x00, 0x00, 0x00, 0x06, 0x10, 0x01, 0x06, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00,
            0x00, 0x00, 0x07, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x21, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x04,
        ];
        let reordered = [
            0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x00, 0x00, 0x00, 0x2a, 0x10, 0x06, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x06, 0x00, 0x00, 0x00, 0x2a, 0x21, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x04,
        ];
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];

        for encoded in [&first[..], &reordered[..]] {
            let normal = ProofCertificateV0::from_canonical_bytes(encoded)
                .unwrap()
                .into_unchecked_normal_form();
            assert_eq!(normal.certificate().to_canonical_bytes(), expected);
        }
    }

    #[test]
    fn exact_reachable_nodes_are_shared_without_sorting_dependency_roles() {
        let x = FreeVariable::new(9);
        let duplicate = duplicate_identity_proof(x);
        let original_steps = duplicate.steps().len();
        let original_bytes = duplicate.to_canonical_bytes().len();
        let normal = duplicate.into_unchecked_normal_form();

        assert_eq!(original_steps, 9);
        assert_eq!(normal.certificate().steps().len(), 7);
        assert!(normal.certificate().to_canonical_bytes().len() < original_bytes);
        assert!(matches!(
            normal.certificate().steps()[2],
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            }
        ));
        assert!(matches!(
            normal.certificate().steps()[5],
            ProofStepV0::ModusPonens {
                premise: 2,
                implication: 4,
            }
        ));

        let formula = Formula::equal(x, x);
        let correct = certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Simplification {
                antecedent: formula.clone(),
                consequent: formula,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ])
        .into_unchecked_normal_form();
        let swapped = certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Simplification {
                antecedent: Formula::equal(x, x),
                consequent: Formula::equal(x, x),
            },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 0,
            },
        ])
        .into_unchecked_normal_form();

        assert_ne!(
            correct.certificate().to_canonical_bytes(),
            swapped.certificate().to_canonical_bytes()
        );
    }

    #[test]
    fn proof_reference_leaves_deduplicate_only_by_exact_proof_id() {
        let first_id = ProofId::from_bytes([0x11; 32]);
        let second_id = ProofId::from_bytes([0x22; 32]);
        let duplicate = certificate(vec![
            ProofStepV0::ProofReference { proof_id: first_id },
            ProofStepV0::ProofReference { proof_id: first_id },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ])
        .into_unchecked_normal_form();
        let distinct = certificate(vec![
            ProofStepV0::ProofReference { proof_id: first_id },
            ProofStepV0::ProofReference {
                proof_id: second_id,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ])
        .into_unchecked_normal_form();

        assert_eq!(duplicate.certificate().steps().len(), 2);
        assert!(matches!(
            duplicate.certificate().steps()[1],
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 0,
            }
        ));
        assert_eq!(distinct.certificate().steps().len(), 3);
        assert_ne!(
            duplicate.certificate().to_canonical_bytes(),
            distinct.certificate().to_canonical_bytes()
        );
    }

    #[test]
    fn unreachable_steps_are_removed_and_normalization_is_idempotent() {
        let x = FreeVariable::new(13);
        let certificate = certificate(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Generalization {
                premise: 1,
                variable: x,
            },
        ]);
        let original_bytes = certificate.to_canonical_bytes().len();
        let normal = certificate.into_unchecked_normal_form();

        assert_eq!(normal.certificate().steps().len(), 2);
        assert!(normal.certificate().to_canonical_bytes().len() < original_bytes);

        let first_bytes = normal.certificate().to_canonical_bytes();
        let second_bytes = normal
            .certificate()
            .clone()
            .into_unchecked_normal_form()
            .certificate()
            .to_canonical_bytes();
        assert_eq!(second_bytes, first_bytes);
    }

    #[test]
    fn equal_conclusions_with_different_derivations_remain_different_proofs() {
        let x = FreeVariable::new(4);
        let direct = certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .into_unchecked_normal_form();
        let detour = identity_proof(x, false).into_unchecked_normal_form();

        assert_ne!(
            direct.certificate().to_canonical_bytes(),
            detour.certificate().to_canonical_bytes()
        );
    }

    #[test]
    fn every_non_reference_step_payload_is_normalized_in_wire_order() {
        let a = FreeVariable::new(10);
        let b = FreeVariable::new(20);
        let c = FreeVariable::new(30);
        let d = FreeVariable::new(40);
        let e = FreeVariable::new(50);
        let f = FreeVariable::new(60);
        let g = FreeVariable::new(70);
        let h = FreeVariable::new(80);
        let n = FreeVariable::new;
        let cases = vec![
            (
                ProofStepV0::Simplification {
                    antecedent: Formula::member(b, a),
                    consequent: Formula::equal(c, b),
                },
                ProofStepV0::Simplification {
                    antecedent: Formula::member(n(0), n(1)),
                    consequent: Formula::equal(n(2), n(0)),
                },
            ),
            (
                ProofStepV0::Frege {
                    first: Formula::equal(a, b),
                    second: Formula::member(c, a),
                    third: Formula::equal(d, c),
                },
                ProofStepV0::Frege {
                    first: Formula::equal(n(0), n(1)),
                    second: Formula::member(n(2), n(0)),
                    third: Formula::equal(n(3), n(2)),
                },
            ),
            (
                ProofStepV0::ClassicalContraposition {
                    antecedent: Formula::member(b, a),
                    consequent: Formula::equal(c, b),
                },
                ProofStepV0::ClassicalContraposition {
                    antecedent: Formula::member(n(0), n(1)),
                    consequent: Formula::equal(n(2), n(0)),
                },
            ),
            (
                ProofStepV0::UniversalDistribution {
                    variable: c,
                    antecedent: Formula::equal(a, b),
                    consequent: Formula::member(b, c),
                },
                ProofStepV0::UniversalDistribution {
                    variable: n(0),
                    antecedent: Formula::equal(n(1), n(2)),
                    consequent: Formula::member(n(2), n(0)),
                },
            ),
            (
                ProofStepV0::VacuousUniversal {
                    formula: Formula::implies(Formula::equal(a, b), Formula::member(c, a)),
                },
                ProofStepV0::VacuousUniversal {
                    formula: Formula::implies(
                        Formula::equal(n(0), n(1)),
                        Formula::member(n(2), n(0)),
                    ),
                },
            ),
            (
                ProofStepV0::UniversalInstantiation {
                    variable: c,
                    replacement: a,
                    body: Formula::member(b, c),
                },
                ProofStepV0::UniversalInstantiation {
                    variable: n(0),
                    replacement: n(1),
                    body: Formula::member(n(2), n(0)),
                },
            ),
            (
                ProofStepV0::EqualityReflexivity { variable: a },
                ProofStepV0::EqualityReflexivity { variable: n(0) },
            ),
            (
                ProofStepV0::EqualitySubstitution {
                    from: b,
                    to: c,
                    body: Formula::implies(Formula::member(a, b), Formula::equal(c, a)),
                },
                ProofStepV0::EqualitySubstitution {
                    from: n(0),
                    to: n(1),
                    body: Formula::implies(Formula::member(n(2), n(0)), Formula::equal(n(1), n(2))),
                },
            ),
            (
                ProofStepV0::ZfcAxiom(ZfcAxiom::Choice),
                ProofStepV0::ZfcAxiom(ZfcAxiom::Choice),
            ),
            (
                ProofStepV0::Separation(Separation {
                    predicate: Formula::equal(c, b),
                    element: a,
                    source: d,
                    result: e,
                    parameters: vec![b, f, a],
                }),
                ProofStepV0::Separation(Separation {
                    predicate: Formula::equal(n(0), n(1)),
                    element: n(2),
                    source: n(3),
                    result: n(4),
                    parameters: vec![n(1), n(5), n(2)],
                }),
            ),
            (
                ProofStepV0::Replacement(Replacement {
                    predicate: Formula::member(d, c),
                    input: b,
                    output: e,
                    uniqueness_witness: a,
                    source: f,
                    result: g,
                    parameters: vec![c, h, b],
                }),
                ProofStepV0::Replacement(Replacement {
                    predicate: Formula::member(n(0), n(1)),
                    input: n(2),
                    output: n(3),
                    uniqueness_witness: n(4),
                    source: n(5),
                    result: n(6),
                    parameters: vec![n(1), n(7), n(2)],
                }),
            ),
        ];

        for (input, expected) in cases {
            let normal = certificate(vec![input]).into_unchecked_normal_form();
            assert_eq!(normal.certificate().steps(), [expected]);
        }
    }

    #[test]
    fn maximum_step_chain_normalizes_iteratively() {
        let x = FreeVariable::new(u32::MAX);
        let mut steps = Vec::with_capacity(CERTIFICATE_V0_MAX_STEPS);
        steps.push(ProofStepV0::EqualityReflexivity { variable: x });
        while steps.len() < CERTIFICATE_V0_MAX_STEPS {
            let premise = u32::try_from(steps.len() - 1).unwrap();
            steps.push(ProofStepV0::Generalization {
                premise,
                variable: x,
            });
        }

        let normal = certificate(steps).into_unchecked_normal_form();
        assert_eq!(normal.certificate().steps().len(), CERTIFICATE_V0_MAX_STEPS);
    }

    fn identity_proof(variable: FreeVariable, reordered: bool) -> ProofCertificateV0 {
        let formula = Formula::equal(variable, variable);
        let axiom = ProofStepV0::Simplification {
            antecedent: formula.clone(),
            consequent: formula,
        };
        let reflexivity = ProofStepV0::EqualityReflexivity { variable };
        let mut steps = if reordered {
            vec![axiom, reflexivity]
        } else {
            vec![reflexivity, axiom]
        };
        let (premise, implication) = if reordered { (1, 0) } else { (0, 1) };
        steps.push(ProofStepV0::ModusPonens {
            premise,
            implication,
        });
        steps.push(ProofStepV0::ModusPonens {
            premise,
            implication: 2,
        });
        steps.push(ProofStepV0::Generalization {
            premise: 3,
            variable,
        });
        certificate(steps)
    }

    fn duplicate_identity_proof(variable: FreeVariable) -> ProofCertificateV0 {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::implies(equality.clone(), equality.clone());
        certificate(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStepV0::Simplification {
                antecedent: identity.clone(),
                consequent: identity,
            },
            ProofStepV0::ModusPonens {
                premise: 3,
                implication: 5,
            },
            ProofStepV0::ModusPonens {
                premise: 4,
                implication: 6,
            },
            ProofStepV0::Generalization {
                premise: 7,
                variable,
            },
        ])
    }

    fn certificate(steps: Vec<ProofStepV0>) -> ProofCertificateV0 {
        ProofCertificateV0::new(steps).expect("the test proof is structurally valid")
    }
}
