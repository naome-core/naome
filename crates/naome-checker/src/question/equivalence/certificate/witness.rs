//! Elaborate the frozen witness trace into a regular Hilbert certificate.
use crate::derived::{COMMUTATION, Step, Term};
use naome_foundation::{Formula, FreeVariable, Logic};
use naome_proof::{
    ProofCertificate, ProofStep,
    program::{CHUNK_BYTES, Command, ScopedAction, encode_command, encode_records},
};
use std::collections::HashMap;

enum Origin {
    Hypothesis(u8),
    Axiom(Box<ProofStep>),
    Apply { premise: usize, implication: usize },
}

struct Line {
    formula: Formula,
    open: u16,
    origin: Origin,
}

#[derive(Default)]
struct Derivation {
    lines: Vec<Line>,
    axioms: HashMap<Vec<u8>, usize>,
    applications: HashMap<(usize, usize), usize>,
    discharged: HashMap<(u8, usize), usize>,
}

impl Derivation {
    fn push(&mut self, formula: Formula, open: u16, origin: Origin) -> usize {
        assert!(self.lines.len() < 8192, "witness elaboration limit");
        let position = self.lines.len();
        self.lines.push(Line {
            formula,
            open,
            origin,
        });
        position
    }

    fn assume(&mut self, hypothesis: u8, formula: Formula) -> usize {
        self.push(formula, 1 << hypothesis, Origin::Hypothesis(hypothesis))
    }

    fn axiom(&mut self, step: ProofStep, result: Formula) -> usize {
        let key = result.encode_canonical().unwrap();
        if let Some(&id) = self.axioms.get(&key) {
            return id;
        }
        let position = self.push(result, 0, Origin::Axiom(Box::new(step)));
        self.axioms.insert(key, position);
        position
    }

    fn k(&mut self, a: Formula, b: Formula) -> usize {
        self.axiom(
            ProofStep::Simplification {
                antecedent: a.clone().into(),
                consequent: b.clone().into(),
            },
            Logic::simplification(a, b),
        )
    }

    fn s(&mut self, a: Formula, b: Formula, c: Formula) -> usize {
        self.axiom(
            ProofStep::Frege {
                first: a.clone().into(),
                second: b.clone().into(),
                third: c.clone().into(),
            },
            Logic::frege(a, b, c),
        )
    }

    fn apply(&mut self, implication: usize, premise: usize) -> usize {
        if let Some(&position) = self.applications.get(&(implication, premise)) {
            return position;
        }
        let (expected, result) = self.lines[implication].formula.implication_parts().unwrap();
        assert_eq!(expected, self.lines[premise].formula);
        let open = self.lines[implication].open | self.lines[premise].open;
        let position = self.push(
            result,
            open,
            Origin::Apply {
                premise,
                implication,
            },
        );
        self.applications.insert((implication, premise), position);
        position
    }

    fn instantiate(&mut self, rule: usize, witness: FreeVariable) -> usize {
        let fresh = FreeVariable::new(13);
        let body = self.lines[rule]
            .formula
            .open_outer_universal(fresh)
            .unwrap();
        let q3 = self.axiom(
            ProofStep::UniversalInstantiation {
                variable: fresh,
                replacement: witness,
                body: body.clone().into(),
            },
            Logic::universal_instantiation(fresh, witness, body),
        );
        self.apply(q3, rule)
    }

    fn discharge(&mut self, hypothesis: u8, argument: &Formula, root: usize) -> usize {
        if let Some(&position) = self.discharged.get(&(hypothesis, root)) {
            return position;
        }
        let line = &self.lines[root];
        let bit = 1u16 << hypothesis;
        let position = if line.open & bit == 0 {
            let lift = self.k(line.formula.clone(), argument.clone());
            self.apply(lift, root)
        } else {
            match line.origin {
                Origin::Hypothesis(index) => {
                    assert_eq!(index, hypothesis);
                    let aa = Formula::implies(argument.clone(), argument.clone());
                    let frege = self.s(argument.clone(), aa.clone(), argument.clone());
                    let first = self.k(argument.clone(), aa);
                    let second = self.k(argument.clone(), argument.clone());
                    let partial = self.apply(frege, first);
                    self.apply(partial, second)
                }
                Origin::Apply {
                    premise,
                    implication,
                } => {
                    if matches!(self.lines[premise].origin, Origin::Hypothesis(i) if i == hypothesis)
                        && self.lines[implication].open & bit == 0
                    {
                        implication
                    } else {
                        let frege = self.s(
                            argument.clone(),
                            self.lines[premise].formula.clone(),
                            line.formula.clone(),
                        );
                        let implication = self.discharge(hypothesis, argument, implication);
                        let premise = self.discharge(hypothesis, argument, premise);
                        let partial = self.apply(frege, implication);
                        self.apply(partial, premise)
                    }
                }
                Origin::Axiom(_) => unreachable!("axioms have no assumptions"),
            }
        };
        self.discharged.insert((hypothesis, root), position);
        position
    }

    fn commutation(&mut self, a: &Formula, b: &Formula) -> usize {
        let mut formulas: Vec<Formula> = Vec::new();
        for term in COMMUTATION.terms {
            let formula = match *term {
                Term::A => a.clone(),
                Term::B => b.clone(),
                Term::Not(i) => Formula::negate(formulas[i].clone()),
                Term::Implies(i, j) => Formula::implies(formulas[i].clone(), formulas[j].clone()),
            };
            formulas.push(formula);
        }
        let mut lines = Vec::new();
        for step in COMMUTATION.steps {
            let f = |i: usize| formulas[i].clone();
            let line = match *step {
                Step::K(i, j) => self.k(f(i), f(j)),
                Step::S(i, j, k) => self.s(f(i), f(j), f(k)),
                Step::C(i, j) => self.axiom(
                    ProofStep::ClassicalContraposition {
                        antecedent: f(i).into(),
                        consequent: f(j).into(),
                    },
                    Logic::classical_contraposition(f(i), f(j)),
                ),
                Step::Mp(i, j) => self.apply(lines[j], lines[i]),
            };
            lines.push(line);
        }
        lines.pop().unwrap()
    }

    fn join(&mut self, left: usize, right: usize) -> usize {
        let a = self.lines[left].formula.clone();
        let b = self.lines[right].formula.clone();
        let contrary = Formula::implies(a, Formula::negate(b.clone()));
        let assumed = self.assume(9, contrary.clone());
        let negation = self.apply(assumed, left);
        let discharged = self.discharge(9, &contrary, negation);
        let commutation = self.commutation(&contrary, &b);
        let implication = self.apply(commutation, discharged);
        self.apply(implication, right)
    }

    fn certificate(self, root: usize, binders: u8) -> ProofCertificate {
        assert_eq!(self.lines[root].open, 0);
        let mut needed = vec![false; self.lines.len()];
        needed[root] = true;
        for (i, line) in self.lines.iter().enumerate().rev() {
            if needed[i]
                && let Origin::Apply {
                    premise,
                    implication,
                } = line.origin
            {
                needed[premise] = true;
                needed[implication] = true;
            }
        }
        let mut steps = Vec::new();
        let mut positions = vec![0; self.lines.len()];
        for (i, line) in self.lines.into_iter().enumerate() {
            if !needed[i] {
                continue;
            }
            positions[i] = steps.len() as u32;
            steps.push(match line.origin {
                Origin::Axiom(step) => *step,
                Origin::Apply {
                    premise,
                    implication,
                } => ProofStep::ModusPonens {
                    premise: positions[premise],
                    implication: positions[implication],
                },
                Origin::Hypothesis(_) => panic!("open hypothesis in finished witness"),
            });
        }
        for id in (0..binders).rev() {
            steps.push(ProofStep::Generalization {
                premise: steps.len() as u32 - 1,
                variable: FreeVariable::new(u32::from(id)),
            });
        }
        eprintln!(
            "short witness elaborated to {} primitive steps before normalization",
            steps.len()
        );
        ProofCertificate::new(steps).unwrap()
    }
}

#[test]
fn prototype_elaborates_and_discharges_every_assumption() {
    let prototype = include_bytes!("../../../../tests/fixtures/membership-witness.bin");
    let mut bytes = prototype.strip_prefix(b"NPIR").unwrap().iter().copied();
    let binders = bytes.next().unwrap();
    let mut formulas: Vec<Formula> = Vec::new();
    let mut commands = Vec::new();
    let variable = |id| FreeVariable::new(u32::from(id));
    for _ in 0..bytes.next().unwrap() {
        let tag = bytes.next().unwrap();
        let a = bytes.next().unwrap();
        let (formula, command) = match tag {
            1 => {
                let b = bytes.next().unwrap();
                (
                    Formula::member(variable(a), variable(b)),
                    Command::Member {
                        element: u32::from(a),
                        set: u32::from(b),
                    },
                )
            }
            2 => (
                Formula::negate(formulas[a as usize].clone()),
                Command::Not {
                    formula: u64::from(a),
                },
            ),
            3 => {
                let b = bytes.next().unwrap();
                (
                    Formula::implies(formulas[a as usize].clone(), formulas[b as usize].clone()),
                    Command::Implies {
                        antecedent: u64::from(a),
                        consequent: u64::from(b),
                    },
                )
            }
            4 => {
                let b = bytes.next().unwrap();
                (
                    Formula::for_all(variable(a), formulas[b as usize].clone()),
                    Command::ForAll {
                        variable: u32::from(a),
                        body: u64::from(b),
                    },
                )
            }
            _ => panic!("unknown prototype node"),
        };
        formulas.push(formula);
        commands.push(command);
    }
    let assumption_positions = (0..bytes.next().unwrap())
        .map(|_| u64::from(bytes.next().unwrap()))
        .collect::<Vec<_>>();
    let assumptions = assumption_positions
        .iter()
        .map(|&position| formulas[position as usize].clone())
        .collect::<Vec<_>>();
    let target = &formulas[bytes.next().unwrap() as usize];
    // The remaining formula nodes encode the declared target. The program
    // derives it instead of supplying it as a proof operand.
    commands.truncate(1 + *assumption_positions.iter().max().unwrap() as usize);
    let graph_records = commands.len();
    let mut proof = Derivation::default();
    let mut facts = assumptions
        .iter()
        .enumerate()
        .map(|(index, formula)| proof.assume(index as u8, formula.clone()))
        .collect::<Vec<_>>();
    let mut actions = Vec::new();
    for _ in 0..bytes.next().unwrap() {
        let tag = bytes.next().unwrap();
        let first = bytes.next().unwrap();
        let second = bytes.next().unwrap();
        let (result, action) = match tag {
            0x20 | 0x21 => {
                let mut result = proof.instantiate(facts[first as usize], variable(second));
                let premises: Vec<_> = (0..=tag - 0x20)
                    .map(|_| u32::from(bytes.next().unwrap()))
                    .collect();
                for &premise in &premises {
                    result = proof.apply(result, facts[premise as usize]);
                }
                (
                    result,
                    ScopedAction::Instantiate {
                        universal: u32::from(first),
                        replacement: u32::from(second),
                        premises,
                    },
                )
            }
            0x22 => (
                proof.join(facts[first as usize], facts[second as usize]),
                ScopedAction::Conjoin {
                    left: u32::from(first),
                    right: u32::from(second),
                },
            ),
            _ => panic!("unknown prototype action"),
        };
        facts.push(result);
        actions.push(action);
    }
    assert_eq!(actions.len(), 9);
    let scope = Command::Deduce {
        assumptions: assumption_positions,
        actions,
        result: facts.len() as u32 - 1,
    };
    let scope_bytes = encode_command(&scope).unwrap().len();
    commands.push(scope);
    for variable in (0..binders).rev() {
        commands.push(Command::Generalization {
            premise: commands.len() as u64 - 1,
            variable: u32::from(variable),
        });
    }
    commands.push(Command::Seal {
        proof: commands.len() as u64 - 1,
    });
    let program_bytes = encode_records(&commands).unwrap();
    assert_eq!(
        program_bytes,
        include_bytes!("../../../../tests/fixtures/membership-witness.program"),
    );
    assert_eq!(bytes.next(), None);
    let mut root = *facts.last().unwrap();
    assert_eq!(&proof.lines[root].formula, target);
    for (index, assumption) in assumptions.iter().enumerate().rev() {
        root = proof.discharge(index as u8, assumption, root);
    }
    let checked = crate::normalize_and_check(proof.certificate(root, binders)).unwrap();
    let expected = [
        0xd3, 0x0a, 0xd4, 0xee, 0x36, 0x3c, 0x32, 0xa9, 0x67, 0xe4, 0xd7, 0x0d, 0xd7, 0x5b, 0x59,
        0xef, 0x6d, 0xb4, 0x45, 0xb5, 0x32, 0x6a, 0xc7, 0x21, 0x6e, 0x64, 0x19, 0xef, 0xfa, 0x13,
        0xf0, 0xd2,
    ];
    assert_eq!(checked.statement_id().as_bytes(), &expected);
    assert!(checked.direct_artifact_dependencies().is_empty());
    let mut engine =
        crate::program::Engine::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
    engine.append_group(&commands).unwrap();
    let mut quanta = 0;
    while engine
        .advance(17, 32768, &crate::ArtifactState::new())
        .unwrap()
    {
        quanta += engine.last_quantum_steps();
    }
    while !engine.prepare_export(512).unwrap() {}
    let program = engine.checked().unwrap();
    assert_eq!(program.conclusion(), Some(checked.conclusion()));
    assert!(program.dependencies_after(None, 1).unwrap().is_empty());
    assert!(
        program
            .definition_dependencies_after(None, 1)
            .unwrap()
            .is_empty()
    );
    let manifest = program.manifest();
    assert_eq!(manifest.statement_id(), checked.statement_id());
    assert_eq!(manifest.input_bytes as usize, program_bytes.len());
    let graph_bytes = encode_records(&commands[..graph_records]).unwrap().len();
    eprintln!(
        "witness graph_bytes={graph_bytes} scope_bytes={scope_bytes} close_and_seal_bytes={} work_units={quanta}",
        program_bytes.len() - graph_bytes - scope_bytes
    );

    let mut chunk_bytes = 0;
    let mut start = 0;
    while start < manifest.commands {
        let chunk = program.input_chunk(start, 1024, CHUNK_BYTES).unwrap();
        chunk_bytes += chunk.canonical_bytes().unwrap().len();
        start += chunk.records.len() as u64;
    }
    eprintln!(
        "witness regular steps={} certificate bytes={} commands={} records={} manifest={} chunks={}",
        checked.normal_form().certificate().steps().len(),
        checked.normal_form().canonical_bytes().len(),
        manifest.commands,
        manifest.input_bytes,
        manifest.canonical_bytes().unwrap().len(),
        chunk_bytes
    );
}
