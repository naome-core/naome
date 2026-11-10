use super::{Axiom, Command, ScopedAction};
use crate::{
    DefinedFormula, DefinitionId, ProofFormula, ProofNormalForm, ProofStep,
    defined_formula::{Node as Defined, Variable as DefinedVariable},
};
use naome_foundation::{FormulaView, FreeVariable, ZfcAxiom};
use std::collections::{BTreeMap, HashMap, hash_map::Entry};

/// A rejected structural projection of an inference recipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProjectionFailure {
    SiteNotModusPonens = 1,
    MissingInstantiation = 2,
    ReferencedInstantiation = 3,
    EmptyRecipe = 4,
    ForwardReference = 5,
}
impl std::fmt::Display for ProjectionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "projection failure {}", *self as u8)
    }
}
impl std::error::Error for ProjectionFailure {}
impl From<ProjectionFailure> for String {
    fn from(value: ProjectionFailure) -> Self {
        value.to_string()
    }
}

/// A proved source for a leading assumption of a scoped deduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopedInput {
    Axiom(Axiom),
    Proof(crate::ProofId),
}

/// A structural projection of a bounded certificate into a shared program.
/// The program requires independent checking and has its own manifest identity.
pub struct Projection {
    commands: Vec<Command>,
    results: Vec<StepResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepResult {
    Result(u64),
    InstantiationAxiom(u64),
}

#[derive(Clone, Copy)]
enum InstantiationFold {
    Ordinary,
    OmittedAxiom,
    Application {
        axiom: u32,
        premise: u32,
        replacement: FreeVariable,
    },
}

impl Projection {
    pub fn from_normal_form(proof: &ProofNormalForm) -> Self {
        Self::with_instantiations(proof, &[]).expect("unfused projection")
    }

    /// Fold selected instantiation axioms into their sole modus ponens use.
    /// Independently replay the program before treating its results as checked.
    pub fn with_instantiations(
        proof: &ProofNormalForm,
        sites: &[usize],
    ) -> Result<Self, ProjectionFailure> {
        let steps = proof.certificate().steps();
        let uses = reference_counts(steps)?;
        Self::lower_steps(steps, &uses, sites.iter().copied(), &BTreeMap::new())
    }

    fn lower_steps(
        steps: &[ProofStep],
        uses: &[u8],
        sites: impl IntoIterator<Item = usize>,
        authored: &BTreeMap<DefinitionId, DefinedFormula>,
    ) -> Result<Self, ProjectionFailure> {
        let mut folds = vec![InstantiationFold::Ordinary; steps.len()];
        for site in sites {
            let Some(ProofStep::ModusPonens {
                premise,
                implication,
            }) = steps.get(site)
            else {
                return Err(ProjectionFailure::SiteNotModusPonens);
            };
            let axiom = *implication as usize;
            let ProofStep::UniversalInstantiation {
                replacement, body, ..
            } = &steps[axiom]
            else {
                return Err(ProjectionFailure::MissingInstantiation);
            };
            if uses[axiom] != 1
                || body.as_defined().is_some()
                || matches!(folds[axiom], InstantiationFold::OmittedAxiom)
            {
                return Err(ProjectionFailure::ReferencedInstantiation);
            }
            folds[axiom] = InstantiationFold::OmittedAxiom;
            folds[site] = InstantiationFold::Application {
                axiom: *implication,
                premise: *premise,
                replacement: *replacement,
            };
        }

        let mut builder = Builder {
            authored: Some(authored),
            ..Builder::default()
        };
        let mut results = vec![StepResult::Result(0); steps.len()];
        let mut handles = vec![0; steps.len()];
        for (index, (step, fold)) in steps.iter().zip(folds).enumerate() {
            let position = match fold {
                InstantiationFold::Ordinary => builder.step(step, &handles),
                InstantiationFold::OmittedAxiom => continue,
                InstantiationFold::Application {
                    axiom,
                    premise,
                    replacement,
                } => {
                    let position = builder.push(Command::Instantiate {
                        premise: handles[premise as usize],
                        replacement: replacement.identifier(),
                    });
                    results[axiom as usize] = StepResult::InstantiationAxiom(position);
                    position
                }
            };
            handles[index] = position;
            results[index] = StepResult::Result(position);
        }
        builder.push(Command::Seal {
            proof: *handles.last().ok_or(ProjectionFailure::EmptyRecipe)?,
        });
        Ok(Self {
            commands: builder.commands,
            results,
        })
    }

    /// Use a typed instantiation when an axiom has only one application.
    pub fn with_native_instantiations(proof: &ProofNormalForm) -> Result<Self, ProjectionFailure> {
        Self::from_inference_steps(proof.certificate().steps())
    }

    /// Lower an untrusted, dependency-ordered inference recipe directly into
    /// typed commands. The independent program checker validates the result.
    pub fn from_inference_steps(steps: &[ProofStep]) -> Result<Self, ProjectionFailure> {
        Self::from_authored_steps(steps, &BTreeMap::new())
    }

    /// Lower a recipe with formal bodies for selected composed definitions.
    /// Each supplied body is used only where the recipe applies that definition.
    pub fn from_authored_steps(
        steps: &[ProofStep],
        authored: &BTreeMap<DefinitionId, DefinedFormula>,
    ) -> Result<Self, ProjectionFailure> {
        let uses = reference_counts(steps)?;
        let sites = steps.iter().enumerate().filter_map(|(index, step)| {
            let ProofStep::ModusPonens { implication, .. } = step else {
                return None;
            };
            let axiom = *implication as usize;
            matches!(&steps[axiom], ProofStep::UniversalInstantiation { body, .. }
                if uses[axiom] == 1 && body.as_defined().is_none())
            .then_some(index)
        });
        Self::lower_steps(steps, &uses, sites, authored)
    }

    /// Build one scoped deduction, exposing only its discharged conclusion.
    pub fn scoped(
        assumptions: &[ProofFormula],
        actions: &[ScopedAction],
        result: u32,
        binders: &[FreeVariable],
    ) -> Vec<Command> {
        Self::scoped_with_references(assumptions, actions, result, binders, &[])
    }

    /// Discharge a deduction and apply checked proof references to its leading
    /// assumptions before generalizing the remaining goal.
    pub fn scoped_with_references(
        assumptions: &[ProofFormula],
        actions: &[ScopedAction],
        result: u32,
        binders: &[FreeVariable],
        references: &[crate::ProofId],
    ) -> Vec<Command> {
        Self::scoped_with_inputs(
            assumptions,
            actions,
            result,
            binders,
            references.iter().copied().map(ScopedInput::Proof),
        )
    }

    /// Discharge the local scope, then apply proved inputs to its leading
    /// assumptions in order. The checker verifies each input and application.
    pub fn scoped_with_inputs(
        assumptions: &[ProofFormula],
        actions: &[ScopedAction],
        result: u32,
        binders: &[FreeVariable],
        inputs: impl IntoIterator<Item = ScopedInput>,
    ) -> Vec<Command> {
        let mut builder = Builder::default();
        let assumptions = assumptions
            .iter()
            .map(|formula| builder.formula(formula))
            .collect();
        let mut proof = builder.push(Command::Deduce {
            assumptions,
            actions: actions.to_vec(),
            result,
        });
        for input in inputs {
            let premise = builder.push(match input {
                ScopedInput::Axiom(axiom) => Command::Axiom { axiom },
                ScopedInput::Proof(reference) => Command::ProofReference {
                    proof_id: *reference.as_bytes(),
                },
            });
            proof = builder.push(Command::ModusPonens {
                premise,
                implication: proof,
            });
        }
        for variable in binders.iter().rev() {
            proof = builder.push(Command::Generalization {
                premise: proof,
                variable: variable.identifier(),
            });
        }
        builder.push(Command::Seal { proof });
        builder.commands
    }

    /// Construct a checked conjunction from two actual proof references.
    /// Formula operands describe the discharged assumptions, while the
    /// references supply the proofs used to apply them.
    pub fn conjoin(operands: &[(crate::ProofId, ProofFormula); 2]) -> Vec<Command> {
        Self::scoped_with_references(
            &[operands[0].1.clone(), operands[1].1.clone()],
            &[ScopedAction::Conjoin { left: 0, right: 1 }],
            2,
            &[],
            &[operands[0].0, operands[1].0],
        )
    }

    pub fn into_commands(self) -> Vec<Command> {
        self.commands
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    /// Locations of normalized certificate results in the checked trace.
    /// Schema parameter closures map to the last enclosing generalization.
    pub fn results(&self) -> &[StepResult] {
        &self.results
    }
}

fn reference_counts(steps: &[ProofStep]) -> Result<Vec<u8>, ProjectionFailure> {
    // A fold needs exactly one use. Saturation keeps repeated uses repeated.
    let mut uses = vec![0u8; steps.len()];
    for (position, step) in steps.iter().enumerate() {
        for reference in step.local_references().into_iter().flatten() {
            if reference as usize >= position {
                return Err(ProjectionFailure::ForwardReference);
            }
            let count = &mut uses[reference as usize];
            *count = count.saturating_add(1);
        }
    }
    Ok(uses)
}

#[derive(Default)]
struct Builder<'a> {
    authored: Option<&'a BTreeMap<DefinitionId, DefinedFormula>>,
    commands: Vec<Command>,
    formulas: HashMap<Command, u64>,
}

impl Builder<'_> {
    fn push(&mut self, command: Command) -> u64 {
        let position = self.commands.len() as u64;
        self.commands.push(command);
        position
    }

    fn intern(&mut self, command: Command) -> u64 {
        match self.formulas.entry(command) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let position = self.commands.len() as u64;
                self.commands.push(entry.key().clone());
                *entry.insert(position)
            }
        }
    }

    fn formula(&mut self, formula: &ProofFormula) -> u64 {
        if let Some(primitive) = formula.as_primitive() {
            self.primitive(primitive.view())
        } else {
            self.defined(
                formula
                    .as_defined()
                    .expect("definition-aware formula")
                    .graph_root(),
                0,
                self.authored,
            )
        }
    }

    fn primitive(&mut self, formula: FormulaView<'_>) -> u64 {
        let node = formula.graph_node().map(|child| self.primitive(child));
        self.intern(Command::Graph { node })
    }

    fn defined(
        &mut self,
        formula: &Defined,
        depth: u32,
        authored: Option<&BTreeMap<DefinitionId, DefinedFormula>>,
    ) -> u64 {
        let term = |variable| match variable {
            DefinedVariable::Free(id) => id.identifier(),
            DefinedVariable::Bound(index) => bound_identifier(depth, index),
        };
        let command = match formula {
            Defined::Equal(left, right) => Command::Equal {
                left: term(*left),
                right: term(*right),
            },
            Defined::Member(element, set) => Command::Member {
                element: term(*element),
                set: term(*set),
            },
            Defined::Not(body) => Command::Not {
                formula: self.defined(body, depth, authored),
            },
            Defined::Implies(left, right) => Command::Implies {
                antecedent: self.defined(left, depth, authored),
                consequent: self.defined(right, depth, authored),
            },
            Defined::ForAll(body) => Command::ForAll {
                variable: binder(depth),
                body: self.defined(body, depth + 1, authored),
            },
            Defined::DefinedRelation {
                definition_id,
                arguments,
            } => {
                let arguments = arguments.iter().copied().map(term).collect();
                if let Some(body) = authored.and_then(|bodies| bodies.get(definition_id)) {
                    Command::AuthoredRelation {
                        definition_id: *definition_id.as_bytes(),
                        arguments,
                        body: self.defined(body.graph_root(), 0, None),
                    }
                } else {
                    Command::DefinedRelation {
                        definition_id: *definition_id.as_bytes(),
                        arguments,
                    }
                }
            }
        };
        self.intern(command)
    }

    fn step(&mut self, step: &ProofStep, results: &[u64]) -> u64 {
        let id = FreeVariable::identifier;
        let (command, parameters) = match step {
            ProofStep::Separation(schema) => (
                Command::Separation {
                    predicate: self.formula(&schema.predicate),
                    element: id(schema.element),
                    source: id(schema.source),
                    result: id(schema.result),
                },
                schema.parameters.as_slice(),
            ),
            ProofStep::Replacement(schema) => (
                Command::Replacement {
                    predicate: self.formula(&schema.predicate),
                    input: id(schema.input),
                    output: id(schema.output),
                    witness: id(schema.uniqueness_witness),
                    source: id(schema.source),
                    result: id(schema.result),
                },
                schema.parameters.as_slice(),
            ),
            step => {
                let command = self.inference(step, results);
                return self.push(command);
            }
        };
        let mut premise = self.push(command);
        for &variable in parameters.iter().rev() {
            premise = self.push(Command::Generalization {
                premise,
                variable: id(variable),
            });
        }
        premise
    }

    fn inference(&mut self, step: &ProofStep, results: &[u64]) -> Command {
        let id = FreeVariable::identifier;
        let result = |position: u32| results[position as usize];
        match step {
            ProofStep::Simplification {
                antecedent,
                consequent,
            } => Command::Simplification {
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::Frege {
                first,
                second,
                third,
            } => Command::Frege {
                first: self.formula(first),
                second: self.formula(second),
                third: self.formula(third),
            },
            ProofStep::ClassicalContraposition {
                antecedent,
                consequent,
            } => Command::Contraposition {
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::UniversalDistribution {
                variable,
                antecedent,
                consequent,
            } => Command::Distribution {
                variable: id(*variable),
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::VacuousUniversal { formula } => Command::Vacuous {
                formula: self.formula(formula),
            },
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body,
            } => Command::Instantiation {
                variable: id(*variable),
                replacement: id(*replacement),
                body: self.formula(body),
            },
            ProofStep::EqualityReflexivity { variable } => Command::Reflexivity {
                variable: id(*variable),
            },
            ProofStep::EqualitySubstitution { from, to, body } => Command::Substitution {
                from: id(*from),
                to: id(*to),
                body: self.formula(body),
            },
            ProofStep::ZfcAxiom(axiom) => Command::Axiom {
                axiom: match axiom {
                    ZfcAxiom::Extensionality => Axiom::Extensionality,
                    ZfcAxiom::Pairing => Axiom::Pairing,
                    ZfcAxiom::Union => Axiom::Union,
                    ZfcAxiom::PowerSet => Axiom::PowerSet,
                    ZfcAxiom::Infinity => Axiom::Infinity,
                    ZfcAxiom::Foundation => Axiom::Foundation,
                    ZfcAxiom::Choice => Axiom::Choice,
                },
            },
            ProofStep::ProofReference { proof_id } => Command::ProofReference {
                proof_id: *proof_id.as_bytes(),
            },
            ProofStep::ModusPonens {
                premise,
                implication,
            } => Command::ModusPonens {
                premise: result(*premise),
                implication: result(*implication),
            },
            ProofStep::Generalization { premise, variable } => Command::Generalization {
                premise: result(*premise),
                variable: id(*variable),
            },
            ProofStep::Separation(_) | ProofStep::Replacement(_) => {
                unreachable!("schema handled before inference")
            }
        }
    }
}

// Certificate normalization assigns a dense sequence of free identifiers
// bounded by the certificate limits. Reserve the opposite end for binders.
// An open subtree keys on its actual binder identifiers, not tree shape alone.
fn binder(depth: u32) -> u32 {
    u32::MAX - depth
}

fn bound_identifier(depth: u32, index: u32) -> u32 {
    binder(depth - 1 - index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inference_recipe_has_a_typed_failure() {
        assert!(matches!(
            Projection::from_inference_steps(&[]),
            Err(ProjectionFailure::EmptyRecipe)
        ));
    }

    #[test]
    fn heavily_shared_instantiation_is_never_treated_as_single_use() {
        use naome_foundation::Formula;

        let variable = FreeVariable::new(0);
        let mut steps = vec![
            ProofStep::UniversalInstantiation {
                variable,
                replacement: variable,
                body: Formula::equal(variable, variable).into(),
            },
            ProofStep::EqualityReflexivity { variable },
        ];
        steps.extend(std::iter::repeat_n(
            ProofStep::ModusPonens {
                premise: 1,
                implication: 0,
            },
            257,
        ));
        let projection = Projection::from_inference_steps(&steps).unwrap();
        assert!(matches!(projection.results()[0], StepResult::Result(_)));
        assert!(
            projection
                .commands()
                .iter()
                .all(|command| !matches!(command, Command::Instantiate { .. }))
        );
    }

    #[test]
    fn a_selected_instantiation_cannot_be_folded_twice() {
        use crate::ProofCertificate;
        use naome_foundation::Formula;

        let [x, y] = [0, 1].map(FreeVariable::new);
        let proof = ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStep::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: Formula::equal(x, x).into(),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
        ])
        .unwrap()
        .into_unchecked_normal_form();
        let site = proof.certificate().steps().len() - 1;
        assert!(Projection::with_instantiations(&proof, &[site]).is_ok());
        assert!(matches!(
            Projection::with_instantiations(&proof, &[site, site]),
            Err(ProjectionFailure::ReferencedInstantiation)
        ));
    }
}
