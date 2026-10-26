//! Primitive Foundation constants. They grant no authority until full checking.
use naome_foundation::{Formula, Logic};
use naome_proof::{ProofCertificate, ProofStep};
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct Kernel {
    step: ProofStep,
    formula: Formula,
    key: Vec<u8>,
}
impl PartialEq for Kernel {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl Eq for Kernel {}
impl Hash for Kernel {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state)
    }
}

impl Kernel {
    pub fn new(step: ProofStep) -> Result<Self, String> {
        Self::with_context(step, &naome_checker::ArtifactState::new())
    }
    pub fn with_context(
        step: ProofStep,
        context: &dyn naome_checker::ContextView,
    ) -> Result<Self, String> {
        let primitive = |f: &naome_proof::ProofFormula| {
            f.expand_with(context)
                .map(std::borrow::Cow::into_owned)
                .map_err(|e| e.to_string())
        };
        let formula = match &step {
            ProofStep::Simplification {
                antecedent,
                consequent,
            } => Logic::simplification(primitive(antecedent)?, primitive(consequent)?),
            ProofStep::Frege {
                first,
                second,
                third,
            } => Logic::frege(primitive(first)?, primitive(second)?, primitive(third)?),
            ProofStep::ClassicalContraposition {
                antecedent,
                consequent,
            } => Logic::classical_contraposition(primitive(antecedent)?, primitive(consequent)?),
            ProofStep::UniversalDistribution {
                variable,
                antecedent,
                consequent,
            } => Logic::universal_distribution(
                *variable,
                primitive(antecedent)?,
                primitive(consequent)?,
            ),
            ProofStep::VacuousUniversal { formula } => {
                Logic::vacuous_universal(primitive(formula)?)
            }
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body,
            } => Logic::universal_instantiation(*variable, *replacement, primitive(body)?),
            ProofStep::EqualityReflexivity { variable } => Logic::equality_reflexivity(*variable),
            ProofStep::EqualitySubstitution { from, to, body } => {
                Logic::equality_substitution(*from, *to, primitive(body)?)
            }
            ProofStep::ZfcAxiom(axiom) => axiom.formula(),
            _ => return Err("unsupported kernel constant".into()),
        };
        let key = ProofCertificate::new(vec![step.clone()])
            .map_err(|e| e.to_string())?
            .to_canonical_bytes();
        Ok(Self { step, formula, key })
    }
    pub fn formula(&self) -> Formula {
        self.formula.clone()
    }
    pub fn step(&self) -> ProofStep {
        self.step.clone()
    }
}
