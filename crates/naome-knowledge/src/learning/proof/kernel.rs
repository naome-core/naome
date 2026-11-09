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
    pub fn new(step: ProofStep) -> Result<Self, crate::Error> {
        Self::with_context(step, &naome_checker::ArtifactState::new())
    }
    pub fn with_context(
        step: ProofStep,
        context: &dyn naome_checker::ContextView,
    ) -> Result<Self, crate::Error> {
        let primitive = |f: &naome_proof::ProofFormula| {
            f.expand_with(context)
                .map(std::borrow::Cow::into_owned)
                .map_err(crate::Error::from)
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
            ProofStep::Separation(instance) => naome_foundation::Separation {
                predicate: primitive(&instance.predicate)?,
                element: instance.element,
                source: instance.source,
                result: instance.result,
                parameters: instance.parameters.clone(),
            }
            .formula()
            .map_err(crate::Error::from)?,
            ProofStep::Replacement(instance) => naome_foundation::Replacement {
                predicate: primitive(&instance.predicate)?,
                input: instance.input,
                output: instance.output,
                uniqueness_witness: instance.uniqueness_witness,
                source: instance.source,
                result: instance.result,
                parameters: instance.parameters.clone(),
            }
            .formula()
            .map_err(crate::Error::from)?,
            _ => return Err(crate::ResearchFailure::KernelUnsupported.into()),
        };
        let key = ProofCertificate::new(vec![step.clone()])
            .map_err(|error| {
                crate::Error::CertificateConstruction(crate::FormatFailure::from(&error))
            })?
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

#[cfg(test)]
mod tests {
    use super::*;
    use naome_foundation::FreeVariable;

    #[test]
    fn missing_definition_keeps_expansion_diagnostic() {
        let variable = FreeVariable::new(0);
        let missing = naome_proof::DefinitionId::from_bytes([7; 32]);
        let defined = naome_proof::DefinedFormula::defined_relation(missing, [variable]);
        let step = ProofStep::Simplification {
            antecedent: naome_proof::ProofFormula::from_defined(defined).unwrap(),
            consequent: Formula::equal(variable, variable).into(),
        };
        let error = Kernel::new(step).unwrap_err();
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], 0x0006_001d_u32);
        assert!(value["expansion"]["code"].as_u64().is_some());
    }

    #[test]
    fn schema_role_collision_keeps_code_and_variable() {
        let variable = FreeVariable::new(3);
        let step = ProofStep::Separation(naome_proof::ProofSeparation {
            predicate: Formula::equal(variable, variable).into(),
            element: variable,
            source: variable,
            result: FreeVariable::new(4),
            parameters: vec![],
        });
        let error = Kernel::new(step).unwrap_err();
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], 0x0006_001e_u32);
        assert_eq!(
            value["reason"],
            u32::from(crate::SchemaFailure::RoleCollision)
        );
        assert_eq!(value["variable"], 3);
    }
}
