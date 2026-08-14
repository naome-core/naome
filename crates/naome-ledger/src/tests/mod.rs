use std::error::Error;

use naome_checker::{
    ArtifactState, ArtifactStateError, CheckError, normalize_and_check,
    normalize_and_check_with_state,
};
use naome_foundation::{Formula, FreeVariable, LogicError, Separation, ZfcAxiom};
use naome_proof::{
    ArtifactId, ArtifactPayloadError, CERTIFICATE_MAX_BYTES, ProofCertificate,
    ProofCertificateError, ProofId, ProofStep,
};

use super::{AcceptedArtifactRecord, AcceptedProofRecord, LedgerError, LedgerState};

trait ProofAdmissionTestExt {
    fn proof_state(&self) -> &ArtifactState;
    fn apply(&mut self, certificate: ProofCertificate) -> Result<AcceptedProofRecord, LedgerError>;
    fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<AcceptedProofRecord, LedgerError>;
    fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected: ProofId,
    ) -> Result<AcceptedProofRecord, LedgerError>;
    fn validate_canonical_proof_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        expected: ProofId,
    ) -> Result<(), LedgerError>;
}

impl ProofAdmissionTestExt for LedgerState {
    fn proof_state(&self) -> &ArtifactState {
        self.artifact_state()
    }

    fn apply(&mut self, certificate: ProofCertificate) -> Result<AcceptedProofRecord, LedgerError> {
        self.apply_proof(certificate)
    }

    fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        match self.apply_canonical_artifact_bytes(tagged_proof(bytes))? {
            AcceptedArtifactRecord::Proof(record) => Ok(record),
            AcceptedArtifactRecord::Definition(_) => {
                unreachable!("a proof envelope produces a proof record")
            }
        }
    }

    fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected: ProofId,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        match self.apply_canonical_artifact_bytes_with_expected_id(
            tagged_proof(bytes),
            ArtifactId::from_proof_id(expected),
        )? {
            AcceptedArtifactRecord::Proof(record) => Ok(record),
            AcceptedArtifactRecord::Definition(_) => {
                unreachable!("a proof envelope produces a proof record")
            }
        }
    }

    fn validate_canonical_proof_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        expected: ProofId,
    ) -> Result<(), LedgerError> {
        self.validate_canonical_artifact_bytes_with_expected_id(
            tagged_proof(bytes),
            ArtifactId::from_proof_id(expected),
        )
    }
}

fn tagged_proof(bytes: Vec<u8>) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(bytes.len() + 1);
    tagged.push(0);
    tagged.extend(bytes);
    tagged
}

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn identity(variable: FreeVariable) -> ProofCertificate {
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn identity_detour(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone().into(),
            consequent: equality.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable,
        },
    ])
}

fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::for_all(variable, equality);
    certificate(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::VacuousUniversal {
            formula: identity.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
}

fn proof_using_every_reference(
    references: &[(ProofId, Formula)],
    conclusion_axiom: ZfcAxiom,
) -> ProofCertificate {
    let mut steps = references
        .iter()
        .map(|(proof_id, _)| ProofStep::ProofReference {
            proof_id: *proof_id,
        })
        .collect::<Vec<_>>();
    let conclusion = conclusion_axiom.formula();
    steps.push(ProofStep::ZfcAxiom(conclusion_axiom));
    let mut conclusion_step = u32::try_from(steps.len() - 1).unwrap();

    for (reference_step, (_, premise)) in references.iter().enumerate().rev() {
        let implication_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::Simplification {
            antecedent: conclusion.clone().into(),
            consequent: premise.clone().into(),
        });
        let conditional_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: conclusion_step,
            implication: implication_step,
        });
        conclusion_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: u32::try_from(reference_step).unwrap(),
            implication: conditional_step,
        });
    }

    certificate(steps)
}

fn canonical_bytes(certificate: ProofCertificate) -> Vec<u8> {
    certificate
        .into_unchecked_normal_form()
        .into_canonical_bytes()
        .into_vec()
}

fn reordered_identity_detour(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    certificate(vec![
        ProofStep::Simplification {
            antecedent: equality.clone().into(),
            consequent: equality.into(),
        },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 0,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable,
        },
    ])
}

fn duplicate_identity(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::implies(equality.clone(), equality.clone());
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone().into(),
            consequent: equality.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Simplification {
            antecedent: identity.clone().into(),
            consequent: identity.into(),
        },
        ProofStep::ModusPonens {
            premise: 3,
            implication: 5,
        },
        ProofStep::ModusPonens {
            premise: 4,
            implication: 6,
        },
        ProofStep::Generalization {
            premise: 7,
            variable,
        },
    ])
}

mod artifact;
mod single;
