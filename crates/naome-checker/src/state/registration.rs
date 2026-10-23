//! One owner for proof identity, dependency and conclusion registration rules.
use crate::{
    ArtifactStateError, CHECKER_MAX_FORMULA_WORK_BYTES, CheckedProof, ContextError, ContextView,
};
use naome_proof::{DerivationId, ProofId, ProofStep, StatementId};

pub(super) trait RegistrationView: ContextView {
    fn has_proof(&self, id: ProofId) -> Result<bool, ContextError>;
    fn derivation_statement(&self, id: DerivationId) -> Result<Option<StatementId>, ContextError>;
}

pub(super) fn validate(
    state: &impl RegistrationView,
    proof: &CheckedProof,
    aliases: bool,
) -> Result<(), ArtifactStateError> {
    let access = ArtifactStateError::Context;
    if let Some(header) = state.proof_header(proof.proof_id).map_err(access)? {
        if header.derivation != proof.derivation_id || header.statement != proof.statement_id {
            return Err(ArtifactStateError::ProofIdentityCollision {
                proof_id: proof.proof_id,
            });
        }
        same_statement(state, proof)?;
        return Err(ArtifactStateError::DuplicateProof {
            proof_id: proof.proof_id,
        });
    }
    for step in proof.normal_form.certificate().steps() {
        if let ProofStep::ProofReference { proof_id } = step
            && !state.has_proof(*proof_id).map_err(access)?
        {
            return Err(ArtifactStateError::MissingProofDependency {
                proof_id: *proof_id,
            });
        }
        for definition_id in step.definition_references() {
            if state.definition_kind(definition_id).is_none() {
                return Err(ArtifactStateError::MissingDefinitionDependency { definition_id });
            }
        }
    }
    if let Some(statement) = state
        .derivation_statement(proof.derivation_id)
        .map_err(access)?
    {
        if statement != proof.statement_id {
            return Err(ArtifactStateError::DerivationIdentityCollision {
                derivation_id: proof.derivation_id,
            });
        }
        same_statement(state, proof)?;
        if !aliases {
            return Err(ArtifactStateError::DuplicateDerivation {
                derivation_id: proof.derivation_id,
            });
        }
        return Ok(());
    }
    same_statement(state, proof)
}

fn same_statement(
    state: &impl ContextView,
    proof: &CheckedProof,
) -> Result<(), ArtifactStateError> {
    if let Some(formula) = state
        .statement_formula(proof.statement_id, CHECKER_MAX_FORMULA_WORK_BYTES)
        .map_err(ArtifactStateError::Context)?
        && *formula != proof.conclusion
    {
        return Err(ArtifactStateError::StatementIdentityCollision {
            statement_id: proof.statement_id,
        });
    }
    Ok(())
}
