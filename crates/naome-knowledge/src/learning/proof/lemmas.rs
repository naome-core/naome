//! Closed intermediate theorems use the existing checked citation contract.
use super::*;
use naome_proof::ArtifactId;
use std::collections::{BTreeMap, BTreeSet};

pub fn context(
    definitions: &[super::super::definitions::Entry],
    lemmas: &[ProofCertificate],
) -> Result<ArtifactState, String> {
    let limits = crate::resources::limits();
    if lemmas.len() >= limits.closure_objects
        || lemmas
            .iter()
            .map(|c| c.to_canonical_bytes().len())
            .sum::<usize>()
            > limits.closure_bytes
        || lemmas.iter().map(|c| c.steps().len()).sum::<usize>() > limits.closure_steps
    {
        return Err(format!(
            "construction lemma closure capacity: {} objects, {} bytes, {} steps",
            lemmas.len(),
            lemmas
                .iter()
                .map(|c| c.to_canonical_bytes().len())
                .sum::<usize>(),
            lemmas.iter().map(|c| c.steps().len()).sum::<usize>()
        ));
    }
    let mut context = super::super::definitions::context(definitions)?;
    for certificate in lemmas {
        let checked = naome_checker::normalize_and_check_with_state(certificate.clone(), &context)
            .map_err(|e| e.to_string())?;
        context.register_proof(checked).map_err(|e| e.to_string())?;
    }
    Ok(context)
}
pub fn retain(
    root: &naome_checker::CheckedProof,
    definitions: &[super::super::definitions::Entry],
    lemmas: &[ProofCertificate],
) -> Result<Vec<ProofCertificate>, String> {
    let mut context = super::super::definitions::context(definitions)?;
    let mut edges = BTreeMap::new();
    let mut ids = Vec::new();
    for c in lemmas {
        let checked = naome_checker::normalize_and_check_with_state(c.clone(), &context)
            .map_err(|e| e.to_string())?;
        let id = ArtifactId::from_proof_id(checked.proof_id());
        edges.insert(id, checked.direct_artifact_dependencies());
        ids.push(id);
        context.register_proof(checked).map_err(|e| e.to_string())?;
    }
    let mut pending = root.direct_artifact_dependencies().into_vec();
    let mut used = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if used.insert(id)
            && let Some(dependencies) = edges.get(&id)
        {
            pending.extend(dependencies.iter().copied());
        }
    }
    Ok(lemmas
        .iter()
        .zip(ids)
        .filter(|(_, id)| used.contains(id))
        .map(|(c, _)| c.clone())
        .collect())
}
pub fn sources(
    definitions: &[super::super::definitions::Entry],
    lemmas: &[ProofCertificate],
) -> Result<Vec<String>, String> {
    let mut context = super::super::definitions::context(definitions)?;
    let mut output = Vec::new();
    for certificate in lemmas {
        let checked = naome_checker::normalize_and_check_with_state(certificate.clone(), &context)
            .map_err(|e| e.to_string())?;
        let verified = Verified {
            certificate: checked.normal_form().certificate().clone(),
            target: checked.conclusion().clone(),
            native_id: checked.proof_id(),
            payload_bytes: checked.normal_form().canonical_bytes().len(),
            definitions: definitions.to_vec(),
            lemmas: Vec::new(),
        };
        // Source rendering preserves explicit citations; the owning caller
        // compiles these in the same checked topological order.
        output.push(source(&verified)?);
        context.register_proof(checked).map_err(|e| e.to_string())?;
    }
    Ok(output)
}
