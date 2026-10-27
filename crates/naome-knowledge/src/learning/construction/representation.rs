//! Checked, conservative meaning references compress constructed derivations.
use super::super::{definitions, proof};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::collections::{BTreeMap, BTreeSet};

pub fn apply(
    mut original: proof::Verified,
    entries: &[definitions::Entry],
) -> Result<proof::Verified, String> {
    if entries.is_empty() {
        return Ok(original);
    }
    let mut context = definitions::context(entries)?;
    let mut primitive = naome_checker::ArtifactState::new();
    let mut identities = BTreeMap::<ProofId, ProofId>::new();
    let mut lemmas = Vec::new();
    let mut used = BTreeSet::new();
    for (position, certificate) in original
        .lemmas
        .iter()
        .chain(std::iter::once(&original.certificate))
        .enumerate()
    {
        let old = naome_checker::normalize_and_check_with_state(certificate.clone(), &primitive)
            .map_err(|e| e.to_string())?;
        let target = old.conclusion().clone();
        let old_id = old.proof_id();
        primitive.register_proof(old).map_err(|e| e.to_string())?;
        let steps = certificate
            .steps()
            .iter()
            .map(|step| match step {
                ProofStep::ProofReference { proof_id } => Ok(ProofStep::ProofReference {
                    proof_id: *identities
                        .get(proof_id)
                        .ok_or("construction lemma dependency order")?,
                }),
                _ => Ok(step.clone()),
            })
            .collect::<Result<Vec<_>, String>>()?;
        let candidate = proof::Verified {
            certificate: ProofCertificate::new(steps).map_err(|e| e.to_string())?,
            target,
            native_id: old_id,
            payload_bytes: 0,
            lemmas: lemmas.clone(),
            definitions: Vec::new(),
        };
        let source = proof::source_with_definitions(&candidate, entries)?;
        let checked = naome_authoring::compile_against_proof_context(&source, &context)
            .map_err(|e| e.to_string())?
            .into_checked_proof();
        if checked.conclusion() != &candidate.target {
            return Err("construction meaning rewrite changed the claim".into());
        }
        identities.insert(old_id, checked.proof_id());
        used.extend(checked.direct_artifact_dependencies().iter().copied());
        if position == original.lemmas.len() {
            original.certificate = checked.normal_form().certificate().clone();
            original.native_id = checked.proof_id();
            original.payload_bytes = checked.normal_form().canonical_bytes().len();
            original.definitions = entries
                .iter()
                .filter(|e| e.address().is_ok_and(|id| used.contains(&id)))
                .cloned()
                .collect();
            original.lemmas = lemmas;
            return Ok(original);
        }
        lemmas.push(checked.normal_form().certificate().clone());
        context.register_proof(checked).map_err(|e| e.to_string())?;
    }
    Err("missing construction root".into())
}
