//! Closed intermediate theorems use the existing checked citation contract.
use super::*;
use naome_proof::ArtifactId;
use std::collections::{BTreeMap, BTreeSet};

pub fn context(
    definitions: &[super::super::definitions::Entry],
    lemmas: &[ProofCertificate],
) -> Result<ArtifactState, crate::Error> {
    let limits = crate::resources::limits();
    let limit_error = |resource, actual, maximum| {
        crate::Error::from(crate::EvidenceFailure::Limit {
            resource,
            actual,
            maximum,
        })
    };
    if lemmas.len() >= limits.closure_objects {
        return Err(limit_error(
            crate::EvidenceLimit::ClosureObjects,
            lemmas.len(),
            limits.closure_objects.saturating_sub(1),
        ));
    }
    let bytes = lemmas
        .iter()
        .map(|c| c.to_canonical_bytes().len())
        .sum::<usize>();
    if bytes > limits.closure_bytes {
        return Err(limit_error(
            crate::EvidenceLimit::ClosureBytes,
            bytes,
            limits.closure_bytes,
        ));
    }
    let steps = lemmas.iter().map(|c| c.steps().len()).sum::<usize>();
    if steps > limits.closure_steps {
        return Err(limit_error(
            crate::EvidenceLimit::ClosureSteps,
            steps,
            limits.closure_steps,
        ));
    }
    let mut context = super::super::definitions::context(definitions)?;
    for certificate in lemmas {
        let checked = crate::learning::proof::check(certificate.clone(), &context)?;
        context.register_proof(checked)?;
    }
    Ok(context)
}
pub fn retain(
    root: &naome_checker::CheckedProof,
    definitions: &[super::super::definitions::Entry],
    lemmas: &[ProofCertificate],
) -> Result<Vec<ProofCertificate>, crate::Error> {
    let mut context = super::super::definitions::context(definitions)?;
    let mut edges = BTreeMap::new();
    let mut ids = Vec::new();
    for c in lemmas {
        let checked = crate::learning::proof::check(c.clone(), &context)?;
        let id = ArtifactId::from_proof_id(checked.proof_id());
        edges.insert(id, checked.direct_artifact_dependencies());
        ids.push(id);
        context.register_proof(checked)?;
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
) -> Result<Vec<String>, crate::Error> {
    let mut context = super::super::definitions::context(definitions)?;
    let mut output = Vec::new();
    for certificate in lemmas {
        let checked = crate::learning::proof::check(certificate.clone(), &context)?;
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
        output.push(source(&verified));
        context.register_proof(checked)?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lemma_closure_capacity_reports_actual_and_maximum() {
        let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(
            naome_foundation::ZfcAxiom::Pairing,
        )])
        .unwrap();
        let limit = crate::resources::limits().closure_objects;
        let error = context(&[], &vec![certificate; limit]).err().unwrap();
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(
            value["code"],
            u32::from(crate::outcome::EvidenceCode::Limit)
        );
        assert_eq!(
            value["resource"],
            crate::EvidenceLimit::ClosureObjects as u8
        );
        assert_eq!(value["actual"], limit as u64);
        assert_eq!(value["maximum"], limit.saturating_sub(1) as u64);
    }
}
