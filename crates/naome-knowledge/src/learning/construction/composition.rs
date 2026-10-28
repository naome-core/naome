//! Bounded AND/OR reconstruction from exact, independently checked inputs.
use super::{logic, proof};
use naome_foundation::Formula;
use std::{collections::BTreeSet, time::Instant};

pub fn used(verified: &proof::Verified, inputs: &[String]) -> Result<Vec<String>, String> {
    let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
    let mut ids = context
        .proof_conclusions()
        .map(|(id, _, _, _)| crate::hex(id.as_bytes()))
        .collect::<BTreeSet<_>>();
    ids.insert(crate::hex(verified.native_id.as_bytes()));
    Ok(inputs
        .iter()
        .filter(|id| ids.contains(*id))
        .cloned()
        .collect())
}
pub fn validate(packet: &[u8], inputs: &[String], work: usize) -> Result<(), String> {
    if inputs.is_empty()
        || inputs.len() > super::super::knowledge::CAPACITY
        || inputs.iter().collect::<BTreeSet<_>>().len() != inputs.len()
        || work == 0
        || work > 16
    {
        return Err("composition trace capacity".into());
    }
    let verified = super::super::evidence::checked(packet)?;
    if used(&verified, inputs)? != inputs {
        return Err("composition input binding differs".into());
    }
    let mut state = super::super::definitions::context(&verified.definitions)?;
    let mut preceding = Vec::new();
    let mut available = std::collections::BTreeMap::new();
    for certificate in verified
        .lemmas
        .iter()
        .chain(std::iter::once(&verified.certificate))
    {
        let checked = proof::check(certificate.clone(), &state).map_err(|e| e.to_string())?;
        let id = crate::hex(checked.proof_id().as_bytes());
        if inputs.contains(&id) {
            available.insert(
                id,
                proof::Term::Native {
                    certificate: certificate.clone(),
                    lemmas: preceding.clone(),
                    definitions: verified.definitions.clone(),
                    target: checked.conclusion().clone(),
                },
            );
        }
        preceding.push(certificate.clone());
        if !state.contains_proof(checked.proof_id()) {
            state.register_proof(checked).map_err(|e| e.to_string())?;
        }
    }
    let terms = inputs
        .iter()
        .map(|id| {
            available
                .remove(id)
                .ok_or("composition checked input missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (replayed, replay_work) = construct(&verified.target, &terms, work, Instant::now())?;
    if replay_work != work || replayed.is_none_or(|p| p.native_id != verified.native_id) {
        return Err("composition reconstruction differs".into());
    }
    Ok(())
}
pub fn construct(
    target: &Formula,
    context: &[proof::Term],
    maximum: usize,
    started: Instant,
) -> Result<(Option<proof::Verified>, usize), String> {
    let mut search = logic::Search::new(maximum.min(16), started);
    let term = search.prove(target, context)?;
    let proof = term.map(|term| proof::verify(&term, target)).transpose()?;
    Ok((proof, search.work))
}
