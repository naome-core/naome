//! Target-directed, capture-safe specialization of checked universal theorems.

use super::{
    Work,
    deduction::{Failure, INVALID, LIMIT, Plan, Program},
};
use crate::ContextView;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofId, ProofStep, StatementId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The finite question rule set opens at most this many outer binders.
pub(super) const MAX_INSTANTIATIONS: usize = naome_proof::QUESTION_TARGET_MAX_DEPTH;

/// A domain-separated query key, never the identity of a mathematical statement.
fn bytes_key(bytes: &[u8]) -> StatementId {
    let mut digest = Sha256::new();
    digest.update(b"naome:question:universal-pattern\0");
    digest.update(bytes);
    StatementId::from_bytes(digest.finalize().into())
}

pub(super) fn key(formula: &Formula) -> StatementId {
    let wildcard = formula.clone().map_free_variables(|_| FreeVariable::new(0));
    bytes_key(
        &wildcard
            .encode_canonical()
            .expect("checked formula pattern"),
    )
}

pub(super) fn projections(formula: &Formula) -> Vec<StatementId> {
    let Some((opened, _)) = open(formula, &BTreeSet::new()) else {
        return Vec::new();
    };
    let wildcard = opened.map_free_variables(|_| FreeVariable::new(0));
    let mut result = vec![bytes_key(
        &wildcard.encode_canonical().expect("checked universal body"),
    )];
    if let Some(parts) = wildcard
        .canonical_implication()
        .expect("checked implication")
    {
        result.extend(parts.consequents().map(bytes_key));
    }
    result
}

fn open(
    formula: &Formula,
    excluded: &BTreeSet<FreeVariable>,
) -> Option<(Formula, Vec<FreeVariable>)> {
    let mut current = formula.clone();
    let mut variables = Vec::new();
    let mut identifier = u32::MAX;
    for _ in 0..MAX_INSTANTIATIONS {
        while excluded.contains(&FreeVariable::new(identifier))
            || current
                .free_variables()
                .contains(&FreeVariable::new(identifier))
        {
            identifier = identifier.checked_sub(1).expect("bounded variable set");
        }
        let variable = FreeVariable::new(identifier);
        let Some(body) = current.open_outer_universal(variable) else {
            break;
        };
        variables.push(variable);
        current = body;
        identifier = identifier.checked_sub(1).expect("bounded binders");
    }
    (!variables.is_empty()).then_some((current, variables))
}

// Both inputs are well-formed canonical formulas. Compare their prefix shapes
// and bind only outer parameters to free variables: a target's inner bound
// variable must never be captured by specialization.
fn match_variables(pattern: &[u8], target: &[u8]) -> Option<BTreeMap<FreeVariable, FreeVariable>> {
    if pattern.len() != target.len() {
        return None;
    }
    let mut assignments = BTreeMap::new();
    let mut position = 0;
    while position < pattern.len() {
        let tag = pattern[position];
        if tag != target[position] {
            return None;
        }
        position += 1;
        if tag <= 1 {
            for _ in 0..2 {
                let p = &pattern[position..position + 5];
                let t = &target[position..position + 5];
                if p[0] == 0 {
                    if t[0] != 0 {
                        return None;
                    }
                    let from = FreeVariable::new(u32::from_be_bytes(p[1..].try_into().ok()?));
                    let to = FreeVariable::new(u32::from_be_bytes(t[1..].try_into().ok()?));
                    if assignments
                        .insert(from, to)
                        .is_some_and(|previous| previous != to)
                    {
                        return None;
                    }
                } else if p != t {
                    return None;
                }
                position += 5;
            }
        }
    }
    Some(assignments)
}

pub(super) struct Specialized {
    pub(super) formula: Formula,
    pub(super) program: Program,
}

pub(super) fn specialize(
    proof: ProofId,
    source: &Formula,
    target: &Formula,
    artifacts: &dyn ContextView,
    work: &mut Work,
) -> Result<Option<Specialized>, Failure> {
    let source_bytes = source.encode_canonical().map_err(|_| LIMIT)?;
    // Reserve all possible outer openings and projections before cloning.
    let binders = source_bytes
        .iter()
        .take_while(|&&tag| tag == 4)
        .count()
        .min(MAX_INSTANTIATIONS);
    work.formula(
        source_bytes.len(),
        binders
            .checked_mul(8)
            .and_then(|n| n.checked_add(16))
            .ok_or(LIMIT)?,
    )?;
    let excluded = target.free_variables();
    let Some((opened, variables)) = open(source, &excluded) else {
        return Ok(None);
    };
    let target_bytes = target.encode_canonical().map_err(|_| LIMIT)?;
    let mut current = opened.view();
    let assignments = loop {
        work.formula(source_bytes.len(), 8)?;
        let candidate = current.encode_canonical().map_err(|_| LIMIT)?;
        if let Some(assignments) = match_variables(&candidate, &target_bytes) {
            break assignments;
        }
        let Some((_, consequent)) = current.implication_parts() else {
            return Ok(None);
        };
        current = consequent;
    };
    let default = (0..)
        .map(FreeVariable::new)
        .find(|variable| !variables.contains(variable))
        .expect("bounded parameters");
    let mut plan = Plan::new();
    let mut root = plan.reference(proof, artifacts, work)?;
    let mut current = source.clone();
    let mut current_length = source_bytes.len();
    for variable in variables {
        work.formula(current_length, 16)?;
        let body = current.open_outer_universal(variable).ok_or(INVALID)?;
        let replacement = assignments.get(&variable).copied().unwrap_or(default);
        let result = body.clone().substitute_free(variable, replacement);
        let length = result.encode_canonical().map_err(|_| LIMIT)?.len();
        let implication_length = current_length
            .checked_add(length)
            .and_then(|n| n.checked_add(1))
            .ok_or(LIMIT)?;
        let axiom = plan.axiom(
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body: body.into(),
            },
            implication_length,
            work,
        )?;
        root = plan.modus_ponens(root, axiom, length, work)?;
        current = result;
        current_length = length;
    }
    Ok(Some(Specialized {
        formula: current,
        program: plan.into_program(),
    }))
}

#[cfg(test)]
mod tests;
