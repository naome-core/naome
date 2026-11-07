//! Extract closed subproofs and cite them through the existing checker.
use super::{Budget, definitions, proof};
use naome_checker::{
    ArtifactState, CheckedProof,
    diagnostics::{Failure, OperandRole},
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::collections::{BTreeMap, BTreeSet};

const MIN_SAVING: usize = 4096;
const TARGET_SLICE: usize = 56_000;

struct Cut {
    proof: ProofId,
    target: Formula,
    free: Vec<FreeVariable>,
}
fn reachable(
    steps: &[ProofStep],
    root: usize,
    cuts: &BTreeMap<usize, Cut>,
    hypothetical: Option<usize>,
) -> Vec<bool> {
    let mut live = vec![false; root + 1];
    live[root] = true;
    for index in (0..=root).rev() {
        if live[index] && Some(index) != hypothetical && !cuts.contains_key(&index) {
            for child in steps[index].local_references().into_iter().flatten() {
                live[child as usize] = true;
            }
        }
    }
    live
}

fn replay_cut(cut: &Cut, output: &mut Vec<ProofStep>) -> Result<(), String> {
    output.push(ProofStep::ProofReference {
        proof_id: cut.proof,
    });
    let mut target = cut.target.clone();
    for &replacement in &cut.free {
        let used = target.free_variables();
        let variable = (0..=u32::MAX)
            .map(FreeVariable::new)
            .find(|v| *v != replacement && !used.contains(v))
            .ok_or("fresh instantiation name")?;
        let body = target
            .open_outer_universal(variable)
            .ok_or("closed cut binder missing")?;
        let premise = (output.len() - 1) as u32;
        let implication = output.len() as u32;
        output.push(ProofStep::UniversalInstantiation {
            variable,
            replacement,
            body: body.clone().into(),
        });
        output.push(ProofStep::ModusPonens {
            premise,
            implication,
        });
        target = body.substitute_free(variable, replacement);
    }
    Ok(())
}

fn slice(
    steps: &[ProofStep],
    root: usize,
    cuts: &BTreeMap<usize, Cut>,
) -> Result<Vec<ProofStep>, String> {
    let live = reachable(steps, root, cuts, None);
    let mut mapped = vec![None; root + 1];
    let mut result = Vec::new();
    for (i, step) in steps[..=root].iter().enumerate().filter(|(i, _)| live[*i]) {
        if let Some(cut) = cuts.get(&i) {
            replay_cut(cut, &mut result)?;
        } else {
            let get =
                |id: u32| mapped[id as usize].ok_or("cut changed a native local step reference");
            let step = match step {
                ProofStep::ModusPonens {
                    premise,
                    implication,
                } => ProofStep::ModusPonens {
                    premise: get(*premise)?,
                    implication: get(*implication)?,
                },
                ProofStep::Generalization { premise, variable } => ProofStep::Generalization {
                    premise: get(*premise)?,
                    variable: *variable,
                },
                step => step.clone(),
            };
            result.push(step);
        }
        mapped[i] = Some((result.len() - 1) as u32);
    }
    Ok(result)
}

fn certificate(steps: Vec<ProofStep>) -> Result<ProofCertificate, String> {
    ProofCertificate::new(steps).map_err(|e| e.to_string())
}

fn close(mut steps: Vec<ProofStep>, free: &[FreeVariable]) -> Vec<ProofStep> {
    for &variable in free.iter().rev() {
        steps.push(ProofStep::Generalization {
            premise: (steps.len() - 1) as u32,
            variable,
        });
    }
    steps
}

fn original_conclusion(
    steps: &[ProofStep],
    index: usize,
    state: &ArtifactState,
) -> Result<(Formula, Vec<FreeVariable>), String> {
    let sliced = slice(steps, index, &BTreeMap::new())?;
    let (normal_form, origins) = certificate(sliced)?.into_unchecked_normal_form_with_variables();
    let checked_steps = normal_form.certificate().steps().len() as u64;
    let error = match proof::check_normal_form(normal_form, state) {
        Ok(closed) => return Ok((closed.conclusion().clone(), vec![])),
        Err(error) => error,
    };
    let d = error.diagnostic();
    if d.failure != Failure::OpenConclusion
        || d.checked_before != checked_steps
        || d.input.commands != checked_steps
    {
        return Err(error.to_string());
    }
    let variables = d
        .operand(OperandRole::Conclusion)
        .and_then(|v| v.formula.as_ref())
        .ok_or("missing checked open conclusion")?;
    if !variables.free_variables_complete
        || variables.free_variables.is_empty()
        || variables.free_variables.len() > 12
    {
        return Err("bounded complete native free-variable inventory required".into());
    }
    let source_variables = origins
        .into_iter()
        .map(|(source, normal)| (normal.identifier(), source.identifier()))
        .collect::<BTreeMap<_, _>>();
    let free = variables
        .free_variables
        .iter()
        .map(|normal| {
            source_variables
                .get(normal)
                .copied()
                .ok_or("normalized free variable has no source origin")
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .map(FreeVariable::new)
        .collect::<Vec<_>>();
    let closed = proof::check(
        certificate(close(slice(steps, index, &BTreeMap::new())?, &free))?,
        state,
    )
    .map_err(|e| e.to_string())?;
    Ok((closed.conclusion().clone(), free))
}

fn portable(
    checked: CheckedProof,
    expected: &Formula,
    _definitions: &[definitions::Entry],
    state: &ArtifactState,
) -> Result<CheckedProof, String> {
    let limit = crate::resources::limits().proof_bytes;
    if checked.conclusion() != expected || checked.normal_form().canonical_bytes().len() > limit {
        return Err("partition target or native size differs".into());
    }
    let source = proof::artifact(checked.normal_form().certificate());
    if source.len() > 2 * limit {
        return Err("partition artifact exceeds capacity".into());
    }
    let compiled = proof::check_artifact(&source, state)?;
    if compiled.proof_id() != checked.proof_id()
        || compiled.conclusion() != expected
        || compiled.direct_artifact_dependencies() != checked.direct_artifact_dependencies()
        || compiled.normal_form().canonical_bytes() != checked.normal_form().canonical_bytes()
    {
        return Err("partition source replay differs".into());
    }
    Ok(compiled)
}

pub(super) fn append(
    checked: CheckedProof,
    state: &mut ArtifactState,
    pool: &mut Vec<ProofCertificate>,
) -> Result<(), String> {
    if !state.contains_proof(checked.proof_id()) {
        let certificate = checked.normal_form().certificate().clone();
        state.register_proof(checked).map_err(|e| e.to_string())?;
        pool.push(certificate);
    }
    Ok(())
}

pub(super) fn fit(
    original: CheckedProof,
    definitions: &[definitions::Entry],
    state: &mut ArtifactState,
    pool: &mut Vec<ProofCertificate>,
    budget: &mut Budget,
) -> Result<CheckedProof, String> {
    let limits = crate::resources::limits();
    if original.normal_form().canonical_bytes().len() < limits.proof_bytes {
        return Ok(original);
    }
    // Copy-on-write snapshot of the exact checked dependencies of this object.
    budget.charge(1)?;
    let original_state = state.clone();
    let steps = original.normal_form().certificate().steps();
    let root = steps.len() - 1;
    let weights = steps
        .iter()
        .map(ProofStep::encoded_length)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let weight = |set: Vec<bool>| {
        set.into_iter()
            .zip(&weights)
            .filter_map(|(live, size)| live.then_some(*size))
            .sum::<usize>()
    };
    let mut cuts = BTreeMap::new();
    loop {
        budget.charge(2)?;
        let rebuilt = proof::check(certificate(slice(steps, root, &cuts)?)?, state)
            .map_err(|e| e.to_string())?;
        if let Ok(piece) = portable(rebuilt, original.conclusion(), definitions, state) {
            return Ok(piece);
        }

        let present = reachable(steps, root, &cuts, None);
        let total = weight(present.clone());
        let mut candidates = Vec::new();
        for index in 0..root {
            budget.check_time()?;
            if !present[index]
                || cuts.contains_key(&index)
                || steps[index].local_references()[0].is_none()
            {
                continue;
            }
            let size = weight(reachable(steps, index, &cuts, None));
            if !(MIN_SAVING..=TARGET_SLICE.min(limits.proof_bytes)).contains(&size) {
                continue;
            }
            let saving = total.saturating_sub(weight(reachable(steps, root, &cuts, Some(index))));
            if saving >= MIN_SAVING {
                candidates.push((saving, size, index));
            }
        }
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        let mut cut = None;
        for (_, _, index) in candidates {
            budget.charge(5)?;
            let attempt = (|| {
                let (target, free) = original_conclusion(steps, index, &original_state)?;
                let sliced = certificate(close(slice(steps, index, &cuts)?, &free))?;
                let checked = proof::check(sliced, state).map_err(|e| e.to_string())?;
                let piece = portable(checked, &target, definitions, state)?;
                let proof = piece.proof_id();
                append(piece, state, pool)?;
                Ok::<_, String>((
                    index,
                    Cut {
                        proof,
                        target,
                        free,
                    },
                ))
            })();
            if let Ok(found) = attempt {
                cut = Some(found);
                break;
            }
        }
        let (index, cut) = cut.ok_or("no portable construction partition cut")?;
        cuts.insert(index, cut);
    }
}
