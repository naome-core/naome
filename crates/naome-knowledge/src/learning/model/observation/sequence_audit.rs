//! Offline reconstruction of an already completed balanced training schedule.
//! No model, tensor, forward pass, gradient, optimizer or search is invoked.
use super::super::{
    Engine, Pool, Recurrence, TRAINING_UNITS, Targets, TrainingMeasurements, UPDATES_PER_UNIT,
};
use crate::learning::{
    Job, Preparation, Progress, artifact::ArtifactIo, digest, meta, pool::Sample,
};
use serde::Serialize;

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
struct Counts {
    slots: usize,
    masked_slots: usize,
    unmasked_loss_slots: usize,
    potentially_nonconstant_loss_slots: usize,
    sampled_parent_edges: usize,
    edges_with_unmasked_loss_descendants: usize,
    edges_with_potentially_nonconstant_loss_descendants: usize,
    masked_edges_with_unmasked_loss_descendants: usize,
    carry_edges_with_unmasked_loss_descendants: usize,
    carry_edges_with_potentially_nonconstant_loss_descendants: usize,
}
impl Counts {
    fn include(&mut self, other: &Self) -> Result<(), String> {
        macro_rules! add {
            ($($field:ident),+ $(,)?) => { $(self.$field = self.$field.checked_add(other.$field)
                .ok_or("sequence audit counter overflow")?;)+ };
        }
        add!(
            slots,
            masked_slots,
            unmasked_loss_slots,
            potentially_nonconstant_loss_slots,
            sampled_parent_edges,
            edges_with_unmasked_loss_descendants,
            edges_with_potentially_nonconstant_loss_descendants,
            masked_edges_with_unmasked_loss_descendants,
            carry_edges_with_unmasked_loss_descendants,
            carry_edges_with_potentially_nonconstant_loss_descendants
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct Slot {
    graph: String,
    selected: usize,
    parent: Option<usize>,
    auxiliary: bool,
    unmasked_loss: bool,
    potentially_nonconstant_loss: bool,
    ancestor_edge_of_unmasked_loss: bool,
    ancestor_edge_of_potentially_nonconstant_loss: bool,
}

// This is reachability through the exact sampled parent links. An edge into a
// loss-bearing node counts, and a masked intermediate can connect an earlier
// node to a later active objective. Each edge counts once in a batch.
fn reachable_edges(parents: &[Option<usize>], active: &[bool]) -> Result<Vec<bool>, String> {
    if parents.len() != active.len() || parents.len() > 16 {
        return Err("sequence audit batch shape differs".into());
    }
    let mut reachable = vec![false; parents.len()];
    for (index, _) in parents.iter().enumerate() {
        let mut position = index;
        let mut depth = 0;
        while let Some(parent) = parents[position] {
            if parent >= position || depth >= 3 {
                return Err("sequence audit parent or depth differs".into());
            }
            reachable[position] |= active[index];
            position = parent;
            depth += 1;
        }
    }
    Ok(reachable)
}

fn batch(
    pool: &Pool,
    sample: &[Sample<'_>],
    rich: bool,
    recurrence: Recurrence,
) -> Result<(Counts, Vec<Slot>), String> {
    let parents: Vec<_> = sample.iter().map(|s| s.parent).collect();
    let active: Vec<_> = sample.iter().map(|s| !s.auxiliary || rich).collect();
    let potential: Vec<_> = sample
        .iter()
        .zip(&active)
        .map(|(s, active)| {
            let target = pool.target_graph(s.graph, rich);
            // A single-choice or all-positive marginal is constant in exact
            // arithmetic. Cost targets can still make a rich objective nonconstant.
            (*active
                && !target.successes.is_empty()
                && target.successes.len() < target.candidates.len())
                || (rich && !pool.witnesses(s.graph).is_empty())
        })
        .collect();
    let edges = reachable_edges(&parents, &active)?;
    let potential_edges = reachable_edges(&parents, &potential)?;
    let counts = Counts {
        slots: sample.len(),
        masked_slots: active.iter().filter(|v| !**v).count(),
        unmasked_loss_slots: active.iter().filter(|v| **v).count(),
        potentially_nonconstant_loss_slots: potential.iter().filter(|v| **v).count(),
        sampled_parent_edges: parents.iter().filter(|p| p.is_some()).count(),
        edges_with_unmasked_loss_descendants: edges.iter().filter(|v| **v).count(),
        edges_with_potentially_nonconstant_loss_descendants: potential_edges
            .iter()
            .filter(|v| **v)
            .count(),
        masked_edges_with_unmasked_loss_descendants: edges
            .iter()
            .zip(&active)
            .filter(|(edge, active)| **edge && !**active)
            .count(),
        carry_edges_with_unmasked_loss_descendants: if recurrence == Recurrence::Carry {
            edges.iter().filter(|v| **v).count()
        } else {
            0
        },
        carry_edges_with_potentially_nonconstant_loss_descendants: if recurrence
            == Recurrence::Carry
        {
            potential_edges.iter().filter(|v| **v).count()
        } else {
            0
        },
    };
    let slots = sample
        .iter()
        .enumerate()
        .map(|(index, sample)| Slot {
            graph: sample.graph.key(),
            selected: sample.selected,
            parent: sample.parent,
            auxiliary: sample.auxiliary,
            unmasked_loss: active[index],
            potentially_nonconstant_loss: potential[index],
            ancestor_edge_of_unmasked_loss: edges[index],
            ancestor_edge_of_potentially_nonconstant_loss: potential_edges[index],
        })
        .collect();
    Ok((counts, slots))
}

/// The caller restores the original native job, exact receipt and page using
/// the existing source owner. This observer never constructs a replacement
/// history page, chooses source rows, or calls Job::execute.
pub(in crate::learning) fn audit<I: ArtifactIo + ?Sized>(
    original: &Job,
    expected: &Progress,
    targets: Targets,
    recurrence: Recurrence,
    io: &mut I,
    mut available: impl FnMut() -> Result<(), String>,
) -> Result<serde_json::Value, String> {
    available()?;
    original.validate()?;
    if !original.training
        || original.base.preparation != Preparation::Balanced
        || expected.unit < TRAINING_UNITS
        || expected
            .plan
            .as_ref()
            .is_none_or(|s| s.plan != meta::Plan::balanced())
        || expected.rng.wrapping_sub(original.base.draws)
            != u64::from(TRAINING_UNITS) * UPDATES_PER_UNIT * 16
        || original.history.as_ref() != expected.prepared.as_ref().map(|p| &p.page)
    {
        return Err("sequence audit requires an exact completed balanced native trial".into());
    }
    let original_digest = digest(original);
    let expected_digest = digest(expected);
    let mut job = original.clone();
    let mut progress = expected.clone();
    progress.prepared = None;
    let mut engine = Engine::default();
    let material = job
        .prepare_history(&mut progress, &mut engine, io)?
        .ok_or("sequence audit has no prepared native source material")?;
    if progress.prepared != expected.prepared {
        return Err("sequence audit reconstructed another prepared source blob".into());
    }
    available()?;
    let rich = targets == Targets::Rich;
    let mut pool = material
        .state
        .training_pool_for(&material.evidence, false)?;
    pool.reconcile(&material.observations, rich)?;
    let references = if material.state.model.updates > 0 {
        material
            .state
            .preservation_pool(&material.evidence, &pool)?
    } else {
        Pool::default()
    };
    pool.unfocus();
    if pool.is_empty() {
        return Err("sequence audit cannot reproduce an empty training pool".into());
    }
    let derived = pool.derived_counts();
    let actual_pool = (
        pool.graphs().len(),
        derived.transitions,
        derived.fragments,
        derived.omitted,
        derived.unavailable,
        derived.preferences,
        derived.hindsight,
        derived.sequences,
        references.graphs().len(),
    );
    let cost = &expected.training_cost;
    let expected_pool = (
        cost.states,
        cost.checked_transitions,
        cost.checked_fragments,
        cost.omitted_transitions,
        cost.unavailable_fragments,
        cost.witnessed_preferences,
        cost.hindsight_matches,
        cost.observed_sequences,
        cost.preservation_states,
    );
    if actual_pool != expected_pool {
        return Err("sequence audit reconstructed different native pool counts".into());
    }
    let mut cursor = original.base.draws;
    let mut total = TrainingMeasurements::default();
    let mut counts = Counts::default();
    let mut row_digest = digest(&"native-sequence-audit-rows");
    let mut retained = Vec::new();
    let mut omitted_batches = 0;
    for unit in 0..TRAINING_UNITS {
        available()?;
        let mut observed = TrainingMeasurements::default();
        if !references.is_empty() {
            // The proposal checkpoint advances ten updates per actual unit;
            // the parent-owned reference pool and its separate cursor do not
            // alter the primary sampler or require loading any parameters.
            let updates = original.base.model.updates + u64::from(unit) * UPDATES_PER_UNIT;
            let mut reference_cursor = (updates / UPDATES_PER_UNIT).wrapping_mul(16);
            observed.reference(&references.batch(&mut reference_cursor), recurrence);
        }
        for update in 0..UPDATES_PER_UNIT {
            let before = cursor;
            let sample = pool.sequence_batch(&mut cursor);
            let inputs = sample
                .iter()
                .map(|s| pool.target_graph(s.graph, rich))
                .collect::<Vec<_>>();
            observed.observe(&pool, &sample, &inputs, before, recurrence, rich);
            let (current, rows) = batch(&pool, &sample, rich, recurrence)?;
            counts.include(&current)?;
            row_digest = digest(&(&row_digest, unit, update, before, &rows));
            if current.sampled_parent_edges > 0 {
                if retained.len() < 16 {
                    retained.push(serde_json::json!({"unit":unit+1,"update":update,
                        "cursor_before":before,"counts":current,"slots":rows}));
                } else {
                    omitted_batches += 1;
                }
            }
        }
        total.include(&observed)?;
    }
    available()?;
    if cursor != expected.rng
        || counts.sampled_parent_edges != cost.sampled_sequence_edges
        || serde_json::to_value(&total).map_err(|e| e.to_string())?
            != serde_json::to_value(&cost.measurements).map_err(|e| e.to_string())?
        || digest(original) != original_digest
        || digest(expected) != expected_digest
    {
        return Err("sequence audit did not reproduce the actual native sampler record".into());
    }
    let report = serde_json::json!({
        "job_sha256":original_digest,"progress_sha256":expected_digest,
        "prepared":progress.prepared,"targets":format!("{targets:?}"),"recurrence":recurrence,
        "cursor_before":original.base.draws,"cursor_after":cursor,"measurements":total,
        "counts":counts,"all_rows_digest":row_digest,"first_sequence_batches":retained,
        "omitted_sequence_batches":omitted_batches,"exact_original_measurements":true,
        "model_forwards":0,"gradients":0,"optimizer_updates":0,"proof_searches":0,
        "interpretation":"Reachability follows the exact checked sampled ancestry and current loss masks. Potentially nonconstant denotes objective structure, not measured nonzero gradients, causal influence, native search improvement or retained learning quality. All samples contribute to counts and digests; detailed examples are bounded."
    });
    if serde_json::to_vec(&report)
        .map_err(|e| e.to_string())?
        .len()
        > 256 * 1024
    {
        return Err("sequence audit report exceeded its bounded output".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
