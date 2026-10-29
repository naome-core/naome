//! Bounded activation diagnosis using only reconstructed own training proofs.
use super::*;
use crate::learning::model::{Checkpoint, Policy, Runtime};
use crate::learning::{artifact::ArtifactIo, meta};
use burn::module::Module;
use std::{collections::BTreeSet, time::Instant};

pub(in crate::learning) fn inspect<I: ArtifactIo + ?Sized>(
    job: &Job,
    checkpoint: &Checkpoint,
    io: &mut I,
) -> Result<serde_json::Value, String> {
    let started = Instant::now();
    let cpu = meta::cpu_micros()?;
    job.validate()?;
    checkpoint.validate()?;
    let original_job = digest(job);
    let mut sources = own_sources(job);
    sources.sort_by(|a, b| (a.job, &a.proof).cmp(&(b.job, &b.proof)));
    let runtime = Runtime::load(checkpoint, io)?;
    let original = runtime.checkpoint(checkpoint, 0, io)?;
    if &original != checkpoint {
        return Err("diagnosis requires the actual saved checkpoint".into());
    }
    let mut seen = BTreeSet::new();
    let mut results = Vec::new();
    for source in sources.iter().take(4) {
        for graph in source
            .graphs
            .iter()
            .filter(|g| g.candidates.len() > 1)
            .take(2)
        {
            if !seen.insert(graph.key()) {
                continue;
            }
            let silent = runtime.scores_graph(graph)?;
            let mut measured = runtime.policy.valid().activations(
                &[graph],
                &runtime.device.clone().inner(),
                runtime.recurrent(),
            )?;
            let activation = measured.pop().ok_or("activation row missing")?;
            let repeated = runtime.scores_graph(graph)?;
            let bits = silent.iter().map(|v| v.to_bits()).collect::<Vec<_>>();
            if bits != activation.score_bits
                || bits != repeated.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
            {
                return Err("activation observer changed actual score bits".into());
            }
            let best_witnessed = graph
                .successes
                .iter()
                .map(|i| silent[*i])
                .max_by(f32::total_cmp);
            let best_other = silent
                .iter()
                .enumerate()
                .filter(|(i, _)| !graph.successes.contains(i))
                .map(|(_, score)| *score)
                .max_by(f32::total_cmp);
            let witnessed_margin = best_witnessed.zip(best_other).map(|(a, b)| a - b);
            results.push(serde_json::json!({
                "source_job":source.job,"source_proof":source.proof,
                "successful_actions":graph.successes,"witnessed_action":graph.expert,
                "best_witnessed_vs_other_margin":witnessed_margin,
                "other_action_semantics":"Unwitnessed alternatives remain unknown, not false.",
                "measurement":activation,
            }));
        }
    }
    if runtime.checkpoint(checkpoint, 0, io)? != original || digest(job) != original_job {
        return Err("activation observer changed model, optimizer or job".into());
    }
    let output = serde_json::json!({
        "checkpoint":checkpoint,"checkpoint_binding":digest(checkpoint),
        "job_binding":original_job,"observer_definition":Policy::activation_definition(),
        "selection_definition":digest(&include_str!("activation.rs")),
        "conditioning":"Independent current decision with zero working memory; no historical hidden-state reconstruction.",
        "sources_available":sources.len(),"sources_considered":sources.len().min(4),
        "measurements":results,
        "score_bits_unchanged":true,"model_adam_ema_unchanged":true,"job_and_cursors_unchanged":true,
        "cpu_micros":meta::cpu_micros()?.saturating_sub(cpu),
        "wall_micros":u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "interpretation":"Neural activation summaries, not interpreted thoughts, causal influence or evidence of retained whole-proof quality."
    });
    if serde_json::to_vec(&output)
        .map_err(|e| e.to_string())?
        .len()
        > 256 * 1024
    {
        return Err("activation result capacity".into());
    }
    Ok(output)
}

mod run;
#[cfg(test)]
mod tests;
