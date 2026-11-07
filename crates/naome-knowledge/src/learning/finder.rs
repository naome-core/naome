//! Solver-owned, checked-training-only diagnostics for the research finder.
//! This proxy neither changes weights nor establishes proof or promotion quality.
use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Score {
    pub resolution: String,
    pub proof: String,
    pub alignment: i16,
    pub novelty: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Utility {
    pub checkpoint: String,
    pub references: Vec<String>,
    pub scores: Vec<Score>,
    pub cpu_micros: u64,
    pub wall_micros: u64,
    pub gradient_passes: u32,
}
impl Utility {
    pub(crate) fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.checkpoint)?;
        if self.references.is_empty()
            || self.references.len() > 4
            || self.scores.len() > 4
            || self.gradient_passes > 8
        {
            return Err("native finder utility capacity differs".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for reference in &self.references {
            crate::object::id_bytes(reference)?;
        }
        for score in &self.scores {
            crate::object::id_bytes(&score.resolution)?;
            crate::object::id_bytes(&score.proof)?;
            if score.alignment == i16::MIN || !ids.insert(&score.resolution) {
                return Err("native finder utility identity differs".into());
            }
        }
        Ok(())
    }
}
fn example(
    example: &Example,
    evidence: &[Evidence],
) -> Result<Option<(CompiledQuestion, graph::Graph)>, String> {
    if !matches!(example.origin, Origin::Local)
        || curriculum::owned::case(&example.question).is_none()
    {
        return Err("finder utility requires eligible local training proofs".into());
    }
    let q = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
    let target = if example.refuted {
        q.refuted_target()
    } else {
        q.proved_target()
    };
    let (core, _, verified) = search::core::checked(target, example.trajectory(evidence)?)?;
    if crate::hex(verified.native_id.as_bytes()) != example.proof_id {
        return Err("finder utility proof identity differs".into());
    }
    let graphs = search::compile(target, &core)?.1;
    Ok(graphs
        .into_iter()
        .find(|g| g.candidates.len() > 1)
        .map(|graph| (q, graph)))
}
impl State {
    pub(super) fn finder_utility<I: ArtifactIo + ?Sized>(
        &self,
        model: &Checkpoint,
        evidence: &[Evidence],
        engine: &mut Engine,
        io: &mut I,
    ) -> Result<Option<Utility>, String> {
        if !self
            .anchors
            .iter()
            .any(|e| matches!(e.origin, Origin::Local))
            || !self
                .replay
                .iter()
                .any(|e| matches!(e.origin, Origin::Local))
        {
            return Ok(None);
        }
        let wall = std::time::Instant::now();
        let cpu = meta::cpu_micros()?;
        // This small diagnostic shares the admitted native job's original work
        // envelope. Its rechecks, backward passes and IO count in job elapsed.
        let _memory = crate::resources::MemoryLease::acquire(MODEL_REQUIREMENTS.work_bytes / 16)
            .map_err(|e| e.to_string())?;
        let mut references = Vec::new();
        let mut questions = Vec::new();
        let mut graphs = Vec::new();
        for anchor in self
            .anchors
            .iter()
            .filter(|e| matches!(e.origin, Origin::Local))
            .take(4)
        {
            match example(anchor, evidence) {
                Ok(Some((q, g))) => {
                    references.push(anchor.proof_id.clone());
                    questions.push(q);
                    graphs.push(g);
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        if graphs.is_empty() {
            return Ok(None);
        }
        let mut scores = Vec::new();
        let mut passes = 0;
        for candidate in self
            .replay
            .iter()
            .rev()
            .filter(|e| matches!(e.origin, Origin::Local))
            .take(4)
        {
            let (q, g) = match example(candidate, evidence) {
                Ok(Some(value)) => value,
                Ok(None) => continue,
                Err(error) => return Err(error),
            };
            passes += 2;
            let Some(alignment) =
                engine.with(model, io, |runtime| runtime.utility_alignment(&g, &graphs))?
            else {
                continue;
            };
            let duplicate = questions
                .iter()
                .any(|r| r.resolution_id() == q.resolution_id());
            let similarity = questions
                .iter()
                .map(|r| {
                    crate::structure::Features::of(&q)
                        .similarity(&crate::structure::Features::of(r))
                })
                .max()
                .unwrap_or(0);
            let novelty = if duplicate {
                0
            } else {
                (65535 - similarity * 32767 / crate::structure::SCALE) as u16
            };
            if scores
                .iter()
                .any(|s: &Score| s.resolution == crate::hex(q.resolution_id()))
            {
                continue;
            }
            scores.push(Score {
                resolution: crate::hex(q.resolution_id()),
                proof: candidate.proof_id.clone(),
                alignment: (alignment * 32767.).round() as i16,
                novelty,
            });
        }
        let result = Utility {
            checkpoint: digest(model),
            references,
            scores,
            cpu_micros: meta::cpu_micros()?.saturating_sub(cpu),
            wall_micros: wall.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            gradient_passes: passes,
        };
        result.validate()?;
        Ok(Some(result))
    }
}
