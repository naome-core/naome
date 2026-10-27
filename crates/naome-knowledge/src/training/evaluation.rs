//! Reserved evaluation is deliberately unable to update adaptive priorities.
use super::*;

/// Reported whole-pipeline CPU costs. The host running the learner owns actual
/// measurement; this interface checks bounds and matching, not physical usage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compute {
    pub selection_micros: u64,
    pub generation_and_checking_micros: u64,
    pub training_micros: u64,
    pub evaluation_micros: u64,
}
impl Compute {
    fn total(&self) -> Result<u64, Error> {
        [
            self.selection_micros,
            self.generation_and_checking_micros,
            self.training_micros,
            self.evaluation_micros,
        ]
        .into_iter()
        .try_fold(0u64, |n, v| {
            n.checked_add(v)
                .ok_or_else(|| "training compute overflow".into())
        })
    }
}

/// Final evaluation over frozen, reserved question groups. The consumer must
/// run both arms from the same initial model and available premise context, and
/// record the first evaluation before further adaptation. This validates the
/// submitted evidence; it does not run or attest the external training process.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub initial_checkpoint: String,
    pub solver: Solver,
    pub knowledge: String,
    pub total_budget_micros: u64,
    pub compute: Compute,
    pub probes: Vec<Probe>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Results {
    pub total: usize,
    pub verified: usize,
    pub exhausted: usize,
    pub unavailable: usize,
    pub solved_structural_groups: usize,
    pub reported_cpu_micros: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub baseline: Results,
    pub targeted: Results,
    pub paired_new_successes: usize,
    pub paired_regressions: usize,
    pub structural_groups: usize,
}

/// Checks a matched random-vs-targeted trial. Unavailable results remain in the
/// denominator. Identical allowed compute ceilings are required; actual CPU is
/// reported separately. No causal or generalization claim follows from one pair.
pub fn compare(
    graph: &Graph,
    baseline: &Evaluation,
    targeted: &Evaluation,
) -> Result<Comparison, Error> {
    crate::object::id_bytes(&baseline.initial_checkpoint)?;
    crate::object::id_bytes(&targeted.initial_checkpoint)?;
    if baseline.initial_checkpoint != targeted.initial_checkpoint
        || baseline.knowledge != targeted.knowledge
        || baseline.solver.budget != targeted.solver.budget
        || baseline.total_budget_micros == 0
        || baseline.total_budget_micros != targeted.total_budget_micros
    {
        return Err("training comparison conditions differ".into());
    }
    let before = probes(
        graph,
        &baseline.solver,
        &baseline.knowledge,
        &baseline.probes,
        Partition::Reserved,
    )?;
    let after = probes(
        graph,
        &targeted.solver,
        &targeted.knowledge,
        &targeted.probes,
        Partition::Reserved,
    )?;
    if before.is_empty()
        || !before.keys().eq(after.keys())
        || before
            .iter()
            .any(|(id, observed)| after[id].input != observed.input)
    {
        return Err("training comparison reserved questions differ".into());
    }
    let summarize = |report: &Evaluation| -> Result<Results, Error> {
        let cpu = report.compute.total()?;
        if cpu > report.total_budget_micros {
            return Err("training comparison exceeds its total compute budget".into());
        }
        let mut groups = BTreeSet::new();
        let mut results = Results {
            total: report.probes.len(),
            verified: 0,
            exhausted: 0,
            unavailable: 0,
            solved_structural_groups: 0,
            reported_cpu_micros: cpu,
        };
        for probe in &report.probes {
            match probe.result {
                Outcome::Verified { .. } => {
                    results.verified += 1;
                    groups.insert(group(&CompiledQuestion::compile(&probe.question)?));
                }
                Outcome::Exhausted => results.exhausted += 1,
                Outcome::Unavailable => results.unavailable += 1,
            }
        }
        results.solved_structural_groups = groups.len();
        Ok(results)
    };
    let mut gains = 0;
    let mut regressions = 0;
    for (key, observed) in &before {
        let old = observed.solved;
        let new = after[key].solved;
        gains += usize::from(new == Some(true) && old != Some(true));
        regressions += usize::from(old == Some(true) && new != Some(true));
    }
    let groups = baseline
        .probes
        .iter()
        .map(|p| CompiledQuestion::compile(&p.question).map(|q| group(&q)))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(Comparison {
        baseline: summarize(baseline)?,
        targeted: summarize(targeted)?,
        paired_new_successes: gains,
        paired_regressions: regressions,
        structural_groups: groups.len(),
    })
}
