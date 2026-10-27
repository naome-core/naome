//! Neural trial-level operational learning. Native proof validity, admission and
//! immutable resource grants remain outside this controller's authority.
mod model;
mod plan;
#[cfg(test)]
mod tests;
use super::{ArtifactIo, Blob, Preparation, artifact};
pub use plan::{Phase, Plan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const CONTEXT: usize = 32;
pub const FEATURES: usize = CONTEXT + 27;
pub const MEMORY: usize = 4;
/// Upper metadata is contained in the existing whole-learning State allowance.
pub const STATE_BYTES: usize = 4 * 1024;
pub const UPDATES: u64 = 8;
pub const PARAMETERS: usize = model::PARAMETERS;
pub fn cpu_micros() -> Result<u64, String> {
    use nix::sys::{
        resource::{UsageWho, getrusage},
        time::TimeValLike,
    };
    let r = getrusage(UsageWho::RUSAGE_SELF).map_err(|e| e.to_string())?;
    Ok((r.user_time().num_microseconds() + r.system_time().num_microseconds()) as u64)
}
fn specification() -> String {
    let mut h = Sha256::new();
    // A trial value depends on the exact lower data, methods and checker/search
    // contract as well as its own features, network and paired optimizer. The
    // lower fingerprint hashes these source bytes without calling this method.
    h.update(super::model::specification());
    h.update(b"native-trial-value-model;input=59;hidden=12;heads=3;Adam=0.003");
    crate::hex(&h.finalize())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub specification: String,
    pub seed: u64,
    pub updates: u64,
    pub weights: Option<Blob>,
    pub optimizer: Option<Blob>,
}
impl Checkpoint {
    pub fn fresh() -> Self {
        Self {
            specification: specification(),
            seed: 0x4e414f4d455441,
            updates: 0,
            weights: None,
            optimizer: None,
        }
    }
    pub fn blobs(&self) -> impl Iterator<Item = &Blob> {
        self.weights.iter().chain(&self.optimizer)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.specification != specification()
            || self.weights.is_some() != self.optimizer.is_some()
            || self.weights.is_none() && self.updates != 0
        {
            return Err("meta paired input/optimizer binding differs".into());
        }
        for b in self.blobs() {
            b.validate()?;
        }
        if self
            .weights
            .as_ref()
            .is_some_and(|b| b.bytes != PARAMETERS * 4)
            || self
                .optimizer
                .as_ref()
                .is_some_and(|b| b.bytes != 8 + PARAMETERS * 8)
        {
            return Err("meta checkpoint shape differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Experience {
    pub job: u64,
    pub context: [u16; CONTEXT],
    pub plan: Plan,
    pub source_model: String,
    pub selected_model: String,
    pub candidate_model: Option<String>,
    pub source_epoch: u64,
    pub before: u16,
    pub after: u16,
    pub protected_loss: bool,
    pub anchor_loss: bool,
    /// Measured lower units through the last persisted qualification checkpoint.
    /// Final gate/meta CPU remains in Progress and whole-job totals. Freezing this
    /// target makes a partial paired write replay exactly, not a new experiment.
    pub lower_cpu_micros: u64,
    pub lower_wall_micros: u64,
}
impl Experience {
    pub fn validate(&self) -> Result<(), String> {
        self.plan.validate()?;
        crate::object::id_bytes(&self.source_model)?;
        crate::object::id_bytes(&self.selected_model)?;
        if let Some(id) = &self.candidate_model {
            crate::object::id_bytes(id)?;
        }
        if self.job == 0
            || self.context.iter().any(|x| *x > 1000)
            || self.before as usize > super::curriculum::DEVELOPMENT
            || self.after as usize > super::curriculum::DEVELOPMENT
        {
            return Err("meta trial dimensions differ".into());
        }
        Ok(())
    }
    fn features(&self) -> [f32; FEATURES] {
        features(&self.context, &self.plan)
    }
    fn targets(&self) -> [f32; 3] {
        [
            (f32::from(self.after) - f32::from(self.before))
                / super::curriculum::DEVELOPMENT as f32,
            (u8::from(self.protected_loss) + u8::from(self.anchor_loss)) as f32 / 2.,
            (self.lower_cpu_micros as f32 / 180_000_000.).min(2.),
        ]
    }
    fn mask(&self) -> [f32; 3] {
        if self.candidate_model.is_some() {
            [1.; 3]
        } else {
            [0., 0., 1.]
        }
    }
}
fn features(context: &[u16; CONTEXT], plan: &Plan) -> [f32; FEATURES] {
    let mut out = [0.; FEATURES];
    for (i, x) in context.iter().enumerate() {
        out[i] = f32::from(*x) / 1000.;
    }
    out[CONTEXT..].copy_from_slice(&plan.features());
    out
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub model: Checkpoint,
    pub memory: Vec<Experience>,
    pub trials: u64,
    pub draw: u64,
}
impl State {
    pub fn fresh() -> Self {
        Self {
            model: Checkpoint::fresh(),
            memory: Vec::new(),
            trials: 0,
            draw: 991_027,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        self.model.validate()?;
        if self.memory.len() > MEMORY
            || self.memory.len() as u64 > self.trials
            || self.trials.checked_mul(UPDATES) != Some(self.model.updates)
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > STATE_BYTES
        {
            return Err("meta experience memory capacity".into());
        }
        if self
            .memory
            .iter()
            .map(|e| e.job)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.memory.len()
        {
            return Err("duplicate meta source trial".into());
        }
        for e in &self.memory {
            e.validate()?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub context: [u16; CONTEXT],
    pub plan: Plan,
    pub prediction: [f32; 3],
    pub exploration: bool,
    pub draw: u64,
}
impl Selection {
    pub fn validate(&self) -> Result<(), String> {
        self.plan.validate()?;
        if self.context.iter().any(|x| *x > 1000) || self.prediction.iter().any(|x| !x.is_finite())
        {
            Err("meta selection values differ".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub model: Checkpoint,
    pub experience: Experience,
    pub draw: u64,
    pub first_loss: f32,
    pub last_loss: f32,
}
#[derive(Default)]
pub struct Engine {
    cache: Option<(Checkpoint, model::Network)>,
}
impl Engine {
    fn take<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        io: &mut I,
    ) -> Result<model::Network, String> {
        c.validate()?;
        if let Some((key, network)) = self.cache.take()
            && key == *c
        {
            return Ok(network);
        }
        match (&c.weights, &c.optimizer) {
            (Some(w), Some(o)) => {
                model::Network::decode(&artifact::load(io, w)?, &artifact::load(io, o)?, c.updates)
            }
            _ => Ok(model::Network::fresh(c.seed)),
        }
    }
    pub fn select<I: ArtifactIo + ?Sized>(
        &mut self,
        state: &super::State,
        io: &mut I,
    ) -> Result<Selection, String> {
        let context = context(state);
        let mut draw = state.meta.draw;
        let fixed = match state.preparation {
            Preparation::Balanced => Some(Plan::balanced()),
            Preparation::Targeted => Some(Plan::targeted()),
            #[cfg(test)]
            Preparation::ReferenceTargeted => {
                let mut p = Plan::targeted();
                for stage in &mut p.phases {
                    stage.rehearsal = false;
                }
                Some(p)
            }
            #[cfg(test)]
            Preparation::FixedMixture => Some(Plan::mixture()),
            #[cfg(test)]
            Preparation::RandomMixture => Some(Plan::random(&mut draw)),
            Preparation::Meta => None,
        };
        if let Some(plan) = fixed {
            return Ok(Selection {
                context,
                plan,
                prediction: [0.; 3],
                exploration: false,
                draw,
            });
        }
        let network = self.take(&state.meta.model, io)?;
        let mut candidates = vec![Plan::balanced(), Plan::targeted(), Plan::mixture()];
        for _ in 0..13 {
            candidates.push(Plan::random(&mut draw));
        }
        let predictions = candidates
            .iter()
            .map(|p| network.forward(&features(&context, p)).1)
            .collect::<Vec<_>>();
        let exploration =
            state.meta.trials == 0 || super::model::random(&mut draw).is_multiple_of(5);
        let selected = if exploration {
            (super::model::random(&mut draw) % candidates.len() as u64) as usize
        } else {
            (0..candidates.len())
                .max_by(|a, b| {
                    utility(predictions[*a])
                        .total_cmp(&utility(predictions[*b]))
                        .then(b.cmp(a))
                })
                .unwrap()
        };
        let selection = Selection {
            context,
            plan: candidates.swap_remove(selected),
            prediction: predictions[selected],
            exploration,
            draw,
        };
        selection.validate()?;
        self.cache = Some((state.meta.model.clone(), network));
        Ok(selection)
    }
    pub fn learn<I: ArtifactIo + ?Sized>(
        &mut self,
        state: &super::State,
        experience: Experience,
        mut draw: u64,
        io: &mut I,
    ) -> Result<Update, String> {
        experience.validate()?;
        if experience.source_model != super::digest(&state.model)
            || experience.source_epoch != state.epoch
            || experience.context != context(state)
        {
            return Err(
                "meta optimization experience differs from the actual starting context".into(),
            );
        }
        let mut network = self.take(&state.meta.model, io)?;
        let mut memory = state.meta.memory.iter().collect::<Vec<_>>();
        memory.push(&experience);
        let mut first = 0.;
        let mut last = 0.;
        for i in 0..UPDATES {
            let mut batch = vec![&experience];
            for _ in 0..3 {
                batch
                    .push(memory[(super::model::random(&mut draw) % memory.len() as u64) as usize]);
            }
            last = network.update(&batch)?;
            if i == 0 {
                first = last;
            }
        }
        let (w, o) = network.encode();
        let checkpoint = Checkpoint {
            specification: specification(),
            seed: state.meta.model.seed,
            updates: network.updates,
            weights: Some(artifact::save(io, &w)?),
            optimizer: Some(artifact::save(io, &o)?),
        };
        self.cache = Some((checkpoint.clone(), network));
        Ok(Update {
            model: checkpoint,
            experience,
            draw,
            first_loss: first,
            last_loss: last,
        })
    }
}
fn utility(out: [f32; 3]) -> f32 {
    out[0].clamp(-1., 1.) - out[1].clamp(0., 1.) - 0.05 * out[2].clamp(0., 2.)
}
pub fn context(state: &super::State) -> [u16; CONTEXT] {
    let mut out = [0; CONTEXT];
    let summary = state.feedback.development.summary();
    for (i, (n, s, u)) in summary.into_iter().enumerate() {
        out[i * 2] = ((s.saturating_add(1) * 1000) / n.saturating_add(2)).min(1000) as u16;
        out[i * 2 + 1] = ((n.min(100) + u.min(100)) * 5).min(1000) as u16;
    }
    let sources = state.training_sources().collect::<Vec<_>>();
    let count = sources.len().max(1) as u64;
    out[12] = (state.replay.len() * 1000 / 32).min(1000) as u16;
    out[13] = (state.anchors.len() * 250) as u16;
    out[14] = (sources
        .iter()
        .filter(|e| matches!(e.origin, super::Origin::Peer { .. }))
        .count() as u64
        * 1000
        / count) as u16;
    out[15] = (state.model.updates.min(1000)) as u16;
    out[16] = (state.rejections.min(10) * 100) as u16;
    out[17] = (state.promotions.min(10) * 100) as u16;
    let mut skill = [0u64; 6];
    let mut bands = [0u64; 4];
    for e in sources {
        if let Ok(q) = naome_authoring::CompiledQuestion::compile(&e.question) {
            let (s, b) = crate::training::ability::signature(&q);
            for (i, p) in s.into_iter().enumerate() {
                skill[i] += u64::from(p);
            }
            bands[b as usize] += 1;
        }
    }
    for (i, n) in skill.into_iter().enumerate() {
        out[18 + i] = (n * 1000 / count).min(1000) as u16;
    }
    for (i, n) in bands.into_iter().enumerate() {
        out[24 + i] = (n * 1000 / count).min(1000) as u16;
    }
    out[28] = ((state.knowledge.len() * 125).min(1000)) as u16;
    out[29] = ((state.definitions.len() * 125).min(1000)) as u16;
    out[30] = state
        .feedback
        .regressions
        .iter()
        .map(|x| u64::from(*x))
        .sum::<u64>()
        .min(100) as u16
        * 10;
    out[31] = (state
        .meta
        .memory
        .iter()
        .map(|e| e.lower_cpu_micros)
        .fold(0u64, u64::saturating_add)
        / state.meta.memory.len().max(1) as u64
        / 180_000)
        .min(1000) as u16;
    out
}
