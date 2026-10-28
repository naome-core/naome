//! The research 1M graph policy behind a narrow checkpoint/training boundary.
//! Formula graphs, goal-conditioned context attention and typed proof choices
//! use Adam, checked-action cross entropy, batch 16 and LR .001. No weights are imported.
#[cfg(test)]
pub(super) mod observation;
mod policy;
mod preservation;
#[cfg(test)]
mod routing_tests;
mod utility;
use super::graph::Graph;
use super::{
    artifact::{self, ArtifactIo, Blob},
    graph::Batch,
    pool::Pool,
};
use burn::{
    module::{Module, ModuleMapper, Param},
    optim::{AdamConfig, GradientsParams, ModuleOptimizer},
    store::ModuleRecord,
    tensor::{Bytes, Device, Tensor},
};
use naome_foundation::Formula;
pub use policy::Policy;
#[cfg(test)]
pub(super) use preservation::Mode as PreservationMode;
use serde::{Deserialize, Serialize};
/// CPU Flex, maximum graph batch 16x256 and two model/Adam/EMA lifetimes.
/// This is the unchanged finite admission envelope, not an OS RSS limit.
#[derive(Clone, Copy)]
pub(crate) struct Requirements {
    pub chunk_bytes: usize,
    pub blob_bytes: usize,
    pub io_bytes: usize,
    pub work_bytes: usize,
}
pub(crate) const REQUIREMENTS: Requirements = Requirements {
    chunk_bytes: 512 * 1024,
    blob_bytes: 16 * 1024 * 1024,
    io_bytes: 2 * 1024 * 1024 * 1024,
    work_bytes: 768 * 1024 * 1024,
};
pub const PARAMETERS: usize = 1_004_001;
pub const TRAINING_UNITS: u32 = 25;
pub const UPDATES_PER_UNIT: u64 = 10;

pub struct Binding {
    pub formula: Formula,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    DoubleNegation,
    NegatedImplication,
    ModusPonens,
    ImplicationBranch,
    UniversalInstance,
    EqualitySubstitution,
    ExistentialWitness,
    DefinitionReference,
    LemmaReference,
    ConstructionPlan,
}
impl Rule {
    pub fn kind(self) -> i32 {
        match self {
            Self::ExistentialWitness => 15,
            Self::DefinitionReference => 16,
            Self::LemmaReference => 17,
            Self::ConstructionPlan => 18,
            _ => 8 + self as i32,
        }
    }
}
pub struct Candidate {
    pub rule: Rule,
    pub premises: Vec<usize>,
    pub consequences: Vec<Formula>,
}
pub struct Decision {
    pub context: Vec<Binding>,
    pub goal: Formula,
    pub candidates: Vec<Candidate>,
    pub expert: usize,
}
pub trait Ranker {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub specification: String,
    pub seed: u64,
    pub updates: u64,
    pub model: Option<Blob>,
    pub optimizer: Option<Blob>,
}
pub(super) fn specification() -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(include_str!("model/policy.rs"));
    hash.update(include_str!("model/preservation.rs"));
    hash.update(include_str!("model/utility.rs"));
    hash.update(include_str!("finder.rs"));
    hash.update(include_str!("preservation-protocol.json"));
    hash.update(include_str!("mod.rs"));
    hash.update(include_str!("state.rs"));
    hash.update(include_str!("coverage.rs"));
    hash.update(include_str!("history.rs"));
    hash.update(include_str!("experience.rs"));
    hash.update(include_str!("graph.rs"));
    hash.update(include_str!("model.rs"));
    hash.update(include_str!("search.rs"));
    hash.update(include_str!("search/frontier.rs"));
    hash.update(include_str!("search/trace.rs"));
    hash.update(include_str!("search/core.rs"));
    hash.update(include_str!("pool.rs"));
    hash.update(include_str!("meta.rs"));
    hash.update(include_str!("transfer.rs"));
    hash.update(include_str!("meta/model.rs"));
    hash.update(include_str!("meta/plan.rs"));
    hash.update(include_str!("meta/memory.rs"));
    hash.update(include_str!("../training/ability.rs"));
    hash.update(include_str!("../training/planning.rs"));
    hash.update(include_str!("peer.rs"));
    hash.update(include_str!("definitions.rs"));
    hash.update(include_str!("knowledge.rs"));
    hash.update(include_str!("prerequisites.rs"));
    hash.update(include_str!("construction/composition.rs"));
    hash.update(include_str!("evidence.rs"));
    hash.update(include_str!("program.rs"));
    hash.update(include_str!("construction.rs"));
    hash.update(include_str!("construction/selection.rs"));
    hash.update(include_str!("construction/logic.rs"));
    hash.update(include_str!("construction/representation.rs"));
    hash.update(include_str!("proof.rs"));
    hash.update(include_str!("proof/kernel.rs"));
    hash.update(include_str!("proof/combinator.rs"));
    hash.update(include_str!("proof/lemmas.rs"));
    hash.update(include_str!("curriculum/owned.rs"));
    hash.update(include_str!("curriculum/owned-exclusions.json"));
    hash.update(include_str!("curriculum/composition-retired.json"));
    hash.update(include_str!("curriculum.rs"));
    hash.update(include_str!("curriculum/adaptive.rs"));
    hash.update(include_str!("curriculum/frontier.rs"));
    hash.update(include_str!("curriculum/composition.rs"));
    hash.update(include_str!("progress-protocol.json"));
    hash.update(include_str!("knowledge-protocol.json"));
    hash.update(
        b"Adam;successful-action-marginal;hierarchical-cyclic-pool;packed-disjoint-graphs;sparse-parent-mean;batch=16;lr=0.001;float32",
    );
    crate::hex(&hash.finalize())
}
impl Checkpoint {
    pub fn fresh() -> Self {
        Self {
            specification: specification(),
            seed: 0x4e414f4d45,
            updates: 0,
            model: None,
            optimizer: None,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.specification != specification()
            || self.model.is_some() != self.optimizer.is_some()
            || self.model.is_none() && self.updates != 0
        {
            return Err("native model specification or paired optimizer differs".into());
        }
        for blob in self.blobs() {
            blob.validate()?;
        }
        Ok(())
    }
    pub fn blobs(&self) -> impl Iterator<Item = &Blob> {
        self.model.iter().chain(self.optimizer.iter())
    }
}
/// SplitMix64 matches the research sampler. Its state is checkpointed, not reseeded.
pub fn random(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
pub struct Runtime {
    policy: Policy,
    optimizer: ModuleOptimizer,
    preservation: preservation::Preservation,
    preservation_micros: u64,
    device: Device,
}
fn canonical_checkpoint(bytes: Bytes) -> Result<Bytes, String> {
    let reader = burn_pack::Reader::from_bytes(bytes).map_err(|e| e.to_string())?;
    let metadata = reader.metadata().clone();
    let scalars = reader.scalars().clone();
    let mut tensors = reader.into_tensors().map_err(|e| e.to_string())?;
    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let mut writer = burn_pack::Writer::new(tensors);
    for (key, value) in metadata {
        writer = writer.with_metadata(&key, &value);
    }
    for (key, value) in scalars {
        writer = writer.with_scalar(&key, value);
    }
    writer.into_bytes().map_err(|e| e.to_string())
}
impl Runtime {
    pub(super) fn scores_graph(&self, graph: &Graph) -> Result<Vec<f32>, String> {
        // Validation weights are detached. Inputs must use the same plain
        // device, otherwise mixed operations retain needless autodiff state.
        let batch = self.scoring_batch(graph)?;
        self.policy
            .valid()
            .forward(&batch)
            .into_data()
            .try_to_vec::<f32>()
            .map_err(|e| e.to_string())
    }
    fn scoring_batch(&self, graph: &Graph) -> Result<Batch, String> {
        Batch::from_graphs(std::slice::from_ref(graph), &self.device.clone().inner())
    }
    /// Uniform exploration has the same graph/tensor input gates as inference.
    /// Only the unused neural forward pass is omitted.
    pub(super) fn validate_decision(&self, decision: &Decision) -> Result<(), String> {
        self.scoring_batch(&Graph::encode(decision)?).map(drop)
    }
    fn load<I: ArtifactIo + ?Sized>(checkpoint: &Checkpoint, io: &mut I) -> Result<Self, String> {
        checkpoint.validate()?;
        let device = Device::flex().autodiff();
        let mut policy = {
            // Flex has one process-wide RNG, and parameters initialize lazily.
            // Materialize every parameter under the same seed guard before any
            // inference, serialization or other model can advance that RNG.
            static INITIALIZATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = INITIALIZATION
                .lock()
                .map_err(|_| "native model initialization poisoned")?;
            device.seed(checkpoint.seed);
            struct StableParameters(u64);
            impl ModuleMapper for StableParameters {
                fn map_float<const D: usize>(
                    &mut self,
                    mut param: Param<Tensor<D>>,
                ) -> Param<Tensor<D>> {
                    self.0 += 1;
                    param.id = self.0.into();
                    param
                }
            }
            let policy = Policy::new(&device).train().map(&mut StableParameters(0));
            drop(policy.clone().into_record());
            policy
        };
        if policy.num_params() != PARAMETERS {
            return Err("native graph policy parameter count differs".into());
        }
        let mut optimizer = AdamConfig::new().init();
        let mut preservation = preservation::Preservation::fresh(&policy);
        if let (Some(model), Some(adam)) = (&checkpoint.model, &checkpoint.optimizer) {
            let bytes = artifact::load(io, model)?;
            policy = policy
                .try_load_record(
                    ModuleRecord::from_bytes(Bytes::from_bytes_vec(bytes))
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?
                .train();
            let bytes = artifact::load(io, adam)?;
            let adam =
                preservation.decode(Bytes::from_bytes_vec(bytes.clone()), checkpoint.updates)?;
            optimizer = optimizer.from_bytes(adam).map_err(|e| e.to_string())?;
            let restored =
                preservation.encode(optimizer.into_bytes().map_err(|e| e.to_string())?)?;
            if Blob::of(&restored[..]) != Blob::of(&bytes) {
                return Err("native optimizer did not restore exactly".into());
            }
        }
        Ok(Self {
            policy,
            optimizer,
            preservation,
            preservation_micros: 0,
            device,
        })
    }
    fn checkpoint<I: ArtifactIo + ?Sized>(
        &self,
        parent: &Checkpoint,
        updates: u64,
        io: &mut I,
    ) -> Result<Checkpoint, String> {
        let model = canonical_checkpoint(
            self.policy
                .clone()
                .into_record()
                .into_bytes()
                .map_err(|e| e.to_string())?,
        )?;
        let optimizer = self
            .preservation
            .encode(self.optimizer.into_bytes().map_err(|e| e.to_string())?)?;
        Ok(Checkpoint {
            specification: parent.specification.clone(),
            seed: parent.seed,
            updates: parent
                .updates
                .checked_add(updates)
                .ok_or("native model updates overflow")?,
            model: Some(artifact::save(io, &model[..])?),
            optimizer: Some(artifact::save(io, &optimizer[..])?),
        })
    }
    #[cfg(test)]
    fn train(&mut self, graphs: &Pool, rng: &mut u64, updates: u64) -> Result<(f32, f32), String> {
        self.train_using(
            graphs,
            rng,
            updates,
            super::meta::Plan::balanced().phase(0),
            None,
            preservation::Mode::default(),
        )
    }
    fn train_using(
        &mut self,
        graphs: &Pool,
        rng: &mut u64,
        updates: u64,
        phase: super::meta::Phase,
        preservation_pool: Option<(&Pool, u64)>,
        preservation_mode: preservation::Mode,
    ) -> Result<(f32, f32), String> {
        if graphs.is_empty() {
            return Err("training requires own accepted proof decisions".into());
        }
        let mut first = 0.;
        let mut last = 0.;
        let preservation_started = std::time::Instant::now();
        let preservation_gradient = if let Some((pool, mut cursor)) =
            preservation_pool.filter(|(p, _)| preservation_mode.enabled() && !p.is_empty())
        {
            // Separate, reproducible sampling: this never advances the training
            // cursor or consumes a development/transfer prediction as a label.
            let batch = Batch::from_graphs(&pool.batch(&mut cursor), &self.device)?;
            let loss = checked_marginal(self.policy.forward(&batch), &batch);
            loss_value(&loss)?;
            Some(GradientsParams::from_grads(loss.backward(), &self.policy))
        } else {
            None
        };
        self.preservation_micros = micros(preservation_started);
        for update in 0..updates {
            let sample = graphs.batch(rng);
            let batch = Batch::from_graphs(&sample, &self.device)?;
            let logits = self.policy.forward(&batch);
            let marginal = checked_marginal(logits.clone(), &batch);
            // This is preference between witnessed successful search actions
            // and unobserved alternatives, never mathematical false labels.
            let loss = if phase.ranking_quarters == 0 {
                marginal
            } else {
                let good = logits
                    .clone()
                    .mask_fill(batch.successes.clone().equal_elem(0.), -10000.)
                    .max_dim(1);
                let other = logits
                    .mask_fill(batch.successes.clone().greater_elem(0.), -10000.)
                    .mask_fill(batch.invalid.clone(), -10000.)
                    .max_dim(1);
                let ranking = (other - good + 0.2).clamp_min(0.).mean();
                let weight = f32::from(phase.ranking_quarters) / 4.;
                marginal * (1. - weight) + ranking * weight
            };
            let value = loss_value(&loss)?;
            let gradients = GradientsParams::from_grads(loss.backward(), &self.policy);
            let proposed = self.optimizer.step(
                if phase.gentle_rate { 0.0005 } else { 0.001 },
                self.policy.clone(),
                gradients,
            );
            self.policy = if let Some(gradient) = &preservation_gradient {
                let started = std::time::Instant::now();
                let policy =
                    self.preservation
                        .apply(&self.policy, proposed, gradient, preservation_mode)?;
                self.preservation_micros = self.preservation_micros.saturating_add(micros(started));
                policy
            } else {
                proposed
            };
            if update == 0 {
                first = value;
            }
            last = value;
        }
        Ok((first, last))
    }
}
fn checked_marginal(logits: Tensor<2>, batch: &Batch) -> Tensor<1> {
    let probability = burn::tensor::activation::log_softmax(logits, 1).exp();
    -(probability * batch.successes.clone())
        .sum_dim(1)
        .clamp_min(1e-12)
        .log()
        .mean()
}
fn loss_value(loss: &Tensor<1>) -> Result<f32, String> {
    let value = loss
        .clone()
        .into_data()
        .try_to_vec::<f32>()
        .map_err(|e| e.to_string())?[0];
    if !value.is_finite() {
        return Err("non-finite native training loss".into());
    }
    Ok(value)
}
impl Ranker for Runtime {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
        self.scores_graph(&Graph::encode(d)?)
    }
}
#[cfg(test)]
pub(super) fn test_update<I: ArtifactIo + ?Sized>(
    checkpoint: &Checkpoint,
    graphs: &[Graph],
    rng: &mut u64,
    io: &mut I,
) -> Result<Checkpoint, String> {
    let mut runtime = Runtime::load(checkpoint, io)?;
    runtime.train(&Pool::from_graphs(graphs), rng, 1)?;
    runtime.checkpoint(checkpoint, 1, io)
}
/// Only two concrete model lifetimes coexist: incumbent and current candidate.
/// Their binary identities stay outside controller state and accepted mathematics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrainingCost {
    pub replay_micros: u64,
    pub preparation_micros: u64,
    pub load_micros: u64,
    pub update_micros: u64,
    /// Included in update_micros, never added to it a second time.
    pub preservation_micros: u64,
    pub preservation_states: usize,
    pub checkpoint_micros: u64,
    pub states: usize,
}
fn micros(started: std::time::Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}
#[derive(Default)]
pub(crate) struct Engine {
    pub(super) prepared: Option<(Blob, super::history::Working)>,
    pub cost: TrainingCost,
    cache: Vec<(Checkpoint, Runtime)>,
    pool: Option<(String, Pool, Pool)>,
    #[cfg(test)]
    pub(super) preservation_mode: PreservationMode,
    pub meta: super::meta::Engine,
}
impl Engine {
    fn preservation_mode(&self) -> preservation::Mode {
        #[cfg(test)]
        {
            self.preservation_mode
        }
        #[cfg(not(test))]
        {
            preservation::Mode::default()
        }
    }
    #[cfg(test)]
    pub(super) fn snapshot<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        io: &mut I,
    ) -> Result<Checkpoint, String> {
        let runtime = self.take(c, io)?;
        let saved = runtime.checkpoint(c, 0, io)?;
        self.retain(saved.clone(), runtime);
        Ok(saved)
    }
    fn take<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        io: &mut I,
    ) -> Result<Runtime, String> {
        if let Some(index) = self.cache.iter().position(|(key, _)| key == c) {
            return Ok(self.cache.remove(index).1);
        }
        Runtime::load(c, io)
    }
    fn retain(&mut self, c: Checkpoint, r: Runtime) {
        if self.cache.len() >= 2 {
            self.cache.remove(0);
        }
        self.cache.push((c, r));
    }
    pub fn with<I: ArtifactIo + ?Sized, T>(
        &mut self,
        c: &Checkpoint,
        io: &mut I,
        operation: impl FnOnce(&mut Runtime) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut runtime = self.take(c, io)?;
        let result = operation(&mut runtime);
        self.retain(c.clone(), runtime);
        result
    }
    pub fn train_replay_using<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        state: &super::State,
        evidence: &[super::Evidence],
        cursor: &mut u64,
        phase: super::meta::Phase,
        io: &mut I,
    ) -> Result<Option<(Checkpoint, f32, f32)>, String> {
        self.cost = TrainingCost::default();
        let started = std::time::Instant::now();
        let key = super::digest(&(
            &state.model,
            &state.feedback,
            &state.preparation,
            &state.replay,
            &state.anchors,
            phase.rehearsal,
            self.preservation_mode().enabled(),
            evidence,
        ));
        let (mut pool, preservation_pool) = match self.pool.take() {
            Some((previous, pool, preservation_pool)) if previous == key => {
                (pool, preservation_pool)
            }
            _ => {
                let pool = state.training_pool_for(evidence, phase.rehearsal)?;
                #[cfg(test)]
                let mut pool = pool;
                #[cfg(test)]
                if state.preparation == super::Preparation::ReferenceTargeted && !pool.is_empty() {
                    let preparation = std::time::Instant::now();
                    self.with(&state.model, io, |runtime| {
                        pool.reference_focus(&state.feedback, |g| runtime.scores_graph(g))
                    })?;
                    self.cost.preparation_micros = micros(preparation);
                }
                let preservation_pool =
                    if state.model.updates > 0 && self.preservation_mode().enabled() {
                        state.preservation_pool(evidence, &pool)?
                    } else {
                        Pool::default()
                    };
                (pool, preservation_pool)
            }
        };
        let current_focus = phase.focused && {
            #[cfg(test)]
            {
                state.preparation != super::Preparation::ReferenceTargeted
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        if current_focus && !pool.is_empty() {
            let preparation = std::time::Instant::now();
            self.with(c, io, |runtime| {
                pool.focus(&state.feedback, |g| runtime.scores_graph(g))
            })?;
            self.cost.preparation_micros = micros(preparation);
        } else if !phase.focused {
            pool.unfocus();
        }
        self.cost.replay_micros = micros(started).saturating_sub(self.cost.preparation_micros);
        self.cost.states = pool.graphs().len();
        self.cost.preservation_states = preservation_pool.graphs().len();
        let result = if pool.is_empty() {
            Ok(None)
        } else {
            self.train_using(c, &pool, cursor, phase, Some(&preservation_pool), io)
                .map(Some)
        };
        self.pool = Some((key, pool, preservation_pool));
        result
    }
    #[cfg(test)]
    pub fn train<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        graphs: &Pool,
        rng: &mut u64,
        io: &mut I,
    ) -> Result<(Checkpoint, f32, f32), String> {
        self.train_using(
            c,
            graphs,
            rng,
            super::meta::Plan::balanced().phase(0),
            None,
            io,
        )
    }
    fn train_using<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        graphs: &Pool,
        rng: &mut u64,
        phase: super::meta::Phase,
        preservation_pool: Option<&Pool>,
        io: &mut I,
    ) -> Result<(Checkpoint, f32, f32), String> {
        let started = std::time::Instant::now();
        let mut runtime = self.take(c, io)?;
        self.cost.load_micros = micros(started);
        let started = std::time::Instant::now();
        let mode = self.preservation_mode();
        let preservation_pool =
            preservation_pool.map(|p| (p, (c.updates / UPDATES_PER_UNIT).wrapping_mul(16)));
        let (first, last) = runtime.train_using(
            graphs,
            rng,
            UPDATES_PER_UNIT,
            phase,
            preservation_pool,
            mode,
        )?;
        self.cost.update_micros = micros(started);
        self.cost.preservation_micros = runtime.preservation_micros;
        let started = std::time::Instant::now();
        let checkpoint = runtime.checkpoint(c, UPDATES_PER_UNIT, io)?;
        self.cost.checkpoint_micros = micros(started);
        self.retain(checkpoint.clone(), runtime);
        Ok((checkpoint, first, last))
    }
}

#[cfg(test)]
mod tests;
