//! The research 1M graph policy behind a narrow checkpoint/training boundary.
//! Formula graphs, goal-conditioned context attention and typed proof choices
//! use Adam, checked-action cross entropy, batch 16 and LR .001. No weights are imported.
mod policy;
#[cfg(test)]
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
use serde::{Deserialize, Serialize};
/// CPU Flex, maximum graph batch 16x256 and two model/Adam lifetimes.
/// A bounded macOS ARM64 screen measured 206 MB RSS; the reservation includes
/// a substantial buffer. This is a finite admission envelope, not an OS RSS limit.
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
fn specification() -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(include_str!("model/policy.rs"));
    hash.update(include_str!("mod.rs"));
    hash.update(include_str!("state.rs"));
    hash.update(include_str!("graph.rs"));
    hash.update(include_str!("model.rs"));
    hash.update(include_str!("search.rs"));
    hash.update(include_str!("search/core.rs"));
    hash.update(include_str!("pool.rs"));
    hash.update(include_str!("peer.rs"));
    hash.update(include_str!("definitions.rs"));
    hash.update(include_str!("knowledge.rs"));
    hash.update(include_str!("evidence.rs"));
    hash.update(include_str!("program.rs"));
    hash.update(include_str!("construction.rs"));
    hash.update(include_str!("construction/selection.rs"));
    hash.update(include_str!("construction/logic.rs"));
    hash.update(include_str!("construction/representation.rs"));
    hash.update(include_str!("proof.rs"));
    hash.update(include_str!("proof/kernel.rs"));
    hash.update(include_str!("proof/lemmas.rs"));
    hash.update(include_str!("curriculum/owned.rs"));
    hash.update(include_str!("curriculum/owned-exclusions.json"));
    hash.update(include_str!("curriculum/composition-retired.json"));
    hash.update(include_str!("curriculum.rs"));
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
    #[cfg(test)]
    pub(super) fn scores_graph(&self, graph: &Graph) -> Result<Vec<f32>, String> {
        let batch = Batch::from_graphs(std::slice::from_ref(graph), &self.device)?;
        self.policy
            .valid()
            .forward(&batch)
            .into_data()
            .try_to_vec::<f32>()
            .map_err(|e| e.to_string())
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
            optimizer = optimizer
                .from_bytes(Bytes::from_bytes_vec(bytes.clone()))
                .map_err(|e| e.to_string())?;
            let restored =
                canonical_checkpoint(optimizer.into_bytes().map_err(|e| e.to_string())?)?;
            if Blob::of(&restored[..]) != Blob::of(&bytes) {
                return Err("native optimizer did not restore exactly".into());
            }
        }
        Ok(Self {
            policy,
            optimizer,
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
        let optimizer =
            canonical_checkpoint(self.optimizer.into_bytes().map_err(|e| e.to_string())?)?;
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
    fn train(&mut self, graphs: &Pool, rng: &mut u64, updates: u64) -> Result<(f32, f32), String> {
        if graphs.is_empty() {
            return Err("training requires own accepted proof decisions".into());
        }
        let mut first = 0.;
        let mut last = 0.;
        for update in 0..updates {
            let sample = graphs.batch(rng);
            let batch = Batch::from_graphs(&sample, &self.device)?;
            let logits = self.policy.forward(&batch);
            let probability = burn::tensor::activation::log_softmax(logits, 1).exp();
            let loss = -(probability * batch.successes)
                .sum_dim(1)
                .clamp_min(1e-12)
                .log()
                .mean();
            let value = loss
                .clone()
                .into_data()
                .try_to_vec::<f32>()
                .map_err(|e| e.to_string())?[0];
            if !value.is_finite() {
                return Err("non-finite native training loss".into());
            }
            let gradients = GradientsParams::from_grads(loss.backward(), &self.policy);
            self.policy = self.optimizer.step(0.001, self.policy.clone(), gradients);
            if update == 0 {
                first = value;
            }
            last = value;
        }
        Ok((first, last))
    }
}
impl Ranker for Runtime {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
        let batch = Batch::new(std::slice::from_ref(d), &self.device)?;
        self.policy
            .valid()
            .forward(&batch)
            .into_data()
            .try_to_vec::<f32>()
            .map_err(|e| e.to_string())
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
    pub load_micros: u64,
    pub update_micros: u64,
    pub checkpoint_micros: u64,
    pub states: usize,
}
fn micros(started: std::time::Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}
#[derive(Default)]
pub(crate) struct Engine {
    pub cost: TrainingCost,
    cache: Vec<(Checkpoint, Runtime)>,
    pool: Option<(String, Pool)>,
}
impl Engine {
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
    pub fn train_replay<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        state: &super::State,
        evidence: &[super::Evidence],
        cursor: &mut u64,
        io: &mut I,
    ) -> Result<Option<(Checkpoint, f32, f32)>, String> {
        self.cost = TrainingCost::default();
        let started = std::time::Instant::now();
        let key = super::digest(&(&state.replay, evidence));
        let pool = match self.pool.take() {
            Some((previous, pool)) if previous == key => pool,
            _ => state.training_pool(evidence)?,
        };
        self.cost.replay_micros = micros(started);
        self.cost.states = pool.graphs().len();
        let result = if pool.is_empty() {
            Ok(None)
        } else {
            self.train(c, &pool, cursor, io).map(Some)
        };
        self.pool = Some((key, pool));
        result
    }
    pub fn train<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        graphs: &Pool,
        rng: &mut u64,
        io: &mut I,
    ) -> Result<(Checkpoint, f32, f32), String> {
        let started = std::time::Instant::now();
        let mut runtime = self.take(c, io)?;
        self.cost.load_micros = micros(started);
        let started = std::time::Instant::now();
        let (first, last) = runtime.train(graphs, rng, UPDATES_PER_UNIT)?;
        self.cost.update_micros = micros(started);
        let started = std::time::Instant::now();
        let checkpoint = runtime.checkpoint(c, UPDATES_PER_UNIT, io)?;
        self.cost.checkpoint_micros = micros(started);
        self.retain(checkpoint.clone(), runtime);
        Ok((checkpoint, first, last))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::MemoryStore;
    use super::*;
    #[test]
    #[ignore = "Bounded maximum-shape native model memory measurement"]
    fn maximum_supported_batch_memory_is_bounded() {
        use super::super::graph::{Graph, Node};
        let nodes = (0..256)
            .map(|i| Node {
                kind: if i == 0 { 0 } else { 1 + (i % 7) as i32 },
                left: i / 2,
                right: i / 3,
                role: if i == 255 { 1 } else { 2 },
            })
            .collect();
        let graph = Graph {
            binding: String::new(),
            nodes,
            goal: 255,
            context: (1..33).collect(),
            candidates: (32..48).collect(),
            expert: 0,
            successes: vec![0],
        };
        let mut io = MemoryStore::default();
        let fresh = Checkpoint::fresh();
        let mut rng = 71;
        let meter = crate::resources::feedback::Meter::start();
        let mut runtime = Runtime::load(&fresh, &mut io).unwrap();
        runtime
            .train(
                &Pool::from_graphs(std::slice::from_ref(&graph)),
                &mut rng,
                1,
            )
            .unwrap();
        let trained = runtime.checkpoint(&fresh, 1, &mut io).unwrap();
        let mut candidate = Runtime::load(&trained, &mut io).unwrap();
        candidate
            .train(&Pool::from_graphs(&[graph]), &mut rng, 1)
            .unwrap();
        candidate.checkpoint(&trained, 1, &mut io).unwrap();
        let sample = meter.finish(0, true);
        eprintln!(
            "native_maximum_shape batch=16 nodes=256 candidates=16 parameters={} sample={:?}",
            PARAMETERS, sample
        );
    }
    #[test]
    fn sparse_packed_graphs_preserve_the_dense_sixteen_graph_adam_update() {
        let solution = super::super::tests::own_solution();
        let q = naome_authoring::CompiledQuestion::compile(&super::super::tests::own_question())
            .unwrap();
        let graph = super::super::search::compile(q.proved_target(), &solution.tree)
            .unwrap()
            .1
            .remove(0);
        let mut larger = graph.clone();
        while larger.nodes.len() < graph.nodes.len().next_power_of_two() + 1 {
            larger.nodes.push(super::super::graph::Node {
                kind: 6,
                left: 0,
                right: 0,
                role: 2,
            });
            larger.context.push(larger.nodes.len() - 1);
        }
        let mut empty_context = graph.clone();
        empty_context.context.clear();
        let pool = Pool::from_graphs(&[graph.clone(), larger, empty_context]);
        let sample = pool.batch(&mut 0);
        let fresh = Checkpoint::fresh();
        let mut io = MemoryStore::default();
        let mut dense = Runtime::load(&fresh, &mut io).unwrap();
        let mut sparse = Runtime::load(&fresh, &mut io).unwrap();
        let batch = Batch::from_graphs(&sample, &dense.device).unwrap();
        let joint = sparse
            .policy
            .valid()
            .forward(&batch)
            .into_data()
            .try_to_vec::<f32>()
            .unwrap();
        let width = batch.candidates.dims()[1];
        for (index, graph) in sample.iter().enumerate() {
            let separate = sparse.scores_graph(graph).unwrap();
            for (action, value) in separate.iter().enumerate() {
                assert!(
                    (joint[index * width + action] - value).abs() < 1e-4,
                    "an unrelated graph changed this graph's action score"
                );
            }
        }
        let probability =
            burn::tensor::activation::log_softmax(dense.policy.forward_dense(&batch), 1).exp();
        let loss = -(probability * batch.successes)
            .sum_dim(1)
            .clamp_min(1e-12)
            .log()
            .mean();
        let expected_loss = loss.clone().into_data().try_to_vec::<f32>().unwrap()[0];
        let gradients = GradientsParams::from_grads(loss.backward(), &dense.policy);
        dense.policy = dense.optimizer.step(0.001, dense.policy.clone(), gradients);
        let (actual_loss, _) = sparse.train(&pool, &mut 0, 1).unwrap();
        assert!((expected_loss - actual_loss).abs() < 1e-5);
        let a = dense.scores_graph(&graph).unwrap();
        let b = sparse.scores_graph(&graph).unwrap();
        let maximum = a
            .iter()
            .zip(b)
            .map(|(a, b)| (a - b).abs())
            .fold(0f32, f32::max);
        assert!(
            maximum < 1e-4,
            "sparse parent prediction difference {maximum}"
        );
    }
    #[test]
    fn zero_update_snapshot_preserves_fresh_predictions_and_optimizer_continuation() {
        let solution = super::super::tests::own_solution();
        let q = naome_authoring::CompiledQuestion::compile(&super::super::tests::own_question())
            .unwrap();
        let graph = super::super::search::compile(q.proved_target(), &solution.tree)
            .unwrap()
            .1
            .remove(0);
        let mut io = MemoryStore::default();
        let fresh = Checkpoint::fresh();
        let runtime = Runtime::load(&fresh, &mut io).unwrap();
        let expected = runtime.scores_graph(&graph).unwrap();
        let saved = Engine::default().snapshot(&fresh, &mut io).unwrap();
        assert_eq!(saved.updates, 0);
        assert_eq!(
            Runtime::load(&saved, &mut io)
                .unwrap()
                .scores_graph(&graph)
                .unwrap(),
            expected
        );
        let from_seed =
            test_update(&fresh, std::slice::from_ref(&graph), &mut 91, &mut io).unwrap();
        let from_saved = test_update(&saved, &[graph], &mut 91, &mut io).unwrap();
        assert_eq!(
            from_seed, from_saved,
            "initial binary model and optimizer must reproduce the same first real update"
        );
    }
    #[test]
    fn research_policy_trains_and_restores_both_million_parameter_model_and_adam() {
        let source = super::super::tests::own_question();
        struct Ordered;
        impl Ranker for Ordered {
            fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
                Ok(vec![0.; d.candidates.len()])
            }
        }
        let solution = super::super::search_question(&source, &mut Ordered, 128)
            .unwrap()
            .0
            .expect("own checked trace");
        let q = naome_authoring::CompiledQuestion::compile(&source).unwrap();
        let (_, graphs) = super::super::search::compile(q.proved_target(), &solution.tree).unwrap();
        assert!(!graphs.is_empty());
        let graphs = vec![graphs.into_iter().min_by_key(|g| g.nodes.len()).unwrap()];
        let mut io = MemoryStore::default();
        let fresh = Checkpoint::fresh();
        let mut rng = 17;
        let started = std::time::Instant::now();
        let mut runtime = Runtime::load(&fresh, &mut io).unwrap();
        let (first, last) = runtime
            .train(&Pool::from_graphs(&graphs), &mut rng, 1)
            .unwrap();
        let trained = runtime.checkpoint(&fresh, 1, &mut io).unwrap();
        assert_eq!(trained.updates, 1);
        assert!(first.is_finite() && last.is_finite());
        assert_ne!(fresh, trained);
        assert!(trained.model.as_ref().unwrap().bytes >= PARAMETERS * 4);
        assert!(trained.optimizer.as_ref().unwrap().bytes >= PARAMETERS * 8);
        assert!(serde_json::to_vec(&trained).unwrap().len() < 1024);
        let mut resumed = Runtime::load(&trained, &mut io).unwrap();
        let mut continued_rng = rng;
        runtime
            .train(&Pool::from_graphs(&graphs), &mut continued_rng, 1)
            .unwrap();
        let continued = runtime.checkpoint(&trained, 1, &mut io).unwrap();
        resumed
            .train(&Pool::from_graphs(&graphs), &mut rng, 1)
            .unwrap();
        let restored = resumed.checkpoint(&trained, 1, &mut io).unwrap();
        assert_eq!(
            continued, restored,
            "resume must preserve weights and Adam moments exactly"
        );
        let blob = trained.model.as_ref().unwrap();
        io.0.get_mut(&(blob.sha256.clone(), 0)).unwrap()[0] ^= 1;
        assert!(
            Engine::default()
                .with(&trained, &mut io, |_| Ok(()))
                .is_err(),
            "corruption cannot silently initialize new weights"
        );
        eprintln!(
            "native_model_operation parameters={} model_bytes={} optimizer_bytes={} updates={} elapsed_seconds={:.3}",
            PARAMETERS,
            trained.model.unwrap().bytes,
            trained.optimizer.unwrap().bytes,
            continued.updates,
            started.elapsed().as_secs_f64()
        );
    }
}
