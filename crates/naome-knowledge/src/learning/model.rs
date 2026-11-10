//! The native structural policy behind a narrow checkpoint/training boundary.
//! Formula graphs, goal-conditioned context attention and typed proof choices
//! use Adam, checked-action objectives and at most 16 graph slots. Real observed
//! predecessor windows carry bounded working state; the native checker retains
//! all mathematical authority. No pretrained weights are imported.
mod measurement;
mod memory;
use measurement::TrainingMeasurements;
#[cfg(test)]
pub(super) mod observation;
mod policy;
mod sequence;
pub(crate) use memory::Recurrence;
pub use memory::{Memory, Plan};
mod preservation;
#[cfg(test)]
mod routing_tests;
mod utility;
use super::graph::Graph;
use super::{
    artifact::{self, ArtifactIo, Blob},
    graph::Batch,
    pool::{Pool, Sample},
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
pub const PARAMETERS: usize = READOUT_PARAMETERS
    + (19 + super::graph::SYMBOLS + 4 + 4 * policy::LAYERS + 4 * policy::WIDTH + 1) * policy::WIDTH;
pub(super) const READOUT_PARAMETERS: usize = 384_961;
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
    pub replacement: Option<naome_foundation::FreeVariable>,
    pub consequences: Vec<Formula>,
}
pub struct Decision {
    pub context: Vec<Binding>,
    pub goal: Formula,
    pub candidates: Vec<Candidate>,
    pub expert: usize,
}
pub trait Ranker {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error>;
    fn plan(
        &mut self,
        d: &Decision,
        _graph: &Graph,
        _offered: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, crate::Error> {
        if memory.is_some() {
            return Err(crate::ResearchFailure::StatelessRankerMemory.into());
        }
        Ok(Plan::scores(if d.candidates.len() == 1 {
            vec![0.]
        } else {
            self.scores(d)?
        }))
    }
    fn identity(&self) -> Option<String> {
        None
    }
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
    static SPECIFICATION: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| specification_for(&super::curriculum::CORPUS));
    SPECIFICATION.clone()
}

fn specification_for(corpus: &super::curriculum::Corpus) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(include_str!("model/policy.rs"));
    hash.update(include_str!("model/policy/cache.rs"));
    hash.update(include_str!("model/memory.rs"));
    hash.update(include_str!("model/sequence.rs"));
    hash.update(include_str!("model/measurement.rs"));
    hash.update(include_str!("model/preservation.rs"));
    hash.update(include_str!("model/utility.rs"));
    hash.update(include_str!("finder.rs"));
    hash.update(include_str!("mod.rs"));
    hash.update(include_str!("state.rs"));
    hash.update(include_str!("coverage.rs"));
    hash.update(include_str!("history.rs"));
    hash.update(include_str!("experience.rs"));
    hash.update(include_str!("graph.rs"));
    hash.update(include_str!("model.rs"));
    hash.update(include_str!("search.rs"));
    hash.update(include_str!("search/frontier.rs"));
    hash.update(include_str!("search/focus.rs"));
    hash.update(include_str!("search/instantiation.rs"));
    hash.update(include_str!("search/scope.rs"));
    hash.update(include_str!("search/trace.rs"));
    hash.update(include_str!("search/core.rs"));
    hash.update(include_str!("search/derivation.rs"));
    hash.update(include_str!("pool.rs"));
    hash.update(include_str!("pool/preservation.rs"));
    hash.update(include_str!("meta.rs"));
    hash.update(include_str!("../research_value.rs"));
    hash.update(include_str!("transfer.rs"));
    hash.update(include_str!("meta/model.rs"));
    hash.update(include_str!("meta/plan.rs"));
    hash.update(include_str!("meta/memory.rs"));
    hash.update(include_str!("../training/ability.rs"));
    hash.update(include_str!("../training/planning.rs"));
    hash.update(include_str!("peer.rs"));
    hash.update(include_str!("peer/program.rs"));
    hash.update(include_str!("definitions.rs"));
    hash.update(include_str!("knowledge.rs"));
    hash.update(include_str!("prerequisites.rs"));
    hash.update(include_str!("construction/composition.rs"));
    hash.update(include_str!("construction/composition/cuts.rs"));
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
    hash.update(super::curriculum::input_digest(corpus));
    hash.update(include_str!("curriculum/adaptive.rs"));
    hash.update(include_str!("curriculum/frontier.rs"));
    hash.update(include_str!("curriculum/composition.rs"));
    hash.update(
        b"Adam;successful-action-marginal;hierarchical-cyclic-pool;packed-disjoint-graphs;structural-formula-cache;batch=16;lr=0.001;float32",
    );
    crate::hex(&hash.finalize())
}
#[cfg(test)]
#[test]
fn checkpoint_specification_binds_effective_corpus_data() {
    let source = include_str!("curriculum.json");
    let mut corpus: super::curriculum::Corpus = serde_json::from_str(source).unwrap();
    let checkpoint = Checkpoint::fresh();
    assert_eq!(checkpoint.specification, specification_for(&corpus));
    let original = super::curriculum::input_digest(&corpus);
    corpus.cases[0].development = !corpus.cases[0].development;
    assert_eq!(
        corpus.manifest_sha256,
        super::curriculum::CORPUS.manifest_sha256
    );
    assert_eq!(
        corpus.questions_sha256,
        super::curriculum::CORPUS.questions_sha256
    );
    assert_ne!(super::curriculum::input_digest(&corpus), original);
    let mut mismatched = checkpoint.clone();
    mismatched.specification = specification_for(&corpus);
    assert_ne!(mismatched.specification, checkpoint.specification);
    assert_eq!(
        mismatched.validate().unwrap_err(),
        crate::ResearchFailure::ModelCheckpointBinding.into()
    );
    let mut invalid_blob = checkpoint.clone();
    let blob = Blob {
        sha256: "00".repeat(32),
        bytes: 0,
    };
    invalid_blob.model = Some(blob.clone());
    invalid_blob.optimizer = Some(blob);
    assert_eq!(
        invalid_blob.validate().unwrap_err(),
        crate::ResearchFailure::ModelBlobCapacity.into()
    );
    checkpoint.validate().unwrap();
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
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.specification != specification()
            || self.model.is_some() != self.optimizer.is_some()
            || self.model.is_none() && self.updates != 0
        {
            return Err(crate::ResearchFailure::ModelCheckpointBinding.into());
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
    formulas: std::cell::RefCell<policy::FormulaCache>,
    optimizer: ModuleOptimizer,
    preservation: preservation::Preservation,
    preservation_micros: u64,
    device: Device,
    identity: String,
    recurrence: Recurrence,
    rich_targets: bool,
    readout_only: bool,
    sampled_sequence_edges: usize,
    measurements: TrainingMeasurements,
    #[cfg(test)]
    observe_batches: bool,
    #[cfg(test)]
    contextual_preservation: bool,
}
// Backend text may contain paths or other sensitive values. Expose only the
// registered category and structured fields explicitly selected below.
fn backend_failure(code: crate::ResearchFailure) -> crate::Error {
    crate::Error::External(Box::new(crate::ExternalFailure {
        code,
        expected_type: None,
        actual_type: None,
    }))
}
fn pack_failure(error: burn_pack::Error) -> crate::Error {
    use crate::ResearchFailure as F;
    use burn_pack::Error as E;
    let code = match error {
        E::InvalidHeader => F::BackendPackHeader,
        E::InvalidMagicNumber => F::BackendPackMagic,
        E::InvalidVersion => F::BackendPackVersion,
        E::MetadataSerializationError(_) => F::BackendPackMetadataWrite,
        E::MetadataDeserializationError(_) => F::BackendPackMetadataRead,
        E::IoError(_) => F::BackendPackIo,
        E::TensorNotFound(_) => F::BackendPackTensorMissing,
        E::TensorBytesSizeMismatch(_) => F::BackendPackTensorSize,
        E::ValidationError(_) => F::BackendPackValidation,
        E::AlreadyExists(_) => F::BackendPackExists,
    };
    backend_failure(code)
}
fn record_failure(error: burn::store::RecordError) -> crate::Error {
    use burn::store::RecordError as E;
    let code = match error {
        E::Io(_) => crate::ResearchFailure::BackendRecordIo,
        E::Validation(_) => crate::ResearchFailure::BackendRecordValidation,
    };
    backend_failure(code)
}

fn tensor_element_type(value: burn::tensor::DType) -> crate::TensorElementType {
    use crate::TensorElementType as T;
    use burn::tensor::{BoolStore, DType};
    match value {
        DType::F64 => T::F64,
        DType::F32 => T::F32,
        DType::Flex32 => T::Flex32,
        DType::F16 => T::F16,
        DType::BF16 => T::Bf16,
        DType::I64 => T::I64,
        DType::I32 => T::I32,
        DType::I16 => T::I16,
        DType::I8 => T::I8,
        DType::U64 => T::U64,
        DType::U32 => T::U32,
        DType::U16 => T::U16,
        DType::U8 => T::U8,
        DType::Bool(BoolStore::Native) => T::BoolNative,
        DType::Bool(BoolStore::U8) => T::BoolU8,
        DType::Bool(BoolStore::U32) => T::BoolU32,
        DType::QFloat(_) => T::Quantized,
    }
}
fn tensor_data_failure(error: burn::tensor::DataError) -> crate::Error {
    use crate::ResearchFailure as F;
    use burn::tensor::DataError as E;
    if let E::ElementCountMismatch { expected, actual } = error {
        return crate::Error::ResearchMismatch {
            code: F::TensorElementCountMismatch,
            expected: expected as u64,
            actual: actual as u64,
        };
    }
    let types = match &error {
        E::DTypeMismatch { expected, actual } => Some((*expected, *actual)),
        E::UnsupportedConversion { from, to } => Some((*from, *to)),
        _ => None,
    };
    let code = match &error {
        E::StorageAccess(_) => F::TensorStorageAccess,
        E::InvalidRepresentation(_) => F::TensorInvalidRepresentation,
        E::DTypeMismatch { .. } => F::TensorDtypeMismatch,
        E::UnsupportedConversion { .. } => F::TensorUnsupportedConversion,
        E::InvalidByteLength { .. } => F::TensorByteLengthInvalid,
        E::ElementCountMismatch { .. } => unreachable!(),
    };
    let mut failure = backend_failure(code);
    if let (Some((expected, actual)), crate::Error::External(details)) = (types, &mut failure) {
        details.expected_type = Some(tensor_element_type(expected));
        details.actual_type = Some(tensor_element_type(actual));
    }
    failure
}
fn canonical_checkpoint(bytes: Bytes) -> Result<Bytes, crate::Error> {
    let reader = burn_pack::Reader::from_bytes(bytes).map_err(pack_failure)?;
    let metadata = reader.metadata().clone();
    let scalars = reader.scalars().clone();
    let mut tensors = reader.into_tensors().map_err(pack_failure)?;
    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let mut writer = burn_pack::Writer::new(tensors);
    for (key, value) in metadata {
        writer = writer.with_metadata(&key, &value);
    }
    for (key, value) in scalars {
        writer = writer.with_scalar(&key, value);
    }
    writer.into_bytes().map_err(pack_failure)
}
impl Runtime {
    fn observe_batches(&self) -> bool {
        #[cfg(test)]
        {
            self.observe_batches
        }
        #[cfg(not(test))]
        {
            true
        }
    }
    pub(super) fn recurrent(&self) -> bool {
        self.recurrence != Recurrence::Disabled
    }
    pub(super) fn scores_graph(&self, graph: &Graph) -> Result<Vec<f32>, crate::Error> {
        Ok(self.plan_graph(graph, "", None)?.scores)
    }
    fn scoring_batch(&self, graph: &Graph) -> Result<Batch, crate::Error> {
        Ok(Batch::from_graphs(
            std::slice::from_ref(graph),
            &self.device.clone().inner(),
        )?)
    }
    /// Uniform exploration has the same graph/tensor input gates as inference.
    /// Only the unused neural forward pass is omitted.
    pub(super) fn validate_graph(&self, graph: &Graph) -> Result<(), crate::Error> {
        self.scoring_batch(graph).map(drop)
    }
    fn load<I: ArtifactIo + ?Sized>(
        checkpoint: &Checkpoint,
        io: &mut I,
    ) -> Result<Self, crate::Error> {
        checkpoint.validate()?;
        let device = Device::flex().autodiff();
        let mut policy = {
            // Flex has one process-wide RNG, and parameters initialize lazily.
            // Materialize every parameter under the same seed guard before any
            // inference, serialization or other model can advance that RNG.
            static INITIALIZATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = INITIALIZATION
                .lock()
                .map_err(|_| crate::ResearchFailure::ModelInitializationPoisoned)?;
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
        let actual = policy.num_params();
        if actual != PARAMETERS {
            return Err(crate::Error::ResearchMismatch {
                code: crate::ResearchFailure::ModelParameterCountMismatch,
                expected: PARAMETERS as u64,
                actual: actual as u64,
            });
        }
        let mut optimizer = AdamConfig::new().init();
        let mut preservation = preservation::Preservation::fresh(&policy);
        if let (Some(model), Some(adam)) = (&checkpoint.model, &checkpoint.optimizer) {
            let bytes = artifact::load(io, model)?;
            policy = policy
                .try_load_record(
                    ModuleRecord::from_bytes(Bytes::from_bytes_vec(bytes))
                        .map_err(record_failure)?,
                )
                .map_err(record_failure)?
                .train();
            let bytes = artifact::load(io, adam)?;
            let adam =
                preservation.decode(Bytes::from_bytes_vec(bytes.clone()), checkpoint.updates)?;
            optimizer = optimizer.from_bytes(adam).map_err(record_failure)?;
            let restored = preservation.encode(optimizer.into_bytes().map_err(record_failure)?)?;
            if Blob::of(&restored[..]) != Blob::of(&bytes) {
                return Err(crate::ResearchFailure::ModelOptimizerRestorationMismatch.into());
            }
        }
        Ok(Self {
            policy,
            formulas: Default::default(),
            optimizer,
            preservation,
            preservation_micros: 0,
            device,
            identity: super::digest(checkpoint),
            recurrence: Recurrence::default(),
            rich_targets: true,
            readout_only: false,
            sampled_sequence_edges: 0,
            measurements: TrainingMeasurements::default(),
            #[cfg(test)]
            observe_batches: true,
            #[cfg(test)]
            contextual_preservation: false,
        })
    }
    fn checkpoint<I: ArtifactIo + ?Sized>(
        &self,
        parent: &Checkpoint,
        updates: u64,
        io: &mut I,
    ) -> Result<Checkpoint, crate::Error> {
        let total_updates = parent
            .updates
            .checked_add(updates)
            .ok_or(crate::ResearchFailure::ModelUpdatesOverflow)?;
        let model = canonical_checkpoint(
            self.policy
                .clone()
                .into_record()
                .into_bytes()
                .map_err(record_failure)?,
        )?;
        let optimizer = self
            .preservation
            .encode(self.optimizer.into_bytes().map_err(record_failure)?)?;
        Ok(Checkpoint {
            specification: parent.specification.clone(),
            seed: parent.seed,
            updates: total_updates,
            model: Some(artifact::save(io, &model[..])?),
            optimizer: Some(artifact::save(io, &optimizer[..])?),
        })
    }
    #[cfg(test)]
    fn train(&mut self, graphs: &Pool, rng: &mut u64, updates: u64) -> Result<(f32, f32), String> {
        Ok(self.train_using(
            graphs,
            rng,
            updates,
            super::meta::Plan::balanced().phase(0),
            None,
            preservation::Mode::default(),
        )?)
    }
    fn train_using(
        &mut self,
        graphs: &Pool,
        rng: &mut u64,
        updates: u64,
        phase: super::meta::Phase,
        preservation_pool: Option<(&Pool, u64, bool)>,
        preservation_mode: preservation::Mode,
    ) -> Result<(f32, f32), crate::Error> {
        if graphs.is_empty() {
            return Err(crate::ResearchFailure::TrainingPoolEmpty.into());
        }
        self.formulas.get_mut().clear();
        if self.readout_only {
            self.policy = self.policy.clone().readout_training();
        }
        let mut first = 0.;
        let mut last = 0.;
        self.measurements = TrainingMeasurements::default();
        self.measurements.readout_only = self.readout_only;
        self.measurements.trainable_parameters = if self.readout_only {
            READOUT_PARAMETERS
        } else {
            PARAMETERS
        };
        let preservation_started = std::time::Instant::now();
        let reference = preservation_pool
            .filter(|(pool, _, _)| preservation_mode.enabled() && !pool.is_empty());
        let preservation_gradient = if let Some((pool, mut cursor, false)) = reference {
            // Separate, reproducible sampling: this never advances the training
            // cursor or consumes a development/transfer prediction as a label.
            let (batch, logits) = self.preservation_scores(pool, &mut cursor)?;
            let loss = checked_marginal(logits, &batch);
            loss_value(&loss)?;
            Some(GradientsParams::from_grads(loss.backward(), &self.policy))
        } else {
            None
        };
        let mut cold_replay = reference.filter(|(_, _, cold)| *cold);
        self.preservation_micros = micros(preservation_started);
        self.sampled_sequence_edges = 0;
        for update in 0..updates {
            let before = *rng;
            let mut sample = graphs.sequence_batch(rng);
            let inserted_reference = if let Some((pool, cursor, _)) = &mut cold_replay {
                let started = std::time::Instant::now();
                let (reference, inserted) = if let Some(existing) = sample
                    .iter()
                    .find(|entry| !entry.auxiliary && pool.contains_replay_graph(entry.graph))
                {
                    (existing.graph, None)
                } else {
                    // The final slot has no dependents in the observed window.
                    let index = sample.len() - 1;
                    let graph = pool.batch(cursor)[0];
                    sample[index] = Sample {
                        graph,
                        selected: graph.expert,
                        parent: None,
                        auxiliary: false,
                    };
                    (graph, Some(index))
                };
                if self.observe_batches() {
                    self.measurements.record_references(&[reference]);
                }
                self.preservation_micros = self.preservation_micros.saturating_add(micros(started));
                inserted
            } else {
                None
            };
            self.sampled_sequence_edges += sample.iter().filter(|s| s.parent.is_some()).count();
            let inputs = sample
                .iter()
                .enumerate()
                .map(|(index, s)| {
                    if inserted_reference == Some(index) {
                        s.graph.clone()
                    } else {
                        graphs.target_graph(s.graph, self.rich_targets)
                    }
                })
                .collect::<Vec<_>>();
            let batch = Batch::from_graphs(&inputs, &self.device)?;
            if self.observe_batches() {
                self.measurements.observe(
                    graphs,
                    &sample,
                    &inputs,
                    before,
                    self.recurrence,
                    self.rich_targets,
                );
            }
            let logits = self.sequence_scores(&batch, &sample)?;
            let loss = self.sequence_loss(logits, &batch, &sample, graphs, phase);
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
fn loss_value(loss: &Tensor<1>) -> Result<f32, crate::Error> {
    let data = loss.clone().into_data();
    let values = data.as_slice::<f32>().map_err(tensor_data_failure)?;
    if values.len() != 1 {
        return Err(crate::Error::ResearchMismatch {
            code: crate::ResearchFailure::TrainingLossCount,
            expected: 1,
            actual: values.len() as u64,
        });
    }
    let value = values[0];
    if !value.is_finite() {
        return Err(crate::ResearchFailure::TrainingLossNonFinite.into());
    }
    Ok(value)
}

impl Ranker for Runtime {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error> {
        self.scores_graph(&Graph::encode(d)?)
    }
    fn plan(
        &mut self,
        _decision: &Decision,
        graph: &Graph,
        offered: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, crate::Error> {
        self.plan_graph(graph, offered, memory)
    }
    fn identity(&self) -> Option<String> {
        Some(super::digest(&(&self.identity, self.recurrence)))
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
    Ok(runtime.checkpoint(checkpoint, 1, io)?)
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
    pub checked_transitions: usize,
    pub checked_fragments: usize,
    pub omitted_transitions: usize,
    pub unavailable_fragments: usize,
    pub witnessed_preferences: usize,
    pub hindsight_matches: usize,
    pub checked_repairs: usize,
    pub observed_sequences: usize,
    pub sampled_sequence_edges: usize,
    pub measurements: TrainingMeasurements,
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
    #[cfg(test)]
    pub(super) targets: Targets,
    #[cfg(test)]
    pub(super) recurrence: Recurrence,
    #[cfg(test)]
    contextual_preservation: bool,
    #[cfg(test)]
    readout_only: bool,
    pub meta: super::meta::Engine,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Targets {
    Actions,
    #[default]
    Rich,
}
impl Engine {
    #[cfg(test)]
    pub(super) fn with_readout_only(mut self, enabled: bool) -> Self {
        assert!(
            self.cache.is_empty(),
            "training scope is fixed before model loading"
        );
        self.readout_only = enabled;
        self
    }

    #[cfg(test)]
    pub(super) fn with_targets(mut self, targets: Targets) -> Self {
        self.targets = targets;
        self
    }
    #[cfg(test)]
    pub(super) fn with_recurrence(mut self, recurrence: Recurrence) -> Self {
        self.recurrence = recurrence;
        self
    }
    #[cfg(test)]
    pub(super) fn with_contextual_preservation(mut self, contextual: bool) -> Self {
        self.contextual_preservation = contextual;
        self
    }
    fn recurrence(&self) -> Recurrence {
        #[cfg(test)]
        {
            self.recurrence
        }
        #[cfg(not(test))]
        {
            Recurrence::default()
        }
    }
    pub(super) fn rich_targets(&self) -> bool {
        #[cfg(test)]
        {
            self.targets == Targets::Rich
        }
        #[cfg(not(test))]
        {
            true
        }
    }
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
    ) -> Result<Runtime, crate::Error> {
        let mut runtime = if let Some(index) = self.cache.iter().position(|(key, _)| key == c) {
            self.cache.remove(index).1
        } else {
            Runtime::load(c, io)?
        };
        runtime.recurrence = self.recurrence();
        runtime.rich_targets = self.rich_targets();
        #[cfg(test)]
        {
            runtime.contextual_preservation = self.contextual_preservation;
            runtime.readout_only = self.readout_only;
        }
        Ok(runtime)
    }
    fn retain(&mut self, c: Checkpoint, mut r: Runtime) {
        r.identity = super::digest(&c);
        if self.cache.len() >= 2 {
            self.cache.remove(0);
        }
        self.cache.push((c, r));
    }
    #[cfg(test)]
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
    pub fn with_error<I: ArtifactIo + ?Sized, T>(
        &mut self,
        c: &Checkpoint,
        io: &mut I,
        operation: impl FnOnce(&mut Runtime) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let mut runtime = self.take(c, io)?;
        let result = operation(&mut runtime);
        self.retain(c.clone(), runtime);
        result
    }
    pub fn train_replay_using<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        state: &super::State,
        material: (&[super::Evidence], &[super::experience::Observation]),
        cursor: &mut u64,
        phase: super::meta::Phase,
        io: &mut I,
    ) -> Result<Option<(Checkpoint, f32, f32)>, crate::Error> {
        self.cost = TrainingCost::default();
        let (evidence, observations) = material;
        let rich_targets = self.rich_targets();
        let cold = state.model.updates == 0;
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
            observations,
            rich_targets,
        ));
        let (mut pool, preservation_pool) = match self.pool.take() {
            Some((previous, pool, preservation_pool)) if previous == key => {
                (pool, preservation_pool)
            }
            _ => {
                let mut pool = state.training_pool_for(evidence, phase.rehearsal)?;
                pool.reconcile(observations, rich_targets)?;
                #[cfg(test)]
                if state.preparation == super::Preparation::ReferenceTargeted && !pool.is_empty() {
                    let preparation = std::time::Instant::now();
                    self.with_error(&state.model, io, |runtime| {
                        pool.reference_focus(&state.feedback, |g| runtime.scores_graph(g))
                    })?;
                    self.cost.preparation_micros = micros(preparation);
                }
                let preservation_pool = if self.preservation_mode().enabled() {
                    match state.preservation_pool(evidence, &pool) {
                        Err(crate::Error::Research(
                            crate::ResearchFailure::PoolGraphWorkCapacity
                            | crate::ResearchFailure::PoolDerivedWorkCapacity,
                        )) if cold => Pool::default(),
                        result => result?,
                    }
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
            self.with_error(c, io, |runtime| {
                pool.focus(&state.feedback, |g| runtime.scores_graph(g))
            })?;
            self.cost.preparation_micros = micros(preparation);
        } else if !phase.focused {
            pool.unfocus();
        }
        self.cost.states = pool.graphs().len();
        let derived = pool.derived_counts();
        self.cost.checked_transitions = derived.transitions;
        self.cost.checked_fragments = derived.fragments;
        self.cost.omitted_transitions = derived.omitted;
        self.cost.unavailable_fragments = derived.unavailable;
        self.cost.witnessed_preferences = derived.preferences;
        self.cost.hindsight_matches = derived.hindsight;
        self.cost.checked_repairs = derived.repairs;
        self.cost.observed_sequences = derived.sequences;
        self.cost.preservation_states = preservation_pool.graphs().len();
        self.cost.replay_micros = micros(started).saturating_sub(self.cost.preparation_micros);
        let result = if pool.is_empty() {
            Ok(None)
        } else {
            self.train_using(
                c,
                &pool,
                cursor,
                phase,
                Some((&preservation_pool, cold)),
                io,
            )
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
        Ok(self.train_using(
            c,
            graphs,
            rng,
            super::meta::Plan::balanced().phase(0),
            None,
            io,
        )?)
    }
    fn train_using<I: ArtifactIo + ?Sized>(
        &mut self,
        c: &Checkpoint,
        graphs: &Pool,
        rng: &mut u64,
        phase: super::meta::Phase,
        preservation_pool: Option<(&Pool, bool)>,
        io: &mut I,
    ) -> Result<(Checkpoint, f32, f32), crate::Error> {
        let started = std::time::Instant::now();
        let mut runtime = self.take(c, io)?;
        self.cost.load_micros = micros(started);
        let started = std::time::Instant::now();
        let mode = self.preservation_mode();
        let preservation_pool = preservation_pool.map(|(pool, cold)| {
            let offset = if cold {
                c.updates
            } else {
                c.updates / UPDATES_PER_UNIT
            };
            (pool, offset.wrapping_mul(16), cold)
        });
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
        self.cost.sampled_sequence_edges = runtime.sampled_sequence_edges;
        self.cost.measurements = runtime.measurements.clone();
        let started = std::time::Instant::now();
        let checkpoint = runtime.checkpoint(c, UPDATES_PER_UNIT, io)?;
        self.cost.checkpoint_micros = micros(started);
        self.retain(checkpoint.clone(), runtime);
        Ok((checkpoint, first, last))
    }
}

#[cfg(test)]
mod tests;
