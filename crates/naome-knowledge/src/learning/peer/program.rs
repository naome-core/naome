//! Recheck canonical peer program records and learn from their proved operands.
use super::{Binding, Candidate, Decision, Graph, Rule, checked_mp};
mod replay;
use crate::learning::{MODEL_REQUIREMENTS, proof};
use naome_checker::{
    ContextError, ContextStorage, ContextView, DiskArtifactState,
    program::{CheckedProgram, Engine, ProvedFormulas},
};
use naome_foundation::Formula;
use naome_proof::{
    ArtifactPayload, ProofId,
    program::{Command, MANIFEST_MAGIC, Manifest, decode_command, encode_command},
};
use replay::Decisions;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Packet {
    pub manifest: Manifest,
    #[serde(with = "binary")]
    bytes: Vec<u8>,
}

mod binary {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        STANDARD_NO_PAD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > (4 * crate::resources::limits().proof_bytes).div_ceil(3) {
            return Err(serde::de::Error::custom("peer program packet capacity"));
        }
        STANDARD_NO_PAD
            .decode(value)
            .map_err(serde::de::Error::custom)
    }
}

fn frame(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), crate::Error> {
    let width = u32::try_from(bytes.len())
        .map_err(|_| crate::ResearchFailure::PeerProgramFrameOutputWidth)?;
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], crate::Error> {
    let (width, rest) = input
        .split_first_chunk::<4>()
        .ok_or(crate::ResearchFailure::PeerProgramFrameWidth)?;
    let (bytes, rest) = rest
        .split_at_checked(u32::from_le_bytes(*width) as usize)
        .ok_or(crate::ResearchFailure::PeerProgramFrameTruncated)?;
    *input = rest;
    Ok(bytes)
}

struct ReplayStorage {
    limit: usize,
    records: Mutex<Records>,
}
#[derive(Default)]
struct Records {
    bytes: usize,
    values: BTreeMap<[u8; 32], Vec<u8>>,
}
impl ContextStorage for ReplayStorage {
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let records = self.records.lock().map_err(|_| ContextError::Corrupt)?;
        let value = records.values.get(&address).ok_or(ContextError::Corrupt)?;
        if value.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(value.clone())
    }

    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let mut records = self.records.lock().map_err(|_| ContextError::Corrupt)?;
        if let Some(previous) = records.values.get(&address) {
            return if previous == bytes {
                Ok(())
            } else {
                Err(ContextError::Corrupt)
            };
        }
        let total = records
            .bytes
            .checked_add(bytes.len() + 128)
            .ok_or(ContextError::Limit)?;
        if total > self.limit {
            return Err(ContextError::Limit);
        }
        records.bytes = total;
        records.values.insert(address, bytes.to_vec());
        Ok(())
    }
}

fn read_commands(manifest: &Manifest, tail: &mut &[u8]) -> Result<Vec<Command>, crate::Error> {
    if manifest.commands == 0 || manifest.commands > crate::resources::limits().closure_steps as u64
    {
        return Err(crate::ResearchFailure::PeerProgramCommandCapacity.into());
    }
    (0..manifest.commands)
        .map(|_| decode_command(take(tail)?).map_err(crate::Error::from))
        .collect()
}

fn write_commands(out: &mut Vec<u8>, commands: &[Command]) -> Result<(), crate::Error> {
    for command in commands {
        frame(out, &encode_command(command)?)?;
    }
    Ok(())
}

fn evaluate(
    manifest: &Manifest,
    commands: &[Command],
    context: &dyn ContextView,
    work: &mut usize,
) -> Result<CheckedProgram, crate::Error> {
    let limits = crate::resources::limits();
    let conn =
        rusqlite::Connection::open_in_memory().map_err(naome_checker::program::Error::from)?;
    let mut engine = Engine::open(conn)?;
    for group in commands.chunks(naome_proof::program::CHUNK_RECORDS) {
        engine.append_group(group)?;
    }
    let quantum = crate::resources::adaptive::batch(limits.closure_steps).max(1);
    let cache = crate::resources::program_cache(1024 * 1024);
    while !engine.status()?.fully_checked {
        let progress = engine.advance(quantum, cache, context)?;
        let spent = engine.last_quantum_steps();
        *work = work
            .checked_add(spent)
            .ok_or(crate::ResearchFailure::PeerProgramWorkOverflow)?;
        if *work > 16 * limits.closure_steps || !progress && spent == 0 {
            return Err(crate::ResearchFailure::PeerProgramWorkCapacity.into());
        }
    }
    while !engine.prepare_export(quantum)? {}
    let checked = engine.checked()?;
    checked.check_manifest(manifest)?;
    Ok(checked)
}

struct InputChecker {
    context: DiskArtifactState,
    steps: usize,
    work: usize,
    objects: usize,
}

impl InputChecker {
    fn new(steps: usize) -> Self {
        let limits = crate::resources::limits();
        Self {
            context: DiskArtifactState::new(Arc::new(ReplayStorage {
                limit: 24 * limits.closure_bytes,
                records: Mutex::default(),
            })),
            steps,
            work: 0,
            objects: 0,
        }
    }

    fn register(&mut self, bytes: &[u8]) -> Result<(), crate::Error> {
        let limits = crate::resources::limits();
        self.objects += 1;
        if self.objects >= limits.closure_objects {
            return Err(crate::ResearchFailure::PeerProgramContextCapacity.into());
        }
        if let Some(mut inner) = bytes.strip_prefix(MANIFEST_MAGIC) {
            let manifest = Manifest::from_canonical_bytes(take(&mut inner)?)?;
            let commands = read_commands(&manifest, &mut inner)?;
            if !inner.is_empty() {
                return Err(crate::ResearchFailure::PeerProgramDependencyTrailing.into());
            }
            self.steps = self
                .steps
                .checked_add(commands.len())
                .ok_or(crate::ResearchFailure::PeerProgramStepOverflow)?;
            if self.steps > limits.closure_steps {
                return Err(crate::ResearchFailure::PeerProgramStepCapacity.into());
            }
            let checked = evaluate(&manifest, &commands, &self.context, &mut self.work)?;
            let mut registration = self.context.begin_program_registration(&checked)?;
            while !registration.complete() {
                registration.advance(&checked, 64)?;
            }
            self.context = registration.finish()?;
            return Ok(());
        }
        if bytes.len() > limits.proof_bytes {
            return Err(crate::ResearchFailure::PeerProgramObjectCapacity.into());
        }
        match crate::object::decode_payload(bytes)? {
            ArtifactPayload::Proof(certificate) => {
                self.steps = self
                    .steps
                    .checked_add(certificate.steps().len())
                    .ok_or(crate::ResearchFailure::PeerProgramStepOverflow)?;
                if self.steps > limits.closure_steps {
                    return Err(crate::ResearchFailure::PeerProgramStepCapacity.into());
                }
                let checked = proof::check(certificate, &self.context)?;
                self.context.register_proof_for_replication(checked)?;
            }
            ArtifactPayload::Definition(certificate) => {
                let checked =
                    naome_checker::check_definition_with_state(certificate, &self.context)?;
                self.context.register_definition(checked)?;
            }
        }
        Ok(())
    }
}

pub(super) struct Replay {
    pub target: Formula,
    pub graphs: Decisions,
    pub definitions: Vec<naome_proof::DefinitionId>,
    _memory: Arc<crate::resources::MemoryLease>,
}

struct CheckedPacket {
    program: CheckedProgram,
    commands: Vec<Command>,
    context: DiskArtifactState,
    _work: Arc<crate::resources::MemoryLease>,
}

impl CheckedPacket {
    fn conclusion(&self) -> Result<&Formula, crate::Error> {
        self.program
            .conclusion()
            .ok_or_else(|| crate::ResearchFailure::PeerProgramConclusionCapacity.into())
    }
}

// Only already rechecked inputs from this process, keyed by the complete packet
// and exact target. Durable replay always starts with the canonical records.
thread_local! {
    static LAST: std::cell::RefCell<Option<(String, Arc<Replay>)>> = const { std::cell::RefCell::new(None) };
}

impl Packet {
    pub(crate) fn pack(
        manifest: Manifest,
        commands: &[Command],
        context: &[Arc<[u8]>],
    ) -> Result<Option<Self>, crate::Error> {
        let mut raw = Vec::new();
        write_commands(&mut raw, commands)?;
        for artifact in context {
            frame(&mut raw, artifact)?;
        }
        if raw.len() > crate::resources::limits().closure_bytes {
            return Ok(None);
        }
        let bytes = lz4_flex::block::compress_prepend_size(&raw);
        if bytes.len() > crate::resources::limits().proof_bytes {
            return Ok(None);
        }
        let packet = Self { manifest, bytes };
        packet.validate_width()?;
        Ok(Some(packet))
    }

    pub(crate) fn context_record(
        manifest: &Manifest,
        commands: &[Command],
    ) -> Result<Arc<[u8]>, crate::Error> {
        let mut record = MANIFEST_MAGIC.to_vec();
        frame(&mut record, &manifest.canonical_bytes()?)?;
        write_commands(&mut record, commands)?;
        Ok(record.into())
    }

    pub fn validate_width(&self) -> Result<(), crate::Error> {
        let limits = crate::resources::limits();
        if self.manifest.commands == 0
            || self.manifest.commands > limits.closure_steps as u64
            || self.manifest.input_bytes > limits.closure_bytes as u64
            || self.bytes.len() < 4
            || self.bytes.len() > limits.proof_bytes
        {
            return Err(crate::InputLimit::PeerProgramCapacity.into());
        }
        Ok(())
    }

    pub(crate) fn commands(&self) -> Result<Vec<Command>, crate::Error> {
        read_commands(&self.manifest, &mut self.decoded()?.as_slice())
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn target(&self) -> Result<Formula, crate::Error> {
        self.validate_width()?;
        let key = crate::learning::digest(self);
        if let Some(replay) = Self::cached(&key) {
            return Ok(replay.target.clone());
        }
        LAST.with(|last| last.borrow_mut().take());
        Ok(self.check_program()?.conclusion()?.clone())
    }

    pub(crate) fn check_trial(
        &self,
        target: &Formula,
        lemma: ProofId,
    ) -> Result<bool, crate::Error> {
        let checked = self.check_program()?;
        if checked.conclusion()? != target {
            return Err(crate::ResearchFailure::PeerProgramConclusionMismatch.into());
        }
        Ok(contributing_proofs(&checked.commands)?.contains(&lemma))
    }

    pub(super) fn replay(&self, target: &Formula) -> Result<Arc<Replay>, crate::Error> {
        let replay = self.rechecked()?;
        if &replay.target != target {
            return Err(crate::ResearchFailure::PeerProgramConclusionMismatch.into());
        }
        Ok(replay)
    }

    fn rechecked(&self) -> Result<Arc<Replay>, crate::Error> {
        self.validate_width()?;
        let key = crate::learning::digest(self);
        if let Some(value) = Self::cached(&key) {
            return Ok(value);
        }
        // The previous graph-only cache can yield its lease before the checker
        // reserves work for a different source.
        LAST.with(|last| last.borrow_mut().take());
        let replay = Arc::new(self.check()?);
        LAST.with(|last| *last.borrow_mut() = Some((key, Arc::clone(&replay))));
        Ok(replay)
    }

    fn cached(key: &str) -> Option<Arc<Replay>> {
        LAST.with(|last| {
            last.borrow()
                .as_ref()
                .filter(|(known, _)| known == key)
                .map(|(_, replay)| Arc::clone(replay))
        })
    }

    fn decoded(&self) -> Result<Vec<u8>, crate::Error> {
        self.validate_width()?;
        let (width, compressed) = self
            .bytes
            .split_first_chunk::<4>()
            .ok_or(crate::ResearchFailure::PeerProgramFrameWidth)?;
        let width = u32::from_le_bytes(*width) as usize;
        if width > crate::resources::limits().closure_bytes {
            return Err(crate::InputLimit::PeerProgramCapacity.into());
        }
        let mut raw = vec![0; width];
        let actual = lz4_flex::block::decompress_into(compressed, &mut raw)
            .map_err(|error| crate::Error::Compression(error.into()))?;
        if actual != width {
            return Err(crate::Error::Compression(
                crate::CompressionFailure::SizeMismatch {
                    expected: width,
                    actual,
                },
            ));
        }
        Ok(raw)
    }

    pub(crate) fn compose(
        target: &Formula,
        commands: &[Command],
        programs: &[Self],
        artifacts: impl IntoIterator<Item = Arc<[u8]>>,
    ) -> Result<Self, crate::Error> {
        use naome_proof::{
            StatementId,
            program::{Prefix, formula_hash, stream_hash},
        };
        let mut prefix = Prefix::default();
        for command in commands {
            prefix.append(&encode_command(command)?)?;
        }
        let mut stream_root = [0; 32];
        for command in commands.iter().rev() {
            stream_root = stream_hash(&encode_command(command)?, stream_root);
        }
        let bytes = target.encode_canonical()?;
        let statement = StatementId::of_canonical_formula(&bytes)
            .ok_or(crate::ResearchFailure::CandidateStatementWidth)?;
        let manifest = Manifest {
            commands: prefix.commands,
            input_bytes: prefix.input_bytes,
            program_hash: prefix.hash,
            stream_root,
            conclusion: formula_hash(target),
            statement: *statement.as_bytes(),
        };
        let context = Self::ordered_inputs(programs, artifacts)?;
        let packet = Self::pack(manifest, commands, &context)?
            .ok_or(crate::ResearchFailure::PeerProgramPacketCapacity)?;
        packet.replay(target)?;
        Ok(packet)
    }

    fn ordered_inputs(
        programs: &[Self],
        artifacts: impl IntoIterator<Item = Arc<[u8]>>,
    ) -> Result<Vec<Arc<[u8]>>, crate::Error> {
        let mut context = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut extent = 0usize;
        let mut append = |bytes: Arc<[u8]>| -> Result<(), crate::Error> {
            if seen.insert(crate::learning::digest(&bytes.as_ref())) {
                extent = extent
                    .checked_add(bytes.len() + 4)
                    .ok_or(crate::ResearchFailure::PeerProgramContextBytesOverflow)?;
                if extent > crate::resources::limits().closure_bytes {
                    return Err(crate::ResearchFailure::PeerProgramContextBytesCapacity.into());
                }
                context.push(bytes);
            }
            Ok(())
        };
        // Each program carries its own checked prefix in postorder. Register
        // that prefix before processing certificates that cite the program.
        for program in programs {
            let raw = program.decoded()?;
            let mut tail = raw.as_slice();
            let records = read_commands(&program.manifest, &mut tail)?;
            while !tail.is_empty() {
                append(take(&mut tail)?.into())?;
            }
            append(Self::context_record(&program.manifest, &records)?)?;
        }
        for artifact in artifacts {
            append(artifact)?;
        }
        Ok(context)
    }

    pub(crate) fn checked_inputs(
        programs: &[Self],
        artifacts: &[crate::object::Candidate],
    ) -> Result<DiskArtifactState, crate::Error> {
        let mut inputs = InputChecker::new(0);
        for record in Self::ordered_inputs(programs, artifacts.iter().map(|a| a.bytes.clone()))? {
            inputs.register(&record)?;
        }
        for artifact in artifacts {
            match &artifact.payload {
                crate::object::CandidatePayload::Proof(_) => {
                    let header = inputs
                        .context
                        .artifact_proof_header(artifact.id)?
                        .ok_or(crate::ResearchFailure::PeerPrerequisiteProofBinding)?;
                    if Some(header.statement_id()) != artifact.statement {
                        return Err(crate::ResearchFailure::PeerPrerequisiteStatement.into());
                    }
                }
                crate::object::CandidatePayload::Definition(definition) => {
                    let id = definition.definition_id();
                    if inputs.context.definition_canonical_length(id)?.is_none() {
                        return Err(
                            crate::ResearchFailure::PeerPrerequisiteDefinitionBinding.into()
                        );
                    }
                    if let Some(obligation) = artifact.obligation {
                        let header = inputs
                            .context
                            .proof_header(obligation)?
                            .ok_or(crate::ResearchFailure::PeerPrerequisiteObligationMissing)?;
                        let checked = naome_checker::check_definition_with_state(
                            definition.clone(),
                            &inputs.context,
                        )?;
                        if Some(header.statement_id()) != checked.obligation_statement_id() {
                            return Err(
                                crate::ResearchFailure::PeerPrerequisiteObligationBinding.into()
                            );
                        }
                    }
                }
            }
        }
        Ok(inputs.context)
    }

    fn check_program(&self) -> Result<CheckedPacket, crate::Error> {
        let limits = crate::resources::limits();
        let work = crate::resources::MemoryLease::acquire(32 * limits.closure_bytes)?;
        let raw = self.decoded()?;
        let mut tail = raw.as_slice();
        let commands = read_commands(&self.manifest, &mut tail)?;
        let mut inputs = InputChecker::new(commands.len());
        while !tail.is_empty() {
            inputs.register(take(&mut tail)?)?;
        }
        let context = inputs.context;
        let program = evaluate(&self.manifest, &commands, &context, &mut inputs.work)?;
        Ok(CheckedPacket {
            program,
            commands,
            context,
            _work: work,
        })
    }

    fn check(&self) -> Result<Replay, crate::Error> {
        let mut checked = self.check_program()?;
        let target = checked.conclusion()?.clone();
        let used = used_commands(&checked.commands, Command::operands)?;
        let definitions = checked
            .commands
            .iter()
            .zip(used)
            .filter(|(_, contributes)| *contributes)
            .filter_map(|(command, _)| command.definition_reference())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let graph_memory =
            crate::resources::MemoryLease::acquire(MODEL_REQUIREMENTS.work_bytes / 16)?;
        let graphs = graphs(
            &mut checked.program,
            &target,
            &checked.commands,
            &checked.context,
        )?;
        let retained = graphs.work_bytes() + 4 * crate::resources::limits().proof_bytes;
        drop(graph_memory);
        Ok(Replay {
            target,
            graphs,
            definitions,
            _memory: crate::resources::MemoryLease::acquire(retained)?,
        })
    }
}

/// Locate the first differing operand neighborhood without using the
/// observed choice. Matching binders are opened with the same fresh variable.
fn differing_operands(mut left: Formula, mut right: Formula) -> Option<(Formula, Formula)> {
    use naome_foundation::{FreeVariable, graph::Node};
    if left == right {
        return None;
    }
    loop {
        let next = match (left.view().graph_node(), right.view().graph_node()) {
            (Node::Not(a), Node::Not(b)) => (a.to_owned(), b.to_owned()),
            (Node::Implies(a, b), Node::Implies(c, d)) => {
                if a == c {
                    (b.to_owned(), d.to_owned())
                } else {
                    (a.to_owned(), c.to_owned())
                }
            }
            (Node::ForAll(_), Node::ForAll(_)) => {
                let mut used = left.free_variables();
                used.extend(right.free_variables());
                let variable = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|variable| !used.contains(variable))?;
                (
                    left.open_outer_universal(variable)?,
                    right.open_outer_universal(variable)?,
                )
            }
            _ => return Some((left, right)),
        };
        (left, right) = next;
    }
}

fn operand_mp(
    proved: &mut ProvedFormulas<'_>,
    target: &Formula,
    recent: &VecDeque<(usize, Formula, Rule)>,
    observed: (usize, usize),
) -> Result<Option<Graph>, crate::Error> {
    let mut lookup = |position| -> Result<Option<Formula>, crate::Error> {
        if let Some((_, formula, _)) = recent.iter().find(|(index, _, _)| *index == position) {
            return Ok(Some(formula.clone()));
        }
        proved.get(position as u64).map_err(crate::Error::from)
    };
    let (Some(premise), Some(implication)) = (lookup(observed.0)?, lookup(observed.1)?) else {
        return Ok(None);
    };
    let Some((_, consequence)) = implication.view().implication_parts() else {
        return Err(crate::ResearchFailure::PeerImplicationShape.into());
    };
    let alternative = recent.iter().rev().find_map(|(index, formula, rule)| {
        let (antecedent, candidate) = formula.view().implication_parts()?;
        if candidate == consequence {
            return None;
        }
        if antecedent == premise.view() {
            return Some((
                (observed.0, *index),
                premise.clone(),
                formula.clone(),
                candidate.to_owned(),
                *rule,
            ));
        }
        let (other, known, _) = recent
            .iter()
            .rev()
            .find(|(_, known, _)| known.view() == antecedent)?;
        Some((
            (*other, *index),
            known.clone(),
            formula.clone(),
            candidate.to_owned(),
            *rule,
        ))
    });
    let Some(alternative) = alternative else {
        return Ok(None);
    };
    let rule = recent
        .iter()
        .find(|(index, _, _)| *index == observed.1)
        .map_or(Rule::ModusPonens, |(_, _, rule)| *rule);
    let actual = (
        observed,
        premise,
        implication.clone(),
        consequence.to_owned(),
        rule,
    );
    let mut pairs = [actual, alternative];
    pairs.sort_by_key(|(positions, ..)| *positions);
    let expert = usize::from(pairs[1].0 == observed);
    let mut context: Vec<Binding> = Vec::new();
    let mut candidates = Vec::new();
    for (_, premise, implication, conclusion, rule) in pairs {
        let operands = [implication, premise]
            .into_iter()
            .map(|formula| {
                context
                    .iter()
                    .position(|binding| binding.formula == formula)
                    .unwrap_or_else(|| {
                        context.push(Binding { formula });
                        context.len() - 1
                    })
            })
            .collect();
        candidates.push(Candidate {
            rule,
            premises: operands,
            replacement: None,
            consequences: vec![conclusion],
        });
    }
    let decision = Decision {
        goal: target.clone(),
        context,
        candidates,
        expert,
    };
    match Graph::encode(&decision) {
        Ok(graph) => Ok(Some(graph)),
        Err(crate::LearningGraphFailure::Capacity) => Graph::encode_at_depth(&decision, 4)
            .map(Some)
            .map_err(Into::into),
        Err(error) => Err(error.into()),
    }
}

fn used_commands(
    commands: &[Command],
    operands: impl Fn(&Command) -> Vec<u64>,
) -> Result<Vec<bool>, crate::Error> {
    let Some((Command::Seal { .. }, prefix)) = commands.split_last() else {
        return Err(crate::ResearchFailure::PeerSealMissing.into());
    };
    let mut used = vec![false; commands.len()];
    let mut pending = vec![prefix.len()];
    while let Some(position) = pending.pop() {
        if std::mem::replace(&mut used[position], true) {
            continue;
        }
        for input in operands(&commands[position]) {
            let index =
                usize::try_from(input).map_err(|_| crate::ResearchFailure::PeerOperandWidth)?;
            if index >= position {
                return Err(crate::ResearchFailure::PeerOperandOrder.into());
            }
            pending.push(index);
        }
    }
    Ok(used)
}

/// Only citations that contribute to the final sealed result teach Finder.
pub(crate) fn contributing_proofs(
    commands: &[Command],
) -> Result<std::collections::BTreeSet<ProofId>, crate::Error> {
    // Formula constructors and deduction assumptions need only the formula,
    // even if the operand happens to carry a proof.
    let proof_operands = |command: &Command| match *command {
        Command::ModusPonens {
            premise,
            implication,
        } => vec![premise, implication],
        Command::Generalization { premise, .. } | Command::Instantiate { premise, .. } => {
            vec![premise]
        }
        Command::Alias { input } | Command::Seal { proof: input } => vec![input],
        Command::Graph { .. }
        | Command::DefinedRelation { .. }
        | Command::AuthoredRelation { .. }
        | Command::Equal { .. }
        | Command::Member { .. }
        | Command::Not { .. }
        | Command::Implies { .. }
        | Command::ForAll { .. }
        | Command::Substitute { .. }
        | Command::Simplification { .. }
        | Command::Frege { .. }
        | Command::Contraposition { .. }
        | Command::Distribution { .. }
        | Command::Vacuous { .. }
        | Command::Instantiation { .. }
        | Command::Deduce { .. }
        | Command::Reflexivity { .. }
        | Command::Substitution { .. }
        | Command::Axiom { .. }
        | Command::ProofReference { .. }
        | Command::Separation { .. }
        | Command::Replacement { .. } => Vec::new(),
    };
    Ok(commands
        .iter()
        .zip(used_commands(commands, proof_operands)?)
        .filter_map(|(command, used)| match command {
            Command::ProofReference { proof_id } if used => Some(ProofId::from_bytes(*proof_id)),
            _ => None,
        })
        .collect())
}

fn graphs(
    engine: &mut CheckedProgram,
    target: &Formula,
    commands: &[Command],
    context: &dyn ContextView,
) -> Result<Decisions, crate::Error> {
    let goal_parts = crate::learning::knowledge::fragments(target);
    let used = used_commands(commands, Command::operands)?;
    let mut recent = VecDeque::new();
    let scopes =
        crate::learning::search::scope::typed_program_graphs(engine, target, commands, &used)?;
    let scopes = if scopes.is_empty() {
        crate::learning::search::scope::program_graphs(target, commands, context)?
    } else {
        scopes
    };
    let mut bytes = scopes.iter().map(Graph::work_bytes).sum::<usize>();
    let mut graphs = Decisions::default();
    for graph in scopes {
        graphs.push(graph);
    }
    let ids = commands
        .iter()
        .filter_map(|command| match command {
            Command::ProofReference { proof_id } => Some(ProofId::from_bytes(*proof_id)),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut available = Vec::new();
    for id in ids.into_iter().take(16) {
        let header = context
            .proof_header(id)
            .map_err(crate::Error::from)?
            .ok_or(crate::ResearchFailure::PeerCitationMissing)?;
        if header.canonical_length() > crate::resources::limits().proof_bytes {
            continue;
        }
        let formula = context
            .proof_formula(header, header.canonical_length())
            .map_err(crate::Error::from)?
            .ok_or(crate::ResearchFailure::PeerCitationFormulaMissing)?
            .into_owned();
        if &formula != target {
            available.push((id, formula));
        }
    }
    let mut proved = engine.proved_formulas();
    for (position, command) in commands.iter().enumerate() {
        // The checked dependency context exists before the program runs.
        // Replay only an actual citation against other legal context proofs.
        if used[position]
            && let Command::ProofReference { proof_id } = command
        {
            let cited = ProofId::from_bytes(*proof_id);
            for group in available.chunks_exact(2) {
                let Some(expert) = group.iter().position(|(id, _)| *id == cited) else {
                    continue;
                };
                let mut decision = Decision {
                    goal: target.clone(),
                    context: group
                        .iter()
                        .map(|(_, formula)| Binding {
                            formula: formula.clone(),
                        })
                        .collect(),
                    candidates: group
                        .iter()
                        .enumerate()
                        .map(|(index, (_, formula))| Candidate {
                            rule: Rule::LemmaReference,
                            premises: vec![index],
                            replacement: None,
                            consequences: vec![formula.clone()],
                        })
                        .collect(),
                    expert,
                };
                let encoded = match Graph::encode(&decision) {
                    Ok(graph) => Some(graph),
                    Err(crate::LearningGraphFailure::Capacity) => {
                        if let Some((left, right)) =
                            differing_operands(group[0].1.clone(), group[1].1.clone())
                        {
                            for ((binding, candidate), operand) in decision
                                .context
                                .iter_mut()
                                .zip(&mut decision.candidates)
                                .zip([left, right])
                            {
                                binding.formula = operand.clone();
                                candidate.consequences = vec![operand];
                            }
                            Some(Graph::encode_at_depth(&decision, 5)?)
                        } else {
                            None
                        }
                    }
                    Err(error) => return Err(error.into()),
                };
                if let Some(mut graph) = encoded {
                    graph.binding = crate::learning::digest(&(position, cited.as_bytes()));
                    bytes = bytes
                        .checked_add(graph.work_bytes())
                        .ok_or(crate::ResearchFailure::PeerGraphOverflow)?;
                    if bytes > MODEL_REQUIREMENTS.work_bytes / 16 {
                        return Err(crate::ResearchFailure::PeerGraphCapacity.into());
                    }
                    graphs.push(graph);
                }
            }
        }
        if used[position]
            && let Command::ModusPonens {
                premise,
                implication,
            } = command
        {
            let operands = (*premise as usize, *implication as usize);
            let graph = checked_mp(
                target,
                &goal_parts,
                recent
                    .iter()
                    .map(|(index, formula, rule)| (*index, formula, *rule)),
                operands,
            )?;
            let graph = match graph {
                Some(graph) => Some(graph),
                None => operand_mp(&mut proved, target, &recent, operands)?,
            };
            if let Some(mut graph) = graph {
                graph.binding = crate::learning::digest(&(position, operands));
                bytes = bytes
                    .checked_add(graph.work_bytes())
                    .ok_or(crate::ResearchFailure::PeerGraphOverflow)?;
                if bytes > MODEL_REQUIREMENTS.work_bytes / 16 {
                    break;
                }
                graphs.push(graph);
            }
        }
        if let Some(formula) = proved.get(position as u64)? {
            if recent.len() == 32 {
                recent.pop_front();
            }
            let rule = match command {
                Command::Instantiation { .. } | Command::Instantiate { .. } => {
                    super::Rule::UniversalInstance
                }
                Command::ProofReference { .. } => super::Rule::LemmaReference,
                _ => super::Rule::ModusPonens,
            };
            recent.push_back((position, formula, rule));
        }
    }
    Ok(graphs.finish())
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn checking_a_packet_target_does_not_materialize_learning_replay() {
        if !crate::learning::tests::isolated(
            "learning::peer::program::capacity_tests::checking_a_packet_target_does_not_materialize_learning_replay",
        ) {
            return;
        }
        use naome_proof::program::Axiom;
        let target = naome_foundation::ZfcAxiom::Pairing.formula();
        let packet = Packet::compose(
            &target,
            &[
                Command::Axiom {
                    axiom: Axiom::Pairing,
                },
                Command::Seal { proof: 0 },
            ],
            &[],
            [],
        )
        .unwrap();
        LAST.with(|last| last.borrow_mut().take());
        assert_eq!(packet.target().unwrap(), target);
        assert!(LAST.with(|last| last.borrow().is_none()));
        assert_eq!(packet.replay(&target).unwrap().target, target);
        assert!(LAST.with(|last| last.borrow().is_some()));

        let mut forged = packet;
        forged.manifest.stream_root[0] ^= 1;
        assert!(matches!(forged.target(), Err(crate::Error::Proof(_))));
    }

    #[test]
    fn input_checker_preserves_artifact_and_proof_diagnostics() {
        let mut inputs = InputChecker::new(0);
        let expected = crate::object::decode_payload(&[]).unwrap_err();
        assert_eq!(inputs.register(&[]).unwrap_err(), expected);
        let certificate =
            naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
                proof_id: ProofId::from_bytes([0; 32]),
            }])
            .unwrap();
        let expected = crate::Error::from(
            proof::check(certificate.clone(), &inputs.context)
                .err()
                .unwrap(),
        );
        let payload = ArtifactPayload::Proof(certificate).to_canonical_bytes();
        assert_eq!(inputs.register(&payload).unwrap_err(), expected);
        assert!(matches!(expected, crate::Error::Proof(_)));
    }

    #[test]
    fn compressed_inputs_share_numeric_failure_details() {
        let bytes = vec![1, 0, 0, 0, 0x10];
        let expected = crate::CompressionFailure::from(
            lz4_flex::block::decompress_into(&bytes[4..], &mut [0]).unwrap_err(),
        );
        let manifest = Manifest {
            commands: 1,
            input_bytes: 1,
            program_hash: [0; 32],
            stream_root: [0; 32],
            conclusion: [0; 32],
            statement: [0; 32],
        };
        let packet = Packet {
            manifest,
            bytes: bytes.clone(),
        };
        assert_eq!(
            packet.decoded().unwrap_err(),
            crate::Error::Compression(expected)
        );
        assert_eq!(
            Packet::checked_inputs(std::slice::from_ref(&packet), &[])
                .err()
                .unwrap(),
            crate::Error::Compression(expected)
        );
        assert!(matches!(super::super::super::evidence::decode(&bytes),
            Err(crate::EvidenceFailure::Compression(actual)) if actual == expected));
        let evidence = serde_json::to_value(crate::EvidenceFailure::Compression(expected)).unwrap();
        let program = serde_json::to_value(crate::Error::Compression(expected)).unwrap();
        assert_eq!(evidence["compression"], program["compression"]);
        let short = vec![1, 0, 0, 0, 0];
        let mismatch = crate::CompressionFailure::SizeMismatch {
            expected: 1,
            actual: 0,
        };
        assert!(matches!(super::super::super::evidence::decode(&short),
            Err(crate::EvidenceFailure::Compression(actual)) if actual == mismatch));
        let packet = Packet {
            manifest: packet.manifest.clone(),
            bytes: short,
        };
        assert_eq!(
            packet.decoded().unwrap_err(),
            crate::Error::Compression(mismatch)
        );
        let width = serde_json::to_value(crate::CompressionFailure::OutputTooSmall {
            expected: 5,
            actual: 2,
        })
        .unwrap();
        assert_eq!(
            width,
            serde_json::json!({"reason": 1, "expected": 5, "actual": 2})
        );
    }

    #[test]
    fn command_frames_preserve_codec_and_truncation_failures() {
        let manifest = Manifest {
            commands: 1,
            input_bytes: 1,
            program_hash: [0; 32],
            stream_root: [0; 32],
            conclusion: [0; 32],
            statement: [0; 32],
        };
        let malformed = [1, 0, 0, 0, 255];
        let packet = Packet {
            manifest: manifest.clone(),
            bytes: lz4_flex::block::compress_prepend_size(&malformed),
        };
        let expected = crate::Error::from(decode_command(&[255]).unwrap_err());
        assert_eq!(packet.commands().unwrap_err(), expected);
        assert!(matches!(expected, crate::Error::ProgramCodec(_)));

        let packet = Packet {
            manifest,
            bytes: lz4_flex::block::compress_prepend_size(&[2, 0, 0, 0, 255]),
        };
        assert_eq!(
            packet.commands().unwrap_err(),
            crate::ResearchFailure::PeerProgramFrameTruncated.into()
        );
    }

    #[test]
    fn invalid_program_capacity_has_registered_code() {
        let packet = Packet {
            manifest: Manifest {
                commands: 0,
                input_bytes: 0,
                program_hash: [0; 32],
                stream_root: [0; 32],
                conclusion: [0; 32],
                statement: [0; 32],
            },
            bytes: vec![],
        };
        let error = packet.validate_width().unwrap_err();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::InputLimit::PeerProgramCapacity)
        );
    }
}
