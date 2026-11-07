//! Recheck canonical peer program records and learn from their proved operands.
use super::{Binding, Candidate, Decision, Graph, Rule, checked_mp};
use crate::learning::{MODEL_REQUIREMENTS, proof};
use naome_checker::{
    ContextError, ContextStorage, ContextView, DiskArtifactState,
    program::{CheckedProgram, Engine},
};
use naome_foundation::Formula;
use naome_proof::{
    ArtifactPayload, ProofId,
    program::{Command, MANIFEST_MAGIC, Manifest, decode_command, encode_command},
};
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

fn frame(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let width = u32::try_from(bytes.len()).map_err(|_| "peer program frame width")?;
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let (width, rest) = input
        .split_first_chunk::<4>()
        .ok_or("peer program frame width")?;
    let (bytes, rest) = rest
        .split_at_checked(u32::from_le_bytes(*width) as usize)
        .ok_or("peer program frame truncated")?;
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

fn read_commands(manifest: &Manifest, tail: &mut &[u8]) -> Result<Vec<Command>, String> {
    if manifest.commands == 0 || manifest.commands > crate::resources::limits().closure_steps as u64
    {
        return Err("peer program replay command capacity".into());
    }
    (0..manifest.commands)
        .map(|_| decode_command(take(tail)?))
        .collect()
}

fn write_commands(out: &mut Vec<u8>, commands: &[Command]) -> Result<(), String> {
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
) -> Result<CheckedProgram, String> {
    let limits = crate::resources::limits();
    let conn = rusqlite::Connection::open_in_memory().map_err(|error| error.to_string())?;
    let mut engine = Engine::open(conn).map_err(|error| error.to_string())?;
    for group in commands.chunks(naome_proof::program::CHUNK_RECORDS) {
        engine
            .append_group(group)
            .map_err(|error| error.to_string())?;
    }
    let quantum = crate::resources::adaptive::batch(limits.closure_steps).max(1);
    let cache = crate::resources::program_cache(1024 * 1024);
    while !engine
        .status()
        .map_err(|error| error.to_string())?
        .fully_checked
    {
        let progress = engine
            .advance(quantum, cache, context)
            .map_err(|error| error.to_string())?;
        let spent = engine.last_quantum_steps();
        *work = work
            .checked_add(spent)
            .ok_or("peer program checker work overflow")?;
        if *work > 16 * limits.closure_steps || !progress && spent == 0 {
            return Err("peer program checker work capacity".into());
        }
    }
    while !engine
        .prepare_export(quantum)
        .map_err(|error| error.to_string())?
    {}
    let checked = engine.checked().map_err(|error| error.to_string())?;
    checked
        .check_manifest(manifest)
        .map_err(|error| error.to_string())?;
    Ok(checked)
}

pub(super) struct Replay {
    pub target: Formula,
    pub graphs: Vec<Graph>,
    pub definitions: Vec<naome_proof::DefinitionId>,
    _memory: Arc<crate::resources::MemoryLease>,
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
    ) -> Result<Option<Self>, String> {
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
    ) -> Result<Arc<[u8]>, String> {
        let mut record = MANIFEST_MAGIC.to_vec();
        frame(&mut record, &manifest.canonical_bytes()?)?;
        write_commands(&mut record, commands)?;
        Ok(record.into())
    }

    pub fn validate_width(&self) -> Result<(), String> {
        let limits = crate::resources::limits();
        if self.manifest.commands == 0
            || self.manifest.commands > limits.closure_steps as u64
            || self.manifest.input_bytes > limits.closure_bytes as u64
            || self.bytes.len() < 4
            || self.bytes.len() > limits.proof_bytes
        {
            return Err("peer program replay capacity".into());
        }
        Ok(())
    }

    pub(crate) fn commands(&self) -> Result<Vec<Command>, String> {
        read_commands(&self.manifest, &mut self.decoded()?.as_slice())
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn target(&self) -> Result<Formula, String> {
        Ok(self.rechecked()?.target.clone())
    }

    pub(super) fn replay(&self, target: &Formula) -> Result<Arc<Replay>, String> {
        let replay = self.rechecked()?;
        if &replay.target != target {
            return Err("peer program conclusion differs".into());
        }
        Ok(replay)
    }

    fn rechecked(&self) -> Result<Arc<Replay>, String> {
        self.validate_width()?;
        let key = crate::learning::digest(self);
        if let Some(value) = LAST.with(|last| {
            last.borrow()
                .as_ref()
                .filter(|(known, _)| known == &key)
                .map(|(_, replay)| Arc::clone(replay))
        }) {
            return Ok(value);
        }
        // The previous graph-only cache can yield its lease before the checker
        // reserves work for a different source.
        LAST.with(|last| last.borrow_mut().take());
        let replay = Arc::new(self.check()?);
        LAST.with(|last| *last.borrow_mut() = Some((key, Arc::clone(&replay))));
        Ok(replay)
    }

    fn decoded(&self) -> Result<Vec<u8>, String> {
        self.validate_width()?;
        let (width, compressed) = self
            .bytes
            .split_first_chunk::<4>()
            .ok_or("peer program frame width")?;
        let width = u32::from_le_bytes(*width) as usize;
        if width > crate::resources::limits().closure_bytes {
            return Err("peer program decoded capacity".into());
        }
        let mut raw = vec![0; width];
        if lz4_flex::block::decompress_into(compressed, &mut raw)
            .map_err(|error| error.to_string())?
            != width
        {
            return Err("peer program decoded extent differs".into());
        }
        Ok(raw)
    }

    pub(crate) fn compose(
        target: &Formula,
        commands: &[Command],
        programs: &[Self],
        artifacts: impl IntoIterator<Item = Arc<[u8]>>,
    ) -> Result<Self, String> {
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
        let bytes = target
            .encode_canonical()
            .map_err(|error| error.to_string())?;
        let statement =
            StatementId::of_canonical_formula(&bytes).ok_or("native program statement width")?;
        let manifest = Manifest {
            commands: prefix.commands,
            input_bytes: prefix.input_bytes,
            program_hash: prefix.hash,
            stream_root,
            conclusion: formula_hash(target),
            statement: *statement.as_bytes(),
        };
        let mut context = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut append = |bytes: Arc<[u8]>| {
            if seen.insert(crate::learning::digest(&bytes.as_ref())) {
                context.push(bytes);
            }
        };
        for artifact in artifacts {
            append(artifact);
        }
        for program in programs {
            let raw = program.decoded()?;
            let mut tail = raw.as_slice();
            let records = read_commands(&program.manifest, &mut tail)?;
            while !tail.is_empty() {
                append(take(&mut tail)?.into());
            }
            append(Self::context_record(&program.manifest, &records)?);
        }
        let packet = Self::pack(manifest, commands, &context)?
            .ok_or("native program replay packet capacity")?;
        packet.replay(target)?;
        Ok(packet)
    }

    fn check(&self) -> Result<Replay, String> {
        let limits = crate::resources::limits();
        let _work = crate::resources::MemoryLease::acquire(32 * limits.closure_bytes)
            .map_err(|error| error.to_string())?;
        let raw = self.decoded()?;
        let mut tail = raw.as_slice();
        let commands = read_commands(&self.manifest, &mut tail)?;
        let mut context = DiskArtifactState::new(Arc::new(ReplayStorage {
            limit: 24 * limits.closure_bytes,
            records: Mutex::default(),
        }));
        let mut steps = commands.len();
        let mut work = 0;
        let mut objects = 0;
        let mut definitions = Vec::new();
        while !tail.is_empty() {
            objects += 1;
            let bytes = take(&mut tail)?;
            if objects >= limits.closure_objects {
                return Err("peer program context capacity".into());
            }
            if let Some(mut inner) = bytes.strip_prefix(MANIFEST_MAGIC) {
                let manifest = Manifest::from_canonical_bytes(take(&mut inner)?)?;
                let commands = read_commands(&manifest, &mut inner)?;
                if !inner.is_empty() {
                    return Err("peer program dependency trailing bytes".into());
                }
                steps = steps
                    .checked_add(commands.len())
                    .ok_or("peer program context step overflow")?;
                if steps > limits.closure_steps {
                    return Err("peer program context step capacity".into());
                }
                let checked = evaluate(&manifest, &commands, &context, &mut work)?;
                let mut registration = context
                    .begin_program_registration(&checked)
                    .map_err(|error| error.to_string())?;
                while !registration.complete() {
                    registration
                        .advance(&checked, 64)
                        .map_err(|error| error.to_string())?;
                }
                context = registration.finish().map_err(|error| error.to_string())?;
                continue;
            }
            if bytes.len() > limits.proof_bytes {
                return Err("peer program context object capacity".into());
            }
            match ArtifactPayload::from_canonical_bytes(bytes).map_err(|error| error.to_string())? {
                ArtifactPayload::Proof(certificate) => {
                    steps = steps
                        .checked_add(certificate.steps().len())
                        .ok_or("peer program context step overflow")?;
                    if steps > limits.closure_steps {
                        return Err("peer program context step capacity".into());
                    }
                    let checked =
                        proof::check(certificate, &context).map_err(|error| error.to_string())?;
                    context
                        .register_proof_for_replication(checked)
                        .map_err(|error| error.to_string())?;
                }
                ArtifactPayload::Definition(certificate) => {
                    let checked = naome_checker::check_definition_with_state(certificate, &context)
                        .map_err(|error| error.to_string())?;
                    context
                        .register_definition(checked)
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        let checked = evaluate(&self.manifest, &commands, &context, &mut work)?;
        let target = checked
            .conclusion()
            .ok_or("peer replay formula capacity")?
            .clone();
        for command in &commands {
            if let Command::DefinedRelation { definition_id, .. } = command {
                let id = naome_proof::DefinitionId::from_bytes(*definition_id);
                if !definitions.contains(&id) {
                    definitions.push(id);
                }
            }
        }
        let graph_memory =
            crate::resources::MemoryLease::acquire(MODEL_REQUIREMENTS.work_bytes / 16)
                .map_err(|error| error.to_string())?;
        let graphs = graphs(&checked, &target, &commands, &context)?;
        let retained = graphs.iter().map(Graph::work_bytes).sum::<usize>() + 4 * limits.proof_bytes;
        drop(graph_memory);
        Ok(Replay {
            target,
            graphs,
            definitions,
            _memory: crate::resources::MemoryLease::acquire(retained)
                .map_err(|error| error.to_string())?,
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

fn graphs(
    engine: &CheckedProgram,
    target: &Formula,
    commands: &[Command],
    context: &dyn ContextView,
) -> Result<Vec<Graph>, String> {
    let goal_parts = crate::learning::knowledge::fragments(target);
    let mut used = vec![false; commands.len()];
    let mut pending = vec![
        commands
            .len()
            .checked_sub(1)
            .ok_or("peer program seal missing")?,
    ];
    while let Some(position) = pending.pop() {
        if std::mem::replace(&mut used[position], true) {
            continue;
        }
        for input in commands[position].operands() {
            let index = usize::try_from(input).map_err(|_| "peer program operand width")?;
            if index >= position {
                return Err("peer program operand order differs".into());
            }
            pending.push(index);
        }
    }
    let mut recent = VecDeque::new();
    let mut graphs = crate::learning::search::scope::program_graphs(target, commands)?;
    let mut bytes = graphs.iter().map(Graph::work_bytes).sum::<usize>();
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
            .map_err(|error| error.to_string())?
            .ok_or("checked peer program citation missing")?;
        if header.canonical_length() > crate::resources::limits().proof_bytes {
            continue;
        }
        let formula = context
            .proof_formula(header, header.canonical_length())
            .map_err(|error| error.to_string())?
            .ok_or("checked peer program citation formula missing")?
            .into_owned();
        if &formula != target {
            available.push((id, formula));
        }
    }
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
                            consequences: vec![formula.clone()],
                        })
                        .collect(),
                    expert,
                };
                let encoded = match Graph::encode(&decision) {
                    Ok(graph) => Some(graph),
                    Err(error) if error == "formula_graph_capacity" => {
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
                    Err(error) => return Err(error),
                };
                if let Some(mut graph) = encoded {
                    graph.binding = crate::learning::digest(&(position, cited.as_bytes()));
                    bytes = bytes
                        .checked_add(graph.work_bytes())
                        .ok_or("peer program graph work overflow")?;
                    if bytes > MODEL_REQUIREMENTS.work_bytes / 16 {
                        return Err("peer program graph work capacity".into());
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
            && let Some(mut graph) = checked_mp(
                target,
                &goal_parts,
                recent
                    .iter()
                    .map(|(index, formula, rule)| (*index, formula, *rule)),
                (*premise as usize, *implication as usize),
            )?
        {
            graph.binding = crate::learning::digest(&(position, &graph.binding));
            bytes = bytes
                .checked_add(graph.work_bytes())
                .ok_or("peer program graph work overflow")?;
            if bytes > MODEL_REQUIREMENTS.work_bytes / 16 {
                return Err("peer program graph work capacity".into());
            }
            graphs.push(graph);
        }
        if let Some(formula) = engine
            .proved_formula(position as u64)
            .map_err(|error| error.to_string())?
        {
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
    Ok(graphs)
}
