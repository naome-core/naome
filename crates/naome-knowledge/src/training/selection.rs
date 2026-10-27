use super::*;
use crate::{object::CandidatePayload, structure::Features};
use naome_checker::ContextView;

struct Loaded {
    example: Example,
    features: Features,
    rules: [bool; signals::RULES],
    cost: usize,
}

enum Omission {
    Unsupported,
    OtherSplit,
}

fn load(graph: &Graph, root: ArtifactId) -> Result<Result<Loaded, Omission>, Error> {
    let mut stack = vec![(root, false)];
    let mut seen = BTreeSet::new();
    let mut objects = BTreeMap::new();
    let mut ordered = Vec::new();
    let mut memory = Vec::new();
    let mut bytes = 0usize;
    let mut cost = 0usize;
    let mut rules = [false; signals::RULES];
    let mut target = None;
    while let Some((id, ready)) = stack.pop() {
        if ready {
            ordered.push(
                objects
                    .remove(&id)
                    .ok_or("training dependency order differs")?,
            );
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > crate::resources::limits().closure_objects {
            return Ok(Err(Omission::Unsupported));
        }
        let header = graph.checked_context().artifact_proof_header(id)?;
        let length = if let Some(header) = header {
            header.canonical_length()
        } else if let Some(definition) = graph.checked_context().artifact_definition_id(id)? {
            graph
                .checked_context()
                .definition_canonical_length(definition)?
                .unwrap_or(0)
        } else {
            return Err("training closure is not checked".into());
        };
        bytes = bytes
            .checked_add(length)
            .ok_or("training closure byte overflow")?;
        if bytes > crate::resources::limits().closure_bytes
            || length > crate::resources::limits().proof_bytes
        {
            return Ok(Err(Omission::Unsupported));
        }
        memory.push(crate::resources::MemoryLease::acquire(
            length
                .checked_mul(8)
                .and_then(|n| n.checked_add(4096))
                .ok_or("training working-set overflow")?,
        )?);
        let envelope = graph.object(id)?.ok_or("training checked object missing")?;
        // Programs require streamed model targets, outside this bounded native
        // certificate interface. Do not mislabel a manifest as a proof program.
        if envelope.payload.starts_with("ff") {
            return Ok(Err(Omission::Unsupported));
        }
        let candidate = envelope.clone().prepare_retained()?;
        if let CandidatePayload::Proof(normal) = &candidate.payload {
            let metadata = match describe(graph, id) {
                Ok(Some(metadata)) => metadata,
                Ok(None) => return Ok(Err(Omission::Unsupported)),
                Err(error) => return Err(error),
            };
            let (_, statement, question) = metadata.compile()?;
            if partition(&question) != Partition::Training {
                return Ok(Err(Omission::OtherSplit));
            }
            signals::rules(normal.certificate().steps(), &mut rules);
            cost = cost.saturating_add(normal.certificate().steps().len());
            if id == root {
                let positive = question
                    .positive_target()
                    .encode_canonical()
                    .map_err(|e| e.to_string())?;
                let positive = naome_proof::StatementId::of_canonical_formula(&positive)
                    .ok_or("training target identity width")?;
                target = Some((question, statement != positive));
            }
        }
        if cost > crate::resources::limits().closure_steps {
            return Ok(Err(Omission::Unsupported));
        }
        let dependencies = candidate.dependencies.iter().copied().collect::<Vec<_>>();
        objects.insert(id, envelope);
        stack.push((id, true));
        stack.extend(dependencies.into_iter().rev().map(|id| (id, false)));
    }
    let Some((question, refuted)) = target else {
        return Ok(Err(Omission::Unsupported));
    };
    let proof = ordered.pop().ok_or("training target closure is empty")?;
    let features = Features::of(&question);
    Ok(Ok(Loaded {
        example: Example {
            input: Problem {
                question: question.source().into(),
                context: ordered,
            },
            target: Target { proof, refuted },
            _memory: memory,
            provenance: Provenance {
                resolution: crate::hex(question.resolution_id()),
                structural_group: group(&question),
                proof_rules: signals::NAMES
                    .iter()
                    .zip(rules)
                    .filter_map(|(name, present)| present.then_some((*name).to_owned()))
                    .collect(),
                priority: 1,
            },
        },
        features,
        rules,
        cost,
    }))
}

pub(super) fn select(graph: &Graph, request: &Request) -> Result<Batch, Error> {
    crate::resources::require_work_admission()?;
    request.solver.validate()?;
    let limits = crate::resources::active_limits();
    if request.scan == 0
        || request.scan > limits.id_page.min(16)
        || request.take == 0
        || request.take > request.scan
        || request.training_roots.len() > limits.question_page
    {
        return Err(Error::InputLimit("training selection page limit"));
    }
    let _working = crate::resources::MemoryLease::acquire(limits.question_cache_bytes)?;
    let mut signals = profile(graph, request)?;
    let after = request
        .after
        .as_deref()
        .map(crate::object::id_bytes)
        .transpose()?
        .map(ArtifactId::from_bytes);
    let ids = graph.ids_page(after, request.scan)?;
    let mut counts = Counts {
        scanned: ids.len(),
        ..Counts::default()
    };
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for id in &ids {
        let metadata = match describe(graph, *id) {
            Ok(Some(metadata)) => metadata,
            Ok(None) => {
                counts.unsupported += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if !canonical(graph, *id)? {
            counts.duplicates += 1;
            continue;
        }
        let (_, _, target) = metadata.compile()?;
        if partition(&target) != Partition::Training {
            counts.reserved += 1;
            continue;
        }
        if !seen.insert(*target.resolution_id()) {
            counts.duplicates += 1;
            continue;
        }
        match load(graph, *id)? {
            Ok(example) => candidates.push(example),
            Err(Omission::OtherSplit) => counts.dependent_on_other_split += 1,
            Err(Omission::Unsupported) => counts.unsupported += 1,
        }
    }
    counts.eligible = candidates.len();
    let mut random = crate::sampling::Random::new(request.seed);
    let mut examples = Vec::new();
    let mut selected_groups = BTreeMap::<String, u64>::new();
    while !candidates.is_empty() && examples.len() < request.take {
        let weighted = candidates
            .iter()
            .map(|candidate| {
                let group = &candidate.example.provenance.structural_group;
                let weight =
                    signals.priority(&candidate.features, &candidate.rules, candidate.cost)
                        / (1 + 4 * selected_groups.get(group).copied().unwrap_or(0));
                (group.clone(), weight.max(1))
            })
            .collect::<Vec<_>>();
        let index = crate::sampling::choose(&mut random, &weighted, request.random_only);
        let mut candidate = candidates.remove(index);
        candidate.example.provenance.priority =
            signals.priority(&candidate.features, &candidate.rules, candidate.cost);
        signals.covered(&candidate.features, &candidate.rules);
        *selected_groups
            .entry(candidate.example.provenance.structural_group.clone())
            .or_default() += 1;
        examples.push(candidate.example);
    }
    Ok(Batch {
        solver: request.solver.clone(),
        knowledge: crate::hex(&graph.content_root()),
        request_digest: request_digest(request)?,
        next_after: (ids.len() == request.scan)
            .then(|| ids.last().map(|id| crate::hex(id.as_bytes())))
            .flatten(),
        counts,
        examples,
    })
}

pub(super) fn profile(graph: &Graph, request: &Request) -> Result<Signals, Error> {
    let mut signals = Signals::new(graph, request)?;
    let mut trained = BTreeSet::new();
    for root in &request.training_roots {
        let target = question(graph, root)?;
        if partition(&target) != Partition::Training {
            return Err("reported training root belongs to another split".into());
        }
        if trained.insert(*target.resolution_id()) {
            let root = ArtifactId::from_bytes(crate::object::id_bytes(root)?);
            let example = load(graph, root)?
                .map_err(|_| Error::from("reported training closure is not eligible"))?;
            signals.covered(&example.features, &example.rules);
        }
    }
    Ok(signals)
}

pub(super) fn canonical(graph: &Graph, id: ArtifactId) -> Result<bool, Error> {
    let Some(header) = graph.checked_context().artifact_proof_header(id)? else {
        return Ok(false);
    };
    Ok(graph
        .checked_context()
        .statement_header(header.statement_id())?
        .is_some_and(|witness| ArtifactId::from_proof_id(witness.proof_id()) == id))
}
