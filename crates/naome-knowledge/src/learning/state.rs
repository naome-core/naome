//! Parent-owned replay, provenance and curriculum progress.
use super::*;
// This process-local cache contains only exact inputs already checked by the
// unchanged native kernel. It is never serialized; reopening rechecks all data.
std::thread_local! { static VERIFIED: std::cell::RefCell<std::collections::BTreeSet<String>> = const { std::cell::RefCell::new(std::collections::BTreeSet::new()) }; }
fn validate_example(e: &Example) -> Result<(), String> {
    let key = digest(e);
    if VERIFIED.with(|known| known.borrow().contains(&key)) {
        return Ok(());
    }
    if e.job == 0 {
        return Err("learning example lacks an owned job".into());
    }
    let q = CompiledQuestion::compile(&e.question).map_err(|e| e.to_string())?;
    if curriculum::owned::case(&e.question).is_none() {
        return Err("learning example outside eligible dependency split".into());
    }
    crate::object::id_bytes(&e.proof_id)?;
    if let Origin::Peer { artifact, peer } = &e.origin {
        crate::object::id_bytes(artifact)?;
        let parsed: libp2p::PeerId = peer.parse().map_err(|_| "peer replay origin syntax")?;
        if parsed.to_string() != *peer {
            return Err("peer replay origin encoding".into());
        }
    }
    if let search::Tree::Stored {
        steps,
        bytes,
        ref binding,
    } = e.tree
    {
        return if bytes <= REPLAY * 8 * 1024
            && crate::object::id_bytes(binding).is_ok()
            && steps > 0
            && steps <= crate::resources::limits().closure_steps.min(16_384)
        {
            Ok(())
        } else {
            Err("peer replay pointer differs".into())
        };
    }
    let target = if e.refuted {
        q.refuted_target().clone()
    } else {
        q.proved_target().clone()
    };
    let (term, _) = search::compile(&target, &e.tree)?;
    let verified = proof::verify(&term, &target)?;
    if crate::hex(verified.native_id.as_bytes()) != e.proof_id {
        return Err("learning proof provenance differs".into());
    }
    VERIFIED.with(|known| {
        let mut known = known.borrow_mut();
        if known.len() >= 64 {
            known.pop_first();
        }
        known.insert(key);
    });
    Ok(())
}
pub(super) fn proof_steps(
    target: &naome_foundation::Formula,
    tree: &search::Tree,
) -> Result<usize, String> {
    if let search::Tree::Stored { steps, .. } = tree {
        return Ok(*steps);
    }
    let checked = search::core::checked(target, tree)?.2;
    Ok(checked.certificate.steps().len()
        + checked
            .lemmas
            .iter()
            .map(|c| c.steps().len())
            .sum::<usize>())
}
impl State {
    pub fn sample_counts(&self) -> (u64, u64) {
        (self.local_examples, self.peer_examples)
    }
    pub fn replay_sources(&self) -> impl Iterator<Item = &Example> {
        self.replay.iter().filter(|e| e.evidence_job().is_some())
    }
    pub fn examples(&self) -> impl Iterator<Item = &Example> {
        self.replay.iter().chain(&self.anchors)
    }
    pub fn blobs(&self) -> impl Iterator<Item = &Blob> {
        self.model.blobs()
    }
    pub fn fresh() -> Self {
        Self {
            model: Checkpoint::fresh(),
            definitions: Vec::new(),
            definition_uses: BTreeMap::new(),
            knowledge: Vec::new(),
            replay: Vec::new(),
            anchors: Vec::new(),
            accepted: 0,
            epoch: 0,
            draws: 0,
            trained: 0,
            attempted: 0,
            peer_cursor: 0,
            local_examples: 0,
            peer_examples: 0,
            promotions: 0,
            rejections: 0,
            statistics: BTreeMap::new(),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        self.model.validate()?;
        knowledge::validate(&self.knowledge)?;
        let _ = definitions::context(&self.definitions)?;
        if self.definition_uses.keys().any(|id| {
            !self
                .definitions
                .iter()
                .any(|e| e.address().is_ok_and(|a| crate::hex(a.as_bytes()) == *id))
        }) {
            return Err("definition utility lacks a checked meaning".into());
        }
        if self.anchors.len() > 4
            || self.replay.len() > REPLAY
            || self.accepted > self.epoch
            || self.trained > self.epoch
            || self.attempted > self.epoch
            || self.local_examples.checked_add(self.peer_examples) != Some(self.accepted)
            || self
                .replay
                .iter()
                .filter_map(|e| {
                    if let search::Tree::Stored { bytes, .. } = e.tree {
                        Some(bytes)
                    } else {
                        None
                    }
                })
                .sum::<usize>()
                > REPLAY * 8 * 1024
            || self.statistics.len() > 64
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len()
                > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
        {
            return Err("local learning state capacity or sequence".into());
        }
        let mut strategies = BTreeMap::new();
        for e in self.replay.iter().chain(&self.anchors) {
            validate_example(e)?;
        }
        for e in &self.replay {
            let q = CompiledQuestion::compile(&e.question).map_err(|e| e.to_string())?;
            let count = strategies
                .entry(crate::hex(q.resolution_id()))
                .or_insert(0usize);
            *count += 1;
            if *count > 2 {
                return Err("question replay strategy capacity".into());
            }
        }
        for s in self.statistics.values() {
            if s.successes > s.attempts || s.recent > 1_000_000 {
                return Err("learning statistics differ".into());
            }
        }
        Ok(())
    }
    pub fn remember_definition(&mut self, entry: definitions::Entry) -> Result<bool, String> {
        let _ = definitions::context(std::slice::from_ref(&entry))?;
        if self.definitions.contains(&entry) {
            return Ok(false);
        }
        let mut next = self.clone();
        while next.definitions.len() >= definitions::CAPACITY - 1
            || next
                .definitions
                .iter()
                .map(definitions::Entry::bytes)
                .sum::<usize>()
                + entry.bytes()
                > definitions::BYTES
        {
            if next.definitions.is_empty() {
                return Ok(false);
            }
            let index = next
                .definitions
                .iter()
                .enumerate()
                .min_by_key(|(i, e)| {
                    let id = crate::hex(e.address().expect("checked definition").as_bytes());
                    (next.definition_uses.get(&id).copied().unwrap_or(0), *i)
                })
                .map(|(i, _)| i)
                .expect("retained definition");
            let removed = next.definitions.remove(index);
            next.definition_uses
                .remove(&crate::hex(removed.address()?.as_bytes()));
        }
        next.definition_uses
            .insert(crate::hex(entry.address()?.as_bytes()), 0);
        next.definitions.push(entry);
        while serde_json::to_vec(&next).map_err(|e| e.to_string())?.len()
            > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
        {
            if next.replay.is_empty() {
                return Ok(false);
            }
            next.remove_replay();
        }
        next.validate()?;
        *self = next;
        Ok(true)
    }
    pub fn remember_theorem(&mut self, entry: knowledge::Entry) -> Result<bool, String> {
        let verified = entry.verified()?;
        let q = CompiledQuestion::from_formula(verified.target).map_err(|e| e.to_string())?;
        if !Self::eligible(q.source()) || self.knowledge.contains(&entry) {
            return Ok(false);
        }
        let mut next = self.clone();
        while next.knowledge.len() >= knowledge::CAPACITY
            || next.knowledge.iter().map(|e| e.packet.len()).sum::<usize>() + entry.packet.len()
                > knowledge::BYTES
        {
            if next.knowledge.is_empty() {
                return Ok(false);
            }
            next.knowledge.remove(0);
        }
        next.knowledge.push(entry);
        // Derived hints do not evict replay or expand the existing journal cap.
        if crate::checkpoint::encode(&next)?.len()
            > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
        {
            return Ok(false);
        }
        next.validate()?;
        *self = next;
        Ok(true)
    }
    pub fn job(&self) -> Job {
        Job {
            evidence: Vec::new(),
            training: false,
            base_hash: digest(self),
            base: self.clone(),
            progress: None,
            written: Vec::new(),
            io_bytes: 0,
            io_operations: 0,
        }
    }
    pub fn question(&self, cursor: u64) -> String {
        let cases: Vec<_> = curriculum::learning_cases().collect();
        let mut families: BTreeMap<&str, Vec<&curriculum::Case>> = BTreeMap::new();
        for q in cases {
            families
                .entry(curriculum::statistics_key(q))
                .or_default()
                .push(q);
        }
        // Two easy lanes preserve known prerequisites, two frontier lanes
        // revisit partial success/search exhaustion, two explore unseen work.
        let lane = cursor % 6;
        let easy_available = self.statistics.values().any(|s| s.successes > 0);
        let frontier_available = self
            .statistics
            .values()
            .any(|s| s.attempts > s.successes && (s.successes > 0 || s.failures[0] > 0));
        let chosen = families
            .iter()
            .max_by(|(a, _), (b, _)| {
                let score = |family: &&str| {
                    let s = self.statistics.get(*family).cloned().unwrap_or_default();
                    let opportunity = match lane {
                        0 | 1 => {
                            if s.successes > 0 {
                                2. + f64::from(s.recent) / 1e6
                            } else {
                                f64::from(!easy_available)
                            }
                        }
                        2 | 3 => {
                            if s.attempts > s.successes && (s.successes > 0 || s.failures[0] > 0) {
                                2. + 1. - f64::from(s.recent) / 1e6
                            } else {
                                f64::from(!frontier_available)
                            }
                        }
                        _ => 1.,
                    };
                    opportunity / (1. + s.selections as f64).sqrt()
                };
                score(a).total_cmp(&score(b)).then_with(|| b.cmp(a))
            })
            .expect("learning families");
        let mut candidates = chosen.1.clone();
        let statistics = self.statistics.get(*chosen.0).cloned().unwrap_or_default();
        if statistics.failures[1] + statistics.failures[2] + statistics.failures[4]
            > statistics.failures[0]
        {
            // Representation/certificate pressure calls for smaller formulas,
            // not a fresh retry allowance for an exhausted original job.
            candidates.sort_by_key(|c| (c.source.len(), &c.id));
        } else {
            candidates.sort_by_key(|c| &c.id);
        }
        candidates[statistics.selections as usize % candidates.len()]
            .source
            .clone()
    }
    pub fn eligible(question: &str) -> bool {
        curriculum::owned::case(question).is_some()
    }
    pub fn needs_training(&self) -> bool {
        if self.replay.len() < 8 || self.epoch.saturating_sub(self.attempted) < 4 {
            return false;
        }
        let groups = self
            .replay
            .iter()
            .filter_map(|e| curriculum::owned::case(&e.question))
            .map(|case| case.dependency)
            .collect::<std::collections::BTreeSet<_>>();
        groups.len() >= 3
    }
    pub fn learning_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn attempted(&mut self, epoch: u64) {
        self.attempted = self.attempted.max(epoch.min(self.epoch));
    }
    pub fn observe(&mut self, question: &str, solved: Option<bool>) {
        let Ok(q) = CompiledQuestion::compile(question) else {
            return;
        };
        if let Some(case) = curriculum::learning(&crate::hex(q.resolution_id())) {
            let s = self
                .statistics
                .entry(curriculum::statistics_key(case).to_owned())
                .or_default();
            if let Some(success) = solved {
                s.attempts = s.attempts.saturating_add(1);
                s.recent = (4 * s.recent + 1_000_000 * u32::from(success)) / 5;
                s.successes = s.successes.saturating_add(u64::from(success));
            } else {
                s.selections = s.selections.saturating_add(1);
            }
        }
    }
    pub fn observe_result(&mut self, question: &str, solved: bool, diagnostic: &str) {
        self.observe(question, Some(solved));
        if !solved
            && let Ok(q) = CompiledQuestion::compile(question)
            && let Some(case) = curriculum::learning(&crate::hex(q.resolution_id()))
        {
            let reason = if diagnostic.contains("search_budget") {
                0
            } else if diagnostic.contains("graph") || diagnostic.contains("decision_capacity") {
                1
            } else if diagnostic.contains("fact_resource") {
                2
            } else if diagnostic.contains("calculus") {
                3
            } else if diagnostic.contains("certificate") {
                4
            } else {
                5
            };
            let s = self
                .statistics
                .entry(curriculum::statistics_key(case).to_owned())
                .or_default();
            s.failures[reason] = s.failures[reason].saturating_add(1);
        }
    }
    pub fn qualify(&mut self, native: &Job) -> bool {
        let Some(p) = &native.progress else {
            return false;
        };
        if p.unit != native.units()
            || native.units() == 1
            || self.model != native.base.model
            || self.trained != native.base.trained
        {
            return false;
        }
        self.draws = self.draws.max(p.rng);
        self.model = p.model.clone();
        self.trained = p.trained;
        self.promotions = self
            .promotions
            .saturating_add(p.promotions - native.base.promotions);
        self.rejections = self
            .rejections
            .saturating_add(p.rejections - native.base.rejections);
        true
    }
    fn remove_replay(&mut self) {
        let mut counts = BTreeMap::new();
        for e in &self.replay {
            let case = curriculum::owned::case(&e.question).expect("eligible replay");
            let key = (
                matches!(e.origin, Origin::Peer { .. }),
                case.dependency.clone(),
            );
            *counts.entry(key).or_insert(0usize) += 1;
        }
        let index = self
            .replay
            .iter()
            .enumerate()
            .max_by_key(|(index, e)| {
                let c = curriculum::owned::case(&e.question).expect("eligible replay");
                let peer = matches!(e.origin, Origin::Peer { .. });
                let origin_count = self
                    .replay
                    .iter()
                    .filter(|r| matches!(r.origin, Origin::Peer { .. }) == peer)
                    .count();
                (
                    origin_count,
                    counts[&(peer, c.dependency.clone())],
                    std::cmp::Reverse(*index),
                )
            })
            .map_or(0, |(index, _)| index);
        self.replay.remove(index);
    }
    pub(super) fn training_pool(&self, evidence: &[Evidence]) -> Result<pool::Pool, String> {
        let mut pool = pool::Pool::default();
        for e in &self.replay {
            let q = CompiledQuestion::compile(&e.question).map_err(|e| e.to_string())?;
            let case = curriculum::owned::case(&e.question).ok_or("training split differs")?;
            let target = if e.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            let tree = if matches!(e.tree, search::Tree::Stored { .. }) {
                let source = evidence
                    .iter()
                    .find(|source| source.job == e.job && source.proof_id == e.proof_id)
                    .ok_or("peer replay snapshot missing")?;
                source.trace.clone()
            } else {
                e.tree.clone()
            };
            let (core, _, verified) = search::core::checked(target, &tree)?;
            if crate::hex(verified.native_id.as_bytes()) != e.proof_id {
                return Err("peer replay snapshot proof differs".into());
            }
            let graphs = search::compile(target, &core)?.1;
            let proof = crate::hex(verified.native_id.as_bytes());
            pool.add(
                matches!(e.origin, Origin::Peer { .. }),
                &case.dependency,
                &case.family,
                &proof,
                graphs,
            )?;
        }
        Ok(pool)
    }
    #[cfg(test)]
    pub(super) fn training_graphs(&self) -> Result<Vec<graph::Graph>, String> {
        Ok(self.training_pool(&[])?.graphs().to_vec())
    }
    #[cfg(test)]
    pub fn accept(&mut self, example: Example) -> Result<bool, String> {
        let id = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
        let unique = !self.examples().any(|e| {
            CompiledQuestion::compile(&e.question)
                .is_ok_and(|q| q.resolution_id() == id.resolution_id())
        });
        self.consider(example, unique)
    }
    /// The journal supplies lifetime question/proof history. Replay selection
    /// never creates a fresh unique-sample count or resource allowance.
    pub fn consider(&mut self, mut example: Example, unique: bool) -> Result<bool, String> {
        if self.examples().any(|e| e.proof_id == example.proof_id) {
            return Ok(false);
        }
        let q = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
        if curriculum::owned::case(&example.question).is_none() {
            return Ok(false);
        }
        validate_example(&example)?;
        let target = if example.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let (_, _, checked) = search::core::checked(target, &example.tree)?;
        let native_steps = checked.certificate.steps().len()
            + checked
                .lemmas
                .iter()
                .map(|c| c.steps().len())
                .sum::<usize>();
        let (_, graphs) = search::compile(target, &example.tree)?;
        if graphs.is_empty() {
            return Ok(false);
        }
        let previous = self
            .replay
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                CompiledQuestion::compile(&e.question)
                    .is_ok_and(|old| old.resolution_id() == q.resolution_id())
            })
            .collect::<Vec<_>>();
        let mut replaced = None;
        if !previous.is_empty() {
            let mut witnessed = std::collections::BTreeSet::new();
            let mut costs = Vec::new();
            for (i, e) in &previous {
                costs.push((*i, proof_steps(target, &e.tree)?));
                if matches!(e.tree, search::Tree::Stored { .. }) {
                    continue;
                }
                for g in search::compile(target, &e.tree)?.1 {
                    for action in &g.successes {
                        witnessed.insert((g.key(), *action));
                    }
                }
            }
            let novel = graphs.iter().any(|g| {
                g.successes
                    .iter()
                    .any(|a| !witnessed.contains(&(g.key(), *a)))
            });
            let worst = *costs
                .iter()
                .max_by_key(|(i, c)| (*c, std::cmp::Reverse(*i)))
                .expect("retained strategy");
            if !novel && native_steps >= worst.1 {
                return Ok(false);
            }
            if previous.len() >= 2 {
                replaced = Some(worst.0);
            }
        }
        let mut next = self.clone();
        if let Some(index) = replaced {
            next.replay.remove(index);
        }
        if unique {
            // Count new, checker-admitted goal uses of an already available
            // meaning. Its initial creation and repeated references do not win
            // future utility merely by inflating a certificate.
            let mut used = checked
                .lemmas
                .iter()
                .chain(std::iter::once(&checked.certificate))
                .flat_map(|certificate| certificate.steps().iter())
                .flat_map(naome_proof::ProofStep::definition_references)
                .collect::<std::collections::BTreeSet<_>>();
            loop {
                let before = used.len();
                for entry in &checked.definitions {
                    let certificate = entry.certificate()?;
                    if used.contains(&certificate.definition_id()) {
                        used.extend(certificate.body().definition_references());
                    }
                }
                if used.len() == before {
                    break;
                }
            }
            for entry in definitions::selected(&example.tree)? {
                if used.contains(&entry.certificate()?.definition_id()) {
                    let id = crate::hex(entry.address()?.as_bytes());
                    if let Some(uses) = next.definition_uses.get_mut(&id) {
                        *uses = uses.saturating_add(1);
                    }
                }
            }
            match &example.origin {
                Origin::Local => {
                    next.local_examples = next
                        .local_examples
                        .checked_add(1)
                        .ok_or("local learning count overflow")?
                }
                Origin::Peer { .. } => {
                    next.peer_examples = next
                        .peer_examples
                        .checked_add(1)
                        .ok_or("peer learning count overflow")?
                }
            }
            next.accepted = next
                .accepted
                .checked_add(1)
                .ok_or("learning sequence overflow")?;
        }
        next.epoch = next
            .epoch
            .checked_add(1)
            .ok_or("learning revision overflow")?;
        let trace_bytes = serde_json::to_vec(&example.tree)
            .map_err(|e| e.to_string())?
            .len();
        if trace_bytes > REPLAY * 8 * 1024 {
            return Ok(false);
        }
        if matches!(example.origin, Origin::Peer { .. }) || trace_bytes > 2048 {
            example.tree = search::Tree::Stored {
                steps: native_steps,
                bytes: trace_bytes,
                binding: digest(&example.tree),
            };
        }
        if next.anchors.len() < 4
            && !next.anchors.iter().any(|old| {
                curriculum::owned::case(&old.question).is_some_and(|old| {
                    curriculum::owned::case(&example.question)
                        .is_some_and(|new| old.dependency == new.dependency)
                })
            })
            && crate::checkpoint::encode(&next.anchors)?.len()
                + crate::checkpoint::encode(&example)?.len()
                < 8 * 1024
        {
            next.anchors.push(example.clone());
        }
        next.replay.push(example);
        while next.replay.len() > REPLAY
            || next
                .replay
                .iter()
                .filter_map(|e| {
                    if let search::Tree::Stored { bytes, .. } = e.tree {
                        Some(bytes)
                    } else {
                        None
                    }
                })
                .sum::<usize>()
                > REPLAY * 8 * 1024
        {
            next.remove_replay();
        }
        while crate::checkpoint::encode(&next)?.len()
            > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
            && next.replay.len() > 1
        {
            next.remove_replay();
        }
        if crate::checkpoint::encode(&next)?.len()
            > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
        {
            return Ok(false);
        }

        if digest(&next.replay) == digest(&self.replay) {
            return Ok(false);
        }
        next.validate()?;
        *self = next;
        Ok(true)
    }
}
