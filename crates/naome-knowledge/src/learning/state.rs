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

#[cfg(test)]
mod verification_tests;
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
    /// Complete owned inputs available to every method. Rehearsal selects existing
    /// own/peer anchor proofs, never development outcomes or new truth labels.
    pub fn training_sources(&self) -> impl Iterator<Item = &Example> {
        let mut jobs = std::collections::BTreeSet::new();
        self.replay
            .iter()
            .chain(self.anchors.iter())
            .filter(move |e| jobs.insert(e.job))
    }
    fn training_trace_bytes(&self) -> usize {
        self.training_sources()
            .filter_map(|e| {
                if let search::Tree::Stored { bytes, .. } = e.tree {
                    Some(bytes)
                } else {
                    None
                }
            })
            .sum()
    }
    pub fn examples(&self) -> impl Iterator<Item = &Example> {
        self.replay.iter().chain(&self.anchors)
    }
    pub fn meta_experiences(&self) -> impl Iterator<Item = &meta::Experience> {
        self.meta.memory.iter()
    }
    pub fn meta_updates(&self) -> u64 {
        self.meta.model.updates
    }
    pub fn blobs(&self) -> impl Iterator<Item = &Blob> {
        self.model.blobs().chain(self.meta.model.blobs())
    }
    pub fn fresh() -> Self {
        let model = Checkpoint::fresh();
        let feedback = crate::training::ability::Feedback::fresh(digest(&model));
        Self {
            model,
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
            feedback,
            preparation: Preparation::Meta,
            meta: meta::State::fresh(),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        self.model.validate()?;
        self.meta.validate()?;
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
            || self.training_trace_bytes() > REPLAY * 8 * 1024
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
        self.feedback.validate()?;
        if self.feedback.checkpoint != digest(&self.model) {
            return Err("learning feedback model differs".into());
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
        let q = match CompiledQuestion::from_formula(verified.target) {
            Ok(question) => question,
            // Stored mathematics can exceed the bounded neural question view.
            // Declining a derived hint must not halt the accepted-store owner.
            Err(
                naome_authoring::QuestionError::Limit(_) | naome_authoring::QuestionError::Overflow,
            ) => return Ok(false),
            Err(error) => return Err(error.to_string()),
        };
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
    pub(crate) fn search_budget(&self) -> u32 {
        if self.rejections % 3 == 2 { 256 } else { 128 }
    }
    pub(crate) fn feedback_stamp(&self) -> (&str, u64) {
        (&self.feedback.checkpoint, self.feedback.revision)
    }
    pub(crate) fn feedback(&self) -> crate::training::ability::Feedback {
        self.feedback.clone()
    }
    #[cfg(test)]
    pub fn observe(&mut self, question: &str, solved: Option<bool>) {
        self.observe_attempt(question, solved, 0, 128);
    }
    pub(crate) fn observe_attempt(
        &mut self,
        question: &str,
        solved: Option<bool>,
        micros: u64,
        budget: u32,
    ) {
        if !Self::eligible(question) {
            return;
        }
        let Ok(q) = CompiledQuestion::compile(question) else {
            return;
        };
        self.feedback.attempts.observe(&q, budget, solved, micros);
        self.feedback.revision = self.feedback.revision.saturating_add(1);
    }
    pub fn observe_result(
        &mut self,
        question: &str,
        solved: bool,
        diagnostic: &str,
        micros: u64,
        budget: u32,
    ) {
        self.observe_attempt(
            question,
            crate::training::ability::completion(solved, diagnostic),
            micros,
            budget,
        );
    }
    pub fn qualify(&mut self, native: &Job) -> bool {
        let Some(p) = &native.progress else {
            return false;
        };
        if p.unit != native.units()
            || native.units() == 1
            || self.model != native.base.model
            || self.trained != native.base.trained
            || self.meta.model != native.base.meta.model
            || self.meta.draw != native.base.meta.draw
        {
            return false;
        }
        let mut next = self.clone();
        if let Some(plan) = &p.plan {
            next.meta.draw = plan.draw;
        }
        if let Some(update) = &p.meta_update {
            next.meta.model = update.model.clone();
            next.meta.draw = update.draw;
            next.meta.trials = next.meta.trials.saturating_add(1);
            next.meta.memory.push(update.experience.clone());
            if next.meta.memory.len() > meta::MEMORY {
                next.meta.memory.remove(0);
            }
        }
        next.draws = next.draws.max(p.rng);
        next.model = p.model.clone();
        let key = digest(&next.model);
        let observations = if p.promotions > native.base.promotions {
            &p.development_after
        } else {
            &p.development_before
        };
        if observations.checkpoint != key {
            return false;
        }
        if key != next.feedback.checkpoint {
            next.feedback.attempts = crate::training::ability::Profile::new(key.clone());
        }
        next.feedback.checkpoint = key.clone();
        if !observations.is_empty() || next.feedback.development.checkpoint != key {
            next.feedback.development = observations.clone();
            next.feedback.regressions = p.regressions;
            next.feedback.gains = p.gains;
        }
        next.feedback.revision = next.feedback.revision.saturating_add(1);
        next.trained = p.trained;
        next.promotions = next
            .promotions
            .saturating_add(p.promotions - native.base.promotions);
        next.rejections = next
            .rejections
            .saturating_add(p.rejections - native.base.rejections);
        if next.compact().is_err() {
            return false;
        }
        *self = next;
        true
    }
    /// Keep bounded working data within the installed byte budget after parent
    /// metadata grows. Earlier anchors, checked meanings, knowledge, lifetime
    /// counts and the selected model/Adam pair remain intact. Durable source
    /// records, rather than the replay working set, own proof history.
    pub(crate) fn compact(&mut self) -> Result<(), String> {
        let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
        while crate::checkpoint::encode(self)?.len() > capacity
            || self.training_trace_bytes() > REPLAY * 8 * 1024
        {
            if self.replay.is_empty() {
                return Err("fixed learning snapshot exceeds working byte capacity".into());
            }
            self.remove_replay();
        }
        Ok(())
    }
    /// A matched research context reserves the same upper-state headroom in
    /// every arm before any lower update. The ordinary State cap still applies.
    #[cfg(test)]
    pub(super) fn compact_with_meta_headroom(&mut self, bytes: usize) -> Result<(), String> {
        let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
        let current = crate::checkpoint::encode(&self.meta)?.len();
        if current > bytes {
            return Err("meta context exceeds the frozen matched headroom".into());
        }
        while crate::checkpoint::encode(self)?.len() + bytes - current > capacity {
            if self.replay.is_empty() {
                return Err("matched meta context cannot retain a learning batch".into());
            }
            self.remove_replay();
        }
        self.validate()
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
    #[cfg(test)]
    pub(super) fn training_pool(&self, evidence: &[Evidence]) -> Result<pool::Pool, String> {
        self.training_pool_for(
            evidence,
            !matches!(self.preparation, Preparation::Balanced) && {
                #[cfg(test)]
                {
                    self.preparation != Preparation::ReferenceTargeted
                }
                #[cfg(not(test))]
                {
                    true
                }
            },
        )
    }
    pub(super) fn training_pool_for(
        &self,
        evidence: &[Evidence],
        rehearsal: bool,
    ) -> Result<pool::Pool, String> {
        let mut pool = pool::Pool::default();
        for e in self
            .training_sources()
            .filter(|e| rehearsal || self.replay.iter().any(|r| r.job == e.job))
        {
            let q = CompiledQuestion::compile(&e.question).map_err(|e| e.to_string())?;
            let case = curriculum::owned::case(&e.question).ok_or("training split differs")?;
            let target = if e.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            let tree = e.trajectory(evidence)?;
            let (core, _, verified) = search::core::checked(target, tree)?;
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
        // The original journal owns complete trajectories. Keep each inline
        // trace within its share of the existing small working snapshot so
        // checked knowledge cannot evict the minimum diverse training batch.
        let inline_bytes =
            crate::resources::limits().closure_bytes.min(128 * 1024) / 4 / (2 * REPLAY);
        if matches!(example.origin, Origin::Peer { .. }) || trace_bytes > inline_bytes {
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
        while next.replay.len() > REPLAY || next.training_trace_bytes() > REPLAY * 8 * 1024 {
            if next.replay.is_empty() {
                return Ok(false);
            }
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
