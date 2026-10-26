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
    if curriculum::learning(&crate::hex(q.resolution_id())).is_none() {
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
impl State {
    pub fn sample_counts(&self) -> (u64, u64) {
        (self.local_examples, self.peer_examples)
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
            replay: Vec::new(),
            anchors: Vec::new(),
            accepted: 0,
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
        if self.anchors.len() > 4
            || self.replay.len() > REPLAY
            || self.trained > self.accepted
            || self.attempted > self.accepted
            || self.local_examples.checked_add(self.peer_examples) != Some(self.accepted)
            || self.statistics.len() > 64
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len()
                > crate::resources::limits().closure_bytes.min(128 * 1024) / 4
        {
            return Err("local learning state capacity or sequence".into());
        }
        for e in self.replay.iter().chain(&self.anchors) {
            validate_example(e)?;
        }
        for s in self.statistics.values() {
            if s.successes > s.attempts || s.recent > 1_000_000 || s.previous > 1_000_000 {
                return Err("learning statistics differ".into());
            }
        }
        Ok(())
    }
    pub fn job(&self) -> Job {
        Job {
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
        let cases: Vec<_> = curriculum::CORPUS
            .cases
            .iter()
            .filter(|q| !q.development)
            .collect();
        if cursor.is_multiple_of(4) {
            return cases[(cursor / 4) as usize % cases.len()].source.clone();
        }
        let mut families: BTreeMap<&str, Vec<&curriculum::Case>> = BTreeMap::new();
        for q in cases {
            families.entry(&q.dependency).or_default().push(q);
        }
        let chosen = families
            .iter()
            .max_by(|(a, _), (b, _)| {
                let score = |family: &&str| {
                    let s = self.statistics.get(*family).cloned().unwrap_or_default();
                    f64::from(s.recent.abs_diff(s.previous)) / 1_000_000.
                        + 1. / (1. + s.selections as f64).sqrt()
                };
                score(a).total_cmp(&score(b)).then_with(|| b.cmp(a))
            })
            .expect("learning families")
            .1;
        chosen[(cursor / 4) as usize % chosen.len()].source.clone()
    }
    pub fn eligible(question: &str) -> bool {
        CompiledQuestion::compile(question)
            .ok()
            .is_some_and(|q| curriculum::learning(&crate::hex(q.resolution_id())).is_some())
    }
    pub fn needs_training(&self) -> bool {
        self.accepted > self.attempted
    }
    pub fn learning_epoch(&self) -> u64 {
        self.accepted
    }
    pub fn attempted(&mut self, epoch: u64) {
        self.attempted = self.attempted.max(epoch.min(self.accepted));
    }
    pub fn observe(&mut self, question: &str, solved: Option<bool>) {
        let Ok(q) = CompiledQuestion::compile(question) else {
            return;
        };
        if let Some(case) = curriculum::learning(&crate::hex(q.resolution_id())) {
            let s = self.statistics.entry(case.dependency.clone()).or_default();
            if let Some(success) = solved {
                s.attempts = s.attempts.saturating_add(1);
                s.previous = s.recent;
                s.recent = (4 * s.recent + 1_000_000 * u32::from(success)) / 5;
                s.successes = s.successes.saturating_add(u64::from(success));
            } else {
                s.selections = s.selections.saturating_add(1);
            }
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
        self.model = p.state.model.clone();
        self.trained = p.state.trained;
        self.promotions = self
            .promotions
            .saturating_add(p.state.promotions - native.base.promotions);
        self.rejections = self
            .rejections
            .saturating_add(p.state.rejections - native.base.rejections);
        true
    }
    fn remove_replay(&mut self) {
        let mut counts = BTreeMap::new();
        for e in &self.replay {
            let id = CompiledQuestion::compile(&e.question).expect("verified replay question");
            let case =
                curriculum::learning(&crate::hex(id.resolution_id())).expect("eligible replay");
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
                let q = CompiledQuestion::compile(&e.question).expect("verified replay");
                let c =
                    curriculum::learning(&crate::hex(q.resolution_id())).expect("eligible replay");
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
    pub(super) fn training_graphs(&self) -> Result<Vec<graph::Graph>, String> {
        let mut strata: BTreeMap<bool, BTreeMap<(String, String), Vec<graph::Graph>>> =
            BTreeMap::new();
        for e in &self.replay {
            let q = CompiledQuestion::compile(&e.question).map_err(|e| e.to_string())?;
            let case = curriculum::learning(&crate::hex(q.resolution_id()))
                .ok_or("training split differs")?;
            let target = if e.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            let graphs = search::compile(target, &e.tree)?.1;
            if !graphs.is_empty() {
                strata
                    .entry(matches!(e.origin, Origin::Peer { .. }))
                    .or_default()
                    .entry((case.dependency.clone(), case.family.clone()))
                    .or_default()
                    .extend(graphs);
            }
        }
        let origins: Vec<_> = strata
            .values()
            .map(|groups| groups.values().collect::<Vec<_>>())
            .collect();
        let mut balanced = Vec::new();
        if !origins.is_empty() {
            for i in 0..256 {
                let origin = &origins[i % origins.len()];
                let family = (i / origins.len()) % origin.len();
                let pool = origin[family];
                let example = (i / origins.len() / origin.len()) % pool.len();
                balanced.push(pool[example].clone());
            }
        }
        Ok(balanced)
    }
    pub fn accept(&mut self, example: Example) -> Result<bool, String> {
        if self.replay.iter().any(|e| e.proof_id == example.proof_id) {
            return Ok(false);
        }
        let q = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
        if curriculum::learning(&crate::hex(q.resolution_id())).is_none() {
            return Ok(false);
        }
        let target = if example.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let (_, graphs) = search::compile(target, &example.tree)?;
        if graphs.is_empty() {
            return Ok(false);
        }
        let mut next = self.clone();
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
        if next.anchors.len() < 4
            && !next.anchors.iter().any(|old| {
                let old = CompiledQuestion::compile(&old.question).expect("verified anchor");
                curriculum::learning(&crate::hex(old.resolution_id())).is_some_and(|old| {
                    curriculum::learning(&crate::hex(q.resolution_id()))
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
        while next.replay.len() > REPLAY {
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

        next.validate()?;
        *self = next;
        Ok(true)
    }
}
