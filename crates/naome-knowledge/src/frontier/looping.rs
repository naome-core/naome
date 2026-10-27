//! Recoverable finite prerequisite plans, subordinate to checker and job owners.
use super::*;
pub(crate) struct Work {
    pub planned: Vec<CompiledQuestion>,
    pub pending: Vec<CompiledQuestion>,
    pub required: Vec<String>,
    _memory: Option<Arc<crate::resources::MemoryLease>>,
}
impl Frontier {
    #[cfg(test)]
    pub(crate) fn support_updates(&self) -> u64 {
        self.evidence.model().supports
    }
    pub(crate) fn loop_focus(&self) -> Result<Option<CompiledQuestion>, crate::Error> {
        let mut sources = Vec::new();
        let mut children = std::collections::BTreeSet::new();
        for goal in &self.goals {
            if let Some(record) = self.evidence.get(goal)?
                && record.verified.is_none()
                && !record.loop_disabled
                && !record.helpers.is_empty()
            {
                for source in record.helpers {
                    let helper = CompiledQuestion::compile(&source).map_err(|e| e.to_string())?;
                    children.insert(*helper.resolution_id());
                }
                sources.push(goal);
            }
        }
        Ok(sources
            .into_iter()
            .find(|q| !children.contains(q.resolution_id()))
            .cloned())
    }

    pub(crate) fn abandon_publication(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        self.evidence.abandon_publication(question, job)
    }
    pub(crate) fn exhaust_helpers(
        &mut self,
        question: &CompiledQuestion,
    ) -> Result<(), crate::Error> {
        self.evidence.exhaust_helpers(question)
    }
    /// A finite plan is recovered from the same atomic failed-attempt record.
    pub(crate) fn loop_work(
        &self,
        goal: &CompiledQuestion,
        graph: &Graph,
    ) -> Result<Work, crate::Error> {
        let Some(record) = self.evidence.get(goal)? else {
            return Ok(Work {
                planned: vec![],
                pending: vec![],
                required: vec![],
                _memory: None,
            });
        };
        if record.loop_disabled {
            return Ok(Work {
                planned: vec![],
                pending: vec![],
                required: vec![],
                _memory: None,
            });
        }
        let bytes = record
            .helpers
            .iter()
            .map(|s| s.len().saturating_mul(24).saturating_add(768))
            .sum::<usize>();
        let memory = crate::resources::MemoryLease::acquire(bytes)?;
        let mut planned = Vec::new();
        let mut pending = Vec::new();
        let mut required = Vec::new();
        for source in record.helpers {
            let helper = CompiledQuestion::compile(&source).map_err(|e| e.to_string())?;
            let outcome = self.evidence.get(&helper)?;
            if let Some(verified) = outcome.as_ref().and_then(|r| r.verified.as_ref()) {
                let root = ArtifactId::from_bytes(crate::object::id_bytes(verified)?);
                if Self::checked_target(graph, root, &helper)?
                    && let Some(metadata) = graph.describe(root)?
                {
                    required.push(metadata.proof_id);
                }
            } else if outcome
                .as_ref()
                .is_none_or(|r| r.last_outcome == Outcome::Candidate && !r.publication_abandoned)
            {
                pending.push(helper.clone());
            }
            planned.push(helper);
        }
        Ok(Work {
            planned,
            pending,
            required,
            _memory: Some(memory),
        })
    }
}
