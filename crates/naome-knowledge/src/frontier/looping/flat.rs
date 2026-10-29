//! Frozen one-level scheduling control from commit 0526a173. Test-only.
use super::*;
impl Frontier {
    pub(crate) fn flat_loop_work(
        &self,
        goal: &CompiledQuestion,
        graph: &Graph,
    ) -> Result<Work, crate::Error> {
        let Some(record) = self.evidence.get(goal)? else {
            return Ok(Work {
                target: goal.clone(),
                planned: vec![],
                pending: vec![],
                required: vec![],
                ready: true,
                _memory: Vec::new(),
            });
        };
        if record.loop_disabled {
            return Ok(Work {
                target: goal.clone(),
                planned: vec![],
                pending: vec![],
                required: vec![],
                ready: true,
                _memory: Vec::new(),
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
            target: goal.clone(),
            planned,
            pending,
            required,
            ready: true,
            _memory: vec![memory],
        })
    }
}
