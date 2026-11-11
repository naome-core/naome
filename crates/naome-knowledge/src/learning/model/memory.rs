//! Search-owned working memory. Checkpoints contain weights and Adam; an
//! interrupted native search restarts at its existing unit boundary.
use super::*;
use crate::ResearchFailure;
use std::cell::OnceCell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Recurrence {
    Disabled,
    Reset,
    #[default]
    Carry,
}

#[derive(Clone, Debug, Serialize)]
pub struct Memory {
    model: String,
    state: String,
    offered: String,
    values: Vec<f32>,
}

#[derive(Clone)]
pub struct Plan {
    pub scores: Vec<f32>,
    model: Option<String>,
    successors: Option<policy::Successors>,
    rows: Vec<OnceCell<Vec<f32>>>,
    carry: bool,
}

impl Plan {
    pub(crate) fn scores(scores: Vec<f32>) -> Self {
        Self {
            scores,
            model: None,
            successors: None,
            rows: Vec::new(),
            carry: false,
        }
    }
    /// The search calls this only after applying the actual selected symbolic
    /// action. Siblings each receive a clone of the same parent action state.
    pub(crate) fn child(
        &self,
        selected: usize,
        state: String,
        offered: String,
    ) -> Result<Option<Memory>, crate::Error> {
        if selected >= self.scores.len() {
            return Err(ResearchFailure::MemoryActionIndex.into());
        }
        let Some(successors) = &self.successors else {
            return Ok(None);
        };
        let row = &self.rows[selected];
        if row.get().is_none() {
            let values = successors
                .selected(selected)
                .into_data()
                .try_to_vec::<f32>()
                .map_err(|_| ResearchFailure::MemoryTensorDecode)?;
            if values.len() != policy::WIDTH
                || values.iter().any(|v| !v.is_finite() || v.abs() > 1.)
            {
                return Err(ResearchFailure::MemorySuccessor.into());
            }
            let _ = row.set(values);
        }
        if !self.carry {
            return Ok(None);
        }
        let values = row.get().expect("selected successor row").clone();
        let model = self
            .model
            .clone()
            .ok_or(ResearchFailure::MemoryCheckpointMissing)?;
        let memory = Memory {
            model,
            state,
            offered,
            values,
        };
        memory.validate()?;
        Ok(Some(memory))
    }
}

impl Memory {
    fn validate(&self) -> Result<(), crate::Error> {
        for value in [&self.model, &self.state, &self.offered] {
            crate::object::id_bytes(value)?;
        }
        if self.values.len() != policy::WIDTH
            || self.values.iter().any(|v| !v.is_finite() || v.abs() > 1.)
        {
            return Err(ResearchFailure::MemoryShapeOrValue.into());
        }
        Ok(())
    }
}

impl Runtime {
    pub(super) fn plan_graph(
        &self,
        graph: &Graph,
        offered: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, crate::Error> {
        if let Some(memory) = memory {
            memory.validate()?;
            if self.recurrence != Recurrence::Carry
                || memory.model != self.identity
                || memory.state != graph.binding
                || memory.offered != offered
            {
                return Err(ResearchFailure::MemoryContext.into());
            }
        }
        let batch = self.scoring_batch(graph)?;
        let policy = self.policy.valid();
        let initial = (self.recurrence != Recurrence::Disabled).then(|| {
            Tensor::from_data(
                burn::tensor::TensorData::new(
                    memory.map_or_else(|| vec![0.; policy::WIDTH], |m| m.values.clone()),
                    [1, policy::WIDTH],
                ),
                &self.device.clone().inner(),
            )
        });
        let (scores, successors) = policy.infer(
            policy.encode_cached(&batch, &graph.context, &mut self.token_rows.borrow_mut())?,
            initial,
        );
        let scores = scores
            .into_data()
            .try_to_vec::<f32>()
            .map_err(|_| ResearchFailure::MemoryTensorDecode)?;
        if scores.len() != graph.candidates.len() || scores.iter().any(|x| !x.is_finite()) {
            return Err(ResearchFailure::MemoryPrediction.into());
        }
        let rows = if successors.is_some() {
            vec![OnceCell::new(); scores.len()]
        } else {
            Vec::new()
        };
        Ok(Plan {
            scores,
            model: Some(self.identity.clone()),
            successors,
            rows,
            carry: self.recurrence == Recurrence::Carry,
        })
    }
}

#[cfg(test)]
mod tests;
