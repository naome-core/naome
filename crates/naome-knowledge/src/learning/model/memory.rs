//! Search-owned working memory. Checkpoints contain weights and Adam; an
//! interrupted native search restarts at its existing unit boundary.
use super::*;

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
    successors: Option<Vec<Vec<f32>>>,
    carry: bool,
}

impl Plan {
    pub(crate) fn scores(scores: Vec<f32>) -> Self {
        Self {
            scores,
            model: None,
            successors: None,
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
    ) -> Result<Option<Memory>, String> {
        if selected >= self.scores.len() {
            return Err("native memory action index differs".into());
        }
        if !self.carry {
            return Ok(None);
        }
        let values = self
            .successors
            .as_ref()
            .and_then(|s| s.get(selected))
            .ok_or("native memory transition missing")?
            .clone();
        let model = self
            .model
            .clone()
            .ok_or("native memory checkpoint missing")?;
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
    fn validate(&self) -> Result<(), String> {
        for value in [&self.model, &self.state, &self.offered] {
            crate::object::id_bytes(value)?;
        }
        if self.values.len() != policy::WIDTH
            || self.values.iter().any(|v| !v.is_finite() || v.abs() > 1.)
        {
            return Err("native memory shape or value differs".into());
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
    ) -> Result<Plan, String> {
        if let Some(memory) = memory {
            memory.validate()?;
            if self.recurrence != Recurrence::Carry
                || memory.model != self.identity
                || memory.state != graph.binding
                || memory.offered != offered
            {
                return Err("native working memory context or checkpoint differs".into());
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
        let (scores, successors) = policy.readout(policy.encode(&batch), initial);
        let scores = scores
            .into_data()
            .try_to_vec::<f32>()
            .map_err(|e| e.to_string())?;
        if scores.len() != graph.candidates.len() || scores.iter().any(|x| !x.is_finite()) {
            return Err("native memory prediction differs".into());
        }
        let successors = successors
            .map(|s| -> Result<Vec<Vec<f32>>, String> {
                let values = s
                    .into_data()
                    .try_to_vec::<f32>()
                    .map_err(|e| e.to_string())?;
                if values.len() != scores.len() * policy::WIDTH
                    || values.iter().any(|v| !v.is_finite() || v.abs() > 1.)
                {
                    return Err("native memory successor differs".into());
                }
                Ok(values
                    .chunks_exact(policy::WIDTH)
                    .map(<[f32]>::to_vec)
                    .collect())
            })
            .transpose()?;
        Ok(Plan {
            scores,
            model: Some(self.identity.clone()),
            successors,
            carry: self.recurrence == Recurrence::Carry,
        })
    }
}

#[cfg(test)]
mod tests;
