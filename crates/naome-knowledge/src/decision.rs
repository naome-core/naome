//! Model-independent, bounded categorical inference. No admission authority.
//!
//! The job owner creates one runtime and shares its access explicitly. This
//! module does not know about research questions, interests or graph storage.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) mod liquid;
#[cfg(feature = "developer-tools")]
pub mod probe;
pub(crate) mod runtime;
#[cfg(feature = "developer-tools")]
pub mod screen;

pub const CONTRACT: &str = "naome:decision:categorical:v1";
pub const MAX_STATE_BYTES: usize = 32 * 1024;
pub const MAX_INSTRUCTION_BYTES: usize = 512;
pub const MAX_OPTIONS: usize = 8;
/// Bounded native response metadata and its callers' result reservation.
pub(crate) const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    pub id: String,
    pub description: String,
}

/// Options have stable caller-owned identifiers and an explicit order.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub state: String,
    pub instruction: String,
    pub alternatives: Vec<Alternative>,
}

impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.state.len() > MAX_STATE_BYTES
            || self.instruction.trim().is_empty()
            || self.instruction.len() > MAX_INSTRUCTION_BYTES
            || !(2..=MAX_OPTIONS).contains(&self.alternatives.len())
        {
            return Err("decision request shape or byte limit".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for option in &self.alternatives {
            if option.id.is_empty()
                || option.id.len() > 32
                || !option
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || option.description.trim().is_empty()
                || option.description.len() > 256
                || !names.insert(&option.id)
            {
                return Err("decision alternative identity or description".into());
            }
        }
        Ok(())
    }

    pub fn identity(&self) -> String {
        digest(&(CONTRACT, self))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Probability {
    pub option: String,
    pub probability: f64,
}

/// A distribution is evidence for a caller's policy, never an authorized effect.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    pub request: String,
    pub model: String,
    pub probabilities: Vec<Probability>,
    pub input_tokens: usize,
    pub elapsed_ms: u64,
    pub peak_rss_bytes: u64,
    pub accelerator_bytes: u64,
    pub truncated: bool,
}

impl Distribution {
    pub fn validate(&self, request: &Request, model: &str) -> Result<(), String> {
        request.validate()?;
        if self.request != request.identity()
            || self.model != model
            || self.input_tokens == 0
            || self.truncated
            || self.probabilities.len() != request.alternatives.len()
        {
            return Err("decision response binding or shape differs".into());
        }
        let mut sum = 0.0;
        for (p, option) in self.probabilities.iter().zip(&request.alternatives) {
            if p.option != option.id
                || !p.probability.is_finite()
                || !(0.0..=1.0).contains(&p.probability)
            {
                return Err("invalid decision probability or option order".into());
            }
            sum += p.probability;
        }
        if (sum - 1.0).abs() > 1e-5 {
            return Err("decision distribution is not normalized".into());
        }
        Ok(())
    }
}

pub(crate) fn digest(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("serializable decision identity"),
    ))
}

#[cfg(test)]
mod tests;
