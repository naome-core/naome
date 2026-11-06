//! Receiver-scoped comparisons of immutable native model checkpoints.
//!
//! Gossip authenticates the connection but provides no finality or shared
//! clock. The verifier freezes both registrations before drawing its challenge.
//! Anyone with the registrations, challenge and blobs can derive the same
//! tasks and run the reference evaluator. A remote receipt never authorizes
//! score credit or a local checkpoint change.

use crate::learning::{Blob, model::Checkpoint};
use serde::{Deserialize, Serialize};

mod plan;
pub(crate) use plan::reserved;
mod replay;
pub(crate) use plan::{Challenge, budget};
pub(crate) use replay::{Comparison, decode_finder, encode_finder};
mod bundle;
pub(crate) mod control;
pub(crate) mod protocol;
pub(crate) mod worker;
pub(crate) use bundle::Bundle;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Profile {
    Solver,
    Finder,
}

impl std::str::FromStr for Profile {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "solver" => Ok(Self::Solver),
            "finder" => Ok(Self::Finder),
            _ => Err("model profile must be solver or finder".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Model {
    Solver { checkpoint: Checkpoint },
    Finder { checkpoint: Blob },
}

impl Model {
    pub(crate) fn profile(&self) -> Profile {
        match self {
            Self::Solver { .. } => Profile::Solver,
            Self::Finder { .. } => Profile::Finder,
        }
    }

    pub(crate) fn blobs(&self) -> impl Iterator<Item = &Blob> {
        let (first, second) = match self {
            Self::Solver { checkpoint } => (&checkpoint.model, &checkpoint.optimizer),
            Self::Finder { checkpoint } => return [Some(checkpoint), None].into_iter().flatten(),
        };
        [first.as_ref(), second.as_ref()].into_iter().flatten()
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Solver { checkpoint } => {
                checkpoint.validate()?;
                checkpoint
                    .updates
                    .checked_add(
                        u64::from(crate::learning::TRAINING_UNITS)
                            * crate::learning::model::UPDATES_PER_UNIT,
                    )
                    .ok_or("native checkpoint cannot advance its update count")?;
                Ok(())
            }
            Self::Finder { checkpoint } if checkpoint.bytes <= crate::checkpoint::MAX_HEADER => {
                checkpoint.validate()
            }
            Self::Finder { .. } => Err("finder checkpoint byte capacity".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    pub(crate) reference: String,
    pub(crate) model: Model,
}

impl Registration {
    pub(crate) fn new(model: Model) -> Self {
        Self {
            reference: replay::contract(model.profile()),
            model,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.reference != replay::contract(self.model.profile()) {
            return Err("incompatible model reference contract".into());
        }
        self.model.validate()
    }

    pub(crate) fn id(&self) -> String {
        crate::learning::digest(&("naome:model-registration", self))
    }
}

#[cfg(test)]
mod tests;
