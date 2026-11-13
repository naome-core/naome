//! Local proof search and durable replay using the Lean kernel.

mod archive;
pub mod cli;
mod lean;
mod model;
mod solver;
mod value;

pub use archive::{
    Archive, Artifact, EntryId, KernelArtifact, KernelBundle, KernelImport, PreparedAnswer,
    Question, Verification,
};
pub use solver::{AdaptiveSolver, Outcome, QuestionOutcome, Task};
pub use value::{ActionValues, Experience, LearningSignal};

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const CATALOG_SLOTS: usize = 64;
pub const INTRO: u8 = 0;
pub const EXACT: u8 = 1;
pub const APPLY: u8 = 2;
pub const CONSTRUCTOR: u8 = 3;
pub const RFL: u8 = 4;
pub const ACTIONS: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reference {
    Local(usize),
    Declaration(String),
    Catalog(u8),
    Archived(EntryId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<Reference>,
}

impl Action {
    pub(crate) fn validate(&self) -> Result<()> {
        match (self.id, &self.argument) {
            (INTRO | CONSTRUCTOR | RFL, None) => Ok(()),
            (EXACT | APPLY, Some(Reference::Declaration(name)))
                if name.is_empty() || name.starts_with("NaomeArchive.") =>
            {
                Err("use an explicit archive ID for archived declarations".into())
            }
            (EXACT | APPLY, Some(_)) => Ok(()),
            _ => Err(format!("invalid action or argument for ID {}", self.id).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_artifact_binds_references_to_durable_ids() {
        let prior = "37".repeat(32).parse::<EntryId>().unwrap();
        let make = |reference| Artifact::Proof {
            target: "True".to_owned(),
            steps: vec![Action {
                id: EXACT,
                argument: Some(reference),
            }],
            dependencies: Vec::new(),
        };
        let mut archived = make(Reference::Archived(prior));
        archived.normalize().unwrap();
        assert_eq!(archived.dependencies(), &[prior]);
        let identity = archived.id().unwrap();
        archived.normalize().unwrap();
        assert_eq!(archived.id().unwrap(), identity);
        assert!(make(Reference::Catalog(0)).normalize().is_err());
        assert!(
            make(Reference::Declaration(prior.lean_name()))
                .normalize()
                .is_err()
        );
    }
}
