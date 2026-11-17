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
    fn content_addresses_match_the_pinned_lean_environment() {
        let proof: Artifact = serde_json::from_str(
            r#"{"kind":"proof","target":"True","steps":[{"id":1,"argument":{"declaration":"True.intro"}}],"dependencies":[]}"#,
        )
        .unwrap();
        let kernel: KernelArtifact = serde_json::from_value(serde_json::json!({
            "dependencies": [],
            "terms": {
                "isProof": true,
                "levelParameters": [],
                "type": {"constant": {"name": {"parts": [{"text": {"value": "True"}}]}, "levels": []}},
                "value": {"constant": {"name": {"parts": [
                    {"text": {"value": "True"}}, {"text": {"value": "intro"}}
                ]}, "levels": []}}
            }
        }))
        .unwrap();
        let question = Question::from_bytes(
            br#"{"dependencies":[],"term":{"constant":{"levels":[],"name":{"parts":[{"text":{"value":"True"}}]}}}}"#,
        )
        .unwrap();

        for (id, expected) in [
            (
                proof.id().unwrap(),
                "046e20777076a4047575ae45c2cc8a0086c6bb1d68a64a513fe89d6ddc761de5",
            ),
            (
                kernel.id().unwrap(),
                "3377075d1e1dedb5d0fde4422ec6a3205e7c57c4fbcd55630d243119bed359f3",
            ),
            (
                question.id().unwrap(),
                "14cfa375dcb740286a209d24b084dbf69dd4b52882e4d5342cb8cbdf6f45a7be",
            ),
        ] {
            assert_eq!(id.to_string(), expected);
        }
    }

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
