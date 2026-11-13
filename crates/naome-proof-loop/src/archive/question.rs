use super::{Archive, Artifact, EntryId, LEAN_LIBRARIES, LEAN_TOOLCHAIN, names};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A Lean question with exact portable dependencies.
///
/// Deserialization checks the encoding. Use [Archive::check_question] to
/// establish that decoded terms represent a well-formed proposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    dependencies: Vec<EntryId>,
    term: Value,
}

#[derive(Deserialize)]
pub(crate) struct QuestionType {
    pub dependencies: Vec<String>,
    pub term: Value,
}

impl Question {
    pub const MAX_BYTES: usize = 65_536;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err("question byte limit exceeded".into());
        }
        let question: Self = serde_json::from_slice(bytes)?;
        if question.to_bytes()? != bytes {
            return Err("noncanonical question bytes".into());
        }
        Ok(question)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if !self.term.is_object()
            || self.dependencies.len() >= super::transfer::MAX_OBJECTS
            || self.dependencies.windows(2).any(|ids| ids[0] >= ids[1])
        {
            return Err("invalid question term or dependency order".into());
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > Self::MAX_BYTES {
            return Err("question byte limit exceeded".into());
        }
        Ok(bytes)
    }

    /// Content address under the pinned Lean and Mathlib environment.
    pub fn id(&self) -> Result<EntryId> {
        let bytes = self.to_bytes()?;
        let mut hash = Sha256::new();
        hash.update(b"naome:lean-question\0");
        for part in [
            LEAN_TOOLCHAIN.as_bytes(),
            LEAN_LIBRARIES.as_bytes(),
            bytes.as_slice(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        Ok(EntryId(hash.finalize().into()))
    }

    pub fn dependencies(&self) -> &[EntryId] {
        &self.dependencies
    }

    pub(super) fn from_lean(description: QuestionType) -> Result<Self> {
        let mut dependencies = description
            .dependencies
            .iter()
            .map(|name| {
                name.strip_prefix("NaomeArchive.e_")
                    .ok_or_else(|| "invalid question dependency name".into())
                    .and_then(str::parse)
            })
            .collect::<Result<Vec<EntryId>>>()?;
        dependencies.sort_unstable();
        let question = Self {
            dependencies,
            term: description.term,
        };
        question.to_bytes()?;
        Ok(question)
    }
}

impl Archive {
    /// Elaborate a local goal under the exact imported declarations it uses.
    pub fn question(&mut self, target: &str, dependencies: &[EntryId]) -> Result<Question> {
        if target.len() > Question::MAX_BYTES || dependencies.len() >= super::transfer::MAX_OBJECTS
        {
            return Err("question input limit exceeded".into());
        }
        self.load_question_dependencies(dependencies)?;
        let description = self.lean.question(target, &names(dependencies), None)?;
        Question::from_lean(description)
    }

    /// Check a question reconstructed from untrusted canonical bytes.
    pub fn check_question(&mut self, question: &Question) -> Result<()> {
        question.to_bytes()?;
        self.load_question_dependencies(question.dependencies())?;
        let checked =
            self.lean
                .question("", &names(question.dependencies()), Some(&question.term))?;
        if Question::from_lean(checked)? != *question {
            return Err("checked question does not match its encoding".into());
        }
        Ok(())
    }

    fn load_question_dependencies(&mut self, dependencies: &[EntryId]) -> Result<()> {
        for &id in dependencies {
            if !matches!(self.read(id)?, Artifact::Kernel { .. }) {
                return Err("question dependencies must use portable kernel addresses".into());
            }
        }
        self.load(dependencies)
    }
}
