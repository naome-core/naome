//! Load only the selected dependency closure required by one operation.

use crate::{formal::ARTIFACT_MAX_TOTAL_BYTES, state::Id};
use naome_authoring::{CompileError, CompiledArtifact, compile_artifact_against_proof_context};
use naome_checker::{
    ArtifactState, ArtifactStateError, CheckError, DefinitionCheckError,
    check_definition_with_state, check_normal_form_with_state,
};
use naome_proof::{ArtifactId, ArtifactPayload};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// These bound one resolver operation, never the stored artifact library.
const MAX_CONTEXT_ARTIFACTS: usize = 256;
const MAX_CONTEXT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredArtifact {
    // The indexed address is domain-separated from the ProofId/DefinitionId
    // consumed by .nao citations and definition imports.
    pub id: Id,
    pub reference_id: Id,
    pub source: String,
    pub bytes: Vec<u8>,
    pub dependencies: Vec<Id>,
    pub statement: Option<Id>,
    pub derivation: Option<Id>,
}

pub(super) enum Reference {
    Artifact(Id),
    Statement(Id),
    Derivation(Id),
}

fn missing(error: &CompileError) -> Option<Reference> {
    match error {
        CompileError::DefinitionNotSelected { definition_id, .. } => Some(Reference::Artifact(
            *ArtifactId::from_definition_id(*definition_id).as_bytes(),
        )),
        CompileError::Check { source, .. } => match source.as_ref() {
            CheckError::UnknownProofReference { proof_id, .. } => Some(Reference::Artifact(
                *ArtifactId::from_proof_id(*proof_id).as_bytes(),
            )),
            _ => None,
        },
        CompileError::DefinitionCheck { source, .. } => match source.as_ref() {
            DefinitionCheckError::UnknownObligationStatement { statement_id } => {
                Some(Reference::Statement(*statement_id.as_bytes()))
            }
            _ => None,
        },
        _ => None,
    }
}

fn register(bytes: &[u8], state: &mut ArtifactState) -> Result<(), String> {
    match ArtifactPayload::from_canonical_bytes(bytes).map_err(|e| e.to_string())? {
        ArtifactPayload::Proof(proof) => {
            let normal = proof
                .into_unchecked_normal_form()
                .with_matching_canonical_bytes(bytes[1..].into())
                .ok_or("context proof canonical mismatch")?;
            let proof = check_normal_form_with_state(normal, state).map_err(|e| e.to_string())?;
            match state.register_proof(proof) {
                Ok(_)
                | Err(ArtifactStateError::DuplicateProof { .. })
                | Err(ArtifactStateError::DuplicateDerivation { .. }) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        ArtifactPayload::Definition(definition) => {
            let definition =
                check_definition_with_state(definition, state).map_err(|e| e.to_string())?;
            match state.register_definition(definition) {
                Ok(_) | Err(ArtifactStateError::DuplicateDefinition { .. }) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

struct Loader<'a, F> {
    lookup: &'a mut F,
    published: ArtifactState,
    loaded: BTreeSet<Id>,
    visiting: BTreeSet<Id>,
    bytes: usize,
}
impl<F> Loader<'_, F>
where
    F: FnMut(Reference) -> Result<Option<StoredArtifact>, String>,
{
    fn load(&mut self, reference: Reference) -> Result<(), String> {
        let artifact = (self.lookup)(reference)?
            .ok_or("required artifact is absent from selected local history")?;
        if self.loaded.contains(&artifact.id) {
            return Ok(());
        }
        if self.visiting.len() + self.loaded.len() >= MAX_CONTEXT_ARTIFACTS
            || !self.visiting.insert(artifact.id)
        {
            return Err("selected context count/cycle bound".into());
        }
        self.bytes = self
            .bytes
            .checked_add(artifact.bytes.len())
            .ok_or("context byte overflow")?;
        if self.bytes > MAX_CONTEXT_BYTES {
            return Err("selected context exceeds per-operation byte limit".into());
        }
        for dependency in &artifact.dependencies {
            self.load(Reference::Artifact(*dependency))?;
        }
        let payload =
            ArtifactPayload::from_canonical_bytes(&artifact.bytes).map_err(|e| e.to_string())?;
        let (identity, reference_id) = match payload {
            ArtifactPayload::Proof(proof) => {
                let normal = proof
                    .into_unchecked_normal_form()
                    .with_matching_canonical_bytes(artifact.bytes[1..].into())
                    .ok_or("context canonical mismatch")?;
                let checked = check_normal_form_with_state(normal, &self.published)
                    .map_err(|e| e.to_string())?;
                (
                    *ArtifactId::from_proof_id(checked.proof_id()).as_bytes(),
                    *checked.proof_id().as_bytes(),
                )
            }
            ArtifactPayload::Definition(definition) => {
                let checked = check_definition_with_state(definition, &self.published)
                    .map_err(|e| e.to_string())?;
                (
                    *ArtifactId::from_definition_id(checked.definition_id()).as_bytes(),
                    *checked.definition_id().as_bytes(),
                )
            }
        };
        if identity != artifact.id || reference_id != artifact.reference_id {
            return Err("stored selected artifact identity mismatch".into());
        }
        register(&artifact.bytes, &mut self.published)?;
        self.visiting.remove(&artifact.id);
        self.loaded.insert(artifact.id);
        Ok(())
    }
}

/// Compilation diagnostics request exact selected dependencies. Provided
/// helpers stay on a temporary branch; the returned base excludes them so
/// check_answer still checks ordered minimal helper closure independently.
pub(super) fn prepare<F>(
    sources: &[&str],
    mut lookup: F,
) -> Result<(ArtifactState, Vec<StoredArtifact>), String>
where
    F: FnMut(Reference) -> Result<Option<StoredArtifact>, String>,
{
    let mut loader = Loader {
        lookup: &mut lookup,
        published: ArtifactState::new(),
        loaded: BTreeSet::new(),
        visiting: BTreeSet::new(),
        bytes: 0,
    };
    for _ in 0..=MAX_CONTEXT_ARTIFACTS {
        let mut scratch = loader.published.clone();
        let mut artifacts: Vec<StoredArtifact> = vec![];
        let mut canonical_bytes = 0usize;
        let mut requested = None;
        for source in sources {
            let compiled = match compile_artifact_against_proof_context(source, &scratch) {
                Ok(value) => value,
                Err(error) => {
                    if let Some(reference) = missing(&error) {
                        requested = Some(reference);
                        break;
                    }
                    return Err(format!("authoring failed: {error}"));
                }
            };
            let id = *compiled.artifact_id().as_bytes();
            let reference_id = match &compiled {
                CompiledArtifact::Proof(proof) => *proof.proof_id().as_bytes(),
                CompiledArtifact::Definition(definition) => *definition.definition_id().as_bytes(),
            };
            let bytes = compiled.canonical_artifact_bytes();
            canonical_bytes = canonical_bytes
                .checked_add(bytes.len())
                .ok_or("artifact byte overflow")?;
            if canonical_bytes > ARTIFACT_MAX_TOTAL_BYTES {
                return Err("canonical artifact byte limit".into());
            }
            let (dependencies, statement, derivation) = match &compiled {
                CompiledArtifact::Proof(proof) => {
                    // Load the previously selected concrete representative of an
                    // existing derivation; copied possession must not publish aliases.
                    if !loader.loaded.contains(&id)
                        && let Some(existing) = (loader.lookup)(Reference::Derivation(
                            *proof.derivation_id().as_bytes(),
                        ))?
                        && !loader.loaded.contains(&existing.id)
                    {
                        requested = Some(Reference::Artifact(existing.id));
                        break;
                    }
                    let payload =
                        ArtifactPayload::from_canonical_bytes(&bytes).map_err(|e| e.to_string())?;
                    let ArtifactPayload::Proof(proof_payload) = payload else {
                        return Err("proof payload expected".into());
                    };
                    let normal = proof_payload
                        .into_unchecked_normal_form()
                        .with_matching_canonical_bytes(bytes[1..].into())
                        .ok_or("canonical normal form expected")?;
                    let checked = check_normal_form_with_state(normal, &scratch)
                        .map_err(|e| e.to_string())?;
                    (
                        checked
                            .direct_artifact_dependencies()
                            .iter()
                            .map(|id| *id.as_bytes())
                            .collect(),
                        Some(*checked.statement_id().as_bytes()),
                        Some(*checked.derivation_id().as_bytes()),
                    )
                }
                CompiledArtifact::Definition(_) => {
                    let payload =
                        ArtifactPayload::from_canonical_bytes(&bytes).map_err(|e| e.to_string())?;
                    let ArtifactPayload::Definition(definition) = payload else {
                        return Err("definition payload expected".into());
                    };
                    let checked = check_definition_with_state(definition, &scratch)
                        .map_err(|e| e.to_string())?;
                    let mut dependencies = vec![];
                    if let Some(statement) = checked.obligation_statement_id() {
                        let id = *statement.as_bytes();
                        if let Some(witness) = artifacts.iter().find(|a| a.statement == Some(id)) {
                            dependencies.push(witness.id);
                        } else {
                            dependencies.push(
                                (loader.lookup)(Reference::Statement(id))?
                                    .ok_or("selected obligation witness absent")?
                                    .id,
                            );
                        }
                    }
                    (dependencies, None, None)
                }
            };
            register(&bytes, &mut scratch)?;
            artifacts.push(StoredArtifact {
                id,
                reference_id,
                source: (*source).into(),
                bytes,
                dependencies,
                statement,
                derivation,
            });
        }
        if let Some(reference) = requested {
            let before = loader.loaded.len();
            loader.load(reference)?;
            if loader.loaded.len() == before {
                return Err("unresolved context dependency".into());
            }
        } else {
            return Ok((loader.published, artifacts));
        }
    }
    Err("selected context work bound exceeded".into())
}
