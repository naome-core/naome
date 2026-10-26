//! Canonical outputs produced only from sealed checked artifacts.

use super::*;

/// Canonical checked output of one successful source compilation.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CompiledProof {
    checked: naome_checker::CheckedProof,
}

/// Canonical checked output of one successful definition compilation.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CompiledDefinition {
    checked: naome_checker::CheckedDefinition,
    canonical_definition_bytes: Box<[u8]>,
}

impl CompiledDefinition {
    /// Returns the exact canonical definition-certificate bytes.
    pub fn canonical_definition_bytes(&self) -> &[u8] {
        &self.canonical_definition_bytes
    }

    /// Consumes this result and returns the exact canonical definition bytes.
    pub fn into_canonical_definition_bytes(self) -> Box<[u8]> {
        self.canonical_definition_bytes
    }

    /// Returns the checked definition identity.
    pub const fn definition_id(&self) -> DefinitionId {
        self.checked.definition_id()
    }

    /// Returns the typed artifact identity used by blocks.
    pub fn artifact_id(&self) -> ArtifactId {
        ArtifactId::from_definition_id(self.definition_id())
    }

    /// Retain semantic checking for registration in the selected context.
    pub fn into_checked_definition(self) -> naome_checker::CheckedDefinition {
        self.checked
    }
}

/// One typed checked artifact produced from a complete `.nao` source.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum CompiledArtifact {
    /// A checked proof and its three proof identities.
    Proof(CompiledProof),
    /// A checked conservative definition.
    Definition(CompiledDefinition),
}

impl CompiledArtifact {
    /// Returns canonical tagged artifact bytes ready for block admission.
    #[must_use]
    pub fn canonical_artifact_bytes(&self) -> Vec<u8> {
        let (tag, payload) = match self {
            Self::Proof(proof) => (ArtifactPayload::PROOF_TAG, proof.canonical_proof_bytes()),
            Self::Definition(definition) => (
                ArtifactPayload::DEFINITION_TAG,
                definition.canonical_definition_bytes(),
            ),
        };
        let mut artifact = Vec::with_capacity(1 + payload.len());
        artifact.push(tag);
        artifact.extend_from_slice(payload);
        artifact
    }

    /// Returns the typed artifact identity used by blocks.
    pub fn artifact_id(&self) -> ArtifactId {
        match self {
            Self::Proof(proof) => ArtifactId::from_proof_id(proof.proof_id()),
            Self::Definition(definition) => definition.artifact_id(),
        }
    }
}

impl CompiledProof {
    /// The common artifact address of this exact checked proof.
    pub fn artifact_id(&self) -> ArtifactId {
        self.proof_id().into()
    }
    /// Returns the exact canonical proof normal-form bytes.
    pub fn canonical_proof_bytes(&self) -> &[u8] {
        self.checked.normal_form().canonical_bytes()
    }

    /// Consumes this result and returns its exact canonical proof bytes.
    pub fn into_canonical_proof_bytes(self) -> Box<[u8]> {
        self.checked.into_normal_form().into_canonical_bytes()
    }

    /// Returns the checked conclusion identity.
    pub const fn statement_id(&self) -> StatementId {
        self.checked.statement_id()
    }

    /// Returns the checked reference-transparent derivation identity.
    pub const fn derivation_id(&self) -> DerivationId {
        self.checked.derivation_id()
    }

    /// Returns the checked concrete canonical proof identity.
    pub const fn proof_id(&self) -> ProofId {
        self.checked.proof_id()
    }
}

impl CompiledProof {
    /// Retains the compiler's sealed mathematical result for registration in
    /// the same immutable dependency context. This grants no publication rights.
    pub fn into_checked_proof(self) -> naome_checker::CheckedProof {
        self.checked
    }

    pub(super) fn from_checked(checked: naome_checker::CheckedProof) -> Self {
        Self { checked }
    }
}

impl CompiledDefinition {
    pub(super) fn from_checked(checked: naome_checker::CheckedDefinition) -> Self {
        let canonical_definition_bytes = checked
            .certificate()
            .to_canonical_bytes()
            .into_boxed_slice();
        Self {
            checked,
            canonical_definition_bytes,
        }
    }
}
