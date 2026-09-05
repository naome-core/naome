//! Canonical outputs produced only from sealed checked artifacts.

use super::*;

/// Canonical checked output of one successful source compilation.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CompiledProof {
    canonical_proof_bytes: Box<[u8]>,
    statement_id: StatementId,
    derivation_id: DerivationId,
    proof_id: ProofId,
}

/// Canonical checked output of one successful definition compilation.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CompiledDefinition {
    canonical_definition_bytes: Box<[u8]>,
    definition_id: DefinitionId,
    artifact_id: ArtifactId,
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
        self.definition_id
    }

    /// Returns the typed artifact identity used by blocks.
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
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
    /// Returns the exact canonical proof normal-form bytes.
    pub fn canonical_proof_bytes(&self) -> &[u8] {
        &self.canonical_proof_bytes
    }

    /// Consumes this result and returns its exact canonical proof bytes.
    pub fn into_canonical_proof_bytes(self) -> Box<[u8]> {
        self.canonical_proof_bytes
    }

    /// Returns the checked conclusion identity.
    pub const fn statement_id(&self) -> StatementId {
        self.statement_id
    }

    /// Returns the checked reference-transparent derivation identity.
    pub const fn derivation_id(&self) -> DerivationId {
        self.derivation_id
    }

    /// Returns the checked concrete canonical proof identity.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }
}

impl CompiledProof {
    pub(super) fn from_checked(checked: naome_checker::CheckedProof) -> Self {
        let statement_id = checked.statement_id();
        let derivation_id = checked.derivation_id();
        let proof_id = checked.proof_id();
        let canonical_proof_bytes = checked.into_normal_form().into_canonical_bytes();
        Self {
            canonical_proof_bytes,
            statement_id,
            derivation_id,
            proof_id,
        }
    }
}

impl CompiledDefinition {
    pub(super) fn from_checked(checked: naome_checker::CheckedDefinition) -> Self {
        let definition_id = checked.definition_id();
        let artifact_id = ArtifactId::from_definition_id(definition_id);
        let canonical_definition_bytes = checked
            .into_certificate()
            .to_canonical_bytes()
            .into_boxed_slice();
        Self {
            canonical_definition_bytes,
            definition_id,
            artifact_id,
        }
    }
}
