//! Canonical complete state records and exact-parent replay for NAOME.
//!
//! [`StateRecord`] binds authenticated operations, certified time, deterministic
//! effects, and the complete ledger commitment. [`FinalizedStateRecord`] owns
//! the wire envelope binding that proposal to consensus evidence. Consensus
//! authenticates and verifies the envelope; storage owns durable selection.
//! Decoding or provisional execution alone never grants finality.
//!
//! The artifact DAG and legacy single-artifact block APIs below remain during
//! integration. Their callers must be removed before the complete state history
//! becomes the sole executable authority. They are not an additional component
//! of the complete state record.

pub mod state;
pub use state::{FinalizedStateRecord, StateRecord, StateRecordExecution, StateTransition};

mod block;

// Temporary source compatibility for V0 library callers pending retirement.
// All artifact admission and DAG ownership now belong to naome-ledger.
pub use block::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockDecodeError,
    ArtifactBlockId, ArtifactBlockPrepareError, ArtifactChainBranchSnapshot,
    ArtifactChainDefinition, ArtifactChainDefinitionDecodeError, ArtifactChainId,
    ArtifactChainState,
};
pub use naome_ledger::{
    ARTIFACT_SET_PROOF_MAX_BYTES, ArtifactDag, ArtifactSetMembership, ArtifactSetProof,
    ArtifactSetProofError, ArtifactSetRoot,
};

#[cfg(test)]
mod tests;
