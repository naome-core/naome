//! Caller-owned acquisition and unselected reconstruction workflows.

use crate::*;

pub(crate) mod block_ancestry;
pub(crate) mod block_ancestry_import;
pub(crate) mod block_candidate_ancestry_fill;
pub(crate) mod block_candidate_branch_payload_fill;
pub(crate) mod block_candidate_payload_fill;
pub(crate) mod block_catch_up;
pub(crate) mod block_import;
pub(crate) mod head_broadcast;
pub(crate) mod head_survey;
pub(crate) mod peer_selection;

use crate::transport::OutboundArtifactOutcome;

pub(crate) mod candidate_retention;
pub(crate) mod recovery_bundle_staging;

use naome_chain::ArtifactBlockId;
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

pub(crate) fn selected_context_contains_block(
    selected: &ArtifactChainJournal,
    current_head: ArtifactBlockId,
    virtual_genesis: ArtifactBlockId,
    block_id: ArtifactBlockId,
) -> Result<bool, ArtifactChainJournalError> {
    Ok(block_id == current_head
        || block_id == virtual_genesis
        || selected.block(block_id)?.is_some())
}
