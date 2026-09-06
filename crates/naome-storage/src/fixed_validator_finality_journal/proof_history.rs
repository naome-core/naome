//! Sealed proof reading without journal or signer acknowledgement authority.

use super::{
    ConsensusContextV0, ConsensusHeight, FixedValidatorAnchoredFinalityJournalV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityRecordV0,
};

mod sealed {
    pub trait Sealed {}
}

/// Read-only access to the first retained complete proof at one exact height.
///
/// Only the independently anchored finality journal implements this interface.
/// Every lookup checks that owner is healthy, including foreign-context and
/// missing-height requests. Borrowed proof bytes confer no verification,
/// selection, signing, height-handoff, or signer-stop authority.
///
/// The projection cannot issue a signer-height acknowledgement:
///
/// ```compile_fail,E0599
/// use naome_consensus::ConsensusHeight;
/// use naome_storage::SelectedFinalityProofHistoryV0;
/// fn handoff(history: &dyn SelectedFinalityProofHistoryV0, height: ConsensusHeight) {
///     let _ = history.acknowledge_signer_height_transition(height);
/// }
/// ```
///
/// Nor can it issue a signer-stop acknowledgement:
///
/// ```compile_fail,E0599
/// use naome_storage::SelectedFinalityProofHistoryV0;
/// fn stop(history: &dyn SelectedFinalityProofHistoryV0) {
///     let _ = history.acknowledge_signer_stop();
/// }
/// ```
pub trait SelectedFinalityProofHistoryV0: sealed::Sealed {
    /// Returns no proof for a foreign context, height zero, or a missing height.
    /// A stopped or poisoned owner returns its existing journal error instead.
    fn selected_finality_proof(
        &self,
        context: ConsensusContextV0,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0>;
}

impl sealed::Sealed for FixedValidatorAnchoredFinalityJournalV0 {}

impl SelectedFinalityProofHistoryV0 for FixedValidatorAnchoredFinalityJournalV0 {
    fn selected_finality_proof(
        &self,
        context: ConsensusContextV0,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0> {
        self.head()?;
        if context != self.context() {
            return Ok(None);
        }
        self.finality_record(height)
    }
}
