//! Formal-world freshness and provider-selection validity are separate contracts.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FormalContext {
    pub(super) snapshot: Identity,
    pub(super) policy: Identity,
}
impl FormalContext {
    pub(super) fn of(decision: &PrefilterDecision) -> Self {
        Self {
            snapshot: decision.snapshot,
            policy: decision.policy,
        }
    }
    pub(crate) fn binding(self) -> crate::jobs::Binding {
        crate::jobs::Binding::new(self.snapshot, self.policy)
    }
}

/// A cheap change indicator; formal authority still uses the complete snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Revision {
    pub(super) checked_artifacts: usize,
    pub(super) registered_questions: usize,
    pub(super) policy: Identity,
    pub(crate) selection: Option<Identity>,
}

/// Captured before provider work. Only a positive checked completion can seal
/// it into an assessment, and unrelated graph growth does not renew this input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectionContext {
    pub(super) source: Identity,
    pub(super) policy: Identity,
    pub(super) owner: Identity,
}
