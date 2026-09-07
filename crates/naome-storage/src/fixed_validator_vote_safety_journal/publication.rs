//! Read-only publication source under the existing anchored signer ownership.

use super::*;

/// A borrowed, fully completed signed record. It grants no new key operation.
#[derive(Clone, Copy, Debug)]
pub enum FixedValidatorCompletedPublicationV0<'journal> {
    Proposal(&'journal FixedValidatorSignedProposalV0),
    Vote(&'journal FixedValidatorSignedVoteV0),
}

impl FixedValidatorCompletedPublicationV0<'_> {
    pub fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        match self {
            Self::Proposal(proposal) => proposal.state_id(),
            Self::Vote(vote) => vote.state_id(),
        }
    }

    pub fn position(self) -> ConsensusPosition {
        match self {
            Self::Proposal(proposal) => proposal.position(),
            Self::Vote(vote) => vote.position(),
        }
    }

    /// Proposal, prevote, precommit order within the exact height and round.
    pub fn phase(self) -> FixedValidatorLockPhaseV0 {
        match self {
            Self::Proposal(_) => FixedValidatorLockPhaseV0::Proposal,
            Self::Vote(vote) => phase_for_vote_role(vote.role()),
        }
    }
}

/// Sealed immutable access to completions covered by the held signer anchor.
/// No caller-provided journal, key, record, or state identity can construct it.
#[must_use]
pub struct FixedValidatorPublicationHistoryV0<'journal> {
    core: &'journal FixedValidatorVoteSafetyJournalCore<File>,
}

impl FixedValidatorPublicationHistoryV0<'_> {
    pub fn context(&self) -> ConsensusContextV0 {
        self.core.context
    }
    pub fn fixed_set_id(&self) -> FixedAgreementSetId {
        self.core.fixed_set_id
    }
    pub fn signer(&self) -> ConsensusKey {
        self.core.signer
    }

    /// Unordered history, bounded by the journal's independent replay limits.
    /// Its monotonically increasing (height, round, phase) coordinates recover
    /// signing-completion order without confusing the latest checkpoint ID
    /// with a message's original completion ID.
    pub fn entries(&self) -> impl Iterator<Item = FixedValidatorCompletedPublicationV0<'_>> {
        self.core
            .proposals
            .values()
            .filter_map(|entry| entry.signed.as_ref())
            .map(FixedValidatorCompletedPublicationV0::Proposal)
            .chain(
                self.core
                    .votes
                    .values()
                    .filter_map(|entry| entry.signed.as_ref())
                    .map(FixedValidatorCompletedPublicationV0::Vote),
            )
    }
}

impl FixedValidatorAnchoredVoteSafetySigningSessionV0<'_> {
    /// Borrows only strictly completed records; ambiguous or stopped owners
    /// cannot provide publication recovery authority.
    pub fn publication_history(
        &self,
    ) -> Result<FixedValidatorPublicationHistoryV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        let core = &self.session.journal.core;
        core.ensure_not_halted()?;
        if core.anchor.is_none() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned);
        }
        // A live prepare may coexist with read-only diagnostics, but this
        // surface never supplies bytes for that uncompleted intent.
        Ok(FixedValidatorPublicationHistoryV0 { core })
    }
}
