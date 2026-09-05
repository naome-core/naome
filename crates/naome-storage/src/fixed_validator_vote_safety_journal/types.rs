//! Limits, immutable capabilities, and retained evidence types.

use super::*;

/// Positive caller-provisioned maximum number of distinct prepared votes.
///
/// The cap bounds prepared-vote replay and the retained vote map. Idempotent
/// duplicate preparation does not consume another slot. Every accepted
/// preparation reserves room for its matching completion, and one terminal
/// conflict record remains admissible after the cap is reached. Higher-round
/// checkpoints are individually bounded but do not consume this vote-only cap,
/// so it does not bound their cumulative count or the append-only file size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorVoteSafetyReplayLimitV0(pub(super) u64);

impl FixedValidatorVoteSafetyReplayLimitV0 {
    /// Constructs one positive local prepared-vote ceiling.
    pub const fn new(
        max_prepared_votes: u64,
    ) -> Result<Self, FixedValidatorVoteSafetyReplayLimitErrorV0> {
        if max_prepared_votes == 0 {
            Err(FixedValidatorVoteSafetyReplayLimitErrorV0)
        } else {
            Ok(Self(max_prepared_votes))
        }
    }

    /// Returns the configured inclusive prepared-vote ceiling.
    pub const fn max_prepared_votes(self) -> u64 {
        self.0
    }
}

/// A zero local prepared-vote replay ceiling is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorVoteSafetyReplayLimitErrorV0;

impl fmt::Display for FixedValidatorVoteSafetyReplayLimitErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed-validator vote-safety replay limit must be positive")
    }
}

impl Error for FixedValidatorVoteSafetyReplayLimitErrorV0 {}

/// Positive caller-provisioned maximum number of distinct prepared proposals.
///
/// This independent cap becomes part of journal state through one explicit
/// activation record. It does not consume or redefine the header-bound vote
/// replay limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorProposalReplayLimitV0(pub(super) u64);

impl FixedValidatorProposalReplayLimitV0 {
    /// Constructs one positive local prepared-proposal ceiling.
    pub const fn new(
        max_prepared_proposals: u64,
    ) -> Result<Self, FixedValidatorProposalReplayLimitErrorV0> {
        if max_prepared_proposals == 0 {
            Err(FixedValidatorProposalReplayLimitErrorV0)
        } else {
            Ok(Self(max_prepared_proposals))
        }
    }

    /// Returns the configured inclusive prepared-proposal ceiling.
    pub const fn max_prepared_proposals(self) -> u64 {
        self.0
    }
}

/// A zero local prepared-proposal replay ceiling is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorProposalReplayLimitErrorV0;

impl fmt::Display for FixedValidatorProposalReplayLimitErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed-validator proposal replay limit must be positive")
    }
}

impl Error for FixedValidatorProposalReplayLimitErrorV0 {}

/// Chained identity of one exact durable vote-safety journal state.
///
/// The genesis identity commits the synchronized header. Every later identity
/// commits the preceding identity and one exact prepare, completion, halt,
/// signing-lineage, finality-conflict stop, or higher-round checkpoint record.
/// This local persistence identity is not consensus ancestry, a vote identity,
/// finality, or a globally trusted checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct FixedValidatorVoteSafetyJournalStateIdV0(pub(super) [u8; Self::BYTE_LENGTH]);

impl FixedValidatorVoteSafetyJournalStateIdV0 {
    /// Exact width of one journal-state identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs one externally retained expected identity from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw journal-state identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct VoteSlot {
    pub(super) position: ConsensusPosition,
    pub(super) role: ConsensusVoteRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigningLineageIdV0(pub(super) [u8; SIGNING_LINEAGE_ID_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedSigningLineageV0 {
    pub(crate) height: ConsensusHeight,
    pub(crate) id: SigningLineageIdV0,
    pub(super) state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl VoteSlot {
    pub(super) const fn new(position: ConsensusPosition, role: ConsensusVoteRole) -> Self {
        Self { position, role }
    }
}

/// Opaque identity of one exact durably prepared vote.
///
/// Its private fields bind the journal state and slot that produced it. The
/// signing session accepts it only when creating an exact external-durability
/// acknowledgement; the prepared value alone grants no signing authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorPreparedVoteV0 {
    pub(super) slot: VoteSlot,
    pub(super) target: ConsensusVoteTarget,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

/// Read-only summary of the sole durable but uncompleted preparation.
///
/// Unlike [`FixedValidatorPreparedVoteV0`], this value cannot be supplied to
/// the signing session to create an external-durability acknowledgement. A
/// journal reopened at this state exposes only this summary and remains
/// fail-closed for every signing operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorPendingVoteV0 {
    pub(super) position: ConsensusPosition,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorPendingVoteV0 {
    /// Returns the exact prepared height and round.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact prepared role.
    pub const fn role(self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the exact prepared target.
    pub const fn target(self) -> ConsensusVoteTarget {
        self.target
    }

    /// Returns the durable state identity of the preparation.
    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

impl FixedValidatorPreparedVoteV0 {
    /// Returns the exact prepared height and round.
    pub const fn position(self) -> ConsensusPosition {
        self.slot.position
    }

    /// Returns the exact prepared vote role.
    pub const fn role(self) -> ConsensusVoteRole {
        self.slot.role
    }

    /// Returns the exact prepared nil-or-proposal target.
    pub const fn target(self) -> ConsensusVoteTarget {
        self.target
    }

    /// Returns the durable state identity of the prepare record.
    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

/// One canonical signed vote released only after its completion record synced.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorSignedVoteV0 {
    pub(super) position: ConsensusPosition,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
    pub(super) vote_id: ConsensusVoteId,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorSignedVoteV0 {
    /// Returns the exact signed height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the signed vote role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the signed nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.target
    }

    /// Returns the semantic, signature-invariant vote identity.
    pub const fn vote_id(&self) -> ConsensusVoteId {
        self.vote_id
    }

    /// Returns the exact canonical signed-vote bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the durable completion state identity.
    pub const fn state_id(&self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.state_id
    }
}

/// Opaque identity of one exact durably prepared proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorPreparedProposalV0 {
    pub(super) position: ConsensusPosition,
    pub(super) proposal_signing_root: ProposalSigningRoot,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorPreparedProposalV0 {
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    pub const fn proposal_signing_root(self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }

    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

/// Read-only summary of a durable but uncompleted proposal preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorPendingProposalV0 {
    pub(super) position: ConsensusPosition,
    pub(super) proposal_signing_root: ProposalSigningRoot,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorPendingProposalV0 {
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    pub const fn proposal_signing_root(self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }

    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

/// One canonical proposal control released only after durable completion.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorSignedProposalV0 {
    pub(super) position: ConsensusPosition,
    pub(super) proposal_signing_root: ProposalSigningRoot,
    pub(super) canonical_proposal_control_bytes: Vec<u8>,
    pub(super) state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorSignedProposalV0 {
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    pub const fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }

    pub fn canonical_proposal_control_bytes(&self) -> &[u8] {
        &self.canonical_proposal_control_bytes
    }

    pub const fn state_id(&self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.state_id
    }
}

/// Durable terminal summary for a second intent at one proposal slot.
///
/// The full retained and conflicting intent bytes remain chained in the
/// journal. This summary is local safety diagnostics, not objective
/// equivocation proof, signer attribution, peer evidence, or branch/finality
/// authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorProposalSafetyHaltV0 {
    pub(super) position: ConsensusPosition,
    pub(super) retained_root: ProposalSigningRoot,
    pub(super) conflicting_root: ProposalSigningRoot,
    pub(super) retained_intent_digest: [u8; 32],
    pub(super) conflicting_intent_digest: [u8; 32],
    pub(super) state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorProposalSafetyHaltV0 {
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    pub const fn retained_root(self) -> ProposalSigningRoot {
        self.retained_root
    }

    pub const fn conflicting_root(self) -> ProposalSigningRoot {
        self.conflicting_root
    }

    pub const fn retained_intent_digest(self) -> [u8; 32] {
        self.retained_intent_digest
    }

    pub const fn conflicting_intent_digest(self) -> [u8; 32] {
        self.conflicting_intent_digest
    }

    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.state_id
    }
}

/// Durable terminal summary for a second non-identical intent at one vote slot.
///
/// The full retained and conflicting intent bytes remain chained in the
/// journal. This summary is local safety diagnostics, not equivocation proof,
/// signer attribution, peer evidence, or branch/finality authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorVoteSafetyHaltV0 {
    pub(super) position: ConsensusPosition,
    pub(super) role: ConsensusVoteRole,
    pub(super) retained_target: ConsensusVoteTarget,
    pub(super) conflicting_target: ConsensusVoteTarget,
    pub(super) state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorVoteSafetyHaltV0 {
    /// Returns the conflicted height and round.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the conflicted vote role.
    pub const fn role(self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the target in the first durable intent.
    pub const fn retained_target(self) -> ConsensusVoteTarget {
        self.retained_target
    }

    /// Returns the target in the non-identical conflicting intent.
    pub const fn conflicting_target(self) -> ConsensusVoteTarget {
        self.conflicting_target
    }

    /// Returns whether the two intents selected distinct vote targets.
    pub fn changes_target(self) -> bool {
        self.retained_target != self.conflicting_target
    }

    /// Returns the terminal durable state identity.
    pub const fn state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.state_id
    }
}

/// Durable local signer stop derived from one exact finality conflict.
///
/// The referenced finality journal verified both siblings before issuing the
/// consumed capability. This compact per-key record is an enforcement and
/// audit marker, not a standalone replay-verifiable finality proof and not
/// sibling-selection or rollback authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityConflictSignerStopV0 {
    pub(super) kind: FixedValidatorFinalityHaltKindV0,
    pub(super) finality_state_id: FixedValidatorFinalityJournalStateIdV0,
    pub(super) height: ConsensusHeight,
    pub(super) first_ancestry: ConsensusAncestryId,
    pub(super) first_envelope_id: ConsensusEnvelopeId,
    pub(super) second_ancestry: ConsensusAncestryId,
    pub(super) second_envelope_id: ConsensusEnvelopeId,
    pub(super) vote_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorFinalityConflictSignerStopV0 {
    /// Returns the finality terminal class enforced by this stop.
    pub const fn kind(self) -> FixedValidatorFinalityHaltKindV0 {
        self.kind
    }

    /// Returns the exact anchored finality state that authorized this stop.
    pub const fn finality_state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.finality_state_id
    }

    /// Returns the height at which finality established the terminal conflict.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns the first ancestry in the halt's kind-specific canonical order.
    pub const fn first_ancestry(self) -> ConsensusAncestryId {
        self.first_ancestry
    }

    /// Returns the first envelope in the halt's kind-specific canonical order.
    pub const fn first_envelope_id(self) -> ConsensusEnvelopeId {
        self.first_envelope_id
    }

    /// Returns the second ancestry in the halt's kind-specific canonical order.
    pub const fn second_ancestry(self) -> ConsensusAncestryId {
        self.second_ancestry
    }

    /// Returns the second envelope in the halt's kind-specific canonical order.
    pub const fn second_envelope_id(self) -> ConsensusEnvelopeId {
        self.second_envelope_id
    }

    /// Returns the terminal vote-journal state published by this stop.
    pub const fn vote_state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.vote_state_id
    }

    pub(super) fn same_conflict(self, other: Self) -> bool {
        self.kind == other.kind
            && self.finality_state_id == other.finality_state_id
            && self.height == other.height
            && self.first_ancestry == other.first_ancestry
            && self.first_envelope_id == other.first_envelope_id
            && self.second_ancestry == other.second_ancestry
            && self.second_envelope_id == other.second_envelope_id
    }
}

/// Outcome of explicitly routing finality-conflict authority into one signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorFinalityConflictSignerStopOutcomeV0 {
    /// A new terminal stop record and chained state identity became durable.
    Stopped(FixedValidatorFinalityConflictSignerStopV0),
    /// The exact same finality conflict had already stopped this journal.
    AlreadyStopped(FixedValidatorFinalityConflictSignerStopV0),
}

/// Outcome of durably preparing one exact consensus-provided vote intent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorVotePrepareOutcomeV0 {
    /// A new full intent snapshot was durably prepared.
    Prepared(FixedValidatorPreparedVoteV0),
    /// The byte-identical full intent was already the pending preparation.
    AlreadyPrepared(FixedValidatorPreparedVoteV0),
    /// The byte-identical full intent was already completed and is releasable.
    AlreadySigned(FixedValidatorSignedVoteV0),
    /// A non-identical intent at the same slot durably halted the journal.
    Halted(FixedValidatorVoteSafetyHaltV0),
}

/// Outcome of durably preparing one exact proposal intent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorProposalPrepareOutcomeV0 {
    Prepared(FixedValidatorPreparedProposalV0),
    AlreadyPrepared(FixedValidatorPreparedProposalV0),
    AlreadySigned(FixedValidatorSignedProposalV0),
    Halted(FixedValidatorProposalSafetyHaltV0),
}

/// Internal outcome of completing one exact durably prepared vote.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub(super) enum FixedValidatorVoteSignOutcomeV0 {
    /// The journal signed, strictly self-verified, and durably completed the vote.
    Signed(FixedValidatorSignedVoteV0),
    /// The same prepared capability already completed and its bytes are releasable.
    AlreadySigned(FixedValidatorSignedVoteV0),
}

/// Explicit caller assertion that one exact prepared state identity is durable
/// in the separately protected external monotonic anchor.
///
/// The journal can check that the assertion names its current live preparation,
/// but it cannot inspect or prove the durability of the external store. Private
/// fields and a live-session seal prevent safe callers from constructing or
/// transferring this capability between signing sessions.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorDurablePrepareAcknowledgementV0 {
    pub(super) prepared: FixedValidatorPreparedVoteV0,
    pub(super) session_seal: Arc<()>,
}

/// Opaque assertion that one exact proposal preparation is externally durable.
///
/// The journal checks that the assertion names its current live proposal
/// preparation but cannot inspect the external monotonic store. The anchored
/// wrapper supplies this assertion only after advancing its owned anchor.
/// Private fields and a live-session seal prevent safe cross-session transfer.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorDurableProposalPrepareAcknowledgementV0 {
    pub(super) prepared: FixedValidatorPreparedProposalV0,
    pub(super) session_seal: Arc<()>,
}

/// One exact durable signer-height advance awaiting external acknowledgement.
///
/// The private finality capability keeps its issuing finality journal borrowed
/// from strict reconstruction through external anchoring and live signer
/// advancement. Dropping or forgetting this value requires an anchored journal
/// reopen before the persisted child lineage can issue another session.
#[must_use]
pub struct FixedValidatorPreparedHeightAdvanceV0<'finality> {
    pub(super) transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(super) session_seal: Arc<()>,
}

impl FixedValidatorPreparedHeightAdvanceV0<'_> {
    /// Returns the vote-journal state identity that must be externally durable.
    pub const fn state_id(&self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

/// One exact durable higher-round checkpoint awaiting external acknowledgement.
///
/// The private consensus transition keeps its internally derived target cursor,
/// complete post-jump state, exact quorum evidence, and originating live-state
/// provenance sealed until this same signing session consumes it. Dropping the
/// value leaves the session blocked; an exact anchored reopen is then required.
#[must_use]
pub struct FixedValidatorPreparedHigherRoundAdvanceV0<'branch> {
    pub(super) transition: VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(super) session_seal: Arc<()>,
}

impl FixedValidatorPreparedHigherRoundAdvanceV0<'_> {
    /// Returns the checkpoint state identity that must be externally durable.
    pub const fn state_id(&self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.prepared_state_id
    }
}

/// Inclusive caller-local ceiling for sequential signer-round reconstruction.
///
/// Recovery derives every round from the exact retained branch rather than
/// accepting a caller-selected round. This limit bounds that read-only work;
/// zero permits recovery only at round zero. It is an operator work limit, not
/// consensus validity and not part of either journal's durable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorSignerRecoveryRoundLimitV0(pub(super) u64);

impl FixedValidatorSignerRecoveryRoundLimitV0 {
    /// Constructs an inclusive maximum recoverable round.
    pub const fn new(maximum_round: u64) -> Self {
        Self(maximum_round)
    }

    /// Returns the inclusive maximum recoverable round.
    pub const fn maximum_round(self) -> u64 {
        self.0
    }
}

/// Opaque authority to recover one exact externally anchored signing lineage.
///
/// Only a healthy, recoverable vote journal at its exact externally durable
/// state can issue this non-clone capability. It borrows that journal until a
/// finality journal consumes it, preventing an intervening signer mutation.
/// Private fields deny caller-selected branch, height, round, or signer input.
#[must_use]
pub struct FixedValidatorAnchoredSignerRecoveryV0<'journal> {
    pub(super) _journal: &'journal FixedValidatorVoteSafetyJournalV0,
    pub(crate) lineage: RetainedSigningLineageV0,
    pub(crate) required_position: ConsensusPosition,
    pub(crate) vote_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(crate) signer: ConsensusKey,
    pub(crate) session_seal: Arc<()>,
}

impl FixedValidatorAnchoredSignerRecoveryV0<'_> {
    pub(crate) fn into_recovered(
        self,
        branch: FixedConsensusBranchV0,
    ) -> FixedValidatorRecoveredSignerBranchV0 {
        FixedValidatorRecoveredSignerBranchV0 {
            branch,
            required_position: self.required_position,
            vote_state_id: self.vote_state_id,
            session_seal: self.session_seal,
        }
    }
}

/// Opaque branch reconstructed for one exact anchored signer lineage.
///
/// The value is neither cloneable nor directly inspectable. Only the vote
/// journal that issued the originating capability can consume it to create its
/// sole signing session and release the exact branch alongside that session.
#[must_use]
pub struct FixedValidatorRecoveredSignerBranchV0 {
    pub(crate) branch: FixedConsensusBranchV0,
    pub(crate) required_position: ConsensusPosition,
    pub(crate) vote_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(crate) session_seal: Arc<()>,
}

/// One exact recovered branch paired with the vote journal's sole live session.
///
/// Releasing the branch only after capability, lineage, anchor, provenance, and
/// round replay checks prevents halted finality history from becoming a general
/// branch-read API. The branch itself grants no selection or finality authority.
#[must_use]
pub struct FixedValidatorRecoveredSigningSessionV0<'journal> {
    pub(super) branch: FixedConsensusBranchV0,
    pub(super) session: FixedValidatorVoteSafetySigningSessionV0<'journal>,
}

impl<'journal> FixedValidatorRecoveredSigningSessionV0<'journal> {
    /// Returns the exact branch whose next height is owned by this session.
    pub const fn branch(&self) -> &FixedConsensusBranchV0 {
        &self.branch
    }

    /// Returns read-only access to the recovered signing session.
    pub const fn session(&self) -> &FixedValidatorVoteSafetySigningSessionV0<'journal> {
        &self.session
    }

    /// Returns mutable access to the recovered signing session.
    pub fn session_mut(&mut self) -> &mut FixedValidatorVoteSafetySigningSessionV0<'journal> {
        &mut self.session
    }

    /// Separates the exact recovered branch and its sole signing session.
    pub fn into_parts(
        self,
    ) -> (
        FixedConsensusBranchV0,
        FixedValidatorVoteSafetySigningSessionV0<'journal>,
    ) {
        (self.branch, self.session)
    }
}

/// The sole journal-issued fixed-validator lock-state and signing lineage.
///
/// One open journal handle issues at most one session, and issuance is never
/// restored by dropping or forgetting the value. The session owns the private
/// lock state and exposes only the fixed kernel's explicit transitions,
/// including branch-bound proposal intent preparation. It does not expose
/// mutable state access, raw intent submission, or direct key use.
#[must_use]
pub struct FixedValidatorVoteSafetySigningSessionV0<'journal> {
    pub(super) journal: &'journal mut FixedValidatorVoteSafetyJournalV0,
    pub(super) lock_state: FixedValidatorLockStateV0,
    pub(super) pending_height_advance: Option<FixedValidatorVoteSafetyJournalStateIdV0>,
    pub(super) pending_higher_round_advance: Option<FixedValidatorVoteSafetyJournalStateIdV0>,
}

#[derive(Debug)]
pub(super) struct RetainedVote {
    pub(super) observed_intent: ObservedFixedValidatorVoteIntentV0,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(super) signed: Option<FixedValidatorSignedVoteV0>,
}

#[derive(Debug)]
pub(super) struct RetainedProposal {
    pub(super) observed_intent: ObservedFixedValidatorProposalIntentV0,
    pub(super) prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    pub(super) signed: Option<FixedValidatorSignedProposalV0>,
}

#[derive(Clone, Debug)]
pub(super) enum RetainedCurrentLineageStateV0 {
    Vote(VoteSlot),
    Proposal {
        position: ConsensusPosition,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    HigherRound {
        checkpoint: Box<ObservedFixedValidatorHigherRoundCheckpointV0>,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
}

impl RetainedCurrentLineageStateV0 {
    pub(super) fn position(&self) -> ConsensusPosition {
        match self {
            Self::Vote(slot) => slot.position,
            Self::Proposal { position, .. } => *position,
            Self::HigherRound { checkpoint, .. } => checkpoint.position(),
        }
    }

    pub(super) fn phase(&self) -> FixedValidatorLockPhaseV0 {
        match self {
            Self::Vote(slot) => phase_for_vote_role(slot.role),
            Self::Proposal { .. } => FixedValidatorLockPhaseV0::Proposal,
            Self::HigherRound { checkpoint, .. } => checkpoint.phase(),
        }
    }
}
