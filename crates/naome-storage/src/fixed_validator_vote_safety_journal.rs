//! Crash-consistent fixed-validator V0 vote preparation and release.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusAncestryId, ConsensusContextV0, ConsensusEnvelopeId, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, ConsensusSignature, ConsensusVoteId, ConsensusVoteRole,
    ConsensusVoteTarget, ConsensusVoteVerifyError, FixedAgreementSetId,
    FixedConsensusBranchCoordinateV0, FixedConsensusBranchV0, FixedConsensusRoundV0,
    FixedValidatorHigherRoundCheckpointErrorV0, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateError, FixedValidatorLockStateV0, FixedValidatorLockedValueV0,
    FixedValidatorUnsignedVoteEffectV0, FixedValidatorValidValueV0, FixedValidatorVoteIntentError,
    FixedValidatorVoteIntentV0, ObservedFixedValidatorHigherRoundCheckpointV0,
    ObservedFixedValidatorVoteIntentV0, ProposerSelectionError, VerifiedConsensusVoteV0,
    VerifiedFixedConsensusProposalV0, VerifiedFixedValidatorHigherRoundAdvanceV0,
    VerifiedReplayFixedValidatorHigherRoundCheckpointV0, VerifiedReplayFixedValidatorVoteIntentV0,
};
use sha2::{Digest, Sha256};

use super::fixed_validator_anchor::{
    AnchorPositionV0, FixedValidatorAnchorErrorV0, FixedValidatorAnchorFileV0,
    JournalAnchorTransitionV0, sync_directory,
};
use super::fixed_validator_finality_journal::{
    FixedValidatorDurableFinalityConflictV0, FixedValidatorDurableFinalityTransitionV0,
    FixedValidatorFinalityJournalStateIdV0,
};
use super::{AppendPhase, ExclusiveLockError, StoreIo, open_exclusive_lock};

const JOURNAL_HEADER: &[u8] = b"naome:fixed-validator-vote-safety-journal:v0\0";
const GENESIS_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-state-genesis:v0\0";
const STEP_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-state-step:v0\0";
const FILE_STEM: &str = "fixed-validator-vote-safety-";
const LOCK_SUFFIX: &str = ".lock";
const JOURNAL_SUFFIX: &str = ".journal";

const CHAIN_ID_BYTES: usize = 32;
const GENESIS_ID_BYTES: usize = 32;
const PROTOCOL_VERSION_BYTES: usize = 4;
const FIXED_SET_ID_BYTES: usize = FixedAgreementSetId::BYTE_LENGTH;
const CONSENSUS_KEY_BYTES: usize = 32;
const REPLAY_LIMIT_BYTES: usize = 8;
const HEADER_FIELDS_BYTES: usize = CHAIN_ID_BYTES
    + GENESIS_ID_BYTES
    + PROTOCOL_VERSION_BYTES
    + FIXED_SET_ID_BYTES
    + CONSENSUS_KEY_BYTES
    + REPLAY_LIMIT_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + HEADER_FIELDS_BYTES;

const PREPARE_RECORD: u8 = 1;
const COMPLETE_RECORD: u8 = 2;
const CONFLICT_HALT_RECORD: u8 = 3;
const SIGNING_LINEAGE_RECORD: u8 = 4;
const FINALITY_CONFLICT_STOP_RECORD: u8 = 5;
const HIGHER_ROUND_CHECKPOINT_RECORD: u8 = 6;
const SIGNING_LINEAGE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-signing-lineage:v0\0";
const SIGNING_LINEAGE_ID_BYTES: usize = 32;
const SIGNING_LINEAGE_PAYLOAD_BYTES: usize = 8 + SIGNING_LINEAGE_ID_BYTES;
const SIGNING_LINEAGE_BODY_BYTES: usize = 1 + SIGNING_LINEAGE_PAYLOAD_BYTES;
const FINALITY_CONFLICT_STOP_PAYLOAD_BYTES: usize = 32 + 8 + 32 + 32 + 32 + 32;
const FINALITY_CONFLICT_STOP_BODY_BYTES: usize = 1 + FINALITY_CONFLICT_STOP_PAYLOAD_BYTES;
const RECORD_LENGTH_BYTES: u64 = 4;
const STATE_ID_BYTES: u64 = FixedValidatorVoteSafetyJournalStateIdV0::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = RECORD_LENGTH_BYTES + STATE_ID_BYTES;
const SIGNED_VOTE_BODY_BYTES: usize = 1 + VerifiedConsensusVoteV0::BYTE_LENGTH;
const MIN_RECORD_BODY_BYTES: usize = 1 + FixedValidatorVoteIntentV0::MIN_BYTE_LENGTH;
const MAX_RECORD_BODY_BYTES: usize = 1 + FixedValidatorVoteIntentV0::MAX_BYTE_LENGTH;
const MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH;
const MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH;
const MAX_BOUNDED_RECORD_BODY_BYTES: usize =
    if MAX_RECORD_BODY_BYTES > MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES {
        MAX_RECORD_BODY_BYTES
    } else {
        MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES
    };

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
pub struct FixedValidatorVoteSafetyReplayLimitV0(u64);

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

/// Chained identity of one exact durable vote-safety journal state.
///
/// The genesis identity commits the synchronized header. Every later identity
/// commits the preceding identity and one exact prepare, completion, halt,
/// signing-lineage, finality-conflict stop, or higher-round checkpoint record.
/// This local persistence identity is not consensus ancestry, a vote identity,
/// finality, or a globally trusted checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct FixedValidatorVoteSafetyJournalStateIdV0([u8; Self::BYTE_LENGTH]);

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
struct VoteSlot {
    position: ConsensusPosition,
    role: ConsensusVoteRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigningLineageIdV0([u8; SIGNING_LINEAGE_ID_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedSigningLineageV0 {
    pub(crate) height: ConsensusHeight,
    pub(crate) id: SigningLineageIdV0,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl VoteSlot {
    const fn new(position: ConsensusPosition, role: ConsensusVoteRole) -> Self {
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
    slot: VoteSlot,
    target: ConsensusVoteTarget,
    prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
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
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
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
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    vote_id: ConsensusVoteId,
    canonical_bytes: Vec<u8>,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
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

/// Durable terminal summary for a second non-identical intent at one vote slot.
///
/// The full retained and conflicting intent bytes remain chained in the
/// journal. This summary is local safety diagnostics, not equivocation proof,
/// signer attribution, peer evidence, or branch/finality authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorVoteSafetyHaltV0 {
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    retained_target: ConsensusVoteTarget,
    conflicting_target: ConsensusVoteTarget,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
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
    finality_state_id: FixedValidatorFinalityJournalStateIdV0,
    height: ConsensusHeight,
    selected_ancestry: ConsensusAncestryId,
    selected_envelope_id: ConsensusEnvelopeId,
    conflicting_ancestry: ConsensusAncestryId,
    conflicting_envelope_id: ConsensusEnvelopeId,
    vote_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
}

impl FixedValidatorFinalityConflictSignerStopV0 {
    /// Returns the exact anchored finality state that authorized this stop.
    pub const fn finality_state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.finality_state_id
    }

    /// Returns the height at which finality selected distinct siblings.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns the first selected value ancestry retained by finality.
    pub const fn selected_ancestry(self) -> ConsensusAncestryId {
        self.selected_ancestry
    }

    /// Returns the retained first finality-envelope identity.
    pub const fn selected_envelope_id(self) -> ConsensusEnvelopeId {
        self.selected_envelope_id
    }

    /// Returns the conflicting finalized value ancestry.
    pub const fn conflicting_ancestry(self) -> ConsensusAncestryId {
        self.conflicting_ancestry
    }

    /// Returns the conflicting finality-envelope identity.
    pub const fn conflicting_envelope_id(self) -> ConsensusEnvelopeId {
        self.conflicting_envelope_id
    }

    /// Returns the terminal vote-journal state published by this stop.
    pub const fn vote_state_id(self) -> FixedValidatorVoteSafetyJournalStateIdV0 {
        self.vote_state_id
    }

    fn same_conflict(self, other: Self) -> bool {
        self.finality_state_id == other.finality_state_id
            && self.height == other.height
            && self.selected_ancestry == other.selected_ancestry
            && self.selected_envelope_id == other.selected_envelope_id
            && self.conflicting_ancestry == other.conflicting_ancestry
            && self.conflicting_envelope_id == other.conflicting_envelope_id
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

/// Internal outcome of completing one exact durably prepared vote.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
enum FixedValidatorVoteSignOutcomeV0 {
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
    prepared: FixedValidatorPreparedVoteV0,
    session_seal: Arc<()>,
}

/// One exact durable signer-height advance awaiting external acknowledgement.
///
/// The private finality capability keeps its issuing finality journal borrowed
/// from strict reconstruction through external anchoring and live signer
/// advancement. Dropping or forgetting this value requires an anchored journal
/// reopen before the persisted child lineage can issue another session.
#[must_use]
pub struct FixedValidatorPreparedHeightAdvanceV0<'finality> {
    transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    session_seal: Arc<()>,
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
    transition: VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>,
    prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    session_seal: Arc<()>,
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
pub struct FixedValidatorSignerRecoveryRoundLimitV0(u64);

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
    _journal: &'journal FixedValidatorVoteSafetyJournalV0,
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
    branch: FixedConsensusBranchV0,
    session: FixedValidatorVoteSafetySigningSessionV0<'journal>,
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
/// lock state and exposes only the fixed kernel's explicit transitions. It does
/// not expose mutable state access, raw intent submission, or direct key use.
#[must_use]
pub struct FixedValidatorVoteSafetySigningSessionV0<'journal> {
    journal: &'journal mut FixedValidatorVoteSafetyJournalV0,
    lock_state: FixedValidatorLockStateV0,
    pending_height_advance: Option<FixedValidatorVoteSafetyJournalStateIdV0>,
    pending_higher_round_advance: Option<FixedValidatorVoteSafetyJournalStateIdV0>,
}

#[derive(Debug)]
struct RetainedVote {
    observed_intent: ObservedFixedValidatorVoteIntentV0,
    prepared_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    signed: Option<FixedValidatorSignedVoteV0>,
}

#[derive(Clone, Debug)]
enum RetainedCurrentLineageStateV0 {
    Vote(VoteSlot),
    HigherRound {
        checkpoint: Box<ObservedFixedValidatorHigherRoundCheckpointV0>,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
}

impl RetainedCurrentLineageStateV0 {
    fn position(&self) -> ConsensusPosition {
        match self {
            Self::Vote(slot) => slot.position,
            Self::HigherRound { checkpoint, .. } => checkpoint.position(),
        }
    }

    fn phase(&self) -> FixedValidatorLockPhaseV0 {
        match self {
            Self::Vote(slot) => phase_for_vote_role(slot.role),
            Self::HigherRound { checkpoint, .. } => checkpoint.phase(),
        }
    }
}

/// One exclusively opened, per-key fixed-validator vote-safety journal.
///
/// Construction consumes and privately retains the local [`SigningKey`]. The
/// enabled `zeroize` feature clears its secret bytes on drop. Rust ownership
/// cannot prove that no external seed or key copy exists; anti-equivocation
/// requires this journal to be the sole operational vote-signing path.
///
/// The journal provides no producer authorization, remote-signing protocol,
/// timeout scheduling, networking, peer trust, validator selection, branch
/// choice, or finality authority.
#[must_use]
pub struct FixedValidatorVoteSafetyJournalV0 {
    _lock: File,
    signing_key: SigningKey,
    core: FixedValidatorVoteSafetyJournalCore<File>,
    session_issued: bool,
    session_seal: Arc<()>,
}

/// A per-key vote-safety journal paired with one independent crash-safe anchor.
///
/// Every state-changing frame advances the anchor before the journal publishes
/// its outcome, signing capability, live height or round effect, terminal stop,
/// or signed vote bytes. The two files remain separate commit units and no
/// cross-file atomic transaction or automatic repair is claimed.
#[must_use]
pub struct FixedValidatorAnchoredVoteSafetyJournalV0 {
    journal: FixedValidatorVoteSafetyJournalV0,
}

/// The sole signing session issued by an anchored per-key journal.
#[must_use]
pub struct FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
    session: FixedValidatorVoteSafetySigningSessionV0<'journal>,
}

/// One exactly recovered branch paired with an anchored signing session.
#[must_use]
pub struct FixedValidatorAnchoredRecoveredSigningSessionV0<'journal> {
    branch: FixedConsensusBranchV0,
    session: FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal>,
}

impl FixedValidatorVoteSafetyJournalV0 {
    /// Creates one empty per-key journal without replacing existing bytes.
    ///
    /// The complete header is synchronized before the genesis state identity is
    /// exposed. Parent-directory-entry durability remains a provisioning
    /// responsibility outside this file protocol.
    pub fn create(
        directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)?;
        let state_id = genesis_state_id(&prefix);
        let directory = directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(directory, signer)?;
        let lock = open_key_lock(&lock_path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Create { source })?;
        file.append_write_all(AppendPhase::Body, &prefix)
            .and_then(|()| file.append_sync_all(AppendPhase::Body))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Create { source })?;
        Ok(Self {
            _lock: lock,
            signing_key,
            core: FixedValidatorVoteSafetyJournalCore::empty(
                file,
                context,
                fixed_set_id,
                signer,
                replay_limit,
                state_id,
            ),
            session_issued: false,
            session_seal: Arc::new(()),
        })
    }

    /// Exclusively opens and strictly replays one externally anchored journal.
    ///
    /// Replay returns no key-owning handle unless its complete verified record
    /// prefix has exactly `expected_state_id`. Only then may an incomplete final
    /// record be truncated and synchronized. A complete unanchored suffix,
    /// deletion, corruption, or another expected identity fails closed.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        expected_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let expected_prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)?;
        let directory = directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(directory, signer)?;
        let lock = open_key_lock(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Open { source })?;
        let core = FixedValidatorVoteSafetyJournalCore::replay(
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            expected_prefix,
            expected_state_id,
            None,
        )?;
        Ok(Self {
            _lock: lock,
            signing_key,
            core,
            session_issued: false,
            session_seal: Arc::new(()),
        })
    }

    /// Returns the exact header-bound consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.context
    }

    /// Returns the exact header-bound fixed agreement-set identity.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.core.fixed_set_id
    }

    /// Returns the public consensus key owned by this journal.
    pub const fn signer(&self) -> ConsensusKey {
        self.core.signer
    }

    /// Returns the local prepared-vote replay ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorVoteSafetyReplayLimitV0 {
        self.core.replay_limit
    }

    /// Durably binds the exact current branch lineage used by signing recovery.
    ///
    /// A new or legacy journal without a lineage record appends one synchronized
    /// content binding after strictly constructing or replaying the supplied
    /// typed round. An exact existing binding is no-write idempotence. A
    /// different branch or height fails without replacing it. The returned
    /// state identity must be externally durable before session issuance.
    pub fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.bind_signing_lineage(round)
    }

    /// Issues the only signing session available from this open journal handle.
    ///
    /// The supplied typed round must match the retained signing-lineage record.
    /// An empty current lineage starts from exact branch-derived round zero; a
    /// lineage with a latest durably completed vote or higher-round checkpoint
    /// reconstructs only that exact post-effect state after full typed replay.
    /// The caller must explicitly assert the exact current journal state as
    /// externally durable. A pending preparation or terminal halt cannot issue a
    /// session. The issuance latch is monotonic for this handle: dropping or
    /// forgetting the returned value does not permit a replacement session.
    pub fn issue_signing_session(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorVoteSafetySigningSessionV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let lock_state = self.core.recover_lock_state_for_round(round)?;

        self.session_issued = true;
        Ok(FixedValidatorVoteSafetySigningSessionV0 {
            journal: self,
            lock_state,
            pending_height_advance: None,
            pending_higher_round_advance: None,
        })
    }

    /// Issues authority to reconstruct this exact anchored signing lineage.
    ///
    /// The caller explicitly acknowledges the journal's complete current state
    /// as externally durable. A pending vote, either terminal cause, missing
    /// lineage, or prior session issuance fails before capability publication.
    /// The returned value accepts no caller-selected branch, height, signer, or
    /// round.
    pub fn acknowledge_signer_recovery_is_externally_durable(
        &self,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorAnchoredSignerRecoveryV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let lineage = self
            .core
            .lineage
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)?;
        let required_position = self.core.signer_recovery_position(lineage);
        Ok(FixedValidatorAnchoredSignerRecoveryV0 {
            _journal: self,
            lineage,
            required_position,
            vote_state_id: self.core.state_id,
            signer: self.core.signer,
            session_seal: Arc::clone(&self.session_seal),
        })
    }

    /// Consumes one exact finality-reconstructed branch and issues one session.
    ///
    /// The recovered value must descend from this handle's own anchored
    /// capability. The current external vote anchor, session provenance, exact
    /// lineage, and latest durable current-lineage position are rechecked before
    /// the monotonic issuance latch changes. Sequential round reconstruction is
    /// bounded by the caller-local inclusive work ceiling.
    pub fn issue_recovered_signing_session(
        &mut self,
        recovered: FixedValidatorRecoveredSignerBranchV0,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    ) -> Result<FixedValidatorRecoveredSigningSessionV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.session_seal, &recovered.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignSignerRecovery);
        }
        if recovered.vote_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::StaleSignerRecovery {
                    recovered: recovered.vote_state_id,
                    current: self.core.state_id,
                },
            );
        }
        let required_round = recovered.required_position.round().value();
        if required_round > round_limit.maximum_round() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                    required: required_round,
                    maximum: round_limit.maximum_round(),
                },
            );
        }

        let mut round = recovered
            .branch
            .begin_round_zero()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRound)?;
        if round.position().height() != recovered.required_position.height() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryPositionMismatch {
                    required: recovered.required_position,
                    actual: round.position(),
                },
            );
        }
        for _ in 0..required_round {
            round = round
                .advance_round()
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRound)?;
        }
        debug_assert_eq!(round.position(), recovered.required_position);
        let lock_state = self.core.recover_lock_state_for_round(&round)?;
        drop(round);

        self.session_issued = true;
        Ok(FixedValidatorRecoveredSigningSessionV0 {
            branch: recovered.branch,
            session: FixedValidatorVoteSafetySigningSessionV0 {
                journal: self,
                lock_state,
                pending_height_advance: None,
                pending_higher_round_advance: None,
            },
        })
    }

    /// Returns the current exact journal-state identity, including after either
    /// terminal cause.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.state_id)
    }

    /// Durably stops this signer from one exact anchored finality conflict.
    ///
    /// This path remains available before session issuance and after a live
    /// session is dropped. It accepts conflict authority only for this
    /// journal's exact consensus context and fixed validator set. The stop is
    /// monotonic, may preempt an unresolved preparation, and never performs a
    /// key operation or selects either conflicting sibling.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.core.stop_after_durable_finality_conflict(conflict)
    }

    /// Returns the durable terminal halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorVoteSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.halt)
    }

    /// Returns the durable finality-conflict signer stop, if present.
    pub fn finality_conflict_stop(
        &self,
    ) -> Result<
        Option<FixedValidatorFinalityConflictSignerStopV0>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.core.ensure_healthy()?;
        Ok(self.core.finality_conflict_stop)
    }

    /// Returns a capability for the sole pending durable preparation.
    #[cfg(test)]
    fn pending_prepared_vote(
        &self,
    ) -> Result<Option<FixedValidatorPreparedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.pending_capability())
    }

    /// Returns read-only diagnostics for an uncompleted preparation.
    ///
    /// This remains readable after an anchored reopen has deliberately made
    /// the pending record non-signable.
    pub fn pending_vote(
        &self,
    ) -> Result<Option<FixedValidatorPendingVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.pending_summary())
    }

    /// Durably appends and synchronizes one full consensus-provided intent.
    ///
    /// No signing occurs in this stage. Byte-identical repetition is
    /// idempotent. Any non-identical intent for an existing context/height/
    /// round/role slot durably appends a terminal halt before returning.
    fn prepare_vote(
        &mut self,
        intent: FixedValidatorVoteIntentV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.prepare_vote(intent)
    }

    /// Signs only the exact durable preparation and releases bytes only after sync.
    fn sign_prepared_vote(
        &mut self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorVoteSignOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.sign_prepared_vote(&self.signing_key, prepared)
    }

    /// Returns one retained completed vote for local diagnostics or replay.
    ///
    /// Exact bytes remain available behind a later pending preparation, but
    /// either durable terminal cause denies every vote release.
    pub fn retained_signed_vote(
        &self,
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    ) -> Result<Option<FixedValidatorSignedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_not_halted()?;
        Ok(self
            .core
            .votes
            .get(&VoteSlot::new(position, role))
            .and_then(|record| record.signed.clone()))
    }

    /// Returns the exact state-and-intent bytes behind the latest completed vote.
    ///
    /// A caller may pass these bytes to the consensus crate's non-signing,
    /// typed-round replay verifier to reconstruct lock, valid-value, and phase
    /// state in completed-vote test fixtures. Production session recovery instead
    /// selects the latest durable current-lineage vote or checkpoint. Pending
    /// records are withheld because V0 never permits a restarted caller to advance
    /// from an unresolved prepare boundary. Either durable terminal cause also
    /// denies operational recovery.
    #[cfg(test)]
    fn latest_completed_state_and_vote_intent_bytes(
        &self,
    ) -> Result<Option<&[u8]>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_recoverable()?;
        let Some(latest) = self.core.latest_slot else {
            return Ok(None);
        };
        let retained = self
            .core
            .votes
            .get(&latest)
            .expect("the latest vote slot is retained");
        retained
            .signed
            .as_ref()
            .expect("a healthy non-pending latest vote is durably completed");
        Ok(Some(
            retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes(),
        ))
    }
}

impl FixedValidatorAnchoredVoteSafetyJournalV0 {
    /// Creates one per-key journal and its independently synchronized genesis anchor.
    pub fn create(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredVoteSafetyJournalErrorV0> {
        let journal_directory = journal_directory.as_ref();
        let mut journal = FixedValidatorVoteSafetyJournalV0::create(
            journal_directory,
            context,
            fixed_set_id,
            signing_key,
            replay_limit,
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        sync_directory(journal_directory)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        let state_id = journal
            .state_id()
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let anchor = FixedValidatorAnchorFileV0::create_vote(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            journal.signer(),
            replay_limit.max_prepared_votes(),
            *state_id.as_bytes(),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        journal.core.anchor = Some(anchor);
        Ok(Self { journal })
    }

    /// Strictly opens one per-key journal only at its independent anchor position.
    pub fn open(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let expected_prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let journal_directory = journal_directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(journal_directory, signer)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let lock = open_key_lock(&lock_path)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let anchor = FixedValidatorAnchorFileV0::open_vote(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            signer,
            replay_limit.max_prepared_votes(),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        let anchored = anchor.position();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| {
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal(
                    FixedValidatorVoteSafetyJournalErrorV0::Open { source },
                )
            })?;
        let mut core = FixedValidatorVoteSafetyJournalCore::replay(
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            expected_prefix,
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(anchored.state_id),
            Some(anchored.sequence),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        anchor
            .stabilize()
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        core.anchor = Some(anchor);
        Ok(Self {
            journal: FixedValidatorVoteSafetyJournalV0 {
                _lock: lock,
                signing_key,
                core,
                session_issued: false,
                session_seal: Arc::new(()),
            },
        })
    }

    /// Returns the exact context bound by both journal and anchor.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.journal.context()
    }

    /// Returns the exact fixed agreement-set identity bound by both files.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.journal.fixed_agreement_set_id()
    }

    /// Returns the public consensus key owned by this per-key pair.
    pub const fn signer(&self) -> ConsensusKey {
        self.journal.signer()
    }

    /// Returns the header- and anchor-bound preparation ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorVoteSafetyReplayLimitV0 {
        self.journal.replay_limit()
    }

    /// Returns the current healthy journal-state identity for diagnostics.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.state_id()
    }

    /// Binds the initial lineage and advances the anchor before returning.
    ///
    /// Repeating the exact current binding is no-write idempotence.
    pub fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.bind_signing_lineage(round)
    }

    /// Issues the sole session from the already internally anchored state.
    ///
    /// No caller state identity is accepted because this wrapper owns and
    /// synchronizes the only anchor paired with the journal.
    pub fn issue_signing_session(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<
        FixedValidatorAnchoredVoteSafetySigningSessionV0<'_>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let state_id = self.journal.state_id()?;
        self.journal
            .issue_signing_session(round, state_id)
            .map(|session| FixedValidatorAnchoredVoteSafetySigningSessionV0 { session })
    }

    /// Issues restart authority from the exact internally anchored lineage.
    pub fn acknowledge_signer_recovery(
        &self,
    ) -> Result<FixedValidatorAnchoredSignerRecoveryV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_recovery_is_externally_durable(state_id)
    }

    /// Issues the sole session for one capability-recovered exact branch.
    ///
    /// The wrapper reuses its current internally anchored state and accepts only
    /// the caller-local derivation-work ceiling.
    pub fn issue_recovered_signing_session(
        &mut self,
        recovered: FixedValidatorRecoveredSignerBranchV0,
        round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    ) -> Result<
        FixedValidatorAnchoredRecoveredSigningSessionV0<'_>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let state_id = self.journal.state_id()?;
        let recovered =
            self.journal
                .issue_recovered_signing_session(recovered, state_id, round_limit)?;
        let FixedValidatorRecoveredSigningSessionV0 { branch, session } = recovered;
        Ok(FixedValidatorAnchoredRecoveredSigningSessionV0 {
            branch,
            session: FixedValidatorAnchoredVoteSafetySigningSessionV0 { session },
        })
    }

    /// Appends a proof-backed terminal stop and anchors it before publication.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.journal.stop_after_durable_finality_conflict(conflict)
    }

    /// Returns the durable same-slot terminal halt, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorVoteSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.halt()
    }

    /// Returns the durable proof-backed finality-conflict stop, if present.
    pub fn finality_conflict_stop(
        &self,
    ) -> Result<
        Option<FixedValidatorFinalityConflictSignerStopV0>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.journal.finality_conflict_stop()
    }

    /// Returns read-only diagnostics for an uncompleted preparation.
    pub fn pending_vote(
        &self,
    ) -> Result<Option<FixedValidatorPendingVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.pending_vote()
    }

    /// Returns one retained completed vote unless either terminal cause denies it.
    pub fn retained_signed_vote(
        &self,
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    ) -> Result<Option<FixedValidatorSignedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.retained_signed_vote(position, role)
    }
}

impl FixedValidatorVoteSafetySigningSessionV0<'_> {
    /// Returns the exact current height and round of this sole live lineage.
    pub const fn position(&self) -> ConsensusPosition {
        self.lock_state.position()
    }

    /// Returns the current fixed-validator kernel phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.lock_state.phase()
    }

    /// Returns the current locked value, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.lock_state.locked_value()
    }

    /// Returns the current retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.lock_state.valid_value()
    }

    /// Durably stops this already-live signer from anchored finality conflict.
    ///
    /// Stop authority deliberately preempts pending vote, height, or higher-round
    /// work. Once the terminal record synchronizes, every later session transition
    /// and key-use path fails closed; bytes released before this call cannot be
    /// retracted.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let outcome = self
            .journal
            .core
            .stop_after_durable_finality_conflict(conflict)?;
        self.pending_height_advance = None;
        self.pending_higher_round_advance = None;
        Ok(outcome)
    }

    /// Decides the current proposal path's prevote without exposing mutable state.
    pub fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_prevote_for_proposal(proposal)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Decides the absent-or-rejected-proposal prevote path.
    pub fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_prevote_without_proposal()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Applies one current-round proposal prevote quorum and decides precommit.
    pub fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_for_proposal_quorum(round, proposal, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Applies one current-round nil prevote quorum and decides nil precommit.
    pub fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_for_nil_quorum(round, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Decides nil precommit when no current-round prevote quorum is available.
    pub fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_without_quorum()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Advances this lineage through one exact sequential branch-derived round.
    pub fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .advance_round(next_round)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Advances after one exact current-round precommit/nil quorum.
    ///
    /// Journal health and pending vote, height, or higher-round work are checked
    /// before the kernel verifies the canonical certificate and exact sequential
    /// cursors. Success changes only this session's volatile lock state. Any later
    /// vote at the advanced round still passes through the unchanged durable
    /// prepare, external-anchor acknowledgement, completion, and release boundary.
    ///
    /// This method does not persist the observed quorum, schedule or infer a
    /// timeout, finalize a value, select a branch, or grant networking or peer
    /// authority.
    pub fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .advance_round_for_nil_precommit_quorum(current_round, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Verifies and durably checkpoints one phase-only higher-round catch-up.
    ///
    /// The live lock state remains unchanged while the consensus kernel derives
    /// and fully verifies the target under the caller-local inclusive maximum.
    /// The journal then synchronizes one exact chained checkpoint containing the
    /// canonical QC and complete post-jump state. No vote, key use, or live
    /// higher-round publication occurs in this stage. Every other mutable session
    /// path remains blocked until exact external acknowledgement except the
    /// explicit proof-backed finality-conflict stop, which may preempt it.
    pub fn prepare_higher_round_quorum_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_mutable()?;
        let transition = self
            .lock_state
            .prepare_higher_round_quorum_advance(
                current_round,
                canonical_certificate,
                inclusive_maximum_round,
            )
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        let prepared_state_id = self
            .journal
            .core
            .append_higher_round_checkpoint(transition.canonical_checkpoint_bytes())?;
        self.pending_higher_round_advance = Some(prepared_state_id);
        Ok(FixedValidatorPreparedHigherRoundAdvanceV0 {
            transition,
            prepared_state_id,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Acknowledges one exact durable checkpoint and publishes its live state.
    ///
    /// The external state identity, issuing session, current journal state, and
    /// latest retained checkpoint are rechecked before the consensus transition
    /// changes only position and phase. A wrong, stale, or foreign token changes
    /// no live state and leaves the session blocked; an exact anchored reopen is
    /// then the only recovery route.
    pub fn acknowledge_prepared_higher_round_is_externally_durable<'branch>(
        &mut self,
        prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        if externally_durable_state_id != prepared.prepared_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalHigherRoundAnchorMismatch {
                    prepared: prepared.prepared_state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.journal.session_seal, &prepared.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHigherRoundAdvance);
        }
        self.journal.core.ensure_operational()?;
        let latest_matches = matches!(
            self.journal.core.latest_current_lineage_state.as_ref(),
            Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
                if *state_id == prepared.prepared_state_id
        );
        if self.pending_higher_round_advance != Some(prepared.prepared_state_id)
            || self.journal.core.state_id != prepared.prepared_state_id
            || !latest_matches
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StaleHigherRoundAdvance);
        }
        let target_round = self
            .lock_state
            .apply_prepared_higher_round_quorum_advance(prepared.transition)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.pending_higher_round_advance = None;
        Ok(target_round)
    }

    /// Persists one exact finalized child before advancing signer memory.
    ///
    /// Parent, height, and child round zero are preflighted before the vote
    /// journal appends its next signing-lineage record. The returned capability
    /// keeps the finality journal immutably borrowed until the caller has made
    /// the new vote-journal state externally durable and acknowledges it.
    pub fn prepare_height_with_durable_finality<'finality>(
        &mut self,
        transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    ) -> Result<
        FixedValidatorPreparedHeightAdvanceV0<'finality>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_mutable()?;
        let child_position = self
            .lock_state
            .validate_height_transition(transition.verified_transition())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        let child_lineage_id = signing_lineage_id(
            transition.verified_transition().child_coordinate(),
            child_position.height(),
            self.journal.signer(),
        );
        let prepared_state_id = self
            .journal
            .core
            .append_signing_lineage(child_position.height(), child_lineage_id)?;
        self.pending_height_advance = Some(prepared_state_id);
        Ok(FixedValidatorPreparedHeightAdvanceV0 {
            transition,
            prepared_state_id,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Acknowledges the persisted child lineage and advances signer memory.
    ///
    /// The exact vote-journal state, session provenance, and still-live
    /// finality capability are rechecked before consuming the transition and
    /// advancing this live session. Finality authorization is point-in-time:
    /// once this exact child-lineage state is externally anchored, a later
    /// finality-journal halt alone does not retroactively revoke it. An explicit
    /// durable finality-conflict stop does. If the token is dropped before this
    /// live acknowledgement, strict reopen resumes the anchored child without a
    /// new token unless that stop has been applied.
    pub fn acknowledge_prepared_height_is_externally_durable(
        &mut self,
        prepared: FixedValidatorPreparedHeightAdvanceV0<'_>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if externally_durable_state_id != prepared.prepared_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalHeightAnchorMismatch {
                    prepared: prepared.prepared_state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.journal.session_seal, &prepared.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHeightAdvance);
        }
        self.journal.core.ensure_operational()?;
        if self.pending_height_advance != Some(prepared.prepared_state_id)
            || self.journal.core.state_id != prepared.prepared_state_id
            || self
                .journal
                .core
                .lineage
                .is_none_or(|lineage| lineage.state_id != prepared.prepared_state_id)
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StaleHeightAdvance);
        }
        let child = self
            .lock_state
            .advance_height_with_verified_transition(prepared.transition.into_verified_transition())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.pending_height_advance = None;
        Ok(child)
    }

    /// Durably prepares the exact effect produced by this session's private state.
    ///
    /// This is the only public route into the journal's raw intent preparation.
    /// It performs no key operation and returns only after the prepare body and
    /// chained state-ID footer have both synchronized.
    pub fn prepare_vote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.core.ensure_operational()?;
        self.ensure_no_pending_height_advance()?;
        self.ensure_no_pending_higher_round_advance()?;
        let intent = self
            .lock_state
            .prepare_vote_intent(round, effect, self.journal.signer())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent)?;
        self.journal.prepare_vote(intent)
    }

    /// Explicitly asserts that the exact prepared state ID is externally durable.
    ///
    /// The journal checks identity and live-session provenance, but it cannot
    /// inspect the external monotonic store. Calling this method is therefore a
    /// caller assertion that persistence completed before any key use.
    pub fn acknowledge_prepared_vote_is_externally_durable(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        if externally_durable_state_id != prepared.state_id() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalPrepareAnchorMismatch {
                    prepared: prepared.state_id(),
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        self.journal.core.validate_live_prepared_vote(prepared)?;
        Ok(FixedValidatorDurablePrepareAcknowledgementV0 {
            prepared,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Signs only an explicitly acknowledged live preparation.
    ///
    /// Session provenance, the exact prepared state ID, and current pending
    /// state are validated before the private key is invoked. Signed bytes are
    /// returned only after the completion record and footer synchronize.
    pub fn sign_prepared_vote(
        &mut self,
        acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if !Arc::ptr_eq(&self.journal.session_seal, &acknowledgement.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignPrepareAcknowledgement);
        }
        self.journal
            .core
            .validate_live_prepared_vote(acknowledgement.prepared)?;
        match self.journal.sign_prepared_vote(acknowledgement.prepared)? {
            FixedValidatorVoteSignOutcomeV0::Signed(signed) => Ok(signed),
            FixedValidatorVoteSignOutcomeV0::AlreadySigned(_) => {
                unreachable!("the live-preparation check rejects an already completed vote")
            }
        }
    }

    fn ensure_mutable(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.core.ensure_operational()?;
        self.ensure_no_pending_height_advance()?;
        self.ensure_no_pending_higher_round_advance()?;
        if let Some(pending) = self.journal.core.pending {
            Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            })
        } else {
            Ok(())
        }
    }

    fn ensure_no_pending_height_advance(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if let Some(state_id) = self.pending_height_advance {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance { state_id });
        }
        Ok(())
    }

    fn ensure_no_pending_higher_round_advance(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if let Some(state_id) = self.pending_higher_round_advance {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance { state_id },
            );
        }
        Ok(())
    }
}

impl<'journal> FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
    /// Returns the exact current height and round of this sole live lineage.
    pub const fn position(&self) -> ConsensusPosition {
        self.session.position()
    }

    /// Returns the current fixed-validator kernel phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.session.phase()
    }

    /// Returns the current locked value, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.session.locked_value()
    }

    /// Returns the current retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.session.valid_value()
    }

    /// Appends and anchors a proof-backed terminal signer stop.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session.stop_after_durable_finality_conflict(conflict)
    }

    /// Decides the current proposal path's prevote without persistence.
    pub fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_prevote_for_proposal(proposal)
    }

    /// Decides the absent-or-rejected-proposal prevote path without persistence.
    pub fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_prevote_without_proposal()
    }

    /// Applies one proposal prevote quorum and decides precommit in memory.
    pub fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .decide_precommit_for_proposal_quorum(round, proposal, canonical_certificate)
    }

    /// Applies one nil prevote quorum and decides nil precommit in memory.
    pub fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .decide_precommit_for_nil_quorum(round, canonical_certificate)
    }

    /// Decides nil precommit without a current-round quorum in memory.
    pub fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_precommit_without_quorum()
    }

    /// Advances through one exact sequential typed round in memory.
    pub fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.advance_round(next_round)
    }

    /// Advances in memory after verifying one exact nil-precommit quorum.
    pub fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .advance_round_for_nil_precommit_quorum(current_round, canonical_certificate)
    }

    /// Persists and anchors one verified higher-round checkpoint before return.
    pub fn prepare_higher_round_quorum_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session.prepare_higher_round_quorum_advance(
            current_round,
            canonical_certificate,
            inclusive_maximum_round,
        )
    }

    /// Publishes an already anchored higher-round checkpoint to live state.
    ///
    /// No caller state identity is accepted; the prepare call synchronized the
    /// paired anchor before it returned this private-field capability.
    pub fn acknowledge_prepared_higher_round<'branch>(
        &mut self,
        prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        let state_id = prepared.state_id();
        self.session
            .acknowledge_prepared_higher_round_is_externally_durable(prepared, state_id)
    }

    /// Persists and anchors one exact finality-authorized child lineage.
    pub fn prepare_height_with_durable_finality<'finality>(
        &mut self,
        transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    ) -> Result<
        FixedValidatorPreparedHeightAdvanceV0<'finality>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session
            .prepare_height_with_durable_finality(transition)
    }

    /// Advances live signer memory to an already anchored child lineage.
    ///
    /// No caller state identity is accepted; the prepared capability can only
    /// name the transition already persisted by this paired wrapper.
    pub fn acknowledge_prepared_height(
        &mut self,
        prepared: FixedValidatorPreparedHeightAdvanceV0<'_>,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorVoteSafetyJournalErrorV0> {
        let state_id = prepared.state_id();
        self.session
            .acknowledge_prepared_height_is_externally_durable(prepared, state_id)
    }

    /// Persists and anchors the exact session-derived vote preparation.
    pub fn prepare_vote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.prepare_vote(round, effect)
    }

    /// Converts an already anchored live preparation into key-use authority.
    ///
    /// The wrapper accepts no caller identity and rechecks the private prepared
    /// capability against the exact live journal state.
    pub fn acknowledge_prepared_vote(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.session
            .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
    }

    /// Signs the acknowledged preparation and anchors completion before release.
    pub fn sign_prepared_vote(
        &mut self,
        acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.sign_prepared_vote(acknowledgement)
    }
}

impl<'journal> FixedValidatorAnchoredRecoveredSigningSessionV0<'journal> {
    /// Returns the exact branch recovered for this sole signing session.
    pub const fn branch(&self) -> &FixedConsensusBranchV0 {
        &self.branch
    }

    /// Returns the recovered anchored signing session read-only.
    pub const fn session(&self) -> &FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
        &self.session
    }

    /// Returns the recovered anchored signing session mutably.
    pub fn session_mut<'session>(
        &'session mut self,
    ) -> &'session mut FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
        &mut self.session
    }

    /// Separates the exact recovered branch and its sole anchored session.
    ///
    /// The session continues to borrow the same per-key journal, so this does
    /// not widen key, recovery, or second-session authority.
    pub fn into_parts(
        self,
    ) -> (
        FixedConsensusBranchV0,
        FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal>,
    ) {
        (self.branch, self.session)
    }
}

struct FixedValidatorVoteSafetyJournalCore<F> {
    file: F,
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    signer: ConsensusKey,
    replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    votes: HashMap<VoteSlot, RetainedVote>,
    pending: Option<VoteSlot>,
    live_pending_intent: Option<FixedValidatorVoteIntentV0>,
    latest_slot: Option<VoteSlot>,
    lineage: Option<RetainedSigningLineageV0>,
    latest_current_lineage_state: Option<RetainedCurrentLineageStateV0>,
    prepared_count: u64,
    halt: Option<FixedValidatorVoteSafetyHaltV0>,
    finality_conflict_stop: Option<FixedValidatorFinalityConflictSignerStopV0>,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    record_sequence: u64,
    anchor: Option<FixedValidatorAnchorFileV0>,
    committed_end: u64,
    poisoned: bool,
}

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    fn empty(
        file: F,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Self {
        Self {
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            votes: HashMap::new(),
            pending: None,
            live_pending_intent: None,
            latest_slot: None,
            lineage: None,
            latest_current_lineage_state: None,
            prepared_count: 0,
            halt: None,
            finality_conflict_stop: None,
            state_id,
            record_sequence: 0,
            anchor: None,
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn replay(
        mut file: F,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        expected_prefix: Vec<u8>,
        expected_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        expected_anchor_sequence: Option<u64>,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidHeader);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset: 0, source })?;
        let mut actual_prefix = allocate_bytes(JOURNAL_PREFIX_BYTES, 0)?;
        read_exact_at(&mut file, &mut actual_prefix, 0)?;
        if actual_prefix != expected_prefix {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch);
        }

        let state_id = genesis_state_id(&actual_prefix);
        let mut core = Self::empty(file, context, fixed_set_id, signer, replay_limit, state_id);
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;
        let mut recovery_offset = None;
        while entry_start < file_len {
            if file_len - entry_start < RECORD_LENGTH_BYTES {
                recovery_offset = Some(entry_start);
                break;
            }
            core.file
                .seek(SeekFrom::Start(entry_start))
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read {
                    offset: entry_start,
                    source,
                })?;
            let mut body_length_bytes = [0_u8; 4];
            read_exact_at(&mut core.file, &mut body_length_bytes, entry_start)?;
            let body_length_u32 = u32::from_be_bytes(body_length_bytes);
            let body_length = usize::try_from(body_length_u32)
                .expect("every u32 record length fits supported Rust targets");
            if !(MIN_RECORD_BODY_BYTES..=MAX_RECORD_BODY_BYTES).contains(&body_length)
                && body_length != SIGNED_VOTE_BODY_BYTES
                && body_length != SIGNING_LINEAGE_BODY_BYTES
                && body_length != FINALITY_CONFLICT_STOP_BODY_BYTES
                && !(MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES
                    ..=MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES)
                    .contains(&body_length)
            {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordLength {
                        entry,
                        offset: entry_start,
                        actual: body_length_u32,
                        minimum: u32::try_from(MIN_RECORD_BODY_BYTES)
                            .expect("minimum vote-safety record length fits u32"),
                        maximum: u32::try_from(MAX_BOUNDED_RECORD_BODY_BYTES)
                            .expect("maximum vote-safety record length fits u32"),
                    },
                );
            }
            let entry_length = ENTRY_FIXED_BYTES
                .checked_add(u64::from(body_length_u32))
                .ok_or(
                    FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                        entry,
                        offset: entry_start,
                    },
                )?;
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                recovery_offset = Some(entry_start);
                break;
            }
            if core.halt.is_some() || core.finality_conflict_stop.is_some() {
                return Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt {
                    offset: entry_start,
                });
            }
            let mut body = allocate_bytes(body_length, entry)?;
            let body_offset = entry_start + RECORD_LENGTH_BYTES;
            read_exact_at(&mut core.file, &mut body, body_offset)?;
            let footer_offset = body_offset + u64::from(body_length_u32);
            let mut stored_state_id = [0_u8; FixedValidatorVoteSafetyJournalStateIdV0::BYTE_LENGTH];
            read_exact_at(&mut core.file, &mut stored_state_id, footer_offset)?;
            let expected_entry_state_id = step_state_id(core.state_id, body_length_bytes, &body);
            let actual_entry_state_id =
                FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(stored_state_id);
            if actual_entry_state_id != expected_entry_state_id {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch {
                        entry,
                        offset: entry_start,
                        expected: expected_entry_state_id,
                        actual: actual_entry_state_id,
                    },
                );
            }
            core.replay_record(entry, entry_start, body, actual_entry_state_id)?;
            core.state_id = actual_entry_state_id;
            core.record_sequence = core
                .record_sequence
                .checked_add(1)
                .ok_or(FixedValidatorVoteSafetyJournalErrorV0::RecordSequenceExhausted)?;
            core.committed_end = entry_end;
            entry_start = entry_end;
            entry += 1;
        }

        if let Some(expected_sequence) = expected_anchor_sequence
            && (core.record_sequence != expected_sequence || core.state_id != expected_state_id)
        {
            return Err(match core.record_sequence.cmp(&expected_sequence) {
                std::cmp::Ordering::Greater => {
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                        anchored_sequence: expected_sequence,
                        journal_sequence: core.record_sequence,
                    }
                }
                std::cmp::Ordering::Less => FixedValidatorVoteSafetyJournalErrorV0::AnchorAhead {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Equal => {
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorStateMismatch {
                        sequence: expected_sequence,
                    }
                }
            });
        }
        if core.state_id != expected_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                    expected: expected_state_id,
                    actual: core.state_id,
                },
            );
        }
        if let Some(offset) = recovery_offset {
            core.file
                .set_len(offset)
                .and_then(|()| core.file.sync_all())
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Recovery {
                    offset,
                    source,
                })?;
        } else {
            core.file
                .sync_all()
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Stabilize { source })?;
        }
        Ok(core)
    }

    fn replay_record(
        &mut self,
        entry: u64,
        offset: u64,
        body: Vec<u8>,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let (&tag, payload) = body.split_first().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordLength {
                entry,
                offset,
                actual: 0,
                minimum: 1,
                maximum: u32::try_from(MAX_BOUNDED_RECORD_BODY_BYTES)
                    .expect("maximum record length fits u32"),
            },
        )?;
        match tag {
            PREPARE_RECORD => self.replay_prepare(entry, offset, payload, state_id),
            COMPLETE_RECORD => self.replay_completion(entry, offset, payload, state_id),
            CONFLICT_HALT_RECORD => self.replay_halt(entry, offset, payload, state_id),
            SIGNING_LINEAGE_RECORD => self.replay_signing_lineage(entry, payload, state_id),
            FINALITY_CONFLICT_STOP_RECORD => {
                self.replay_finality_conflict_stop(entry, payload, state_id)
            }
            HIGHER_ROUND_CHECKPOINT_RECORD => {
                self.replay_higher_round_checkpoint(entry, offset, payload, state_id)
            }
            actual => Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordTag {
                entry,
                offset,
                actual,
            }),
        }
    }

    fn replay_signing_lineage(
        &mut self,
        entry: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != SIGNING_LINEAGE_PAYLOAD_BYTES {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidSigningLineageLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        if self.pending.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageWhilePending { entry },
            );
        }
        let had_lineage = self.lineage.is_some();
        let height = ConsensusHeight::new(u64::from_be_bytes(
            payload[..8]
                .try_into()
                .expect("the signing-lineage height has exact width"),
        ));
        if height.value() == 0 {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidSigningLineageHeight {
                    entry,
                    actual: height,
                },
            );
        }
        let id = SigningLineageIdV0(
            payload[8..]
                .try_into()
                .expect("the signing-lineage identity has exact width"),
        );
        match self.lineage {
            Some(previous) => {
                let expected = previous
                    .height
                    .value()
                    .checked_add(1)
                    .map(ConsensusHeight::new)
                    .ok_or(
                        FixedValidatorVoteSafetyJournalErrorV0::SigningLineageHeightExhausted {
                            entry,
                            previous: previous.height,
                        },
                    )?;
                if height != expected {
                    return Err(
                        FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                            entry,
                            expected,
                            actual: height,
                        },
                    );
                }
            }
            None => {
                if let Some(latest) = self.latest_slot
                    && height != latest.position.height()
                {
                    return Err(
                        FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                            entry,
                            expected: latest.position.height(),
                            actual: height,
                        },
                    );
                }
            }
        }
        self.lineage = Some(RetainedSigningLineageV0 {
            height,
            id,
            state_id,
        });
        self.latest_current_lineage_state = if had_lineage {
            None
        } else {
            self.latest_slot
                .filter(|slot| slot.position.height() == height)
                .map(RetainedCurrentLineageStateV0::Vote)
        };
        Ok(())
    }

    fn replay_prepare(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.pending.is_some() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareWhilePending { entry });
        }
        if self.prepared_count >= self.replay_limit.max_prepared_votes() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ReplayLimitExceeded {
                    entry,
                    maximum: self.replay_limit.max_prepared_votes(),
                },
            );
        }
        let intent = self.decode_observed_intent(payload, entry, offset)?;
        let slot = observed_intent_slot(&intent);
        if let Some(lineage) = self.lineage
            && slot.position.height() != lineage.height
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
                    entry,
                    lineage_height: lineage.height,
                    vote_height: slot.position.height(),
                },
            );
        }
        self.require_vote_after_higher_round_checkpoint(entry, intent.position(), intent.phase())?;
        if self.votes.contains_key(&slot) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::DuplicatePrepare { entry });
        }
        if let Some(latest) = self.latest_slot
            && slot <= latest
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicReplay {
                entry,
                previous: latest.position,
                previous_role: latest.role,
                actual: slot.position,
                actual_role: slot.role,
            });
        }
        self.votes.try_reserve(1).map_err(|_| {
            FixedValidatorVoteSafetyJournalErrorV0::HistoryAllocation {
                entry,
                retained_votes: self.votes.len(),
            }
        })?;
        self.votes.insert(
            slot,
            RetainedVote {
                observed_intent: intent,
                prepared_state_id: state_id,
                signed: None,
            },
        );
        self.pending = Some(slot);
        self.latest_slot = Some(slot);
        self.prepared_count += 1;
        Ok(())
    }

    fn replay_completion(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != VerifiedConsensusVoteV0::BYTE_LENGTH {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidCompletionLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        let slot = self
            .pending
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::CompletionWithoutPrepare { entry })?;
        let verified = VerifiedConsensusVoteV0::decode_and_verify(payload, self.context).map_err(
            |source| FixedValidatorVoteSafetyJournalErrorV0::SignedVote {
                entry,
                offset,
                source,
            },
        )?;
        let retained = self
            .votes
            .get_mut(&slot)
            .expect("every pending slot has one retained preparation");
        require_verified_vote(
            &verified,
            self.signer,
            slot,
            retained.observed_intent.target(),
        )
        .map_err(
            |reason| FixedValidatorVoteSafetyJournalErrorV0::CompletionMismatch { entry, reason },
        )?;
        let canonical_bytes = clone_bytes(payload, entry)?;
        retained.signed = Some(signed_vote_from_verified(
            &verified,
            canonical_bytes,
            state_id,
        ));
        self.pending = None;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::Vote(slot));
        Ok(())
    }

    fn replay_higher_round_checkpoint(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let checkpoint = self.validate_higher_round_checkpoint(entry, offset, payload)?;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::HigherRound {
            checkpoint: Box::new(checkpoint),
            state_id,
        });
        Ok(())
    }

    fn validate_higher_round_checkpoint(
        &self,
        entry: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<ObservedFixedValidatorHigherRoundCheckpointV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        if self.pending.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointWhilePending { entry },
            );
        }
        let lineage = self.lineage.ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointWithoutLineage { entry },
        )?;
        let checkpoint = ObservedFixedValidatorHigherRoundCheckpointV0::decode_and_verify(
            payload,
            self.context,
            self.fixed_set_id,
        )
        .map_err(|source| {
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpoint {
                entry,
                offset,
                source,
            }
        })?;
        if checkpoint.position().height() != lineage.height {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointOutsideLineage {
                    entry,
                    lineage_height: lineage.height,
                    checkpoint_height: checkpoint.position().height(),
                },
            );
        }
        let (current_position, current_phase) =
            self.current_lineage_state_coordinate(lineage.height);
        if state_coordinate_cmp(
            checkpoint.source_position(),
            checkpoint.source_phase(),
            current_position,
            current_phase,
        )
        .is_lt()
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointSourceBehindState {
                    entry,
                    current_position,
                    current_phase,
                    source_position: checkpoint.source_position(),
                    source_phase: checkpoint.source_phase(),
                },
            );
        }
        Ok(checkpoint)
    }

    fn replay_halt(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let intent = self.decode_observed_intent(payload, entry, offset)?;
        let slot = observed_intent_slot(&intent);
        let retained = self
            .votes
            .get(&slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry })?;
        if retained
            .observed_intent
            .canonical_state_and_vote_intent_bytes()
            == payload
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry });
        }
        self.halt = Some(FixedValidatorVoteSafetyHaltV0 {
            position: slot.position,
            role: slot.role,
            retained_target: retained.observed_intent.target(),
            conflicting_target: intent.target(),
            state_id,
        });
        self.pending = None;
        Ok(())
    }

    fn replay_finality_conflict_stop(
        &mut self,
        entry: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != FINALITY_CONFLICT_STOP_PAYLOAD_BYTES {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStopLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        let finality_state_id = FixedValidatorFinalityJournalStateIdV0::from_bytes(
            payload[..32]
                .try_into()
                .expect("the finality state identity has exact width"),
        );
        let height = ConsensusHeight::new(u64::from_be_bytes(
            payload[32..40]
                .try_into()
                .expect("the finality-conflict height has exact width"),
        ));
        if height.value() == 0 {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStop { entry },
            );
        }
        let selected_ancestry = ConsensusAncestryId::from_bytes(
            payload[40..72]
                .try_into()
                .expect("the selected ancestry has exact width"),
        );
        let selected_envelope_id = ConsensusEnvelopeId::from_bytes(
            payload[72..104]
                .try_into()
                .expect("the selected envelope identity has exact width"),
        );
        let conflicting_ancestry = ConsensusAncestryId::from_bytes(
            payload[104..136]
                .try_into()
                .expect("the conflicting ancestry has exact width"),
        );
        let conflicting_envelope_id = ConsensusEnvelopeId::from_bytes(
            payload[136..168]
                .try_into()
                .expect("the conflicting envelope identity has exact width"),
        );
        self.finality_conflict_stop = Some(FixedValidatorFinalityConflictSignerStopV0 {
            finality_state_id,
            height,
            selected_ancestry,
            selected_envelope_id,
            conflicting_ancestry,
            conflicting_envelope_id,
            vote_state_id: state_id,
        });
        Ok(())
    }

    fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_healthy()?;
        if conflict.context() != self.context {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictContextMismatch);
        }
        if conflict.fixed_agreement_set_id() != self.fixed_set_id {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictFixedSetMismatch);
        }
        let halt = conflict.halt();
        let proposed = FixedValidatorFinalityConflictSignerStopV0 {
            finality_state_id: halt.state_id(),
            height: halt.height(),
            selected_ancestry: halt.selected_ancestry(),
            selected_envelope_id: halt.selected_envelope_id(),
            conflicting_ancestry: halt.conflicting_ancestry(),
            conflicting_envelope_id: halt.conflicting_envelope_id(),
            vote_state_id: self.state_id,
        };
        if let Some(existing) = self.finality_conflict_stop {
            if existing.same_conflict(proposed) {
                return Ok(
                    FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing),
                );
            }
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                    retained_height: existing.height,
                    incoming_height: proposed.height,
                },
            );
        }
        if let Some(existing) = self.halt {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
                position: existing.position,
                role: existing.role,
            });
        }
        let body = finality_conflict_stop_record(proposed, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        let stopped = FixedValidatorFinalityConflictSignerStopV0 {
            vote_state_id: next_state_id,
            ..proposed
        };
        self.finality_conflict_stop = Some(stopped);
        self.live_pending_intent = None;
        self.state_id = next_state_id;
        Ok(FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(
            stopped,
        ))
    }

    fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_recoverable()?;
        let lock_state = self.restore_lock_state_for_round(round)?;
        let height = lock_state.position().height();
        let id = signing_lineage_id(round.parent_coordinate(), height, self.signer);
        if let Some(lineage) = self.lineage {
            if lineage.height == height && lineage.id == id {
                return Ok(self.state_id);
            }
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
                    expected_height: lineage.height,
                    actual_height: height,
                },
            );
        }
        self.append_signing_lineage(height, id)
    }

    fn recover_lock_state_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_recoverable()?;
        let lineage = self
            .lineage
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)?;
        let lock_state = self.restore_lock_state_for_round(round)?;
        let height = lock_state.position().height();
        let id = signing_lineage_id(round.parent_coordinate(), height, self.signer);
        if lineage.height != height || lineage.id != id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
                    expected_height: lineage.height,
                    actual_height: height,
                },
            );
        }
        Ok(lock_state)
    }

    fn signer_recovery_position(&self, lineage: RetainedSigningLineageV0) -> ConsensusPosition {
        self.latest_current_lineage_state
            .as_ref()
            .filter(|state| state.position().height() == lineage.height)
            .map_or(
                ConsensusPosition::new(lineage.height, ConsensusRound::new(0)),
                RetainedCurrentLineageStateV0::position,
            )
    }

    fn restore_lock_state_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if round.context() != self.context
            || round.parent_coordinate().fixed_agreement_set_id() != self.fixed_set_id
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionRoundMismatch);
        }
        match self.latest_current_lineage_state.as_ref() {
            None => FixedValidatorLockStateV0::try_from_round_zero(round)
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState),
            Some(RetainedCurrentLineageStateV0::Vote(latest)) => {
                let retained = self
                    .votes
                    .get(latest)
                    .expect("the latest completed vote remains retained");
                retained
                    .signed
                    .as_ref()
                    .expect("a recoverable latest vote is durably completed");
                VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
                    retained
                        .observed_intent
                        .canonical_state_and_vote_intent_bytes(),
                    round,
                    self.signer,
                )
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent)
                .map(VerifiedReplayFixedValidatorVoteIntentV0::into_lock_state)
            }
            Some(RetainedCurrentLineageStateV0::HigherRound { checkpoint, .. }) => checkpoint
                .as_ref()
                .clone()
                .verify_for_round(round)
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay)
                .map(VerifiedReplayFixedValidatorHigherRoundCheckpointV0::into_lock_state),
        }
    }

    fn current_lineage_state_coordinate(
        &self,
        height: ConsensusHeight,
    ) -> (ConsensusPosition, FixedValidatorLockPhaseV0) {
        self.latest_current_lineage_state
            .as_ref()
            .filter(|state| state.position().height() == height)
            .map_or(
                (
                    ConsensusPosition::new(height, ConsensusRound::new(0)),
                    FixedValidatorLockPhaseV0::Proposal,
                ),
                |state| (state.position(), state.phase()),
            )
    }

    fn require_vote_after_higher_round_checkpoint(
        &self,
        entry: u64,
        position: ConsensusPosition,
        phase: FixedValidatorLockPhaseV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let Some(RetainedCurrentLineageStateV0::HigherRound { checkpoint, .. }) =
            self.latest_current_lineage_state.as_ref()
        else {
            return Ok(());
        };
        if !state_coordinate_cmp(position, phase, checkpoint.position(), checkpoint.phase()).is_gt()
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteStateDoesNotFollowHigherRoundCheckpoint {
                    entry,
                    checkpoint_position: checkpoint.position(),
                    checkpoint_phase: checkpoint.phase(),
                    vote_position: position,
                    vote_phase: phase,
                },
            );
        }
        Ok(())
    }

    fn append_signing_lineage(
        &mut self,
        height: ConsensusHeight,
        id: SigningLineageIdV0,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_operational()?;
        let had_lineage = self.lineage.is_some();
        if let Some(pending) = self.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if let Some(previous) = self.lineage {
            let expected = previous
                .height
                .value()
                .checked_add(1)
                .map(ConsensusHeight::new)
                .ok_or(
                    FixedValidatorVoteSafetyJournalErrorV0::SigningLineageHeightExhausted {
                        entry: self.prepared_count,
                        previous: previous.height,
                    },
                )?;
            if height != expected {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                        entry: self.prepared_count,
                        expected,
                        actual: height,
                    },
                );
            }
        }
        let body = signing_lineage_record(height, id, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        self.lineage = Some(RetainedSigningLineageV0 {
            height,
            id,
            state_id: next_state_id,
        });
        self.latest_current_lineage_state = if had_lineage {
            None
        } else {
            self.latest_slot
                .filter(|slot| slot.position.height() == height)
                .map(RetainedCurrentLineageStateV0::Vote)
        };
        self.state_id = next_state_id;
        Ok(next_state_id)
    }

    fn append_higher_round_checkpoint(
        &mut self,
        canonical_checkpoint: &[u8],
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_operational()?;
        let checkpoint = self.validate_higher_round_checkpoint(
            self.prepared_count,
            self.committed_end,
            canonical_checkpoint,
        )?;
        let body = tagged_record(
            HIGHER_ROUND_CHECKPOINT_RECORD,
            canonical_checkpoint,
            self.prepared_count,
        )?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::HigherRound {
            checkpoint: Box::new(checkpoint),
            state_id: next_state_id,
        });
        self.state_id = next_state_id;
        Ok(next_state_id)
    }

    fn prepare_vote(
        &mut self,
        intent: FixedValidatorVoteIntentV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        if intent.context() != self.context
            || intent.fixed_agreement_set_id() != self.fixed_set_id
            || intent.signer() != self.signer
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::IntentHeaderMismatch);
        }
        let canonical_intent = intent.canonical_state_and_vote_intent_bytes();
        let observed = self.decode_observed_intent(canonical_intent, self.prepared_count, 0)?;
        let slot = observed_intent_slot(&observed);
        if let Some(lineage) = self.lineage
            && slot.position.height() != lineage.height
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
                    entry: self.prepared_count,
                    lineage_height: lineage.height,
                    vote_height: slot.position.height(),
                },
            );
        }
        self.require_vote_after_higher_round_checkpoint(
            self.prepared_count,
            observed.position(),
            observed.phase(),
        )?;
        let target = observed.target();
        if let Some(retained) = self.votes.get(&slot) {
            if retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
                == canonical_intent
            {
                if let Some(signed) = &retained.signed {
                    return Ok(FixedValidatorVotePrepareOutcomeV0::AlreadySigned(
                        signed.clone(),
                    ));
                }
                return Ok(FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(
                    prepared_capability(slot, retained),
                ));
            }
            let retained_target = retained.observed_intent.target();
            let body = tagged_record(CONFLICT_HALT_RECORD, canonical_intent, self.prepared_count)?;
            let next_state_id = self.append_record(&body, self.prepared_count)?;
            let halt = FixedValidatorVoteSafetyHaltV0 {
                position: slot.position,
                role: slot.role,
                retained_target,
                conflicting_target: target,
                state_id: next_state_id,
            };
            self.halt = Some(halt);
            self.pending = None;
            self.live_pending_intent = None;
            self.state_id = next_state_id;
            return Ok(FixedValidatorVotePrepareOutcomeV0::Halted(halt));
        }
        if let Some(pending) = self.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if self.prepared_count >= self.replay_limit.max_prepared_votes() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded {
                    maximum: self.replay_limit.max_prepared_votes(),
                },
            );
        }
        if let Some(latest) = self.latest_slot
            && slot <= latest
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicSlot {
                previous: latest.position,
                previous_role: latest.role,
                actual: slot.position,
                actual_role: slot.role,
            });
        }
        let entry = self.prepared_count;
        self.votes.try_reserve(1).map_err(|_| {
            FixedValidatorVoteSafetyJournalErrorV0::HistoryAllocation {
                entry,
                retained_votes: self.votes.len(),
            }
        })?;
        let body = tagged_record(PREPARE_RECORD, canonical_intent, entry)?;
        let next_state_id = self.append_record(&body, entry)?;
        self.votes.insert(
            slot,
            RetainedVote {
                observed_intent: observed,
                prepared_state_id: next_state_id,
                signed: None,
            },
        );
        self.pending = Some(slot);
        self.live_pending_intent = Some(intent);
        self.latest_slot = Some(slot);
        self.prepared_count += 1;
        self.state_id = next_state_id;
        Ok(FixedValidatorVotePrepareOutcomeV0::Prepared(
            self.pending_capability()
                .expect("new preparation is the sole pending vote"),
        ))
    }

    fn sign_prepared_vote(
        &mut self,
        signing_key: &SigningKey,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorVoteSignOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        let retained = self
            .votes
            .get(&prepared.slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::UnknownPreparedVote)?;
        if retained.prepared_state_id != prepared.prepared_state_id
            || retained.observed_intent.target() != prepared.target
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        if let Some(signed) = &retained.signed {
            return Ok(FixedValidatorVoteSignOutcomeV0::AlreadySigned(
                signed.clone(),
            ));
        }
        if self.pending != Some(prepared.slot) || self.state_id != prepared.prepared_state_id {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let intent = self.live_pending_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: prepared.slot.position,
                role: prepared.slot.role,
            },
        )?;
        if intent.canonical_state_and_vote_intent_bytes()
            != retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let dalek_signature = signing_key.sign(intent.signing_transcript());
        let signature = ConsensusSignature::from_bytes(dalek_signature.to_bytes());
        let verified = intent
            .complete_with_signature(signature)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SelfVerification)?;
        require_verified_vote(&verified, self.signer, prepared.slot, prepared.target)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SelfVerificationMismatch)?;
        let canonical_bytes = verified.to_canonical_bytes().to_vec();
        let body = tagged_record(COMPLETE_RECORD, &canonical_bytes, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        let signed = signed_vote_from_verified(&verified, canonical_bytes, next_state_id);
        self.votes
            .get_mut(&prepared.slot)
            .expect("prepared vote remains retained through completion")
            .signed = Some(signed.clone());
        self.pending = None;
        self.live_pending_intent = None;
        self.latest_current_lineage_state =
            Some(RetainedCurrentLineageStateV0::Vote(prepared.slot));
        self.state_id = next_state_id;
        Ok(FixedValidatorVoteSignOutcomeV0::Signed(signed))
    }

    fn validate_live_prepared_vote(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        let retained = self
            .votes
            .get(&prepared.slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::UnknownPreparedVote)?;
        if retained.prepared_state_id != prepared.prepared_state_id
            || retained.observed_intent.target() != prepared.target
            || retained.signed.is_some()
            || self.pending != Some(prepared.slot)
            || self.state_id != prepared.prepared_state_id
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let intent = self.live_pending_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: prepared.slot.position,
                role: prepared.slot.role,
            },
        )?;
        if intent.canonical_state_and_vote_intent_bytes()
            != retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        Ok(())
    }

    fn append_record(
        &mut self,
        body: &[u8],
        entry: u64,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        let body_length =
            u32::try_from(body.len()).expect("bounded vote-safety journal record length fits u32");
        let body_length_bytes = body_length.to_be_bytes();
        let next_state_id = step_state_id(self.state_id, body_length_bytes, body);
        let next_sequence = self
            .record_sequence
            .checked_add(1)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::RecordSequenceExhausted)?;
        let entry_length = ENTRY_FIXED_BYTES
            .checked_add(u64::from(body_length))
            .ok_or(
                FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: self.committed_end,
                },
            )?;
        let next_committed_end = self.committed_end.checked_add(entry_length).ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                entry,
                offset: self.committed_end,
            },
        )?;
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            self.file.append_write_all(AppendPhase::Body, body)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, next_state_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            if let Some(anchor) = self.anchor.as_mut() {
                let transition = JournalAnchorTransitionV0::new(
                    anchor.pairing_seal(),
                    AnchorPositionV0 {
                        sequence: self.record_sequence,
                        state_id: *self.state_id.as_bytes(),
                    },
                    *next_state_id.as_bytes(),
                )
                .map_err(io::Error::other)?;
                debug_assert_eq!(transition.next().sequence, next_sequence);
                anchor.advance(transition).map_err(io::Error::other)?;
            }
            Ok(())
        })();
        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(FixedValidatorVoteSafetyJournalErrorV0::Commit {
                proposed_state_id: next_state_id,
                source,
            });
        }
        self.committed_end = next_committed_end;
        self.record_sequence = next_sequence;
        Ok(next_state_id)
    }

    fn decode_observed_intent(
        &self,
        bytes: &[u8],
        entry: u64,
        offset: u64,
    ) -> Result<ObservedFixedValidatorVoteIntentV0, FixedValidatorVoteSafetyJournalErrorV0> {
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            bytes,
            self.context,
            self.fixed_set_id,
            self.signer,
        )
        .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Intent {
            entry,
            offset,
            source,
        })
    }

    fn pending_capability(&self) -> Option<FixedValidatorPreparedVoteV0> {
        self.live_pending_intent.as_ref()?;
        let slot = self.pending?;
        let retained = self
            .votes
            .get(&slot)
            .expect("every pending slot has a retained vote");
        Some(prepared_capability(slot, retained))
    }

    fn pending_summary(&self) -> Option<FixedValidatorPendingVoteV0> {
        let slot = self.pending?;
        let retained = self
            .votes
            .get(&slot)
            .expect("every pending slot has a retained vote");
        Some(FixedValidatorPendingVoteV0 {
            position: slot.position,
            role: slot.role,
            target: retained.observed_intent.target(),
            prepared_state_id: retained.prepared_state_id,
        })
    }

    fn ensure_healthy(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.poisoned {
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_operational(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_healthy()?;
        self.ensure_not_halted()?;
        if let Some(pending) = self.restarted_pending() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: pending.position,
                role: pending.role,
            });
        }
        Ok(())
    }

    fn ensure_not_halted(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_healthy()?;
        if let Some(halt) = self.halt {
            Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
                position: halt.position,
                role: halt.role,
            })
        } else if let Some(stop) = self.finality_conflict_stop {
            Err(
                FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                    height: stop.height,
                },
            )
        } else {
            Ok(())
        }
    }

    fn restarted_pending(&self) -> Option<VoteSlot> {
        self.pending.filter(|_| self.live_pending_intent.is_none())
    }

    fn ensure_recoverable(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_not_halted()?;
        if let Some(pending) = self.pending {
            Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied {
                    position: pending.position,
                    role: pending.role,
                },
            )
        } else {
            Ok(())
        }
    }
}

fn prepared_capability(slot: VoteSlot, retained: &RetainedVote) -> FixedValidatorPreparedVoteV0 {
    FixedValidatorPreparedVoteV0 {
        slot,
        target: retained.observed_intent.target(),
        prepared_state_id: retained.prepared_state_id,
    }
}

fn observed_intent_slot(intent: &ObservedFixedValidatorVoteIntentV0) -> VoteSlot {
    VoteSlot::new(intent.position(), intent.role())
}

const fn phase_for_vote_role(role: ConsensusVoteRole) -> FixedValidatorLockPhaseV0 {
    match role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    }
}

const fn phase_rank(phase: FixedValidatorLockPhaseV0) -> u8 {
    match phase {
        FixedValidatorLockPhaseV0::Proposal => 0,
        FixedValidatorLockPhaseV0::Prevote => 1,
        FixedValidatorLockPhaseV0::Precommit => 2,
    }
}

fn state_coordinate_cmp(
    left_position: ConsensusPosition,
    left_phase: FixedValidatorLockPhaseV0,
    right_position: ConsensusPosition,
    right_phase: FixedValidatorLockPhaseV0,
) -> std::cmp::Ordering {
    (
        left_position.height().value(),
        left_position.round().value(),
        phase_rank(left_phase),
    )
        .cmp(&(
            right_position.height().value(),
            right_position.round().value(),
            phase_rank(right_phase),
        ))
}

fn signed_vote_from_verified(
    verified: &VerifiedConsensusVoteV0,
    canonical_bytes: Vec<u8>,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
) -> FixedValidatorSignedVoteV0 {
    FixedValidatorSignedVoteV0 {
        position: verified.position(),
        role: verified.role(),
        target: verified.target(),
        vote_id: verified.id(),
        canonical_bytes,
        state_id,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One field by which signed bytes can fail to match their prepared intent.
pub enum FixedValidatorVoteCompletionMismatchV0 {
    /// The verified signer differs from the header-bound local key.
    Signer,
    /// The verified height or round differs from the prepared position.
    Position,
    /// The verified prevote or precommit role differs from the prepared role.
    Role,
    /// The verified nil-or-proposal target differs from the prepared target.
    Target,
}

fn require_verified_vote(
    verified: &VerifiedConsensusVoteV0,
    signer: ConsensusKey,
    slot: VoteSlot,
    target: ConsensusVoteTarget,
) -> Result<(), FixedValidatorVoteCompletionMismatchV0> {
    if verified.signer() != signer {
        return Err(FixedValidatorVoteCompletionMismatchV0::Signer);
    }
    if verified.position() != slot.position {
        return Err(FixedValidatorVoteCompletionMismatchV0::Position);
    }
    if verified.role() != slot.role {
        return Err(FixedValidatorVoteCompletionMismatchV0::Role);
    }
    if verified.target() != target {
        return Err(FixedValidatorVoteCompletionMismatchV0::Target);
    }
    Ok(())
}

pub(crate) fn signing_lineage_id(
    coordinate: FixedConsensusBranchCoordinateV0,
    height: ConsensusHeight,
    signer: ConsensusKey,
) -> SigningLineageIdV0 {
    let context = coordinate.context();
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_LINEAGE_DOMAIN);
    hasher.update(context.chain_id().as_bytes());
    hasher.update(context.genesis_id().as_bytes());
    hasher.update(context.protocol_version().value().to_be_bytes());
    match coordinate.verified_height() {
        None => {
            hasher.update([0]);
            hasher.update(0_u64.to_be_bytes());
        }
        Some(parent_height) => {
            hasher.update([1]);
            hasher.update(parent_height.value().to_be_bytes());
        }
    }
    hasher.update(coordinate.ancestry_id().as_bytes());
    hasher.update(coordinate.artifact_head_block_id().as_bytes());
    hasher.update(coordinate.artifact_set_root().as_bytes());
    hasher.update(coordinate.fixed_agreement_set_id().as_bytes());
    hasher.update(coordinate.proposer_priority_state_id().as_bytes());
    hasher.update(height.value().to_be_bytes());
    hasher.update(signer.as_bytes());
    SigningLineageIdV0(hasher.finalize().into())
}

fn signing_lineage_record(
    height: ConsensusHeight,
    id: SigningLineageIdV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut payload = [0_u8; SIGNING_LINEAGE_PAYLOAD_BYTES];
    payload[..8].copy_from_slice(&height.value().to_be_bytes());
    payload[8..].copy_from_slice(&id.0);
    tagged_record(SIGNING_LINEAGE_RECORD, &payload, entry)
}

fn finality_conflict_stop_record(
    stop: FixedValidatorFinalityConflictSignerStopV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut payload = [0_u8; FINALITY_CONFLICT_STOP_PAYLOAD_BYTES];
    payload[..32].copy_from_slice(stop.finality_state_id.as_bytes());
    payload[32..40].copy_from_slice(&stop.height.value().to_be_bytes());
    payload[40..72].copy_from_slice(stop.selected_ancestry.as_bytes());
    payload[72..104].copy_from_slice(stop.selected_envelope_id.as_bytes());
    payload[104..136].copy_from_slice(stop.conflicting_ancestry.as_bytes());
    payload[136..168].copy_from_slice(stop.conflicting_envelope_id.as_bytes());
    tagged_record(FINALITY_CONFLICT_STOP_RECORD, &payload, entry)
}

fn tagged_record(
    tag: u8,
    payload: &[u8],
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let length = payload
        .len()
        .checked_add(1)
        .expect("bounded vote-safety record length cannot overflow usize");
    let mut body = Vec::new();
    body.try_reserve_exact(length).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: length,
        }
    })?;
    body.push(tag);
    body.extend_from_slice(payload);
    Ok(body)
}

fn canonical_prefix(
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    signer: ConsensusKey,
    replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(JOURNAL_PREFIX_BYTES)
        .map_err(|_| FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry: 0,
            bytes: JOURNAL_PREFIX_BYTES,
        })?;
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(context.chain_id().as_bytes());
    prefix.extend_from_slice(context.genesis_id().as_bytes());
    prefix.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    prefix.extend_from_slice(fixed_set_id.as_bytes());
    prefix.extend_from_slice(signer.as_bytes());
    prefix.extend_from_slice(&replay_limit.max_prepared_votes().to_be_bytes());
    debug_assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);
    Ok(prefix)
}

fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

fn keyed_paths(
    directory: &Path,
    signer: ConsensusKey,
) -> Result<(PathBuf, PathBuf), FixedValidatorVoteSafetyJournalErrorV0> {
    let mut stem = String::new();
    stem.try_reserve_exact(FILE_STEM.len() + CONSENSUS_KEY_BYTES * 2)
        .map_err(|_| FixedValidatorVoteSafetyJournalErrorV0::PathAllocation)?;
    stem.push_str(FILE_STEM);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in signer.as_bytes() {
        stem.push(HEX[usize::from(byte >> 4)] as char);
        stem.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    let mut lock_name = stem.clone();
    lock_name.push_str(LOCK_SUFFIX);
    let mut journal_name = stem;
    journal_name.push_str(JOURNAL_SUFFIX);
    Ok((directory.join(lock_name), directory.join(journal_name)))
}

fn open_key_lock(path: &Path) -> Result<File, FixedValidatorVoteSafetyJournalErrorV0> {
    let directory = path.parent().expect("keyed lock path always has a parent");
    let file_name = path
        .file_name()
        .expect("keyed lock path always has a file name")
        .to_string_lossy();
    open_exclusive_lock(directory, &file_name).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            FixedValidatorVoteSafetyJournalErrorV0::LockFile { source }
        }
        ExclusiveLockError::Locked => FixedValidatorVoteSafetyJournalErrorV0::Locked,
        ExclusiveLockError::Lock(source) => FixedValidatorVoteSafetyJournalErrorV0::Lock { source },
    })
}

fn genesis_state_id(prefix: &[u8]) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_STATE_DOMAIN);
    hasher.update(prefix);
    FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(hasher.finalize().into())
}

fn step_state_id(
    prior: FixedValidatorVoteSafetyJournalStateIdV0,
    body_length: [u8; 4],
    body: &[u8],
) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(STEP_STATE_DOMAIN);
    hasher.update(prior.as_bytes());
    hasher.update(body_length);
    hasher.update(body);
    FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(hasher.finalize().into())
}

fn allocate_bytes(
    length: usize,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: length,
        }
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn clone_bytes(
    bytes: &[u8],
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: bytes.len(),
        }
    })?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn read_exact_at<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
    file.read_exact(bytes)
        .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset, source })
}

/// Failure to create or strictly open one paired per-key journal and anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    Journal(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    Anchor(FixedValidatorAnchorErrorV0),
}

impl FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    fn journal(source: FixedValidatorVoteSafetyJournalErrorV0) -> Self {
        Self::Journal(Box::new(source))
    }
}

impl fmt::Display for FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => {
                write!(formatter, "anchored vote-safety journal failed: {source}")
            }
            Self::Anchor(source) => write!(formatter, "vote-safety anchor failed: {source}"),
        }
    }
}

impl Error for FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source.as_ref()),
            Self::Anchor(source) => Some(source),
        }
    }
}

/// A fail-closed fixed-validator vote-safety journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorVoteSafetyJournalErrorV0 {
    LockFile {
        source: io::Error,
    },
    Locked,
    Lock {
        source: io::Error,
    },
    PathAllocation,
    Create {
        source: io::Error,
    },
    Open {
        source: io::Error,
    },
    Read {
        offset: u64,
        source: io::Error,
    },
    InvalidHeader,
    HeaderMismatch,
    InvalidRecordLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    EntryOffsetOverflow {
        entry: u64,
        offset: u64,
    },
    Allocation {
        entry: u64,
        bytes: usize,
    },
    HistoryAllocation {
        entry: u64,
        retained_votes: usize,
    },
    InvalidRecordTag {
        entry: u64,
        offset: u64,
        actual: u8,
    },
    InvalidSigningLineageLength {
        entry: u64,
        actual: usize,
    },
    InvalidSigningLineageHeight {
        entry: u64,
        actual: ConsensusHeight,
    },
    SigningLineageWhilePending {
        entry: u64,
    },
    SigningLineageHeightExhausted {
        entry: u64,
        previous: ConsensusHeight,
    },
    NonSequentialSigningLineage {
        entry: u64,
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    VoteOutsideSigningLineage {
        entry: u64,
        lineage_height: ConsensusHeight,
        vote_height: ConsensusHeight,
    },
    RecordStateIdMismatch {
        entry: u64,
        offset: u64,
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
        actual: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    Intent {
        entry: u64,
        offset: u64,
        source: FixedValidatorVoteIntentError,
    },
    IntentHeaderMismatch,
    FinalityConflictContextMismatch,
    FinalityConflictFixedSetMismatch,
    SigningSessionAlreadyIssued,
    SigningSessionRoundMismatch,
    SigningLineageRequired,
    SigningLineageMismatch {
        expected_height: ConsensusHeight,
        actual_height: ConsensusHeight,
    },
    ExternalSessionAnchorMismatch {
        required: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignSignerRecovery,
    StaleSignerRecovery {
        recovered: FixedValidatorVoteSafetyJournalStateIdV0,
        current: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    SignerRecoveryRoundLimitExceeded {
        required: u64,
        maximum: u64,
    },
    SignerRecoveryPositionMismatch {
        required: ConsensusPosition,
        actual: ConsensusPosition,
    },
    SignerRecoveryRound(ProposerSelectionError),
    LockState(FixedValidatorLockStateError),
    SigningSessionIntent(FixedValidatorVoteIntentError),
    HigherRoundCheckpoint {
        entry: u64,
        offset: u64,
        source: FixedValidatorHigherRoundCheckpointErrorV0,
    },
    HigherRoundCheckpointReplay(FixedValidatorHigherRoundCheckpointErrorV0),
    HigherRoundCheckpointWithoutLineage {
        entry: u64,
    },
    HigherRoundCheckpointWhilePending {
        entry: u64,
    },
    HigherRoundCheckpointOutsideLineage {
        entry: u64,
        lineage_height: ConsensusHeight,
        checkpoint_height: ConsensusHeight,
    },
    HigherRoundCheckpointSourceBehindState {
        entry: u64,
        current_position: ConsensusPosition,
        current_phase: FixedValidatorLockPhaseV0,
        source_position: ConsensusPosition,
        source_phase: FixedValidatorLockPhaseV0,
    },
    VoteStateDoesNotFollowHigherRoundCheckpoint {
        entry: u64,
        checkpoint_position: ConsensusPosition,
        checkpoint_phase: FixedValidatorLockPhaseV0,
        vote_position: ConsensusPosition,
        vote_phase: FixedValidatorLockPhaseV0,
    },
    ExternalPrepareAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignPrepareAcknowledgement,
    SignedVote {
        entry: u64,
        offset: u64,
        source: ConsensusVoteVerifyError,
    },
    InvalidCompletionLength {
        entry: u64,
        actual: usize,
    },
    CompletionMismatch {
        entry: u64,
        reason: FixedValidatorVoteCompletionMismatchV0,
    },
    CompletionWithoutPrepare {
        entry: u64,
    },
    PrepareWhilePending {
        entry: u64,
    },
    DuplicatePrepare {
        entry: u64,
    },
    InvalidConflictHalt {
        entry: u64,
    },
    InvalidFinalityConflictSignerStopLength {
        entry: u64,
        actual: usize,
    },
    InvalidFinalityConflictSignerStop {
        entry: u64,
    },
    ConflictingFinalityConflictSignerStop {
        retained_height: ConsensusHeight,
        incoming_height: ConsensusHeight,
    },
    RecordAfterHalt {
        offset: u64,
    },
    ReplayLimitExceeded {
        entry: u64,
        maximum: u64,
    },
    NonMonotonicReplay {
        entry: u64,
        previous: ConsensusPosition,
        previous_role: ConsensusVoteRole,
        actual: ConsensusPosition,
        actual_role: ConsensusVoteRole,
    },
    ExpectedStateIdMismatch {
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
        actual: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    AnchorBehind {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    AnchorAhead {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    AnchorStateMismatch {
        sequence: u64,
    },
    RecordSequenceExhausted,
    Recovery {
        offset: u64,
        source: io::Error,
    },
    Stabilize {
        source: io::Error,
    },
    PendingPreparation {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    PendingHeightAdvance {
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    PendingHigherRoundAdvance {
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ExternalHeightAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignHeightAdvance,
    StaleHeightAdvance,
    ExternalHigherRoundAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignHigherRoundAdvance,
    StaleHigherRoundAdvance,
    PendingRecoveryDenied {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    PrepareLimitExceeded {
        maximum: u64,
    },
    NonMonotonicSlot {
        previous: ConsensusPosition,
        previous_role: ConsensusVoteRole,
        actual: ConsensusPosition,
        actual_role: ConsensusVoteRole,
    },
    UnknownPreparedVote,
    StalePreparedVote,
    RestartedPending {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    SelfVerification(ConsensusVoteVerifyError),
    SelfVerificationMismatch(FixedValidatorVoteCompletionMismatchV0),
    TerminalHalt {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    TerminalFinalityConflictSignerStop {
        height: ConsensusHeight,
    },
    Commit {
        proposed_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        source: io::Error,
    },
    Poisoned,
}

impl fmt::Display for FixedValidatorVoteSafetyJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "vote-safety lock file failed: {source}"),
            Self::Locked => formatter.write_str("this consensus key's vote-safety journal is already exclusively open"),
            Self::Lock { source } => write!(formatter, "vote-safety journal locking failed: {source}"),
            Self::PathAllocation => formatter.write_str("vote-safety journal path could not allocate"),
            Self::Create { source } => write!(formatter, "vote-safety journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "vote-safety journal opening failed: {source}"),
            Self::Read { offset, source } => write!(formatter, "vote-safety journal read failed at byte {offset}: {source}"),
            Self::InvalidHeader => formatter.write_str("invalid fixed-validator vote-safety journal header"),
            Self::HeaderMismatch => formatter.write_str("vote-safety journal header does not match the expected context, fixed set, signer, and replay limit"),
            Self::InvalidRecordLength { entry, offset, actual, minimum, maximum } => write!(formatter, "vote-safety record {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}, the exact signed-vote width, signing-lineage width, finality-stop width, or bounded higher-round checkpoint width"),
            Self::EntryOffsetOverflow { entry, offset } => write!(formatter, "vote-safety record {entry} at byte {offset} exceeds the offset range"),
            Self::Allocation { entry, bytes } => write!(formatter, "vote-safety record {entry} could not allocate {bytes} bytes"),
            Self::HistoryAllocation { entry, retained_votes } => write!(formatter, "vote-safety record {entry} could not grow history beyond {retained_votes} prepared votes"),
            Self::InvalidRecordTag { entry, offset, actual } => write!(formatter, "vote-safety record {entry} at byte {offset} has unsupported tag {actual}"),
            Self::InvalidSigningLineageLength { entry, actual } => write!(formatter, "signing-lineage record {entry} has {actual} payload bytes"),
            Self::InvalidSigningLineageHeight { entry, actual } => write!(formatter, "signing-lineage record {entry} has reserved height {}", actual.value()),
            Self::SigningLineageWhilePending { entry } => write!(formatter, "signing-lineage record {entry} follows an uncompleted vote preparation"),
            Self::SigningLineageHeightExhausted { entry, previous } => write!(formatter, "signing-lineage record {entry} cannot advance exhausted height {}", previous.value()),
            Self::NonSequentialSigningLineage { entry, expected, actual } => write!(formatter, "signing-lineage record {entry} has height {}, expected {}", actual.value(), expected.value()),
            Self::VoteOutsideSigningLineage { entry, lineage_height, vote_height } => write!(formatter, "vote record {entry} has height {}, outside retained signing-lineage height {}", vote_height.value(), lineage_height.value()),
            Self::RecordStateIdMismatch { entry, offset, expected, actual } => write!(formatter, "vote-safety record {entry} at byte {offset} commits state {actual:?}, expected {expected:?}"),
            Self::Intent { entry, offset, source } => write!(formatter, "vote-safety intent record {entry} at byte {offset} failed strict replay: {source}"),
            Self::IntentHeaderMismatch => formatter.write_str("sealed vote intent does not match this journal's exact context, fixed set, and signer"),
            Self::FinalityConflictContextMismatch => formatter.write_str("finality-conflict stop authority does not match this vote journal's exact consensus context"),
            Self::FinalityConflictFixedSetMismatch => formatter.write_str("finality-conflict stop authority does not match this vote journal's fixed validator set"),
            Self::SigningSessionAlreadyIssued => formatter.write_str("this open vote-safety journal handle has already issued its sole signing session"),
            Self::SigningSessionRoundMismatch => formatter.write_str("signing-session round does not match this journal's exact context and fixed set"),
            Self::SigningLineageRequired => formatter.write_str("a durable signing-lineage binding is required before session issuance"),
            Self::SigningLineageMismatch { expected_height, actual_height } => write!(formatter, "signing-session lineage at height {} does not match retained height {}", actual_height.value(), expected_height.value()),
            Self::ExternalSessionAnchorMismatch { required, acknowledged } => write!(formatter, "external session acknowledgement names state {acknowledged:?}, expected current state {required:?}"),
            Self::ForeignSignerRecovery => formatter.write_str("recovered signer branch belongs to another open vote-safety journal handle"),
            Self::StaleSignerRecovery { recovered, current } => write!(formatter, "recovered signer branch names vote state {recovered:?}, but the current state is {current:?}"),
            Self::SignerRecoveryRoundLimitExceeded { required, maximum } => write!(formatter, "signer recovery requires round {required}, above caller-local ceiling {maximum}"),
            Self::SignerRecoveryPositionMismatch { required, actual } => write!(formatter, "recovered signer branch begins at {actual:?}, but anchored recovery requires {required:?}"),
            Self::SignerRecoveryRound(source) => write!(formatter, "signer recovery could not derive its exact sequential round: {source}"),
            Self::LockState(source) => write!(formatter, "vote-safety signing-session lock-state transition failed: {source}"),
            Self::SigningSessionIntent(source) => write!(formatter, "vote-safety signing session could not seal or restore its exact intent state: {source}"),
            Self::HigherRoundCheckpoint { entry, offset, source } => write!(formatter, "higher-round checkpoint record {entry} at byte {offset} failed structural replay: {source}"),
            Self::HigherRoundCheckpointReplay(source) => write!(formatter, "higher-round checkpoint failed exact typed replay: {source}"),
            Self::HigherRoundCheckpointWithoutLineage { entry } => write!(formatter, "higher-round checkpoint record {entry} has no retained signing lineage"),
            Self::HigherRoundCheckpointWhilePending { entry } => write!(formatter, "higher-round checkpoint record {entry} follows an uncompleted vote preparation"),
            Self::HigherRoundCheckpointOutsideLineage { entry, lineage_height, checkpoint_height } => write!(formatter, "higher-round checkpoint record {entry} has height {}, outside retained signing-lineage height {}", checkpoint_height.value(), lineage_height.value()),
            Self::HigherRoundCheckpointSourceBehindState { entry, current_position, current_phase, source_position, source_phase } => write!(formatter, "higher-round checkpoint record {entry} starts at {source_position:?}/{source_phase:?}, behind durable state {current_position:?}/{current_phase:?}"),
            Self::VoteStateDoesNotFollowHigherRoundCheckpoint { entry, checkpoint_position, checkpoint_phase, vote_position, vote_phase } => write!(formatter, "vote state in record {entry} at {vote_position:?}/{vote_phase:?} does not follow higher-round checkpoint {checkpoint_position:?}/{checkpoint_phase:?}"),
            Self::ExternalPrepareAnchorMismatch { prepared, acknowledged } => write!(formatter, "external durability acknowledgement names state {acknowledged:?}, expected prepared state {prepared:?}"),
            Self::ForeignPrepareAcknowledgement => formatter.write_str("external durability acknowledgement belongs to another signing session"),
            Self::SignedVote { entry, offset, source } => write!(formatter, "signed-vote record {entry} at byte {offset} failed strict verification: {source}"),
            Self::InvalidCompletionLength { entry, actual } => write!(formatter, "signed-vote record {entry} has {actual} payload bytes"),
            Self::CompletionMismatch { entry, reason } => write!(formatter, "signed-vote record {entry} does not complete its exact preparation: {reason:?}"),
            Self::CompletionWithoutPrepare { entry } => write!(formatter, "signed-vote record {entry} has no pending preparation"),
            Self::PrepareWhilePending { entry } => write!(formatter, "prepare record {entry} follows an uncompleted preparation"),
            Self::DuplicatePrepare { entry } => write!(formatter, "prepare record {entry} repeats an existing vote slot instead of using idempotent in-memory classification"),
            Self::InvalidConflictHalt { entry } => write!(formatter, "conflict record {entry} is not a non-identical intent at an existing vote slot"),
            Self::InvalidFinalityConflictSignerStopLength { entry, actual } => write!(formatter, "finality-conflict signer-stop record {entry} has {actual} payload bytes"),
            Self::InvalidFinalityConflictSignerStop { entry } => write!(formatter, "finality-conflict signer-stop record {entry} has an invalid reserved height"),
            Self::ConflictingFinalityConflictSignerStop { retained_height, incoming_height } => write!(formatter, "signer already stopped for finality conflict at height {}, so conflict at height {} cannot replace it", retained_height.value(), incoming_height.value()),
            Self::RecordAfterHalt { offset } => write!(formatter, "vote-safety journal contains bytes after terminal halt at byte {offset}"),
            Self::ReplayLimitExceeded { entry, maximum } => write!(formatter, "prepare record {entry} exceeds replay ceiling {maximum}"),
            Self::NonMonotonicReplay { entry, previous, previous_role, actual, actual_role } => write!(formatter, "prepare record {entry} moves backward from {previous:?}/{previous_role:?} to {actual:?}/{actual_role:?}"),
            Self::ExpectedStateIdMismatch { expected, actual } => write!(formatter, "vote-safety journal state mismatch: expected {expected:?}, replayed {actual:?}"),
            Self::AnchorBehind { anchored_sequence, journal_sequence } => write!(formatter, "vote-safety anchor is behind at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"),
            Self::AnchorAhead { anchored_sequence, journal_sequence } => write!(formatter, "vote-safety anchor is ahead at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"),
            Self::AnchorStateMismatch { sequence } => write!(formatter, "vote-safety anchor and journal have different state identities at sequence {sequence}"),
            Self::RecordSequenceExhausted => formatter.write_str("vote-safety journal frame sequence is exhausted"),
            Self::Recovery { offset, source } => write!(formatter, "incomplete vote-safety tail at byte {offset} could not be recovered: {source}"),
            Self::Stabilize { source } => write!(formatter, "replayed vote-safety journal stabilization failed: {source}"),
            Self::PendingPreparation { position, role } => write!(formatter, "vote {position:?}/{role:?} must complete before another slot can prepare"),
            Self::PendingHeightAdvance { state_id } => write!(formatter, "signer-height advance at vote-journal state {state_id:?} must be externally acknowledged before another transition"),
            Self::PendingHigherRoundAdvance { state_id } => write!(formatter, "higher-round checkpoint at vote-journal state {state_id:?} must be externally acknowledged before another transition"),
            Self::ExternalHeightAnchorMismatch { prepared, acknowledged } => write!(formatter, "external height-advance acknowledgement names state {acknowledged:?}, expected prepared state {prepared:?}"),
            Self::ForeignHeightAdvance => formatter.write_str("prepared signer-height advance belongs to another signing session"),
            Self::StaleHeightAdvance => formatter.write_str("prepared signer-height advance does not match the current durable lineage"),
            Self::ExternalHigherRoundAnchorMismatch { prepared, acknowledged } => write!(formatter, "external higher-round acknowledgement names state {acknowledged:?}, expected checkpoint state {prepared:?}"),
            Self::ForeignHigherRoundAdvance => formatter.write_str("prepared higher-round advance belongs to another signing session"),
            Self::StaleHigherRoundAdvance => formatter.write_str("prepared higher-round advance does not match the current durable checkpoint"),
            Self::PendingRecoveryDenied { position, role } => write!(formatter, "completed lock-state recovery is denied behind pending vote {position:?}/{role:?}"),
            Self::PrepareLimitExceeded { maximum } => write!(formatter, "prepared-vote ceiling {maximum} is exhausted"),
            Self::NonMonotonicSlot { previous, previous_role, actual, actual_role } => write!(formatter, "vote slot {actual:?}/{actual_role:?} does not follow retained {previous:?}/{previous_role:?}"),
            Self::UnknownPreparedVote => formatter.write_str("prepared-vote capability does not name retained state"),
            Self::StalePreparedVote => formatter.write_str("prepared-vote capability does not match the current durable preparation"),
            Self::RestartedPending { position, role } => write!(formatter, "reopened vote-safety journal has a non-signable pending preparation at {position:?}/{role:?}"),
            Self::SelfVerification(source) => write!(formatter, "new local signature failed strict consensus self-verification: {source}"),
            Self::SelfVerificationMismatch(reason) => write!(formatter, "new local signature verified as the wrong prepared vote field: {reason:?}"),
            Self::TerminalHalt { position, role } => write!(formatter, "vote-safety journal is terminally halted at {position:?}/{role:?}"),
            Self::TerminalFinalityConflictSignerStop { height } => write!(formatter, "vote-safety journal is terminally stopped by finality conflict at height {}", height.value()),
            Self::Commit { proposed_state_id, source } => write!(formatter, "vote-safety append proposing state {proposed_state_id:?} has unknown durability: {source}"),
            Self::Poisoned => formatter.write_str("vote-safety journal is poisoned after ambiguous I/O; drop it and reopen with a trusted state ID"),
        }
    }
}

impl Error for FixedValidatorVoteSafetyJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockFile { source }
            | Self::Lock { source }
            | Self::Create { source }
            | Self::Open { source }
            | Self::Read { source, .. }
            | Self::Recovery { source, .. }
            | Self::Stabilize { source }
            | Self::Commit { source, .. } => Some(source),
            Self::Intent { source, .. } => Some(source),
            Self::SignerRecoveryRound(source) => Some(source),
            Self::LockState(source) => Some(source),
            Self::SigningSessionIntent(source) => Some(source),
            Self::HigherRoundCheckpoint { source, .. }
            | Self::HigherRoundCheckpointReplay(source) => Some(source),
            Self::SignedVote { source, .. } | Self::SelfVerification(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
