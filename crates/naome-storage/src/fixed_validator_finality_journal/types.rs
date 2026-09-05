//! Limits, immutable capabilities, and retained evidence types.

use super::*;

/// Positive caller-provisioned maximum persisted finality round.
///
/// The ceiling bounds local journal admission and replay work. It is stored in
/// the journal header and is not a protocol-wide assertion that a higher-round
/// certificate is cryptographically invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityReplayLimitV0(pub(super) u64);

impl FixedValidatorFinalityReplayLimitV0 {
    /// Constructs one positive local maximum round.
    pub const fn new(max_round: u64) -> Result<Self, FixedValidatorFinalityReplayLimitErrorV0> {
        if max_round == 0 {
            Err(FixedValidatorFinalityReplayLimitErrorV0)
        } else {
            Ok(Self(max_round))
        }
    }

    /// Returns the configured inclusive maximum round.
    pub const fn max_round(self) -> u64 {
        self.0
    }
}

/// A zero local replay-round ceiling is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorFinalityReplayLimitErrorV0;

impl fmt::Display for FixedValidatorFinalityReplayLimitErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed-validator finality replay round limit must be positive")
    }
}

impl Error for FixedValidatorFinalityReplayLimitErrorV0 {}

/// Chained identity of one exact durable fixed-validator journal state.
///
/// The empty identity commits the complete synchronized header. Every later
/// identity commits the preceding identity and one exact finalized or halt
/// record. It is local persistence identity, not consensus ancestry, envelope,
/// artifact, checkpoint, or globally trusted finality by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct FixedValidatorFinalityJournalStateIdV0(pub(super) [u8; Self::BYTE_LENGTH]);

impl FixedValidatorFinalityJournalStateIdV0 {
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

/// Exact first finality proof retained for one selected height.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorFinalityRecordV0 {
    pub(super) position: ConsensusPosition,
    pub(super) value: ConsensusValueV0,
    pub(super) envelope_id: ConsensusEnvelopeId,
    pub(super) canonical_record_body: Vec<u8>,
    pub(super) envelope_end: usize,
    pub(super) state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl FixedValidatorFinalityRecordV0 {
    /// Returns the exact authenticated height and round of the retained proof.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact evidence-free finalized value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the evidence-variant identity of the retained first envelope.
    pub const fn envelope_id(&self) -> ConsensusEnvelopeId {
        self.envelope_id
    }

    /// Returns the exact retained canonical envelope bytes.
    pub fn canonical_envelope_bytes(&self) -> &[u8] {
        &self.canonical_record_body[RECORD_HEADER_BYTES..self.envelope_end]
    }

    /// Returns the exact retained canonical artifact payload bytes.
    pub fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_record_body[self.envelope_end..]
    }

    /// Returns the journal-state identity published by this finality record.
    pub const fn state_id(&self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }

    pub(super) fn canonical_record_body(&self) -> &[u8] {
        &self.canonical_record_body
    }
}

/// The semantic class of one durable terminal safety failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorFinalityHaltKindV0 {
    /// One already selected value received a distinct verified sibling proof.
    SelectedSibling,
    /// Two distinct unselected direct children were verified as a neutral pair.
    PreselectionPair,
}

/// Durable terminal safety-failure evidence summary.
///
/// `first` and `second` are diagnostic evidence order only. For a selected-
/// sibling halt they retain selected then conflicting evidence. For a paired
/// preselection halt they retain ascending proposal-signing-root order. Neither
/// order grants branch, winner, rollback, or finality-selection authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityHaltV0 {
    pub(super) kind: FixedValidatorFinalityHaltKindV0,
    pub(super) height: ConsensusHeight,
    pub(super) first_ancestry: ConsensusAncestryId,
    pub(super) first_envelope_id: ConsensusEnvelopeId,
    pub(super) second_ancestry: ConsensusAncestryId,
    pub(super) second_envelope_id: ConsensusEnvelopeId,
    pub(super) state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl FixedValidatorFinalityHaltV0 {
    /// Returns the terminal evidence class.
    pub const fn kind(self) -> FixedValidatorFinalityHaltKindV0 {
        self.kind
    }

    /// Returns the height at which the terminal conflict was established.
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

    /// Returns the terminal journal-state identity published by the halt.
    pub const fn state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }
}

/// Result of consuming one completely verified transition at the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorFinalityCommitOutcomeV0 {
    /// One direct child became durable and operable after the commit sync.
    Finalized {
        position: ConsensusPosition,
        ancestry_id: ConsensusAncestryId,
        envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// The exact value was already selected; no bytes or identity changed.
    AlreadyFinalized {
        height: ConsensusHeight,
        ancestry_id: ConsensusAncestryId,
        retained_envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// A distinct valid sibling was durably recorded and operation halted.
    Halted(FixedValidatorFinalityHaltV0),
}

/// One exact candidate-backed direct child installed as durable finality.
///
/// Candidate and payload stores supplied availability only. The complete
/// authenticated envelope remains the sole authority for this finality
/// transition, and the source-store entries remain retained and unmodified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBackedFinalityCommitV0 {
    pub(super) target: ArtifactBlockId,
    pub(super) position: ConsensusPosition,
    pub(super) ancestry_id: ConsensusAncestryId,
    pub(super) envelope_id: ConsensusEnvelopeId,
    pub(super) state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl CandidateBackedFinalityCommitV0 {
    /// Returns the exact caller-selected block that became finalized.
    pub const fn target(self) -> ArtifactBlockId {
        self.target
    }

    /// Returns the authenticated height and round.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the installed consensus ancestry identity.
    pub const fn ancestry_id(self) -> ConsensusAncestryId {
        self.ancestry_id
    }

    /// Returns the retained complete-envelope identity.
    pub const fn envelope_id(self) -> ConsensusEnvelopeId {
        self.envelope_id
    }

    /// Returns the new durable finality-journal state identity.
    pub const fn state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }
}

/// One exact caller-selected candidate that proved a finalized sibling conflict.
///
/// Source-store availability grants no finality or conflict authority. Only the
/// fully authenticated distinct sibling may produce the retained terminal halt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBackedFinalityConflictV0 {
    pub(super) target: ArtifactBlockId,
    pub(super) halt: FixedValidatorFinalityHaltV0,
}

impl CandidateBackedFinalityConflictV0 {
    /// Returns the exact caller-selected conflicting block.
    pub const fn target(self) -> ArtifactBlockId {
        self.target
    }

    /// Returns the durable terminal finality halt.
    pub const fn halt(self) -> FixedValidatorFinalityHaltV0 {
        self.halt
    }
}

/// A rejection or durable-finality failure at the candidate-backed boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBackedFinalityErrorV0 {
    /// The finality journal is not healthy and operable.
    FinalityJournal(FixedValidatorFinalityJournalErrorV0),
    /// The operation-local work ceiling exceeds the journal's persisted ceiling.
    RoundWorkLimitExceedsJournal { requested: u64, journal: u64 },
    /// The explicit batch evidence round exceeds the operation-local work ceiling.
    EvidenceRoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The exact historical consensus round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The candidate store belongs to another artifact chain.
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// Exact candidate lookup or integrity verification failed.
    CandidateStore(ArtifactBlockCandidateStoreError),
    /// The exact caller-selected candidate is not retained.
    CandidateUnavailable { target: ArtifactBlockId },
    /// The envelope embeds another block address than the caller-selected target.
    EnvelopeTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The proposal embeds another block address than the caller-selected target.
    ProposalTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The retained candidate bytes differ from the supplied evidence's exact block.
    CandidateBlockMismatch { target: ArtifactBlockId },
    /// Exact payload lookup or integrity verification failed.
    PayloadStore(CanonicalArtifactPayloadStoreError),
    /// The retained candidate's exact committed payload is unavailable.
    PayloadUnavailable { artifact_id: ArtifactId },
    /// Bounded complete-envelope verification against the selected parent failed.
    Envelope(FixedConsensusBoundedEnvelopeVerifyError),
    /// Complete proposal-control or artifact-payload admission failed.
    Proposal(ConsensusProposalVerifyError),
    /// The exact signed-precommit batch could not seal the admitted proposal.
    PrecommitBatch(FixedConsensusPrecommitBatchSealErrorV0),
    /// The supplied evidence does not name an already selected positive height.
    SelectedHeightUnavailable { height: ConsensusHeight },
    /// The evidence-free value is the already selected value, not a sibling.
    SelectedValueNotDistinct { height: ConsensusHeight },
    /// An unreachable lower-level idempotent outcome violated this direct-child API.
    UnexpectedAlreadyFinalized { height: ConsensusHeight },
    /// An unreachable lower-level conflict outcome violated this direct-child API.
    UnexpectedConflictHalt { height: ConsensusHeight },
    /// An unreachable replay outcome violated the distinct-conflict API.
    UnexpectedSelectedValueReplay { height: ConsensusHeight },
    /// An unreachable new-height outcome violated the conflict API.
    UnexpectedNewFinality { height: ConsensusHeight },
}

impl fmt::Display for CandidateBackedFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalityJournal(error) => error.fmt(formatter),
            Self::RoundWorkLimitExceedsJournal { requested, journal } => write!(
                formatter,
                "candidate-backed finality work ceiling {requested} exceeds journal replay ceiling {journal}"
            ),
            Self::EvidenceRoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "candidate-backed finality evidence round {required:?} exceeds caller-local ceiling {maximum:?}"
            ),
            Self::Round(error) => write!(
                formatter,
                "candidate-backed finality round could not be reconstructed: {error}"
            ),
            Self::CandidateChainMismatch { expected, actual } => write!(
                formatter,
                "candidate store chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateStore(error) => error.fmt(formatter),
            Self::CandidateUnavailable { target } => {
                write!(formatter, "candidate block {target:?} is not retained")
            }
            Self::EnvelopeTargetMismatch { expected, actual } => write!(
                formatter,
                "consensus envelope block mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProposalTargetMismatch { expected, actual } => write!(
                formatter,
                "consensus proposal block mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateBlockMismatch { target } => write!(
                formatter,
                "retained candidate bytes differ from consensus envelope block {target:?}"
            ),
            Self::PayloadStore(error) => error.fmt(formatter),
            Self::PayloadUnavailable { artifact_id } => write!(
                formatter,
                "candidate artifact payload {artifact_id:?} is not retained"
            ),
            Self::Envelope(error) => error.fmt(formatter),
            Self::Proposal(error) => write!(
                formatter,
                "candidate-backed finality proposal was rejected: {error}"
            ),
            Self::PrecommitBatch(error) => write!(
                formatter,
                "candidate-backed finality precommit batch was rejected: {error}"
            ),
            Self::SelectedHeightUnavailable { height } => write!(
                formatter,
                "candidate-backed finality conflict requires an already selected height, but height {} is unavailable",
                height.value()
            ),
            Self::SelectedValueNotDistinct { height } => write!(
                formatter,
                "candidate-backed conflict input at height {} names the already selected value",
                height.value()
            ),
            Self::UnexpectedAlreadyFinalized { height } => write!(
                formatter,
                "candidate-backed direct child unexpectedly resolved as already finalized at height {}",
                height.value()
            ),
            Self::UnexpectedConflictHalt { height } => write!(
                formatter,
                "candidate-backed direct child unexpectedly produced a conflict halt at height {}",
                height.value()
            ),
            Self::UnexpectedSelectedValueReplay { height } => write!(
                formatter,
                "candidate-backed finality conflict unexpectedly resolved as selected-value replay at height {}",
                height.value()
            ),
            Self::UnexpectedNewFinality { height } => write!(
                formatter,
                "candidate-backed finality conflict unexpectedly finalized new height {}",
                height.value()
            ),
        }
    }
}

impl Error for CandidateBackedFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FinalityJournal(error) => Some(error),
            Self::CandidateStore(error) => Some(error),
            Self::PayloadStore(error) => Some(error),
            Self::Envelope(error) => Some(error),
            Self::Proposal(error) => Some(error),
            Self::PrecommitBatch(error) => Some(error),
            Self::Round(error) => Some(error),
            _ => None,
        }
    }
}

/// A retained selected transition whose exact finality state was acknowledged.
///
/// Private fields prevent caller construction. The live immutable journal
/// borrow keeps the issuing finality lineage operational and unchanged until a
/// key-owning vote-safety session consumes the capability.
#[must_use]
pub struct FixedValidatorDurableFinalityTransitionV0<'journal> {
    pub(super) _journal: &'journal FixedValidatorFinalityJournalV0,
    pub(super) transition: OwnedVerifiedFixedConsensusTransitionV0,
}

/// Opaque authority to stop matching local signers after durable finality conflict.
///
/// Private fields prevent callers from fabricating or changing the conflict
/// evidence. The live immutable journal borrow keeps the exact externally
/// anchored terminal state healthy and unchanged until one vote-safety journal
/// consumes this capability. It grants no sibling selection or rollback
/// authority.
#[must_use]
pub struct FixedValidatorDurableFinalityConflictV0<'journal> {
    pub(super) _journal: &'journal FixedValidatorFinalityJournalV0,
    pub(super) context: ConsensusContextV0,
    pub(super) fixed_set_id: FixedAgreementSetId,
    pub(super) halt: FixedValidatorFinalityHaltV0,
}

impl FixedValidatorDurableFinalityConflictV0<'_> {
    pub(crate) const fn context(&self) -> ConsensusContextV0 {
        self.context
    }

    pub(crate) const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.fixed_set_id
    }

    pub(crate) const fn halt(&self) -> FixedValidatorFinalityHaltV0 {
        self.halt
    }
}

impl FixedValidatorDurableFinalityTransitionV0<'_> {
    pub(crate) const fn verified_transition(&self) -> &OwnedVerifiedFixedConsensusTransitionV0 {
        &self.transition
    }

    pub(crate) fn into_verified_transition(self) -> OwnedVerifiedFixedConsensusTransitionV0 {
        self.transition
    }
}
