use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::mem;

use naome_consensus::{
    ConsensusKey, ConsensusPosition, ConsensusVoteTarget, FixedConsensusBranchCoordinateV0,
    FixedConsensusProposalPrevoteVerifyErrorV0, FixedConsensusRoundV0, ProposalSigningRoot,
    VerifiedConsensusVoteV0,
};

use super::{
    FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeProposalBufferDrainV0,
    FixedValidatorNodeProposalBufferInsertErrorV0, FixedValidatorNodeProposalBufferInsertOutcomeV0,
    FixedValidatorNodeProposalBufferLimitsV0, FixedValidatorNodeProposalBufferV0,
};

/// Positive caller-local limits for one volatile proposal/prevote inbox.
///
/// The entry limit counts proposal tokens and distinct canonical prevote
/// variants together. The byte limit counts proposal control plus artifact
/// bytes and complete canonical signed-prevote bytes. Neither limit is a
/// protocol-wide admission rule or a total resident-memory bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeHigherRoundInboxLimitsV0 {
    max_entries: usize,
    max_total_canonical_input_bytes: u64,
}

impl FixedValidatorNodeHigherRoundInboxLimitsV0 {
    /// Constructs one positive combined entry and canonical-input byte budget.
    pub const fn new(
        max_entries: usize,
        max_total_canonical_input_bytes: u64,
    ) -> Result<Self, FixedValidatorNodeHigherRoundInboxLimitsErrorV0> {
        if max_entries == 0 {
            return Err(FixedValidatorNodeHigherRoundInboxLimitsErrorV0::ZeroMaxEntries);
        }
        if max_total_canonical_input_bytes == 0 {
            return Err(
                FixedValidatorNodeHigherRoundInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes,
            );
        }
        Ok(Self {
            max_entries,
            max_total_canonical_input_bytes,
        })
    }

    /// Returns the maximum combined proposal-token and prevote-variant count.
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum combined canonical-input byte count.
    pub const fn max_total_canonical_input_bytes(self) -> u64 {
        self.max_total_canonical_input_bytes
    }
}

/// A rejected volatile higher-round inbox limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxLimitsErrorV0 {
    /// At least one retained input must be permitted.
    ZeroMaxEntries,
    /// At least one canonical input byte must be permitted.
    ZeroMaxTotalCanonicalInputBytes,
}

impl fmt::Display for FixedValidatorNodeHigherRoundInboxLimitsErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("higher-round inbox entry limit must be positive")
            }
            Self::ZeroMaxTotalCanonicalInputBytes => formatter.write_str(
                "higher-round inbox aggregate canonical-input-byte limit must be positive",
            ),
        }
    }
}

impl Error for FixedValidatorNodeHigherRoundInboxLimitsErrorV0 {}

/// The immutable reason this inbox denied all ordinary access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxSaturationV0 {
    /// One nonduplicate input would exceed at least one configured local limit.
    Capacity {
        attempted_entries: usize,
        maximum_entries: usize,
        attempted_canonical_input_bytes: u64,
        maximum_canonical_input_bytes: u64,
    },
    /// Counting one more distinct input overflowed the platform range.
    EntryCountOverflow { maximum_entries: usize },
    /// Summing exact retained input lengths overflowed `u64`.
    CanonicalInputByteCountOverflow { maximum_canonical_input_bytes: u64 },
}

impl fmt::Display for FixedValidatorNodeHigherRoundInboxSaturationV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity {
                attempted_entries,
                maximum_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "higher-round inbox capacity exceeded: {attempted_entries} entries and {attempted_canonical_input_bytes} canonical input bytes were attempted, with limits {maximum_entries} and {maximum_canonical_input_bytes}"
            ),
            Self::EntryCountOverflow { maximum_entries } => write!(
                formatter,
                "higher-round inbox entry count overflowed with configured limit {maximum_entries}"
            ),
            Self::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "higher-round inbox canonical input byte count overflowed with configured limit {maximum_canonical_input_bytes}"
            ),
        }
    }
}

/// A saturated inbox denied insertion or explicit pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorNodeHigherRoundInboxAccessErrorV0 {
    saturation: FixedValidatorNodeHigherRoundInboxSaturationV0,
}

impl FixedValidatorNodeHigherRoundInboxAccessErrorV0 {
    /// Returns the immutable reason ordinary inbox access is denied.
    pub const fn saturation(self) -> FixedValidatorNodeHigherRoundInboxSaturationV0 {
        self.saturation
    }
}

impl fmt::Display for FixedValidatorNodeHigherRoundInboxAccessErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "saturated higher-round inbox denies ordinary access: {}",
            self.saturation
        )
    }
}

impl Error for FixedValidatorNodeHigherRoundInboxAccessErrorV0 {}

/// Result of retaining one fully admitted proposal token.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0 {
    /// The inbox now owns this distinct proposal-evidence variant.
    Inserted,
    /// Both canonical input strings were already retained without growth.
    AlreadyRetained {
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    },
}

enum FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0 {
    Saturated {
        saturation: FixedValidatorNodeHigherRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    ProposalBuffer(FixedValidatorNodeProposalBufferInsertErrorV0),
}

/// A lossless proposal insertion failure.
pub struct FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
    proposal: Option<Box<FixedValidatorNodeDeferredProposalV0>>,
    kind: FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0,
}

impl FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
    /// Returns the exact proposal token that was not inserted.
    pub fn attempted_proposal(&self) -> &FixedValidatorNodeDeferredProposalV0 {
        match (&self.proposal, &self.kind) {
            (Some(proposal), _) => proposal,
            (
                None,
                FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source),
            ) => source.attempted_proposal(),
            (
                None,
                FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated { .. },
            ) => {
                unreachable!("saturation insertion failures retain their proposal directly")
            }
        }
    }

    /// Consumes the error and returns the exact token that was not inserted.
    pub fn into_attempted_proposal(self) -> Box<FixedValidatorNodeDeferredProposalV0> {
        match (self.proposal, self.kind) {
            (Some(proposal), _) => proposal,
            (
                None,
                FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source),
            ) => source.into_attempted_proposal(),
            (
                None,
                FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated { .. },
            ) => {
                unreachable!("saturation insertion failures retain their proposal directly")
            }
        }
    }

    /// Returns the outer inbox saturation reason, if capacity failed.
    pub const fn saturation(&self) -> Option<FixedValidatorNodeHigherRoundInboxSaturationV0> {
        match self.kind {
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated {
                saturation,
                ..
            } => Some(saturation),
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(_) => None,
        }
    }

    /// Returns whether this attempt first moved the inbox into saturation.
    pub const fn newly_saturated(&self) -> bool {
        matches!(
            self.kind,
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated {
                newly_saturated: true,
                ..
            }
        )
    }

    /// Returns whether fallible proposal-buffer reservation failed.
    pub fn is_reservation_failure(&self) -> bool {
        match &self.kind {
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source) => {
                source.is_reservation_failure()
            }
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated { .. } => false,
        }
    }
}

impl fmt::Debug for FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug =
            formatter.debug_struct("FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0");
        debug
            .field("position", &self.attempted_proposal().position())
            .field(
                "proposal_signing_root",
                &self.attempted_proposal().proposal_signing_root(),
            );
        match &self.kind {
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated {
                saturation,
                newly_saturated,
            } => debug
                .field("saturation", saturation)
                .field("newly_saturated", newly_saturated),
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source) => {
                debug.field("proposal_buffer", source)
            }
        };
        debug.finish()
    }
}

impl fmt::Display for FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated {
                saturation,
                ..
            } => write!(formatter, "proposal was not inserted because {saturation}"),
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source) => {
                source.fmt(formatter)
            }
        }
    }
}

impl Error for FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(source) => {
                Some(source)
            }
            FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated { .. } => None,
        }
    }
}

/// Result of retaining one exact active proposal-prevote variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0 {
    /// The inbox now owns this distinct complete canonical vote.
    Inserted,
    /// This exact parent-bound canonical vote was already retained.
    AlreadyRetained,
}

/// Rejection while verifying or retaining one proposal prevote.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0 {
    /// The inbox is saturated; the input was not inspected.
    Saturated {
        saturation: FixedValidatorNodeHigherRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    /// Exact typed-round signature, field, or active-membership admission failed.
    Admission(FixedConsensusProposalPrevoteVerifyErrorV0),
    /// Fallible vote-collection reservation failed without changing the inbox.
    Reservation(std::collections::TryReserveError),
}

impl FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0 {
    /// Returns the inbox saturation reason, if capacity failed or was latched.
    pub const fn saturation(&self) -> Option<FixedValidatorNodeHigherRoundInboxSaturationV0> {
        match self {
            Self::Saturated { saturation, .. } => Some(*saturation),
            Self::Admission(_) | Self::Reservation(_) => None,
        }
    }

    /// Returns whether this attempt first moved the inbox into saturation.
    pub const fn newly_saturated(&self) -> bool {
        matches!(
            self,
            Self::Saturated {
                newly_saturated: true,
                ..
            }
        )
    }
}

impl fmt::Display for FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saturated { saturation, .. } => {
                write!(
                    formatter,
                    "proposal prevote was not inserted because {saturation}"
                )
            }
            Self::Admission(source) => source.fmt(formatter),
            Self::Reservation(source) => write!(
                formatter,
                "higher-round inbox vote collection reservation failed before insertion: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Reservation(source) => Some(source),
            Self::Saturated { .. } => None,
        }
    }
}

pub(super) struct FixedValidatorNodeRetainedProposalPrevoteV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    signer: ConsensusKey,
    canonical_bytes: [u8; VerifiedConsensusVoteV0::BYTE_LENGTH],
}

impl FixedValidatorNodeRetainedProposalPrevoteV0 {
    pub(super) const fn parent_coordinate(&self) -> FixedConsensusBranchCoordinateV0 {
        self.parent_coordinate
    }

    pub(super) const fn position(&self) -> ConsensusPosition {
        self.position
    }

    pub(super) const fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }

    pub(super) const fn signer(&self) -> ConsensusKey {
        self.signer
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// One losslessly drained higher-round inbox item.
///
/// The complete vote stays inline so draining never allocates or loses an item
/// merely to balance the enum's variant sizes.
#[allow(clippy::large_enum_variant)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeHigherRoundInboxDrainItemV0 {
    /// One fully admitted proposal token.
    Proposal(Box<FixedValidatorNodeDeferredProposalV0>),
    /// One exact canonical active proposal prevote.
    ProposalPrevote([u8; VerifiedConsensusVoteV0::BYTE_LENGTH]),
}

/// Lossless iterator returned by explicit inbox drain-and-reset.
#[must_use]
pub struct FixedValidatorNodeHigherRoundInboxDrainV0 {
    proposals: FixedValidatorNodeProposalBufferDrainV0,
    prevotes: std::vec::IntoIter<FixedValidatorNodeRetainedProposalPrevoteV0>,
}

impl Iterator for FixedValidatorNodeHigherRoundInboxDrainV0 {
    type Item = FixedValidatorNodeHigherRoundInboxDrainItemV0;

    fn next(&mut self) -> Option<Self::Item> {
        self.proposals
            .next()
            .map(FixedValidatorNodeHigherRoundInboxDrainItemV0::Proposal)
            .or_else(|| {
                self.prevotes.next().map(|vote| {
                    FixedValidatorNodeHigherRoundInboxDrainItemV0::ProposalPrevote(
                        vote.canonical_bytes,
                    )
                })
            })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for FixedValidatorNodeHigherRoundInboxDrainV0 {
    fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.prevotes.len())
            .expect("drained inbox length was previously representable")
    }
}

impl FusedIterator for FixedValidatorNodeHigherRoundInboxDrainV0 {}

/// One caller-owned, process-local proposal and proposal-prevote inbox.
///
/// Every retained proposal was fully admitted before insertion. Every retained
/// vote was strictly verified against one exact typed branch round, including
/// active membership, before insertion. Pairing still rederives and rechecks
/// the selected inputs against live node state. This type has no durable or
/// canonical encoding and is intentionally not cloneable.
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeHigherRoundInboxV0;
///
/// fn duplicate(inbox: FixedValidatorNodeHigherRoundInboxV0) {
///     let _ = inbox.clone();
/// }
/// ```
#[must_use]
pub struct FixedValidatorNodeHigherRoundInboxV0 {
    limits: FixedValidatorNodeHigherRoundInboxLimitsV0,
    pub(super) proposals: FixedValidatorNodeProposalBufferV0,
    pub(super) prevotes: Vec<FixedValidatorNodeRetainedProposalPrevoteV0>,
    total_canonical_input_bytes: u64,
    saturation: Option<FixedValidatorNodeHigherRoundInboxSaturationV0>,
}

impl FixedValidatorNodeHigherRoundInboxV0 {
    /// Constructs one empty healthy process-local inbox.
    pub fn new(limits: FixedValidatorNodeHigherRoundInboxLimitsV0) -> Self {
        let proposal_limits = FixedValidatorNodeProposalBufferLimitsV0::new(
            limits.max_entries,
            limits.max_total_canonical_input_bytes,
        )
        .expect("higher-round inbox limits are positive");
        Self {
            limits,
            proposals: FixedValidatorNodeProposalBufferV0::new(proposal_limits),
            prevotes: Vec::new(),
            total_canonical_input_bytes: 0,
            saturation: None,
        }
    }

    /// Returns this inbox's exact caller-local limits.
    pub const fn limits(&self) -> FixedValidatorNodeHigherRoundInboxLimitsV0 {
        self.limits
    }

    /// Returns the combined retained proposal-token and vote-variant count.
    pub fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.prevotes.len())
            .expect("retained inbox length stayed representable at insertion")
    }

    /// Returns whether no proposal token or proposal prevote is retained.
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty() && self.prevotes.is_empty()
    }

    /// Returns the retained proposal-token count.
    pub fn proposal_len(&self) -> usize {
        self.proposals.len()
    }

    /// Returns the retained distinct canonical prevote-variant count.
    pub fn prevote_len(&self) -> usize {
        self.prevotes.len()
    }

    /// Returns the combined checked canonical-input byte count.
    pub const fn total_canonical_input_bytes(&self) -> u64 {
        self.total_canonical_input_bytes
    }

    /// Returns the immutable saturation reason, if ordinary access is denied.
    pub const fn saturation(&self) -> Option<FixedValidatorNodeHigherRoundInboxSaturationV0> {
        self.saturation
    }

    /// Retains one fully admitted proposal token under the combined budget.
    pub fn try_insert_proposal(
        &mut self,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    ) -> Result<
        FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0,
        FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0,
    > {
        if let Some(saturation) = self.saturation {
            return Err(self.proposal_saturation_error(proposal, saturation, false));
        }
        if self.proposals.contains_exact_proposal(&proposal) {
            return Ok(
                FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::AlreadyRetained {
                    proposal,
                },
            );
        }
        let canonical_input_bytes = match proposal_canonical_input_bytes(&proposal) {
            Some(bytes) => bytes,
            None => {
                let saturation =
                    FixedValidatorNodeHigherRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                        maximum_canonical_input_bytes: self.limits.max_total_canonical_input_bytes,
                    };
                self.saturation = Some(saturation);
                return Err(self.proposal_saturation_error(proposal, saturation, true));
            }
        };
        let prospective_total = match checked_prospective_totals(
            self.len(),
            self.total_canonical_input_bytes,
            canonical_input_bytes,
            self.limits,
        ) {
            Ok((_, total)) => total,
            Err(saturation) => {
                self.saturation = Some(saturation);
                return Err(self.proposal_saturation_error(proposal, saturation, true));
            }
        };

        match self.proposals.try_insert(proposal) {
            Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted) => {
                self.total_canonical_input_bytes = prospective_total;
                Ok(FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::Inserted)
            }
            Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { proposal }) => {
                Ok(
                    FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::AlreadyRetained {
                        proposal,
                    },
                )
            }
            Err(source) => Err(FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
                proposal: None,
                kind: FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::ProposalBuffer(
                    source,
                ),
            }),
        }
    }

    /// Verifies and retains one exact active non-nil prevote for `round`.
    ///
    /// The round contributes its complete parent coordinate, exact position,
    /// branch context, and immutable fixed active set. The verified opaque
    /// proposal root is descriptive grouping data only. No proposal existence,
    /// quorum, pairing, progression, or persistence authority is created.
    pub fn try_insert_proposal_prevote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_signed_prevote: &[u8],
    ) -> Result<
        FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0,
        FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0,
    > {
        if let Some(saturation) = self.saturation {
            return Err(
                FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Saturated {
                    saturation,
                    newly_saturated: false,
                },
            );
        }
        let vote = round
            .decode_and_verify_active_proposal_prevote(canonical_signed_prevote)
            .map_err(FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Admission)?;
        let parent_coordinate = round.parent_coordinate();
        let canonical_bytes = vote.to_canonical_bytes();
        if self.prevotes.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate
                && retained.canonical_bytes == canonical_bytes
        }) {
            return Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::AlreadyRetained);
        }
        let canonical_input_bytes = u64::try_from(VerifiedConsensusVoteV0::BYTE_LENGTH)
            .expect("canonical signed-vote length fits u64");
        let prospective_total = match checked_prospective_totals(
            self.len(),
            self.total_canonical_input_bytes,
            canonical_input_bytes,
            self.limits,
        ) {
            Ok((_, total)) => total,
            Err(saturation) => {
                self.saturation = Some(saturation);
                return Err(
                    FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Saturated {
                        saturation,
                        newly_saturated: true,
                    },
                );
            }
        };
        self.prevotes
            .try_reserve(1)
            .map_err(FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Reservation)?;
        let proposal_signing_root = match vote.target() {
            ConsensusVoteTarget::Proposal(root) => root,
            ConsensusVoteTarget::Nil => {
                unreachable!("typed proposal-prevote admission rejects nil")
            }
        };
        self.prevotes
            .push(FixedValidatorNodeRetainedProposalPrevoteV0 {
                parent_coordinate,
                position: vote.position(),
                proposal_signing_root,
                signer: vote.signer(),
                canonical_bytes,
            });
        self.total_canonical_input_bytes = prospective_total;
        Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::Inserted)
    }

    /// Returns all retained inputs and restores this same owner to healthy empty.
    ///
    /// Proposal items are yielded before vote items only as collection detail.
    /// Drain order grants no evidence or proposal preference.
    pub fn drain_and_reset(&mut self) -> FixedValidatorNodeHigherRoundInboxDrainV0 {
        let proposals = self.proposals.drain_and_reset();
        let prevotes = mem::take(&mut self.prevotes).into_iter();
        self.total_canonical_input_bytes = 0;
        self.saturation = None;
        FixedValidatorNodeHigherRoundInboxDrainV0 {
            proposals,
            prevotes,
        }
    }

    pub(super) fn ensure_access(
        &self,
    ) -> Result<(), FixedValidatorNodeHigherRoundInboxAccessErrorV0> {
        match self.saturation {
            Some(saturation) => Err(FixedValidatorNodeHigherRoundInboxAccessErrorV0 { saturation }),
            None => Ok(()),
        }
    }

    pub(super) fn note_selected_proposal_removed(&mut self, canonical_input_bytes: u64) {
        self.total_canonical_input_bytes = self
            .total_canonical_input_bytes
            .checked_sub(canonical_input_bytes)
            .expect("selected proposal bytes were included in combined inbox accounting");
    }

    fn proposal_saturation_error(
        &self,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
        saturation: FixedValidatorNodeHigherRoundInboxSaturationV0,
        newly_saturated: bool,
    ) -> FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
        FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0 {
            proposal: Some(proposal),
            kind: FixedValidatorNodeHigherRoundInboxProposalInsertErrorKindV0::Saturated {
                saturation,
                newly_saturated,
            },
        }
    }
}

impl fmt::Debug for FixedValidatorNodeHigherRoundInboxV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedValidatorNodeHigherRoundInboxV0")
            .field("limits", &self.limits)
            .field("proposals", &self.proposals.len())
            .field("prevote_variants", &self.prevotes.len())
            .field(
                "total_canonical_input_bytes",
                &self.total_canonical_input_bytes,
            )
            .field("saturation", &self.saturation)
            .finish()
    }
}

fn proposal_canonical_input_bytes(proposal: &FixedValidatorNodeDeferredProposalV0) -> Option<u64> {
    let control = u64::try_from(proposal.canonical_proposal_control_bytes().len()).ok()?;
    let artifact = u64::try_from(proposal.canonical_artifact_bytes().len()).ok()?;
    control.checked_add(artifact)
}

fn checked_prospective_totals(
    current_entries: usize,
    current_canonical_input_bytes: u64,
    inserted_canonical_input_bytes: u64,
    limits: FixedValidatorNodeHigherRoundInboxLimitsV0,
) -> Result<(usize, u64), FixedValidatorNodeHigherRoundInboxSaturationV0> {
    let attempted_entries = current_entries.checked_add(1).ok_or(
        FixedValidatorNodeHigherRoundInboxSaturationV0::EntryCountOverflow {
            maximum_entries: limits.max_entries,
        },
    )?;
    let attempted_canonical_input_bytes = current_canonical_input_bytes
        .checked_add(inserted_canonical_input_bytes)
        .ok_or(
            FixedValidatorNodeHigherRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            },
        )?;
    if attempted_entries > limits.max_entries
        || attempted_canonical_input_bytes > limits.max_total_canonical_input_bytes
    {
        return Err(FixedValidatorNodeHigherRoundInboxSaturationV0::Capacity {
            attempted_entries,
            maximum_entries: limits.max_entries,
            attempted_canonical_input_bytes,
            maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
        });
    }
    Ok((attempted_entries, attempted_canonical_input_bytes))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn combined_limits_are_positive_and_exact() {
        assert_eq!(
            FixedValidatorNodeHigherRoundInboxLimitsV0::new(0, 1),
            Err(FixedValidatorNodeHigherRoundInboxLimitsErrorV0::ZeroMaxEntries)
        );
        assert_eq!(
            FixedValidatorNodeHigherRoundInboxLimitsV0::new(1, 0),
            Err(FixedValidatorNodeHigherRoundInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes)
        );
        let limits = FixedValidatorNodeHigherRoundInboxLimitsV0::new(5, 991).unwrap();
        assert_eq!(limits.max_entries(), 5);
        assert_eq!(limits.max_total_canonical_input_bytes(), 991);
    }

    #[test]
    fn prospective_totals_reject_arithmetic_overflow_without_inputs() {
        let limits = FixedValidatorNodeHigherRoundInboxLimitsV0::new(usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            checked_prospective_totals(usize::MAX, 0, 1, limits),
            Err(
                FixedValidatorNodeHigherRoundInboxSaturationV0::EntryCountOverflow {
                    maximum_entries: usize::MAX,
                }
            )
        );
        assert_eq!(
            checked_prospective_totals(0, u64::MAX, 1, limits),
            Err(
                FixedValidatorNodeHigherRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: u64::MAX,
                }
            )
        );
    }
}
