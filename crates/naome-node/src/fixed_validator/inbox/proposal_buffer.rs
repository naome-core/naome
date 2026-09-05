use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::mem;

use naome_consensus::{ConsensusPosition, FixedConsensusBranchCoordinateV0, ProposalSigningRoot};

use crate::fixed_validator::FixedValidatorNodeDeferredProposalV0;

/// Positive caller-local limits for one volatile deferred-proposal buffer.
///
/// The byte limit counts only the exact canonical proposal-control and artifact
/// payload lengths owned by retained tokens. It is neither a consensus limit nor
/// a bound on allocator metadata or the buffer's fixed per-entry bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeProposalBufferLimitsV0 {
    max_entries: usize,
    max_total_canonical_input_bytes: u64,
}

impl FixedValidatorNodeProposalBufferLimitsV0 {
    /// Constructs positive entry-count and aggregate canonical-input limits.
    pub const fn new(
        max_entries: usize,
        max_total_canonical_input_bytes: u64,
    ) -> Result<Self, FixedValidatorNodeProposalBufferLimitsErrorV0> {
        if max_entries == 0 {
            return Err(FixedValidatorNodeProposalBufferLimitsErrorV0::ZeroMaxEntries);
        }
        if max_total_canonical_input_bytes == 0 {
            return Err(
                FixedValidatorNodeProposalBufferLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes,
            );
        }
        Ok(Self {
            max_entries,
            max_total_canonical_input_bytes,
        })
    }

    /// Returns the maximum number of tokens owned by this buffer.
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum sum of both canonical input lengths for all entries.
    pub const fn max_total_canonical_input_bytes(self) -> u64 {
        self.max_total_canonical_input_bytes
    }
}

/// A rejected volatile proposal-buffer limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalBufferLimitsErrorV0 {
    /// At least one retained token must be permitted.
    ZeroMaxEntries,
    /// At least one canonical input byte must be permitted.
    ZeroMaxTotalCanonicalInputBytes,
}

impl fmt::Display for FixedValidatorNodeProposalBufferLimitsErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("proposal buffer entry limit must be positive")
            }
            Self::ZeroMaxTotalCanonicalInputBytes => formatter
                .write_str("proposal buffer aggregate canonical-input-byte limit must be positive"),
        }
    }
}

impl Error for FixedValidatorNodeProposalBufferLimitsErrorV0 {}

/// The immutable reason a volatile proposal buffer entered saturation.
///
/// Capacity reports both prospective totals so simultaneous item and byte
/// excess has no diagnostic precedence. Arithmetic overflow also saturates:
/// the unrepresentable total cannot fit any configured `usize` or `u64` limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalBufferSaturationV0 {
    /// One nonduplicate token would exceed at least one declared local limit.
    Capacity {
        attempted_entries: usize,
        maximum_entries: usize,
        attempted_canonical_input_bytes: u64,
        maximum_canonical_input_bytes: u64,
    },
    /// Counting one more nonduplicate token overflowed the platform range.
    EntryCountOverflow { maximum_entries: usize },
    /// Summing exact canonical input lengths overflowed `u64`.
    CanonicalInputByteCountOverflow { maximum_canonical_input_bytes: u64 },
}

impl fmt::Display for FixedValidatorNodeProposalBufferSaturationV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity {
                attempted_entries,
                maximum_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "proposal buffer capacity exceeded: {attempted_entries} entries and {attempted_canonical_input_bytes} canonical input bytes were attempted, with limits {maximum_entries} and {maximum_canonical_input_bytes}"
            ),
            Self::EntryCountOverflow { maximum_entries } => write!(
                formatter,
                "proposal buffer entry count overflowed with configured limit {maximum_entries}"
            ),
            Self::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "proposal buffer canonical input byte count overflowed with configured limit {maximum_canonical_input_bytes}"
            ),
        }
    }
}

/// Result of one healthy-buffer insertion attempt.
///
/// An exact duplicate compares both complete canonical byte strings. The
/// attempted duplicate is returned intact rather than silently dropped.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalBufferInsertOutcomeV0 {
    /// The buffer now owns the unique token.
    Inserted,
    /// Exact bytes were already retained; counts and saturation are unchanged.
    AlreadyRetained {
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    },
}

enum FixedValidatorNodeProposalBufferInsertErrorKindV0 {
    Saturated {
        saturation: FixedValidatorNodeProposalBufferSaturationV0,
        newly_saturated: bool,
    },
    Reservation(TryReserveError),
}

/// A lossless insertion failure for one volatile proposal buffer.
///
/// The attempted token is always retained by this error. Declared-capacity or
/// checked-arithmetic failure puts the buffer into its immutable saturated
/// state. A fallible collection reservation leaves the healthy buffer entirely
/// unchanged and is reported separately from configured saturation.
pub struct FixedValidatorNodeProposalBufferInsertErrorV0 {
    proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    kind: FixedValidatorNodeProposalBufferInsertErrorKindV0,
}

impl FixedValidatorNodeProposalBufferInsertErrorV0 {
    /// Returns the exact token that was not inserted.
    pub const fn attempted_proposal(&self) -> &FixedValidatorNodeDeferredProposalV0 {
        &self.proposal
    }

    /// Consumes the error and returns the exact token that was not inserted.
    pub fn into_attempted_proposal(self) -> Box<FixedValidatorNodeDeferredProposalV0> {
        self.proposal
    }

    /// Returns the buffer's saturation reason, if this is a saturation failure.
    pub const fn saturation(&self) -> Option<FixedValidatorNodeProposalBufferSaturationV0> {
        match self.kind {
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated { saturation, .. } => {
                Some(saturation)
            }
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(_) => None,
        }
    }

    /// Returns whether this attempt first moved the buffer into saturation.
    pub const fn newly_saturated(&self) -> bool {
        matches!(
            self.kind,
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated {
                newly_saturated: true,
                ..
            }
        )
    }

    /// Returns whether fallible local collection reservation failed.
    pub const fn is_reservation_failure(&self) -> bool {
        matches!(
            self.kind,
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(_)
        )
    }

    fn saturated(
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
        saturation: FixedValidatorNodeProposalBufferSaturationV0,
        newly_saturated: bool,
    ) -> Self {
        Self {
            proposal,
            kind: FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated {
                saturation,
                newly_saturated,
            },
        }
    }

    fn reservation(
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
        source: TryReserveError,
    ) -> Self {
        Self {
            proposal,
            kind: FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(source),
        }
    }
}

impl fmt::Debug for FixedValidatorNodeProposalBufferInsertErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("FixedValidatorNodeProposalBufferInsertErrorV0");
        debug
            .field("parent_coordinate", &self.proposal.parent_coordinate())
            .field("position", &self.proposal.position())
            .field(
                "proposal_signing_root",
                &self.proposal.proposal_signing_root(),
            )
            .field(
                "proposal_control_bytes",
                &self.proposal.canonical_proposal_control_bytes().len(),
            )
            .field(
                "artifact_bytes",
                &self.proposal.canonical_artifact_bytes().len(),
            );
        match &self.kind {
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated {
                saturation,
                newly_saturated,
            } => debug
                .field("saturation", saturation)
                .field("newly_saturated", newly_saturated),
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(source) => {
                debug.field("reservation", source)
            }
        };
        debug.finish()
    }
}

impl fmt::Display for FixedValidatorNodeProposalBufferInsertErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated { saturation, .. } => {
                write!(formatter, "proposal was not inserted because {saturation}")
            }
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(source) => write!(
                formatter,
                "proposal buffer collection reservation failed before insertion: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeProposalBufferInsertErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Saturated { .. } => None,
            FixedValidatorNodeProposalBufferInsertErrorKindV0::Reservation(source) => Some(source),
        }
    }
}

/// A saturated buffer denied ordinary exact retrieval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorNodeProposalBufferAccessErrorV0 {
    saturation: FixedValidatorNodeProposalBufferSaturationV0,
}

impl FixedValidatorNodeProposalBufferAccessErrorV0 {
    /// Returns the immutable reason ordinary buffer access is denied.
    pub const fn saturation(self) -> FixedValidatorNodeProposalBufferSaturationV0 {
        self.saturation
    }
}

impl fmt::Display for FixedValidatorNodeProposalBufferAccessErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "saturated proposal buffer denies retrieval: {}",
            self.saturation
        )
    }
}

impl Error for FixedValidatorNodeProposalBufferAccessErrorV0 {}

struct FixedValidatorNodeBufferedProposalV0 {
    canonical_input_bytes: u64,
    proposal: Box<FixedValidatorNodeDeferredProposalV0>,
}

pub(in crate::fixed_validator) struct FixedValidatorNodeProposalBufferLeaseV0<'buffer> {
    buffer: &'buffer mut FixedValidatorNodeProposalBufferV0,
    entry: Option<FixedValidatorNodeBufferedProposalV0>,
    original_index: usize,
}

impl FixedValidatorNodeProposalBufferLeaseV0<'_> {
    pub(in crate::fixed_validator) fn proposal(&self) -> &FixedValidatorNodeDeferredProposalV0 {
        self.entry
            .as_ref()
            .expect("proposal-buffer lease retains its entry until release")
            .proposal
            .as_ref()
    }

    pub(in crate::fixed_validator) fn release(
        mut self,
    ) -> Box<FixedValidatorNodeDeferredProposalV0> {
        self.entry
            .take()
            .expect("proposal-buffer lease releases its entry at most once")
            .proposal
    }
}

impl Drop for FixedValidatorNodeProposalBufferLeaseV0<'_> {
    fn drop(&mut self) {
        let Some(entry) = self.entry.take() else {
            return;
        };
        self.buffer.total_canonical_input_bytes = self
            .buffer
            .total_canonical_input_bytes
            .checked_add(entry.canonical_input_bytes)
            .expect("leased proposal byte accounting restores exactly");
        let restored_index = self.buffer.proposals.len();
        debug_assert!(self.original_index <= restored_index);
        self.buffer.proposals.push(entry);
        if self.original_index < restored_index {
            self.buffer
                .proposals
                .swap(self.original_index, restored_index);
        }
    }
}

/// A lossless owning iterator returned by explicit buffer drain-and-reset.
///
/// Its order is local collection detail and grants no preference or selection
/// authority. Dropping the iterator explicitly drops any tokens not yet taken.
#[must_use]
pub struct FixedValidatorNodeProposalBufferDrainV0 {
    entries: std::vec::IntoIter<FixedValidatorNodeBufferedProposalV0>,
}

impl Iterator for FixedValidatorNodeProposalBufferDrainV0 {
    type Item = Box<FixedValidatorNodeDeferredProposalV0>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|entry| entry.proposal)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for FixedValidatorNodeProposalBufferDrainV0 {
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl FusedIterator for FixedValidatorNodeProposalBufferDrainV0 {}

/// One separately composed, process-local fixed-validator proposal buffer.
///
/// The buffer privately owns only fully admitted deferred tokens. A caller may
/// retain this value outside and mutably capture it in one or more consuming
/// signing callbacks, so the entries outlive those callbacks without entering a
/// signer, journal, or startup record. There is no encoding or reconstruction
/// path; a fresh owner is empty after process or runtime-owner loss.
///
/// This type is deliberately not cloneable:
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeProposalBufferV0;
///
/// fn duplicate(buffer: FixedValidatorNodeProposalBufferV0) {
///     let _ = buffer.clone();
/// }
/// ```
#[must_use]
pub struct FixedValidatorNodeProposalBufferV0 {
    limits: FixedValidatorNodeProposalBufferLimitsV0,
    proposals: Vec<FixedValidatorNodeBufferedProposalV0>,
    total_canonical_input_bytes: u64,
    saturation: Option<FixedValidatorNodeProposalBufferSaturationV0>,
}

impl FixedValidatorNodeProposalBufferV0 {
    /// Constructs one empty healthy buffer under exact caller-local limits.
    pub const fn new(limits: FixedValidatorNodeProposalBufferLimitsV0) -> Self {
        Self {
            limits,
            proposals: Vec::new(),
            total_canonical_input_bytes: 0,
            saturation: None,
        }
    }

    /// Returns the exact local limits selected for this buffer.
    pub const fn limits(&self) -> FixedValidatorNodeProposalBufferLimitsV0 {
        self.limits
    }

    /// Returns the number of uniquely retained exact input pairs.
    pub fn len(&self) -> usize {
        self.proposals.len()
    }

    /// Returns whether this buffer retains no proposal token.
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    /// Returns the checked sum of retained canonical control and payload lengths.
    pub const fn total_canonical_input_bytes(&self) -> u64 {
        self.total_canonical_input_bytes
    }

    /// Returns the immutable saturation reason, if ordinary access is denied.
    pub const fn saturation(&self) -> Option<FixedValidatorNodeProposalBufferSaturationV0> {
        self.saturation
    }

    /// Retains one fully admitted token without selecting among proposal roots.
    ///
    /// Exact control-plus-payload duplicates are checked before capacity. A
    /// nonduplicate cap or arithmetic failure enters saturation without retaining
    /// the attempted token. Collection-reservation failure is no-mutation and
    /// stays healthy.
    pub fn try_insert(
        &mut self,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    ) -> Result<
        FixedValidatorNodeProposalBufferInsertOutcomeV0,
        FixedValidatorNodeProposalBufferInsertErrorV0,
    > {
        if let Some(saturation) = self.saturation {
            return Err(FixedValidatorNodeProposalBufferInsertErrorV0::saturated(
                proposal, saturation, false,
            ));
        }

        if self
            .proposals
            .iter()
            .any(|entry| exact_inputs_match(&entry.proposal, &proposal))
        {
            return Ok(
                FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { proposal },
            );
        }

        let canonical_input_bytes = match canonical_input_bytes(&proposal) {
            Some(bytes) => bytes,
            None => {
                let saturation =
                    FixedValidatorNodeProposalBufferSaturationV0::CanonicalInputByteCountOverflow {
                        maximum_canonical_input_bytes: self.limits.max_total_canonical_input_bytes,
                    };
                self.saturation = Some(saturation);
                return Err(FixedValidatorNodeProposalBufferInsertErrorV0::saturated(
                    proposal, saturation, true,
                ));
            }
        };
        let (_, attempted_canonical_input_bytes) = match checked_prospective_totals(
            self.proposals.len(),
            self.total_canonical_input_bytes,
            canonical_input_bytes,
            self.limits,
        ) {
            Ok(totals) => totals,
            Err(saturation) => {
                self.saturation = Some(saturation);
                return Err(FixedValidatorNodeProposalBufferInsertErrorV0::saturated(
                    proposal, saturation, true,
                ));
            }
        };

        if let Err(source) = self.proposals.try_reserve(1) {
            return Err(FixedValidatorNodeProposalBufferInsertErrorV0::reservation(
                proposal, source,
            ));
        }
        self.proposals.push(FixedValidatorNodeBufferedProposalV0 {
            canonical_input_bytes,
            proposal,
        });
        self.total_canonical_input_bytes = attempted_canonical_input_bytes;
        Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted)
    }

    pub(in crate::fixed_validator) fn contains_exact_proposal(
        &self,
        proposal: &FixedValidatorNodeDeferredProposalV0,
    ) -> bool {
        self.proposals
            .iter()
            .any(|entry| exact_inputs_match(&entry.proposal, proposal))
    }

    pub(in crate::fixed_validator) fn retained_positions(
        &self,
    ) -> impl Iterator<Item = ConsensusPosition> + '_ {
        self.proposals.iter().map(|entry| entry.proposal.position())
    }

    pub(in crate::fixed_validator) fn retained_identities(
        &self,
    ) -> impl Iterator<
        Item = (
            FixedConsensusBranchCoordinateV0,
            ConsensusPosition,
            ProposalSigningRoot,
        ),
    > + '_ {
        self.proposals.iter().map(|entry| {
            (
                entry.proposal.parent_coordinate(),
                entry.proposal.position(),
                entry.proposal.proposal_signing_root(),
            )
        })
    }

    pub(in crate::fixed_validator) fn preferred_proposal_inputs(
        &self,
        parent_coordinate: FixedConsensusBranchCoordinateV0,
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    ) -> Option<(&[u8], &[u8], u64)> {
        self.proposals
            .iter()
            .filter(|entry| {
                proposal_identity_matches(
                    &entry.proposal,
                    parent_coordinate,
                    position,
                    proposal_signing_root,
                )
            })
            .min_by(|left, right| {
                left.proposal
                    .canonical_proposal_control_bytes()
                    .cmp(right.proposal.canonical_proposal_control_bytes())
                    .then_with(|| {
                        left.proposal
                            .canonical_artifact_bytes()
                            .cmp(right.proposal.canonical_artifact_bytes())
                    })
            })
            .map(|entry| {
                (
                    entry.proposal.canonical_proposal_control_bytes(),
                    entry.proposal.canonical_artifact_bytes(),
                    entry.canonical_input_bytes,
                )
            })
    }

    /// Removes only one healthy-buffer token matching both complete byte strings.
    ///
    /// No position, proposal root, insertion order, or evidence preference is
    /// accepted as an address. Saturation denies this ordinary retrieval path.
    pub fn take_exact(
        &mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: &[u8],
    ) -> Result<
        Option<Box<FixedValidatorNodeDeferredProposalV0>>,
        FixedValidatorNodeProposalBufferAccessErrorV0,
    > {
        Ok(self
            .take_exact_lease(canonical_proposal_control_bytes, canonical_artifact_bytes)?
            .map(FixedValidatorNodeProposalBufferLeaseV0::release))
    }

    pub(in crate::fixed_validator) fn take_exact_lease(
        &mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: &[u8],
    ) -> Result<
        Option<FixedValidatorNodeProposalBufferLeaseV0<'_>>,
        FixedValidatorNodeProposalBufferAccessErrorV0,
    > {
        if let Some(saturation) = self.saturation {
            return Err(FixedValidatorNodeProposalBufferAccessErrorV0 { saturation });
        }
        let Some(index) = self.proposals.iter().position(|entry| {
            exact_inputs_match_bytes(
                &entry.proposal,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            )
        }) else {
            return Ok(None);
        };
        Ok(Some(self.take_lease_at(index)))
    }

    fn take_lease_at(&mut self, index: usize) -> FixedValidatorNodeProposalBufferLeaseV0<'_> {
        let entry = self.proposals.swap_remove(index);
        self.total_canonical_input_bytes = self
            .total_canonical_input_bytes
            .checked_sub(entry.canonical_input_bytes)
            .expect("retained proposal byte accounting stays internally consistent");
        FixedValidatorNodeProposalBufferLeaseV0 {
            buffer: self,
            entry: Some(entry),
            original_index: index,
        }
    }

    /// Returns every retained token and restores the same buffer to healthy empty.
    ///
    /// This is the sole saturated-state recovery operation. The returned order is
    /// not a proposal or evidence preference and must not be used as authority.
    pub fn drain_and_reset(&mut self) -> FixedValidatorNodeProposalBufferDrainV0 {
        let entries = mem::take(&mut self.proposals).into_iter();
        self.total_canonical_input_bytes = 0;
        self.saturation = None;
        FixedValidatorNodeProposalBufferDrainV0 { entries }
    }
}

impl fmt::Debug for FixedValidatorNodeProposalBufferV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedValidatorNodeProposalBufferV0")
            .field("limits", &self.limits)
            .field("entries", &self.proposals.len())
            .field(
                "total_canonical_input_bytes",
                &self.total_canonical_input_bytes,
            )
            .field("saturation", &self.saturation)
            .finish()
    }
}

fn exact_inputs_match(
    left: &FixedValidatorNodeDeferredProposalV0,
    right: &FixedValidatorNodeDeferredProposalV0,
) -> bool {
    exact_inputs_match_bytes(
        left,
        right.canonical_proposal_control_bytes(),
        right.canonical_artifact_bytes(),
    )
}

fn exact_inputs_match_bytes(
    retained: &FixedValidatorNodeDeferredProposalV0,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: &[u8],
) -> bool {
    retained.canonical_proposal_control_bytes() == canonical_proposal_control_bytes
        && retained.canonical_artifact_bytes() == canonical_artifact_bytes
}

fn proposal_identity_matches(
    proposal: &FixedValidatorNodeDeferredProposalV0,
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
) -> bool {
    proposal.parent_coordinate() == parent_coordinate
        && proposal.position() == position
        && proposal.proposal_signing_root() == proposal_signing_root
}

fn canonical_input_bytes(proposal: &FixedValidatorNodeDeferredProposalV0) -> Option<u64> {
    let control = u64::try_from(proposal.canonical_proposal_control_bytes().len()).ok()?;
    let artifact = u64::try_from(proposal.canonical_artifact_bytes().len()).ok()?;
    control.checked_add(artifact)
}

fn checked_prospective_totals(
    current_entries: usize,
    current_canonical_input_bytes: u64,
    inserted_canonical_input_bytes: u64,
    limits: FixedValidatorNodeProposalBufferLimitsV0,
) -> Result<(usize, u64), FixedValidatorNodeProposalBufferSaturationV0> {
    super::budget::checked_totals(
        current_entries,
        current_canonical_input_bytes,
        inserted_canonical_input_bytes,
        limits.max_entries,
        limits.max_total_canonical_input_bytes,
    )
    .map_err(|error| match error {
        super::budget::BudgetExceeded::EntriesOverflow => {
            FixedValidatorNodeProposalBufferSaturationV0::EntryCountOverflow {
                maximum_entries: limits.max_entries,
            }
        }
        super::budget::BudgetExceeded::BytesOverflow => {
            FixedValidatorNodeProposalBufferSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            }
        }
        super::budget::BudgetExceeded::Capacity { entries, bytes } => {
            FixedValidatorNodeProposalBufferSaturationV0::Capacity {
                attempted_entries: entries,
                maximum_entries: limits.max_entries,
                attempted_canonical_input_bytes: bytes,
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            }
        }
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn limit_configuration_is_positive_and_exact() {
        assert_eq!(
            FixedValidatorNodeProposalBufferLimitsV0::new(0, 1),
            Err(FixedValidatorNodeProposalBufferLimitsErrorV0::ZeroMaxEntries)
        );
        assert_eq!(
            FixedValidatorNodeProposalBufferLimitsV0::new(1, 0),
            Err(FixedValidatorNodeProposalBufferLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes)
        );
        let limits = FixedValidatorNodeProposalBufferLimitsV0::new(3, 17).unwrap();
        assert_eq!(limits.max_entries(), 3);
        assert_eq!(limits.max_total_canonical_input_bytes(), 17);
    }

    #[test]
    fn prospective_totals_reject_arithmetic_overflow_without_inputs() {
        let limits = FixedValidatorNodeProposalBufferLimitsV0::new(usize::MAX, u64::MAX).unwrap();
        assert_eq!(
            checked_prospective_totals(usize::MAX, 0, 1, limits),
            Err(
                FixedValidatorNodeProposalBufferSaturationV0::EntryCountOverflow {
                    maximum_entries: usize::MAX,
                }
            )
        );
        assert_eq!(
            checked_prospective_totals(0, u64::MAX, 1, limits),
            Err(
                FixedValidatorNodeProposalBufferSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: u64::MAX,
                }
            )
        );
    }
}
