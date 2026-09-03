use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::mem;

use naome_consensus::{
    ConsensusKey, ConsensusPosition, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusBranchCoordinateV0, FixedConsensusProposalPrevoteVerifyErrorV0,
    FixedConsensusRoundV0, ProposalSigningRoot, QuorumCertificateBuildError,
    VerifiedConsensusVoteV0,
};

use super::FixedValidatorNodeDeferredProposalV0;

/// Positive caller-local limits for current-round proposal and prevote custody.
///
/// These limits are separate from the higher-round recovery inbox so current-
/// round equivocation cannot consume the capacity reserved for catch-up. They
/// are process-local resource policy, not consensus admission limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeCurrentRoundInboxLimitsV0 {
    max_entries: usize,
    max_total_canonical_input_bytes: u64,
}

impl FixedValidatorNodeCurrentRoundInboxLimitsV0 {
    /// Constructs one positive entry and canonical-input byte budget.
    pub const fn new(
        max_entries: usize,
        max_total_canonical_input_bytes: u64,
    ) -> Result<Self, FixedValidatorNodeCurrentRoundInboxLimitsErrorV0> {
        if max_entries == 0 {
            return Err(FixedValidatorNodeCurrentRoundInboxLimitsErrorV0::ZeroMaxEntries);
        }
        if max_total_canonical_input_bytes == 0 {
            return Err(
                FixedValidatorNodeCurrentRoundInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes,
            );
        }
        Ok(Self {
            max_entries,
            max_total_canonical_input_bytes,
        })
    }

    /// Returns the maximum combined proposal and prevote count.
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum combined canonical-input byte count.
    pub const fn max_total_canonical_input_bytes(self) -> u64 {
        self.max_total_canonical_input_bytes
    }
}

/// A rejected volatile current-round inbox limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundInboxLimitsErrorV0 {
    /// At least one retained input must be permitted.
    ZeroMaxEntries,
    /// At least one canonical input byte must be permitted.
    ZeroMaxTotalCanonicalInputBytes,
}

impl fmt::Display for FixedValidatorNodeCurrentRoundInboxLimitsErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("current-round inbox entry limit must be positive")
            }
            Self::ZeroMaxTotalCanonicalInputBytes => formatter.write_str(
                "current-round inbox aggregate canonical-input-byte limit must be positive",
            ),
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundInboxLimitsErrorV0 {}

/// The immutable reason current-round retention entered deny-only saturation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundInboxSaturationV0 {
    /// One nonduplicate input would exceed a configured local limit.
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

impl fmt::Display for FixedValidatorNodeCurrentRoundInboxSaturationV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity {
                attempted_entries,
                maximum_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current-round inbox capacity exceeded: {attempted_entries} entries and {attempted_canonical_input_bytes} canonical input bytes were attempted, with limits {maximum_entries} and {maximum_canonical_input_bytes}"
            ),
            Self::EntryCountOverflow { maximum_entries } => write!(
                formatter,
                "current-round inbox entry count overflowed with configured limit {maximum_entries}"
            ),
            Self::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current-round inbox canonical input byte count overflowed with configured limit {maximum_canonical_input_bytes}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CurrentRoundInboxInsertOutcomeV0 {
    Inserted,
    AlreadyRetained,
}

pub(super) enum CurrentRoundProposalInsertErrorV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    Reservation(TryReserveError),
}

pub(super) enum CurrentRoundPrevoteInsertErrorV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    Admission(FixedConsensusProposalPrevoteVerifyErrorV0),
    Reservation(TryReserveError),
}

pub(super) enum CurrentRoundProposalSelectionV0<'inbox> {
    None,
    One {
        proposal_signing_root: ProposalSigningRoot,
        canonical_proposal_control_bytes: &'inbox [u8],
        canonical_artifact_bytes: &'inbox [u8],
    },
    Ambiguous {
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
}

pub(super) enum CurrentRoundQuorumSelectionV0 {
    None,
    One { canonical_certificate: Vec<u8> },
}

struct RetainedCurrentProposalV0 {
    proposal: Box<FixedValidatorNodeDeferredProposalV0>,
}

struct RetainedCurrentPrevoteV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    signer: ConsensusKey,
    canonical_bytes: [u8; VerifiedConsensusVoteV0::BYTE_LENGTH],
}

/// One losslessly drained current-round evidence item.
#[allow(clippy::large_enum_variant)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundInboxDrainItemV0 {
    /// Complete raw inputs from one previously admitted current proposal.
    Proposal {
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    },
    /// One exact canonical active proposal prevote.
    ProposalPrevote([u8; VerifiedConsensusVoteV0::BYTE_LENGTH]),
}

/// Lossless iterator returned by a current-only inbox drain-and-reset.
#[must_use]
pub struct FixedValidatorNodeCurrentRoundInboxDrainV0 {
    proposals: std::vec::IntoIter<RetainedCurrentProposalV0>,
    prevotes: std::vec::IntoIter<RetainedCurrentPrevoteV0>,
}

impl Iterator for FixedValidatorNodeCurrentRoundInboxDrainV0 {
    type Item = FixedValidatorNodeCurrentRoundInboxDrainItemV0;

    fn next(&mut self) -> Option<Self::Item> {
        self.proposals
            .next()
            .map(|retained| {
                let (canonical_proposal_control_bytes, canonical_artifact_bytes) =
                    retained.proposal.into_unverified_boxed_inputs();
                FixedValidatorNodeCurrentRoundInboxDrainItemV0::Proposal {
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                }
            })
            .or_else(|| {
                self.prevotes.next().map(|vote| {
                    FixedValidatorNodeCurrentRoundInboxDrainItemV0::ProposalPrevote(
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

impl ExactSizeIterator for FixedValidatorNodeCurrentRoundInboxDrainV0 {
    fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.prevotes.len())
            .expect("drained current-round inbox length was previously representable")
    }
}

impl FusedIterator for FixedValidatorNodeCurrentRoundInboxDrainV0 {}

pub(super) struct CurrentRoundInboxV0 {
    limits: FixedValidatorNodeCurrentRoundInboxLimitsV0,
    proposals: Vec<RetainedCurrentProposalV0>,
    prevotes: Vec<RetainedCurrentPrevoteV0>,
    total_canonical_input_bytes: u64,
    saturation: Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundInboxSaturationV0,
    )>,
}

impl CurrentRoundInboxV0 {
    pub(super) const fn new(limits: FixedValidatorNodeCurrentRoundInboxLimitsV0) -> Self {
        Self {
            limits,
            proposals: Vec::new(),
            prevotes: Vec::new(),
            total_canonical_input_bytes: 0,
            saturation: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.prevotes.len())
            .expect("retained current-round inbox length stayed representable at insertion")
    }

    pub(super) const fn total_canonical_input_bytes(&self) -> u64 {
        self.total_canonical_input_bytes
    }

    pub(super) const fn saturation(
        &self,
    ) -> Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundInboxSaturationV0,
    )> {
        self.saturation
    }

    pub(super) fn try_insert_proposal(
        &mut self,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    ) -> Result<CurrentRoundInboxInsertOutcomeV0, CurrentRoundProposalInsertErrorV0> {
        let position = proposal.position();
        if let Some((saturation_position, saturation)) = self.saturation {
            return Err(CurrentRoundProposalInsertErrorV0::Saturated {
                position: saturation_position,
                saturation,
                newly_saturated: false,
            });
        }
        if self.proposals.iter().any(|retained| {
            retained.proposal.canonical_proposal_control_bytes()
                == proposal.canonical_proposal_control_bytes()
                && retained.proposal.canonical_artifact_bytes()
                    == proposal.canonical_artifact_bytes()
        }) {
            return Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained);
        }
        let canonical_input_bytes = proposal_canonical_input_bytes(&proposal).ok_or_else(|| {
            let saturation =
                FixedValidatorNodeCurrentRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: self.limits.max_total_canonical_input_bytes,
                };
            self.saturation = Some((position, saturation));
            CurrentRoundProposalInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated: true,
            }
        })?;
        let prospective_total = match checked_prospective_totals(
            self.len(),
            self.total_canonical_input_bytes,
            canonical_input_bytes,
            self.limits,
        ) {
            Ok((_, total)) => total,
            Err(saturation) => {
                self.saturation = Some((position, saturation));
                return Err(CurrentRoundProposalInsertErrorV0::Saturated {
                    position,
                    saturation,
                    newly_saturated: true,
                });
            }
        };
        self.proposals
            .try_reserve(1)
            .map_err(CurrentRoundProposalInsertErrorV0::Reservation)?;
        self.proposals.push(RetainedCurrentProposalV0 { proposal });
        self.total_canonical_input_bytes = prospective_total;
        Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
    }

    pub(super) fn try_insert_prevote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_signed_prevote: &[u8],
    ) -> Result<CurrentRoundInboxInsertOutcomeV0, CurrentRoundPrevoteInsertErrorV0> {
        if let Some((position, saturation)) = self.saturation {
            return Err(CurrentRoundPrevoteInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated: false,
            });
        }
        let vote = round
            .decode_and_verify_active_proposal_prevote(canonical_signed_prevote)
            .map_err(CurrentRoundPrevoteInsertErrorV0::Admission)?;
        let parent_coordinate = round.parent_coordinate();
        let position = vote.position();
        let canonical_bytes = vote.to_canonical_bytes();
        if self.prevotes.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate
                && retained.canonical_bytes == canonical_bytes
        }) {
            return Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained);
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
                self.saturation = Some((position, saturation));
                return Err(CurrentRoundPrevoteInsertErrorV0::Saturated {
                    position,
                    saturation,
                    newly_saturated: true,
                });
            }
        };
        self.prevotes
            .try_reserve(1)
            .map_err(CurrentRoundPrevoteInsertErrorV0::Reservation)?;
        let proposal_signing_root = match vote.target() {
            ConsensusVoteTarget::Proposal(root) => root,
            ConsensusVoteTarget::Nil => {
                unreachable!("active proposal-prevote admission excludes nil")
            }
        };
        self.prevotes.push(RetainedCurrentPrevoteV0 {
            parent_coordinate,
            position,
            proposal_signing_root,
            signer: vote.signer(),
            canonical_bytes,
        });
        self.total_canonical_input_bytes = prospective_total;
        Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
    }

    pub(super) fn select_unique_proposal(
        &self,
        parent_coordinate: FixedConsensusBranchCoordinateV0,
        position: ConsensusPosition,
    ) -> CurrentRoundProposalSelectionV0<'_> {
        let mut first: Option<&RetainedCurrentProposalV0> = None;
        let mut second: Option<&RetainedCurrentProposalV0> = None;
        for candidate in self.proposals.iter().filter(|retained| {
            retained.proposal.parent_coordinate() == parent_coordinate
                && retained.proposal.position() == position
        }) {
            if first.is_none_or(|current| proposal_inputs_cmp(candidate, current).is_lt()) {
                second = first;
                first = Some(candidate);
            } else if second.is_none_or(|current| proposal_inputs_cmp(candidate, current).is_lt()) {
                second = Some(candidate);
            }
        }
        let Some(first) = first else {
            return CurrentRoundProposalSelectionV0::None;
        };
        if let Some(second) = second {
            return CurrentRoundProposalSelectionV0::Ambiguous {
                first: first.proposal.proposal_signing_root(),
                second: second.proposal.proposal_signing_root(),
            };
        }
        CurrentRoundProposalSelectionV0::One {
            proposal_signing_root: first.proposal.proposal_signing_root(),
            canonical_proposal_control_bytes: first.proposal.canonical_proposal_control_bytes(),
            canonical_artifact_bytes: first.proposal.canonical_artifact_bytes(),
        }
    }

    pub(super) fn select_proposal_quorum(
        &self,
        round: &FixedConsensusRoundV0<'_>,
        proposal_signing_root: ProposalSigningRoot,
    ) -> Result<CurrentRoundQuorumSelectionV0, CurrentRoundQuorumSelectionErrorV0> {
        let parent_coordinate = round.parent_coordinate();
        let position = round.position();
        let mut candidates: Vec<&RetainedCurrentPrevoteV0> = Vec::new();
        candidates
            .try_reserve_exact(self.prevotes.len())
            .map_err(CurrentRoundQuorumSelectionErrorV0::Reservation)?;
        candidates.extend(self.prevotes.iter().filter(|vote| {
            vote.parent_coordinate == parent_coordinate
                && vote.position == position
                && vote.proposal_signing_root == proposal_signing_root
        }));
        candidates.sort_unstable_by(|left, right| {
            left.signer
                .cmp(&right.signer)
                .then_with(|| left.canonical_bytes.cmp(&right.canonical_bytes))
        });
        let mut preferred_votes: Vec<&[u8]> = Vec::new();
        preferred_votes
            .try_reserve_exact(candidates.len())
            .map_err(CurrentRoundQuorumSelectionErrorV0::Reservation)?;
        let mut previous_signer = None;
        for vote in candidates {
            if previous_signer == Some(vote.signer) {
                continue;
            }
            previous_signer = Some(vote.signer);
            preferred_votes.push(&vote.canonical_bytes);
        }
        match round.build_quorum_certificate_from_signed_votes(
            &preferred_votes,
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(proposal_signing_root),
        ) {
            Ok(certificate) => Ok(CurrentRoundQuorumSelectionV0::One {
                canonical_certificate: certificate.to_canonical_bytes(),
            }),
            Err(
                QuorumCertificateBuildError::EmptyVoteBatch
                | QuorumCertificateBuildError::InsufficientAgreementWeight { .. },
            ) => Ok(CurrentRoundQuorumSelectionV0::None),
            Err(source) => Err(CurrentRoundQuorumSelectionErrorV0::Invariant(source)),
        }
    }

    pub(super) fn drain_and_reset(&mut self) -> FixedValidatorNodeCurrentRoundInboxDrainV0 {
        self.total_canonical_input_bytes = 0;
        self.saturation = None;
        FixedValidatorNodeCurrentRoundInboxDrainV0 {
            proposals: mem::take(&mut self.proposals).into_iter(),
            prevotes: mem::take(&mut self.prevotes).into_iter(),
        }
    }
}

pub(super) enum CurrentRoundQuorumSelectionErrorV0 {
    Reservation(TryReserveError),
    Invariant(QuorumCertificateBuildError),
}

fn proposal_inputs_cmp(
    left: &RetainedCurrentProposalV0,
    right: &RetainedCurrentProposalV0,
) -> std::cmp::Ordering {
    left.proposal
        .canonical_proposal_control_bytes()
        .cmp(right.proposal.canonical_proposal_control_bytes())
        .then_with(|| {
            left.proposal
                .canonical_artifact_bytes()
                .cmp(right.proposal.canonical_artifact_bytes())
        })
}

fn proposal_canonical_input_bytes(proposal: &FixedValidatorNodeDeferredProposalV0) -> Option<u64> {
    u64::try_from(proposal.canonical_proposal_control_bytes().len())
        .ok()?
        .checked_add(u64::try_from(proposal.canonical_artifact_bytes().len()).ok()?)
}

fn checked_prospective_totals(
    current_entries: usize,
    current_canonical_input_bytes: u64,
    inserted_canonical_input_bytes: u64,
    limits: FixedValidatorNodeCurrentRoundInboxLimitsV0,
) -> Result<(usize, u64), FixedValidatorNodeCurrentRoundInboxSaturationV0> {
    let attempted_entries = current_entries.checked_add(1).ok_or(
        FixedValidatorNodeCurrentRoundInboxSaturationV0::EntryCountOverflow {
            maximum_entries: limits.max_entries,
        },
    )?;
    let attempted_canonical_input_bytes = current_canonical_input_bytes
        .checked_add(inserted_canonical_input_bytes)
        .ok_or(
            FixedValidatorNodeCurrentRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            },
        )?;
    if attempted_entries > limits.max_entries
        || attempted_canonical_input_bytes > limits.max_total_canonical_input_bytes
    {
        return Err(FixedValidatorNodeCurrentRoundInboxSaturationV0::Capacity {
            attempted_entries,
            maximum_entries: limits.max_entries,
            attempted_canonical_input_bytes,
            maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
        });
    }
    Ok((attempted_entries, attempted_canonical_input_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_inbox_limits_require_positive_independent_caps() {
        assert_eq!(
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(0, 1),
            Err(FixedValidatorNodeCurrentRoundInboxLimitsErrorV0::ZeroMaxEntries)
        );
        assert_eq!(
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(1, 0),
            Err(FixedValidatorNodeCurrentRoundInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes)
        );
        assert_eq!(
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(2, 3)
                .unwrap()
                .max_entries(),
            2
        );
        assert_eq!(
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(2, 3)
                .unwrap()
                .max_total_canonical_input_bytes(),
            3
        );
    }

    #[test]
    fn current_inbox_accounting_fails_closed_at_capacity_and_overflow() {
        let exact = FixedValidatorNodeCurrentRoundInboxLimitsV0::new(2, 5).unwrap();
        assert_eq!(checked_prospective_totals(1, 2, 3, exact), Ok((2, 5)));
        assert!(matches!(
            checked_prospective_totals(2, 5, 1, exact),
            Err(FixedValidatorNodeCurrentRoundInboxSaturationV0::Capacity {
                attempted_entries: 3,
                attempted_canonical_input_bytes: 6,
                ..
            })
        ));

        let maximum =
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(usize::MAX, u64::MAX).unwrap();
        assert!(matches!(
            checked_prospective_totals(usize::MAX, 0, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundInboxSaturationV0::EntryCountOverflow {
                    maximum_entries: usize::MAX
                }
            )
        ));
        assert!(matches!(
            checked_prospective_totals(0, u64::MAX, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundInboxSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: u64::MAX
                }
            )
        ));
    }
}
