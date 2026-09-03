use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::mem;

use naome_consensus::{
    ConsensusKey, ConsensusPosition, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusBranchCoordinateV0, FixedConsensusProposalPrecommitVerifyErrorV0,
    FixedConsensusRoundV0, ProposalSigningRoot, QuorumCertificateBuildError,
    VerifiedConsensusVoteV0,
};

use super::FixedValidatorNodeDeferredProposalV0;

/// Positive process-local limits for current proposal-finality evidence.
///
/// This budget is independent of both ordinary current voting and higher-round
/// catch-up. It bounds retained logical canonical inputs and grants no consensus
/// validity, finality, selection, or network authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0 {
    max_entries: usize,
    max_total_canonical_input_bytes: u64,
}

impl FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0 {
    /// Constructs positive entry and aggregate canonical-input-byte limits.
    pub const fn new(
        max_entries: usize,
        max_total_canonical_input_bytes: u64,
    ) -> Result<Self, FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0> {
        if max_entries == 0 {
            return Err(FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0::ZeroMaxEntries);
        }
        if max_total_canonical_input_bytes == 0 {
            return Err(
                FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes,
            );
        }
        Ok(Self {
            max_entries,
            max_total_canonical_input_bytes,
        })
    }

    /// Returns the maximum combined proposal and precommit count.
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum aggregate logical canonical-input byte count.
    pub const fn max_total_canonical_input_bytes(self) -> u64 {
        self.max_total_canonical_input_bytes
    }
}

/// A rejected current proposal-finality inbox limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0 {
    /// At least one retained input must be permitted.
    ZeroMaxEntries,
    /// At least one canonical input byte must be permitted.
    ZeroMaxTotalCanonicalInputBytes,
}

impl fmt::Display for FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => formatter
                .write_str("current proposal-finality inbox entry limit must be positive"),
            Self::ZeroMaxTotalCanonicalInputBytes => formatter.write_str(
                "current proposal-finality inbox aggregate canonical-input-byte limit must be positive",
            ),
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0 {}

/// The immutable reason current proposal-finality retention saturated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0 {
    /// One nonduplicate input would exceed a configured local limit.
    Capacity {
        attempted_entries: usize,
        maximum_entries: usize,
        attempted_canonical_input_bytes: u64,
        maximum_canonical_input_bytes: u64,
    },
    /// Counting one more distinct input overflowed the platform range.
    EntryCountOverflow { maximum_entries: usize },
    /// Summing retained logical input lengths overflowed `u64`.
    CanonicalInputByteCountOverflow { maximum_canonical_input_bytes: u64 },
}

impl fmt::Display for FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity {
                attempted_entries,
                maximum_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current proposal-finality inbox capacity exceeded: {attempted_entries} entries and {attempted_canonical_input_bytes} canonical input bytes were attempted, with limits {maximum_entries} and {maximum_canonical_input_bytes}"
            ),
            Self::EntryCountOverflow { maximum_entries } => write!(
                formatter,
                "current proposal-finality inbox entry count overflowed with configured limit {maximum_entries}"
            ),
            Self::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current proposal-finality inbox canonical input byte count overflowed with configured limit {maximum_canonical_input_bytes}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CurrentRoundFinalityInboxInsertOutcomeV0 {
    Inserted,
    AlreadyRetained,
}

pub(super) enum CurrentRoundFinalityProposalInsertErrorV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
        newly_saturated: bool,
    },
    Reservation(TryReserveError),
}

pub(super) enum CurrentRoundFinalityPrecommitInsertErrorV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
        newly_saturated: bool,
    },
    Admission(FixedConsensusProposalPrecommitVerifyErrorV0),
    Reservation(TryReserveError),
}

pub(super) enum CurrentRoundFinalityClassificationV0<'inbox> {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    },
    None,
    OneQuorumMissingProposal {
        proposal_signing_root: ProposalSigningRoot,
        canonical_precommit_certificate: Vec<u8>,
    },
    One {
        proposal_signing_root: ProposalSigningRoot,
        canonical_proposal_control_bytes: &'inbox [u8],
        canonical_artifact_bytes: &'inbox [u8],
        canonical_precommit_certificate: Vec<u8>,
    },
    ConflictingRoots {
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CurrentRoundFinalityPreclassificationV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    },
    NoMatchingPrecommit,
    NeedsRound,
}

pub(super) enum CurrentRoundFinalityClassificationErrorV0 {
    Reservation(TryReserveError),
    Invariant(QuorumCertificateBuildError),
}

struct RetainedCurrentFinalityProposalV0 {
    proposal: Box<FixedValidatorNodeDeferredProposalV0>,
}

struct RetainedCurrentProposalPrecommitV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    signer: ConsensusKey,
    canonical_bytes: [u8; VerifiedConsensusVoteV0::BYTE_LENGTH],
}

/// One losslessly drained current proposal-finality evidence item.
#[allow(clippy::large_enum_variant)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0 {
    /// Complete raw inputs from one fully admitted finality proposal.
    Proposal {
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    },
    /// One exact canonical active proposal precommit.
    ProposalPrecommit([u8; VerifiedConsensusVoteV0::BYTE_LENGTH]),
}

/// Lossless iterator returned by a finality-only inbox drain-and-reset.
#[must_use]
pub struct FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {
    proposals: std::vec::IntoIter<RetainedCurrentFinalityProposalV0>,
    precommits: std::vec::IntoIter<RetainedCurrentProposalPrecommitV0>,
}

impl Iterator for FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {
    type Item = FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0;

    fn next(&mut self) -> Option<Self::Item> {
        self.proposals
            .next()
            .map(|retained| {
                let (canonical_proposal_control_bytes, canonical_artifact_bytes) =
                    retained.proposal.into_unverified_boxed_inputs();
                FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0::Proposal {
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                }
            })
            .or_else(|| {
                self.precommits.next().map(|vote| {
                    FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0::ProposalPrecommit(
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

impl ExactSizeIterator for FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {
    fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.precommits.len())
            .expect("drained finality inbox length was previously representable")
    }
}

impl FusedIterator for FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {}

pub(super) struct CurrentRoundFinalityInboxV0 {
    limits: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    proposals: Vec<RetainedCurrentFinalityProposalV0>,
    precommits: Vec<RetainedCurrentProposalPrecommitV0>,
    total_canonical_input_bytes: u64,
    saturation: Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    )>,
}

impl CurrentRoundFinalityInboxV0 {
    pub(super) const fn new(limits: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0) -> Self {
        Self {
            limits,
            proposals: Vec::new(),
            precommits: Vec::new(),
            total_canonical_input_bytes: 0,
            saturation: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.proposals
            .len()
            .checked_add(self.precommits.len())
            .expect("retained current finality inbox length stayed representable at insertion")
    }

    pub(super) const fn total_canonical_input_bytes(&self) -> u64 {
        self.total_canonical_input_bytes
    }

    pub(super) const fn saturation(
        &self,
    ) -> Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    )> {
        self.saturation
    }

    pub(super) fn preclassify(
        &self,
        parent_coordinate: FixedConsensusBranchCoordinateV0,
        position: ConsensusPosition,
    ) -> CurrentRoundFinalityPreclassificationV0 {
        if let Some((position, saturation)) = self.saturation {
            return CurrentRoundFinalityPreclassificationV0::Saturated {
                position,
                saturation,
            };
        }
        if self.precommits.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate && retained.position == position
        }) {
            CurrentRoundFinalityPreclassificationV0::NeedsRound
        } else {
            CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
        }
    }

    pub(super) fn try_insert_proposal(
        &mut self,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    ) -> Result<CurrentRoundFinalityInboxInsertOutcomeV0, CurrentRoundFinalityProposalInsertErrorV0>
    {
        let position = proposal.position();
        if let Some((saturation_position, saturation)) = self.saturation {
            return Err(CurrentRoundFinalityProposalInsertErrorV0::Saturated {
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
            return Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained);
        }
        let canonical_input_bytes = proposal_canonical_input_bytes(&proposal).ok_or_else(|| {
            let saturation = FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: self.limits.max_total_canonical_input_bytes,
            };
            self.saturation = Some((position, saturation));
            CurrentRoundFinalityProposalInsertErrorV0::Saturated {
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
                return Err(CurrentRoundFinalityProposalInsertErrorV0::Saturated {
                    position,
                    saturation,
                    newly_saturated: true,
                });
            }
        };
        self.proposals
            .try_reserve(1)
            .map_err(CurrentRoundFinalityProposalInsertErrorV0::Reservation)?;
        self.proposals
            .push(RetainedCurrentFinalityProposalV0 { proposal });
        self.total_canonical_input_bytes = prospective_total;
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    }

    pub(super) fn try_insert_precommit(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_signed_precommit: &[u8],
    ) -> Result<CurrentRoundFinalityInboxInsertOutcomeV0, CurrentRoundFinalityPrecommitInsertErrorV0>
    {
        if let Some((position, saturation)) = self.saturation {
            return Err(CurrentRoundFinalityPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated: false,
            });
        }
        let vote = round
            .decode_and_verify_active_proposal_precommit(canonical_signed_precommit)
            .map_err(CurrentRoundFinalityPrecommitInsertErrorV0::Admission)?;
        let parent_coordinate = round.parent_coordinate();
        let position = vote.position();
        let canonical_bytes = vote.to_canonical_bytes();
        if self.precommits.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate
                && retained.canonical_bytes == canonical_bytes
        }) {
            return Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained);
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
                return Err(CurrentRoundFinalityPrecommitInsertErrorV0::Saturated {
                    position,
                    saturation,
                    newly_saturated: true,
                });
            }
        };
        self.precommits
            .try_reserve(1)
            .map_err(CurrentRoundFinalityPrecommitInsertErrorV0::Reservation)?;
        let proposal_signing_root = match vote.target() {
            ConsensusVoteTarget::Proposal(root) => root,
            ConsensusVoteTarget::Nil => {
                unreachable!("active proposal-precommit admission excludes nil")
            }
        };
        self.precommits.push(RetainedCurrentProposalPrecommitV0 {
            parent_coordinate,
            position,
            proposal_signing_root,
            signer: vote.signer(),
            canonical_bytes,
        });
        self.total_canonical_input_bytes = prospective_total;
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    }

    pub(super) fn classify(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<CurrentRoundFinalityClassificationV0<'_>, CurrentRoundFinalityClassificationErrorV0>
    {
        if let Some((position, saturation)) = self.saturation {
            return Ok(CurrentRoundFinalityClassificationV0::Saturated {
                position,
                saturation,
            });
        }
        let parent_coordinate = round.parent_coordinate();
        let position = round.position();
        let mut candidates: Vec<&RetainedCurrentProposalPrecommitV0> = Vec::new();
        candidates
            .try_reserve_exact(self.precommits.len())
            .map_err(CurrentRoundFinalityClassificationErrorV0::Reservation)?;
        candidates.extend(self.precommits.iter().filter(|retained| {
            retained.parent_coordinate == parent_coordinate && retained.position == position
        }));
        candidates.sort_unstable_by(|left, right| {
            left.proposal_signing_root
                .cmp(&right.proposal_signing_root)
                .then_with(|| left.signer.cmp(&right.signer))
                .then_with(|| left.canonical_bytes.cmp(&right.canonical_bytes))
        });

        let mut preferred_votes: Vec<&[u8]> = Vec::new();
        preferred_votes
            .try_reserve_exact(candidates.len())
            .map_err(CurrentRoundFinalityClassificationErrorV0::Reservation)?;

        let mut selected: Option<(ProposalSigningRoot, Vec<u8>)> = None;
        let mut start = 0;
        while start < candidates.len() {
            let proposal_signing_root = candidates[start].proposal_signing_root;
            let mut end = start + 1;
            while end < candidates.len()
                && candidates[end].proposal_signing_root == proposal_signing_root
            {
                end += 1;
            }
            preferred_votes.clear();
            let mut previous_signer = None;
            for vote in &candidates[start..end] {
                if previous_signer == Some(vote.signer) {
                    continue;
                }
                previous_signer = Some(vote.signer);
                preferred_votes.push(&vote.canonical_bytes);
            }
            let certificate = match round.build_quorum_certificate_from_signed_votes(
                &preferred_votes,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(proposal_signing_root),
            ) {
                Ok(certificate) => certificate.to_canonical_bytes(),
                Err(
                    QuorumCertificateBuildError::EmptyVoteBatch
                    | QuorumCertificateBuildError::InsufficientAgreementWeight { .. },
                ) => {
                    start = end;
                    continue;
                }
                Err(source) => {
                    return Err(CurrentRoundFinalityClassificationErrorV0::Invariant(source));
                }
            };
            if let Some((first, _)) = selected {
                return Ok(CurrentRoundFinalityClassificationV0::ConflictingRoots {
                    first,
                    second: proposal_signing_root,
                });
            }
            selected = Some((proposal_signing_root, certificate));
            start = end;
        }

        let Some((proposal_signing_root, canonical_precommit_certificate)) = selected else {
            return Ok(CurrentRoundFinalityClassificationV0::None);
        };
        let proposal = self
            .proposals
            .iter()
            .filter(|retained| {
                retained.proposal.parent_coordinate() == parent_coordinate
                    && retained.proposal.position() == position
                    && retained.proposal.proposal_signing_root() == proposal_signing_root
            })
            .min_by(|left, right| proposal_inputs_cmp(left, right));
        Ok(match proposal {
            Some(proposal) => CurrentRoundFinalityClassificationV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes: proposal
                    .proposal
                    .canonical_proposal_control_bytes(),
                canonical_artifact_bytes: proposal.proposal.canonical_artifact_bytes(),
                canonical_precommit_certificate,
            },
            None => CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
                proposal_signing_root,
                canonical_precommit_certificate,
            },
        })
    }

    pub(super) fn drain_and_reset(&mut self) -> FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {
        self.total_canonical_input_bytes = 0;
        self.saturation = None;
        FixedValidatorNodeCurrentRoundFinalityInboxDrainV0 {
            proposals: mem::take(&mut self.proposals).into_iter(),
            precommits: mem::take(&mut self.precommits).into_iter(),
        }
    }
}

fn proposal_inputs_cmp(
    left: &RetainedCurrentFinalityProposalV0,
    right: &RetainedCurrentFinalityProposalV0,
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
    limits: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
) -> Result<(usize, u64), FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0> {
    let attempted_entries = current_entries.checked_add(1).ok_or(
        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::EntryCountOverflow {
            maximum_entries: limits.max_entries,
        },
    )?;
    let attempted_canonical_input_bytes = current_canonical_input_bytes
        .checked_add(inserted_canonical_input_bytes)
        .ok_or(
            FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            },
        )?;
    if attempted_entries > limits.max_entries
        || attempted_canonical_input_bytes > limits.max_total_canonical_input_bytes
    {
        return Err(
            FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                attempted_entries,
                maximum_entries: limits.max_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            },
        );
    }
    Ok((attempted_entries, attempted_canonical_input_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_inbox_limits_require_positive_independent_caps() {
        assert_eq!(
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(0, 1),
            Err(FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0::ZeroMaxEntries)
        );
        assert_eq!(
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(1, 0),
            Err(
                FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes
            )
        );
        let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 3).unwrap();
        assert_eq!(limits.max_entries(), 2);
        assert_eq!(limits.max_total_canonical_input_bytes(), 3);
    }

    #[test]
    fn finality_inbox_accounting_fails_closed_at_capacity_and_overflow() {
        let exact = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 5).unwrap();
        assert_eq!(checked_prospective_totals(1, 2, 3, exact), Ok((2, 5)));
        assert!(matches!(
            checked_prospective_totals(2, 5, 1, exact),
            Err(
                FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                    attempted_entries: 3,
                    attempted_canonical_input_bytes: 6,
                    ..
                }
            )
        ));

        let maximum =
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(usize::MAX, u64::MAX).unwrap();
        assert!(matches!(
            checked_prospective_totals(usize::MAX, 0, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::EntryCountOverflow {
                    maximum_entries: usize::MAX
                }
            )
        ));
        assert!(matches!(
            checked_prospective_totals(0, u64::MAX, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: u64::MAX
                }
            )
        ));
    }
}
