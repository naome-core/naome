use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::mem;

use naome_consensus::{
    ConsensusKey, ConsensusPosition, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusBranchCoordinateV0, FixedConsensusNilPrecommitVerifyErrorV0,
    FixedConsensusRoundV0, QuorumCertificateBuildError, VerifiedConsensusVoteV0,
};

/// Positive process-local limits for exact-current nil-precommit custody.
///
/// Both caps apply to the same retained byte-distinct vote set. They are a
/// volatile resource policy and grant no consensus admission, quorum,
/// round-progression, finality, network, provenance, or peer-trust authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0 {
    max_entries: usize,
    max_total_canonical_input_bytes: u64,
}

impl FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0 {
    /// Constructs positive entry and aggregate canonical-input-byte limits.
    pub const fn new(
        max_entries: usize,
        max_total_canonical_input_bytes: u64,
    ) -> Result<Self, FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0> {
        if max_entries == 0 {
            return Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0::ZeroMaxEntries,
            );
        }
        if max_total_canonical_input_bytes == 0 {
            return Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes,
            );
        }
        Ok(Self {
            max_entries,
            max_total_canonical_input_bytes,
        })
    }

    /// Returns the maximum combined byte-distinct nil-precommit count.
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the maximum aggregate canonical-input byte count.
    pub const fn max_total_canonical_input_bytes(self) -> u64 {
        self.max_total_canonical_input_bytes
    }
}

/// A rejected exact-current nil-precommit inbox limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0 {
    /// At least one retained input must be permitted.
    ZeroMaxEntries,
    /// At least one canonical input byte must be permitted.
    ZeroMaxTotalCanonicalInputBytes,
}

impl fmt::Display for FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("current nil-precommit inbox entry limit must be positive")
            }
            Self::ZeroMaxTotalCanonicalInputBytes => formatter.write_str(
                "current nil-precommit inbox aggregate canonical-input-byte limit must be positive",
            ),
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0 {}

/// The immutable reason exact-current nil-precommit retention saturated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0 {
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

impl fmt::Display for FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity {
                attempted_entries,
                maximum_entries,
                attempted_canonical_input_bytes,
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current nil-precommit inbox capacity exceeded: {attempted_entries} entries and {attempted_canonical_input_bytes} canonical input bytes were attempted, with limits {maximum_entries} and {maximum_canonical_input_bytes}"
            ),
            Self::EntryCountOverflow { maximum_entries } => write!(
                formatter,
                "current nil-precommit inbox entry count overflowed with configured limit {maximum_entries}"
            ),
            Self::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes,
            } => write!(
                formatter,
                "current nil-precommit inbox canonical input byte count overflowed with configured limit {maximum_canonical_input_bytes}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CurrentRoundNilPrecommitInboxInsertOutcomeV0 {
    Inserted,
    AlreadyRetained,
}

pub(super) enum CurrentRoundNilPrecommitInsertErrorV0 {
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
        newly_saturated: bool,
    },
    Admission(FixedConsensusNilPrecommitVerifyErrorV0),
    Reservation(TryReserveError),
}

pub(super) enum CurrentRoundNilPrecommitQuorumSelectionV0 {
    None,
    One {
        canonical_signed_precommits: Vec<[u8; VerifiedConsensusVoteV0::BYTE_LENGTH]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CurrentRoundNilPrecommitPreclassificationV0 {
    NoMatchingPrecommit,
    NeedsRound,
}

pub(super) enum CurrentRoundNilPrecommitQuorumSelectionErrorV0 {
    Reservation(TryReserveError),
    Invariant(QuorumCertificateBuildError),
}

struct RetainedCurrentNilPrecommitV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    signer: ConsensusKey,
    canonical_bytes: [u8; VerifiedConsensusVoteV0::BYTE_LENGTH],
}

/// Lossless iterator over every exact canonical nil precommit removed by reset.
#[must_use]
pub struct FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {
    precommits: std::vec::IntoIter<RetainedCurrentNilPrecommitV0>,
}

impl Iterator for FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {
    type Item = [u8; VerifiedConsensusVoteV0::BYTE_LENGTH];

    fn next(&mut self) -> Option<Self::Item> {
        self.precommits.next().map(|vote| vote.canonical_bytes)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.precommits.size_hint()
    }
}

impl ExactSizeIterator for FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {
    fn len(&self) -> usize {
        self.precommits.len()
    }
}

impl FusedIterator for FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {}

pub(super) struct CurrentRoundNilPrecommitInboxV0 {
    limits: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    precommits: Vec<RetainedCurrentNilPrecommitV0>,
    total_canonical_input_bytes: u64,
    saturation: Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
    )>,
}

impl CurrentRoundNilPrecommitInboxV0 {
    pub(super) const fn new(
        limits: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    ) -> Self {
        Self {
            limits,
            precommits: Vec::new(),
            total_canonical_input_bytes: 0,
            saturation: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.precommits.len()
    }

    pub(super) const fn total_canonical_input_bytes(&self) -> u64 {
        self.total_canonical_input_bytes
    }

    pub(super) const fn saturation(
        &self,
    ) -> Option<(
        ConsensusPosition,
        FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
    )> {
        self.saturation
    }

    /// Reports whether exact-position input exists before bounded round derivation.
    pub(super) fn preclassify(
        &self,
        parent_coordinate: FixedConsensusBranchCoordinateV0,
        position: ConsensusPosition,
    ) -> CurrentRoundNilPrecommitPreclassificationV0 {
        if self.precommits.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate && retained.position == position
        }) {
            CurrentRoundNilPrecommitPreclassificationV0::NeedsRound
        } else {
            CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
        }
    }

    /// Fully admits and retains one exact-current active nil precommit.
    ///
    /// The borrowed input remains caller-owned on every path. Exact canonical
    /// replay is no-growth; byte-distinct strict-valid signature variants remain
    /// distinct retained evidence.
    pub(super) fn try_insert_nil_precommit(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_signed_precommit: &[u8],
    ) -> Result<CurrentRoundNilPrecommitInboxInsertOutcomeV0, CurrentRoundNilPrecommitInsertErrorV0>
    {
        if let Some((position, saturation)) = self.saturation {
            return Err(CurrentRoundNilPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated: false,
            });
        }
        let vote = round
            .decode_and_verify_active_nil_precommit(canonical_signed_precommit)
            .map_err(CurrentRoundNilPrecommitInsertErrorV0::Admission)?;
        let parent_coordinate = round.parent_coordinate();
        let position = vote.position();
        let canonical_bytes = vote.to_canonical_bytes();
        if self.precommits.iter().any(|retained| {
            retained.parent_coordinate == parent_coordinate
                && retained.canonical_bytes == canonical_bytes
        }) {
            return Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::AlreadyRetained);
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
                return Err(CurrentRoundNilPrecommitInsertErrorV0::Saturated {
                    position,
                    saturation,
                    newly_saturated: true,
                });
            }
        };
        self.precommits
            .try_reserve(1)
            .map_err(CurrentRoundNilPrecommitInsertErrorV0::Reservation)?;
        debug_assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
        debug_assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
        self.precommits.push(RetainedCurrentNilPrecommitV0 {
            parent_coordinate,
            position,
            signer: vote.signer(),
            canonical_bytes,
        });
        self.total_canonical_input_bytes = prospective_total;
        Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
    }

    /// Selects a canonical nil-precommit quorum from the retained exact prefix.
    ///
    /// Saturation intentionally does not short-circuit this operation: a valid
    /// quorum already retained before the first denied insertion remains
    /// actionable. The existing exact certificate builder rechecks every
    /// selected vote and the unchanged active-set denominator.
    pub(super) fn select_nil_quorum(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<
        CurrentRoundNilPrecommitQuorumSelectionV0,
        CurrentRoundNilPrecommitQuorumSelectionErrorV0,
    > {
        let parent_coordinate = round.parent_coordinate();
        let position = round.position();
        let mut candidates: Vec<&RetainedCurrentNilPrecommitV0> = Vec::new();
        candidates
            .try_reserve_exact(self.precommits.len())
            .map_err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Reservation)?;
        candidates.extend(self.precommits.iter().filter(|vote| {
            vote.parent_coordinate == parent_coordinate && vote.position == position
        }));
        candidates.sort_unstable_by(|left, right| {
            left.signer
                .cmp(&right.signer)
                .then_with(|| left.canonical_bytes.cmp(&right.canonical_bytes))
        });

        let mut preferred_votes: Vec<&[u8]> = Vec::new();
        preferred_votes
            .try_reserve_exact(candidates.len())
            .map_err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Reservation)?;
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
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
        ) {
            Ok(_) => {
                let mut canonical_signed_precommits = Vec::new();
                canonical_signed_precommits
                    .try_reserve_exact(preferred_votes.len())
                    .map_err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Reservation)?;
                for canonical_bytes in preferred_votes {
                    canonical_signed_precommits.push(
                        canonical_bytes
                            .try_into()
                            .expect("retained canonical signed-vote width is fixed"),
                    );
                }
                Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One {
                    canonical_signed_precommits,
                })
            }
            Err(
                QuorumCertificateBuildError::EmptyVoteBatch
                | QuorumCertificateBuildError::InsufficientAgreementWeight { .. },
            ) => Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None),
            Err(source) => Err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Invariant(
                source,
            )),
        }
    }

    pub(super) fn drain_and_reset(
        &mut self,
    ) -> FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {
        self.total_canonical_input_bytes = 0;
        self.saturation = None;
        FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0 {
            precommits: mem::take(&mut self.precommits).into_iter(),
        }
    }
}

fn checked_prospective_totals(
    current_entries: usize,
    current_canonical_input_bytes: u64,
    inserted_canonical_input_bytes: u64,
    limits: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
) -> Result<(usize, u64), FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0> {
    let attempted_entries = current_entries.checked_add(1).ok_or(
        FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::EntryCountOverflow {
            maximum_entries: limits.max_entries,
        },
    )?;
    let attempted_canonical_input_bytes = current_canonical_input_bytes
        .checked_add(inserted_canonical_input_bytes)
        .ok_or(
            FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::CanonicalInputByteCountOverflow {
                maximum_canonical_input_bytes: limits.max_total_canonical_input_bytes,
            },
        )?;
    if attempted_entries > limits.max_entries
        || attempted_canonical_input_bytes > limits.max_total_canonical_input_bytes
    {
        return Err(
            FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::Capacity {
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
    fn nil_precommit_inbox_limits_require_positive_independent_caps() {
        assert_eq!(
            FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(0, 1),
            Err(FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0::ZeroMaxEntries)
        );
        assert_eq!(
            FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 0),
            Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0::ZeroMaxTotalCanonicalInputBytes
            )
        );
        let limits = FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(2, 3).unwrap();
        assert_eq!(limits.max_entries(), 2);
        assert_eq!(limits.max_total_canonical_input_bytes(), 3);
    }

    #[test]
    fn nil_precommit_inbox_accounting_fails_closed_at_capacity_and_overflow() {
        let exact = FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(2, 5).unwrap();
        assert_eq!(checked_prospective_totals(1, 2, 3, exact), Ok((2, 5)));
        assert!(matches!(
            checked_prospective_totals(2, 5, 1, exact),
            Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::Capacity {
                    attempted_entries: 3,
                    attempted_canonical_input_bytes: 6,
                    ..
                }
            )
        ));

        let maximum =
            FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(usize::MAX, u64::MAX)
                .unwrap();
        assert!(matches!(
            checked_prospective_totals(usize::MAX, 0, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::EntryCountOverflow {
                    maximum_entries: usize::MAX
                }
            )
        ));
        assert!(matches!(
            checked_prospective_totals(0, u64::MAX, 1, maximum),
            Err(
                FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::CanonicalInputByteCountOverflow {
                    maximum_canonical_input_bytes: u64::MAX
                }
            )
        ));
    }
}
