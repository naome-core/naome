//! Deterministic proposer selection and canonical priority state across
//! caller-preselected immutable agreement snapshots.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};

use super::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, ActiveAgreementSnapshotError, AgreementWeight,
    ConsensusHeight, ConsensusKey, ConsensusPosition, ConsensusRound,
};

const FIXED_AGREEMENT_SET_DOMAIN: &[u8] = b"naome:fixed-agreement-set:v0\0";
const PROPOSER_PRIORITY_STATE_DOMAIN: &[u8] = b"naome:proposer-priority-state:v0\0";
const SIGNED_PRIORITY_BYTES: usize = 32;

/// Content identity of one sorted, fixed validator key-and-weight set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct FixedAgreementSetId([u8; Self::BYTE_LENGTH]);

impl FixedAgreementSetId {
    /// Exact width of one fixed-agreement-set identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// Content identity of one fixed set's exact canonical proposer priorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProposerPriorityStateId([u8; Self::BYTE_LENGTH]);

impl ProposerPriorityStateId {
    /// Exact width of one proposer-priority-state identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedAgreementSetV0 {
    entries: Box<[ActiveAgreementEntry]>,
    total_weight: AgreementWeight,
    id: FixedAgreementSetId,
}

impl FixedAgreementSetV0 {
    pub(crate) fn try_from_preselected(
        entries: &[ActiveAgreementEntry],
    ) -> Result<Self, ActiveAgreementSnapshotError> {
        let snapshot = ActiveAgreementSnapshot::try_from_preselected(
            ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(0)),
            entries,
        )?;
        Ok(Self::from_active_snapshot(&snapshot))
    }

    fn from_active_snapshot(snapshot: &ActiveAgreementSnapshot) -> Self {
        let entries = snapshot.entries().to_vec().into_boxed_slice();
        let total_weight = snapshot.total_weight();
        let id = derive_fixed_set_id(&entries);
        Self {
            entries,
            total_weight,
            id,
        }
    }

    pub(crate) fn positioned_snapshot(
        &self,
        position: ConsensusPosition,
    ) -> ActiveAgreementSnapshot {
        ActiveAgreementSnapshot {
            position,
            entries: self.entries.clone(),
            total_weight: self.total_weight,
        }
    }

    pub(crate) fn entries(&self) -> &[ActiveAgreementEntry] {
        &self.entries
    }

    pub(crate) const fn total_weight(&self) -> AgreementWeight {
        self.total_weight
    }

    pub(crate) const fn id(&self) -> FixedAgreementSetId {
        self.id
    }
}

/// One exact, internally reachable proposer-priority state for one immutable set.
///
/// Priorities have no public raw constructor. V0 starts at zero and publishes
/// successors only through [`Self::select_next`] or the deterministic complete-
/// snapshot transition, so callers cannot substitute a key or priority vector
/// while retaining the same typed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedProposerStateV0 {
    fixed_set: Arc<FixedAgreementSetV0>,
    priorities: Box<[BigInt]>,
    id: ProposerPriorityStateId,
}

impl FixedProposerStateV0 {
    pub(crate) fn try_from_preselected(
        entries: &[ActiveAgreementEntry],
    ) -> Result<Self, ActiveAgreementSnapshotError> {
        Ok(Self::from_zeroed_fixed_set(
            FixedAgreementSetV0::try_from_preselected(entries)?,
        ))
    }

    fn from_zeroed_preselected_snapshot(snapshot: &ActiveAgreementSnapshot) -> Self {
        Self::from_zeroed_fixed_set(FixedAgreementSetV0::from_active_snapshot(snapshot))
    }

    fn from_zeroed_fixed_set(fixed_set: FixedAgreementSetV0) -> Self {
        let fixed_set = Arc::new(fixed_set);
        let priorities = vec![BigInt::from(0_u8); fixed_set.entries().len()].into_boxed_slice();
        let id = derive_priority_state_id(fixed_set.id(), &priorities)
            .expect("zero priorities fit the canonical signed-256-bit representation");
        Self {
            fixed_set,
            priorities,
            id,
        }
    }

    pub(crate) fn select_next(&self) -> Result<(ConsensusKey, Self), ProposerSelectionError> {
        if self.fixed_set.entries().is_empty() {
            return Err(ProposerSelectionError::NoActiveValidators);
        }

        let mut priorities = self.priorities.to_vec();
        normalize_priorities(&mut priorities, self.fixed_set.total_weight())?;

        for (priority, entry) in priorities.iter_mut().zip(self.fixed_set.entries()) {
            *priority += BigInt::from(entry.agreement_weight().units());
        }

        let mut winner_index = 0;
        for index in 1..priorities.len() {
            if priorities[index] > priorities[winner_index] {
                winner_index = index;
            }
        }
        priorities[winner_index] -= BigInt::from(self.fixed_set.total_weight().units());

        let priorities = priorities.into_boxed_slice();
        let id = derive_priority_state_id(self.fixed_set.id(), &priorities)?;
        let proposer = self.fixed_set.entries()[winner_index].consensus_key();
        Ok((
            proposer,
            Self {
                fixed_set: Arc::clone(&self.fixed_set),
                priorities,
                id,
            },
        ))
    }

    /// Applies the exact transition to one complete caller-preselected snapshot.
    ///
    /// This arithmetic does not establish snapshot provenance, canonicality,
    /// activation, branch selection, finality, persistence, or network trust.
    fn transition_to_preselected_snapshot(
        &self,
        final_snapshot: &ActiveAgreementSnapshot,
    ) -> Result<Self, ProposerSelectionError> {
        for priority in &self.priorities {
            encode_signed_i256(priority)?;
        }

        let fixed_set = Arc::new(FixedAgreementSetV0::from_active_snapshot(final_snapshot));
        if fixed_set.entries().is_empty() {
            let priorities = Vec::new().into_boxed_slice();
            let id = derive_priority_state_id(fixed_set.id(), &priorities)?;
            return Ok(Self {
                fixed_set,
                priorities,
                id,
            });
        }

        let removed_weight = self
            .fixed_set
            .entries()
            .iter()
            .filter(|old_entry| {
                fixed_set
                    .entries()
                    .binary_search_by_key(&old_entry.consensus_key(), |entry| entry.consensus_key())
                    .is_err()
            })
            .fold(BigInt::from(0_u8), |total, entry| {
                total + BigInt::from(entry.agreement_weight().units())
            });
        let updated_total = BigInt::from(fixed_set.total_weight().units()) + removed_weight;
        let new_priority = -(&updated_total + (&updated_total / 8_u8));
        encode_signed_i256(&new_priority)?;

        let mut priorities = fixed_set
            .entries()
            .iter()
            .map(|final_entry| {
                self.fixed_set
                    .entries()
                    .binary_search_by_key(&final_entry.consensus_key(), |entry| {
                        entry.consensus_key()
                    })
                    .map_or_else(
                        |_| new_priority.clone(),
                        |old_index| self.priorities[old_index].clone(),
                    )
            })
            .collect::<Vec<_>>();
        normalize_priorities(&mut priorities, fixed_set.total_weight())?;

        let priorities = priorities.into_boxed_slice();
        let id = derive_priority_state_id(fixed_set.id(), &priorities)?;
        Ok(Self {
            fixed_set,
            priorities,
            id,
        })
    }

    pub(crate) fn positioned_snapshot(
        &self,
        position: ConsensusPosition,
    ) -> ActiveAgreementSnapshot {
        self.fixed_set.positioned_snapshot(position)
    }

    pub(crate) fn fixed_set_id(&self) -> FixedAgreementSetId {
        self.fixed_set.id()
    }

    pub(crate) const fn id(&self) -> ProposerPriorityStateId {
        self.id
    }

    #[cfg(test)]
    pub(crate) fn canonical_priorities(&self) -> Result<Vec<[u8; 32]>, ProposerSelectionError> {
        self.priorities.iter().map(encode_signed_i256).collect()
    }
}

/// Opaque arithmetic reference state for caller-preselected agreement snapshots.
///
/// A value starts with zero priorities for one already validated snapshot and
/// can then advance only through [`Self::select_next`] or
/// [`Self::transition_to_preselected_snapshot`]. Snapshot positions are not
/// bound into this state. Construction does not establish genesis, authorize a
/// reset or recovery, or make the supplied snapshot canonical. A returned key
/// is an arithmetic winner only and grants no proposal or signing authority.
///
/// The raw priorities and validator entries are not exposed, and there is no
/// conversion from this reference state into a consensus branch. Cloning,
/// comparing, or deriving identities for alternative states grants none of
/// them activation, branch-selection, finality, persistence, or peer authority.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct PreselectedProposerStateV0(FixedProposerStateV0);

impl PreselectedProposerStateV0 {
    /// Creates the zero-priority arithmetic root for one validated snapshot.
    ///
    /// This operation is not a genesis, reset, recovery, or activation rule.
    pub fn from_zeroed_preselected_snapshot(snapshot: &ActiveAgreementSnapshot) -> Self {
        Self(FixedProposerStateV0::from_zeroed_preselected_snapshot(
            snapshot,
        ))
    }

    /// Computes the next weighted-round-robin key and immutable successor.
    ///
    /// The returned key is not evidence of proposal or signing authority.
    pub fn select_next(&self) -> Result<(ConsensusKey, Self), ProposerSelectionError> {
        let (key, successor) = self.0.select_next()?;
        Ok((key, Self(successor)))
    }

    /// Applies the exact arithmetic transition to a complete validated snapshot.
    ///
    /// This does not establish snapshot provenance, canonicality, activation,
    /// branch selection, finality, persistence, recovery, or network trust. An
    /// empty result is a halt state and grants no authority to resume consensus.
    pub fn transition_to_preselected_snapshot(
        &self,
        final_snapshot: &ActiveAgreementSnapshot,
    ) -> Result<Self, ProposerSelectionError> {
        self.0
            .transition_to_preselected_snapshot(final_snapshot)
            .map(Self)
    }

    /// Returns the content identity of the state's sorted key-and-weight set.
    ///
    /// This identity does not prove provenance, canonicality, or activation.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.0.fixed_set_id()
    }

    /// Returns the content identity of the set and canonical priority vector.
    ///
    /// This identity does not prove provenance, canonicality, or activation.
    pub const fn proposer_priority_state_id(&self) -> ProposerPriorityStateId {
        self.0.id()
    }
}

impl fmt::Debug for PreselectedProposerStateV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreselectedProposerStateV0")
            .field("fixed_agreement_set_id", &self.fixed_agreement_set_id())
            .field(
                "proposer_priority_state_id",
                &self.proposer_priority_state_id(),
            )
            .finish_non_exhaustive()
    }
}

fn derive_fixed_set_id(entries: &[ActiveAgreementEntry]) -> FixedAgreementSetId {
    let count =
        u16::try_from(entries.len()).expect("the active-validator bound is representable as u16");
    let mut hasher = Sha256::new();
    hasher.update(FIXED_AGREEMENT_SET_DOMAIN);
    hasher.update(count.to_be_bytes());
    for entry in entries {
        hasher.update(entry.consensus_key().as_bytes());
        hasher.update(entry.agreement_weight().units().to_be_bytes());
    }
    FixedAgreementSetId(hasher.finalize().into())
}

fn derive_priority_state_id(
    fixed_set_id: FixedAgreementSetId,
    priorities: &[BigInt],
) -> Result<ProposerPriorityStateId, ProposerSelectionError> {
    let count = u16::try_from(priorities.len())
        .expect("the active-validator bound is representable as u16");
    let mut hasher = Sha256::new();
    hasher.update(PROPOSER_PRIORITY_STATE_DOMAIN);
    hasher.update(fixed_set_id.as_bytes());
    hasher.update(count.to_be_bytes());
    for priority in priorities {
        hasher.update(encode_signed_i256(priority)?);
    }
    Ok(ProposerPriorityStateId(hasher.finalize().into()))
}

fn normalize_priorities(
    priorities: &mut [BigInt],
    total_weight: AgreementWeight,
) -> Result<(), ProposerSelectionError> {
    debug_assert!(!priorities.is_empty());
    let total_weight = BigInt::from(total_weight.units());
    let threshold = &total_weight * 2_u8;

    let minimum = priorities
        .iter()
        .min()
        .expect("the caller rejects an empty priority vector")
        .clone();
    let maximum = priorities
        .iter()
        .max()
        .expect("the caller rejects an empty priority vector")
        .clone();
    let difference = maximum - minimum;
    if difference > threshold {
        let ratio = (&difference + &threshold - 1_u8) / &threshold;
        for priority in priorities.iter_mut() {
            *priority /= &ratio;
        }
    }

    let sum: BigInt = priorities.iter().cloned().sum();
    let count = BigInt::from(priorities.len());
    let quotient = &sum / &count;
    let remainder = &sum % &count;
    let average = if sum.sign() == Sign::Minus && remainder != BigInt::from(0_u8) {
        quotient - 1_u8
    } else {
        quotient
    };
    for priority in priorities.iter_mut() {
        *priority -= &average;
        encode_signed_i256(priority)?;
    }
    Ok(())
}

fn encode_signed_i256(
    value: &BigInt,
) -> Result<[u8; SIGNED_PRIORITY_BYTES], ProposerSelectionError> {
    let bytes = value.to_signed_bytes_be();
    let mut output = match value.sign() {
        Sign::Minus => [u8::MAX; SIGNED_PRIORITY_BYTES],
        Sign::NoSign | Sign::Plus => [0_u8; SIGNED_PRIORITY_BYTES],
    };

    let bytes = if bytes.len() <= SIGNED_PRIORITY_BYTES {
        bytes.as_slice()
    } else {
        return Err(ProposerSelectionError::PriorityOutOfRange);
    };
    output[SIGNED_PRIORITY_BYTES - bytes.len()..].copy_from_slice(bytes);
    Ok(output)
}

/// A deterministic proposer-selection failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposerSelectionError {
    /// The immutable active set is empty, so consensus must halt.
    NoActiveValidators,
    /// An internal priority cannot be represented by canonical signed i256 bytes.
    PriorityOutOfRange,
    /// The current position is the terminal `u64` round.
    RoundExhausted,
    /// The current branch is already at the terminal `u64` height.
    HeightExhausted,
}

impl fmt::Display for ProposerSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveValidators => {
                formatter.write_str("the fixed agreement set is empty; proposer selection halts")
            }
            Self::PriorityOutOfRange => {
                formatter.write_str("proposer priority exceeds the canonical signed-256-bit range")
            }
            Self::RoundExhausted => {
                formatter.write_str("consensus round cannot advance beyond u64::MAX")
            }
            Self::HeightExhausted => {
                formatter.write_str("consensus height cannot advance beyond u64::MAX")
            }
        }
    }
}

impl Error for ProposerSelectionError {}

#[cfg(test)]
#[path = "proposer_selection/tests.rs"]
mod tests;
