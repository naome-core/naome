//! Stateless fee-funded validator-share projection.
//!
//! This module combines caller-supplied aggregate validator-pool atoms with a
//! caller-supplied immutable agreement snapshot. The caller must aggregate the
//! complete pool before projecting a share because integer-floor allocation is
//! not distributive across separate fee partitions. The projection establishes
//! no pool provenance or aggregation validity, fee payment, signature or
//! certificate validity, prior-height finality, entitlement,
//! certificate-authoritative signer-list completeness, actual unassigned-atom
//! burn, commission, delegation, claim, credit, settlement, persistence, or
//! economic or consensus state.

use std::error::Error;
use std::fmt;

use naome_consensus::{ActiveAgreementSnapshot, AgreementSignerError, ConsensusKey};
use naome_economy::{
    FeePartition, NaoAtoms, ValidatorPoolAggregationError, aggregate_validator_pool,
};

/// A failure to project one fee-funded validator share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorFeeShareError {
    /// The caller-supplied key is absent from the supplied active snapshot.
    ///
    /// This error establishes no canonical active-set or consensus authority.
    InactiveSigner { consensus_key: ConsensusKey },
}

impl fmt::Display for ValidatorFeeShareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InactiveSigner { consensus_key } => write!(
                formatter,
                "consensus key {consensus_key:?} is not active in the supplied agreement snapshot"
            ),
        }
    }
}

impl Error for ValidatorFeeShareError {}

/// A failure to aggregate fee partitions and project their validator allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorFeeAllocationFromPartitionsError {
    /// The caller-supplied partitions' validator pools cannot be summed.
    PoolAggregation(ValidatorPoolAggregationError),
    /// The caller-supplied signer list is invalid for the supplied snapshot.
    SignerList(AgreementSignerError),
}

impl fmt::Display for ValidatorFeeAllocationFromPartitionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolAggregation(error) => {
                write!(formatter, "validator pool aggregation failed: {error}")
            }
            Self::SignerList(error) => {
                write!(formatter, "validator signer list is invalid: {error}")
            }
        }
    }
}

impl Error for ValidatorFeeAllocationFromPartitionsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PoolAggregation(error) => Some(error),
            Self::SignerList(error) => Some(error),
        }
    }
}

/// One caller-listed signer's projected validator-pool share.
///
/// Ascending key order is an output-normalization rule only. It grants no
/// ranking, selection, certificate, entitlement, or consensus authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProjectedValidatorFeeShare {
    consensus_key: ConsensusKey,
    share: NaoAtoms,
}

impl ProjectedValidatorFeeShare {
    /// Returns the caller-listed active consensus key.
    pub const fn consensus_key(self) -> ConsensusKey {
        self.consensus_key
    }

    /// Returns the key's exact numeric share.
    pub const fn share(self) -> NaoAtoms {
        self.share
    }
}

/// Exact arithmetic allocation over one caller-supplied signer-key list.
///
/// The listed shares are stored in ascending consensus-key order. Unlisted
/// active weight remains in the unchanged denominator, and every pool atom not
/// assigned by the individual floor projections remains numerically
/// unassigned. This summary proves neither signer-list completeness nor actual
/// entitlement, burn, credit, settlement, or state mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProjectedValidatorFeeAllocation {
    validator_pool: NaoAtoms,
    shares: Box<[ProjectedValidatorFeeShare]>,
    unassigned: NaoAtoms,
}

impl ProjectedValidatorFeeAllocation {
    /// Returns the caller-supplied aggregate validator pool.
    pub const fn validator_pool(&self) -> NaoAtoms {
        self.validator_pool
    }

    /// Returns listed shares in ascending consensus-key order.
    pub fn shares(&self) -> &[ProjectedValidatorFeeShare] {
        &self.shares
    }

    /// Returns the exact arithmetic remainder not assigned to listed keys.
    ///
    /// This value is not evidence that the remainder was burned or credited.
    pub const fn unassigned(&self) -> NaoAtoms {
        self.unassigned
    }
}

/// Projects one active signer's share of an already-aggregated validator pool.
///
/// For validator pool `P`, the signer's stored agreement weight `w`, and the
/// snapshot's unchanged total agreement weight `W`, this returns exactly
/// `floor(P * w / W)`. The implementation covers the complete `u128` input
/// range without evaluating the potentially overflowing product `P * w`.
///
/// The caller must supply the complete aggregate pool exactly once. Applying
/// this projection separately to contributing fee partitions can lose atoms to
/// repeated rounding. A missing key fails before zero-pool arithmetic. The
/// returned [`NaoAtoms`] value is an arithmetic projection only and grants none
/// of the protocol authority excluded by this module.
pub fn project_fee_funded_validator_share(
    validator_pool: NaoAtoms,
    snapshot: &ActiveAgreementSnapshot,
    signer: ConsensusKey,
) -> Result<NaoAtoms, ValidatorFeeShareError> {
    let entries = snapshot.entries();
    let entry_index = entries
        .binary_search_by_key(&signer, |entry| entry.consensus_key())
        .map_err(|_| ValidatorFeeShareError::InactiveSigner {
            consensus_key: signer,
        })?;
    let signer_weight = entries[entry_index].agreement_weight().units();
    let total_weight = snapshot.total_weight().units();

    Ok(NaoAtoms::new(floor_weighted_share(
        validator_pool.atoms(),
        signer_weight,
        total_weight,
    )))
}

/// Projects one already-aggregated validator pool over a signer-key list.
///
/// Signer-list validation reuses [`ActiveAgreementSnapshot::signed_weight`],
/// including its entry bound and deterministic duplicate/unknown-key error
/// precedence. Each valid listed key receives the same exact share it would
/// receive from [`project_fee_funded_validator_share`], independently of which
/// other active keys are listed. The result is normalized into ascending key
/// order and conserves the supplied pool as listed shares plus an unassigned
/// arithmetic remainder.
///
/// The caller remains responsible for pool provenance and aggregation,
/// certificate and signer-list authority, finality, entitlement creation,
/// actual remainder burn, commission and delegation, credit, claims,
/// settlement, persistence, and economic or consensus state.
pub fn project_fee_funded_validator_allocation(
    validator_pool: NaoAtoms,
    snapshot: &ActiveAgreementSnapshot,
    signer_keys: &[ConsensusKey],
) -> Result<ProjectedValidatorFeeAllocation, AgreementSignerError> {
    let _ = snapshot.signed_weight(signer_keys)?;

    let mut signer_keys = signer_keys.to_vec();
    signer_keys.sort_unstable();

    let mut assigned_atoms = 0_u128;
    let shares = signer_keys
        .into_iter()
        .map(|consensus_key| {
            let share = project_fee_funded_validator_share(validator_pool, snapshot, consensus_key)
                .expect("validated signer keys remain active in the immutable snapshot");
            assigned_atoms = assigned_atoms
                .checked_add(share.atoms())
                .expect("listed floor shares cannot exceed the source pool");

            ProjectedValidatorFeeShare {
                consensus_key,
                share,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let unassigned = validator_pool
        .atoms()
        .checked_sub(assigned_atoms)
        .expect("listed floor shares cannot exceed the source pool");

    Ok(ProjectedValidatorFeeAllocation {
        validator_pool,
        shares,
        unassigned: NaoAtoms::new(unassigned),
    })
}

/// Aggregates fee partitions once, then projects the resulting validator pool.
///
/// Aggregation deliberately runs before signer-list validation. This makes
/// overflow fail closed without returning a partial pool or allocation and
/// prevents callers from projecting each partition separately, which can lose
/// atoms to repeated floor rounding. On success, this is exactly equivalent to
/// calling [`aggregate_validator_pool`] once and passing its result to
/// [`project_fee_funded_validator_allocation`].
///
/// The caller remains responsible for partition provenance, completeness, and
/// common-height grouping; certificate and signer-list authority; finality;
/// entitlement creation; actual remainder burn; credit, settlement,
/// persistence, and economic or consensus state.
pub fn project_fee_funded_validator_allocation_from_partitions(
    partitions: &[FeePartition],
    snapshot: &ActiveAgreementSnapshot,
    signer_keys: &[ConsensusKey],
) -> Result<ProjectedValidatorFeeAllocation, ValidatorFeeAllocationFromPartitionsError> {
    let validator_pool = aggregate_validator_pool(partitions)
        .map_err(ValidatorFeeAllocationFromPartitionsError::PoolAggregation)?;

    project_fee_funded_validator_allocation(validator_pool, snapshot, signer_keys)
        .map_err(ValidatorFeeAllocationFromPartitionsError::SignerList)
}

fn floor_weighted_share(value: u128, numerator: u128, denominator: u128) -> u128 {
    debug_assert!(denominator > 0);
    debug_assert!(numerator > 0);
    debug_assert!(numerator <= denominator);

    if value == 0 || numerator == denominator {
        return value;
    }

    let mut quotient = 0_u128;
    let mut remainder = 0_u128;
    let significant_bits = u128::BITS - value.leading_zeros();

    for bit in (0..significant_bits).rev() {
        quotient <<= 1;

        let distance_to_denominator = denominator - remainder;
        if remainder >= distance_to_denominator {
            remainder -= distance_to_denominator;
            quotient += 1;
        } else {
            remainder += remainder;
        }

        if value & (1_u128 << bit) != 0 {
            let distance_to_denominator = denominator - numerator;
            if remainder >= distance_to_denominator {
                remainder -= distance_to_denominator;
                quotient += 1;
            } else {
                remainder += numerator;
            }
        }
    }

    quotient
}

#[cfg(test)]
mod tests;
