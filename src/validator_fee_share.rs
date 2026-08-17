//! Stateless fee-funded validator-share projection.
//!
//! This module combines caller-supplied aggregate validator-pool atoms with a
//! caller-supplied immutable agreement snapshot. The caller must aggregate the
//! complete pool before projecting a share because integer-floor allocation is
//! not distributive across separate fee partitions. The projection establishes
//! no pool provenance or aggregation validity, fee payment, signature or
//! certificate validity, prior-height finality, entitlement, complete signer
//! allocation, unassigned-atom burn, commission, delegation, claim, credit,
//! settlement, persistence, or economic or consensus state.

use std::error::Error;
use std::fmt;

use naome_consensus::{ActiveAgreementSnapshot, ConsensusKey};
use naome_economy::NaoAtoms;

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
