//! Exact artifact base-fee floor qualification, fee-partition, citation-pool
//! allocation, and Knowledge Weight origin-batch arithmetic for NAOME.
//!
//! This crate numerically qualifies caller-supplied artifact base-fee atoms against
//! a fixed floor, partitions caller-supplied fee atoms, allocates an already
//! partitioned citation pool over a caller-validated distinct target count,
//! and converts already-matured citation-reward atoms into initial Knowledge
//! Weight with exact 730-epoch origin-batch decay. Floor qualification proves
//! no fee calculation or resource adequacy. Callers remain responsible for fee
//! calculation and classification, payment authorization, target eligibility
//! and deduplication, identities, balances, actual burn and credit, reward
//! settlement, maturity, ownership, persistence, delegation, penalties,
//! height-farming safety, state transitions, and consensus use.

use std::error::Error;
use std::fmt;

const BATCH_LIFETIME_EPOCHS: u64 = 730;
const BATCH_LIFETIME_UNITS: u128 = BATCH_LIFETIME_EPOCHS as u128;
const FEE_PARTS: u128 = 5;

/// Exact number of indivisible NAO atoms in one NAO.
pub const NAO_ATOMS_PER_NAO: u128 = 1_000_000_000;

/// Exact NAO atoms in the in-memory reference economy kernel.
///
/// This `u128` capacity does not define consensus-state or wire encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct NaoAtoms(u128);

impl NaoAtoms {
    /// Zero NAO atoms.
    pub const ZERO: Self = Self(0);

    /// Constructs an exact NAO-atom value.
    pub const fn new(atoms: u128) -> Self {
        Self(atoms)
    }

    /// Returns the exact number of NAO atoms.
    pub const fn atoms(self) -> u128 {
        self.0
    }

    /// Returns whether this value is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Exact numeric minimum for caller-supplied artifact base-fee atoms.
///
/// This constant does not establish fee calculation, resource adequacy,
/// payment, inclusion, or economic-state authority.
pub const MINIMUM_ARTIFACT_BASE_FEE: NaoAtoms = NaoAtoms::new(5);

/// One exact, conserved partition of caller-supplied fee atoms.
///
/// Construction does not establish the fee's protocol validity, classify an
/// operation, authorize a payer, select recipients, or mutate state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FeePartition {
    fee: NaoAtoms,
    citation_pool: NaoAtoms,
    validator_pool: NaoAtoms,
    burned: NaoAtoms,
}

impl FeePartition {
    /// Partitions an already-computed artifact base fee.
    ///
    /// The citation pool is `floor(2 * fee / 5)`, the validator pool is
    /// `floor(fee / 5)`, and every remaining atom is burned. Quotient and
    /// remainder arithmetic avoids doubling the full `u128` fee. This raw
    /// arithmetic path does not enforce [`MINIMUM_ARTIFACT_BASE_FEE`] and
    /// accepts below-floor values; it proves no fee adequacy, payment, actual
    /// burn or credit, state transition, or height-farming safety.
    pub const fn from_artifact_base_fee(fee: NaoAtoms) -> Self {
        let quotient = fee.atoms() / FEE_PARTS;
        let remainder = fee.atoms() % FEE_PARTS;
        let citation_pool = quotient * 2 + (remainder * 2) / FEE_PARTS;
        let validator_pool = quotient;
        let burned = fee.atoms() - citation_pool - validator_pool;

        Self {
            fee,
            citation_pool: NaoAtoms::new(citation_pool),
            validator_pool: NaoAtoms::new(validator_pool),
            burned: NaoAtoms::new(burned),
        }
    }

    /// Partitions an already-computed non-artifact operation fee.
    ///
    /// No citation pool is created. The validator pool is `floor(fee / 5)`,
    /// and every remaining atom is burned.
    pub const fn from_non_artifact_operation_fee(fee: NaoAtoms) -> Self {
        let validator_pool = fee.atoms() / FEE_PARTS;
        let burned = fee.atoms() - validator_pool;

        Self {
            fee,
            citation_pool: NaoAtoms::ZERO,
            validator_pool: NaoAtoms::new(validator_pool),
            burned: NaoAtoms::new(burned),
        }
    }

    /// Allocates this partition's citation pool over a validated target count.
    ///
    /// The caller remains responsible for establishing that the count covers
    /// exactly the distinct eligible citation targets. A zero count assigns no
    /// reward and burns the complete citation pool. Otherwise, every target
    /// receives `floor(citation_pool / count)` and the division remainder is
    /// burned. This operation does not identify or credit any target.
    pub const fn allocate_citation_pool(
        self,
        distinct_eligible_target_count: u128,
    ) -> CitationPoolAllocation {
        let citation_pool = self.citation_pool;
        let (per_target_reward, burned_remainder) = match distinct_eligible_target_count {
            0 => (NaoAtoms::ZERO, citation_pool),
            target_count => {
                let citation_atoms = citation_pool.atoms();
                (
                    NaoAtoms::new(citation_atoms / target_count),
                    NaoAtoms::new(citation_atoms % target_count),
                )
            }
        };

        CitationPoolAllocation {
            citation_pool,
            distinct_eligible_target_count,
            per_target_reward,
            burned_remainder,
        }
    }

    /// Returns the caller-supplied fee.
    pub const fn fee(self) -> NaoAtoms {
        self.fee
    }

    /// Returns the citation-reward pool.
    pub const fn citation_pool(self) -> NaoAtoms {
        self.citation_pool
    }

    /// Returns the validator-reward pool.
    pub const fn validator_pool(self) -> NaoAtoms {
        self.validator_pool
    }

    /// Returns the atoms assigned to explicit burn.
    pub const fn burned(self) -> NaoAtoms {
        self.burned
    }
}

/// A numeric artifact-base-fee floor qualification error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBaseFeeFloorError {
    /// The caller-supplied atom amount is below the exact numeric floor.
    ///
    /// This variant proves only the failed integer comparison and carries no
    /// fee-calculation, payment, inclusion, or state authority.
    BelowMinimum { actual: NaoAtoms, minimum: NaoAtoms },
}

impl fmt::Display for ArtifactBaseFeeFloorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowMinimum { actual, minimum } => write!(
                formatter,
                "artifact base fee has {} atoms, below numeric minimum {}",
                actual.atoms(),
                minimum.atoms()
            ),
        }
    }
}

impl Error for ArtifactBaseFeeFloorError {}

/// Caller-supplied artifact base-fee atoms that meet the exact numeric floor.
///
/// This value proves only the integer comparison performed by
/// [`Self::try_from_fee_atoms`]. It does not prove fee calculation, resource
/// adequacy, artifact classification, payer authorization, payment, balance,
/// inclusion, finality, actual burn or credit, settlement, economic state, or
/// height-farming safety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FloorQualifiedArtifactBaseFee {
    fee_atoms: NaoAtoms,
}

impl FloorQualifiedArtifactBaseFee {
    /// Qualifies caller-supplied atoms against the exact numeric floor.
    ///
    /// Success proves only `fee_atoms >= MINIMUM_ARTIFACT_BASE_FEE`; it does
    /// not establish that the amount was computed, paid, or applied to state.
    pub const fn try_from_fee_atoms(
        fee_atoms: NaoAtoms,
    ) -> Result<Self, ArtifactBaseFeeFloorError> {
        if fee_atoms.atoms() < MINIMUM_ARTIFACT_BASE_FEE.atoms() {
            return Err(ArtifactBaseFeeFloorError::BelowMinimum {
                actual: fee_atoms,
                minimum: MINIMUM_ARTIFACT_BASE_FEE,
            });
        }

        Ok(Self { fee_atoms })
    }

    /// Returns the exact caller-supplied atom amount.
    pub const fn fee_atoms(self) -> NaoAtoms {
        self.fee_atoms
    }

    /// Returns the existing exact artifact base-fee arithmetic partition.
    ///
    /// The result is an arithmetic summary only. It proves no computed-fee
    /// adequacy, payment, actual burn or credit, state transition, settlement,
    /// or height-farming safety.
    pub const fn partition(self) -> FeePartition {
        FeePartition::from_artifact_base_fee(self.fee_atoms)
    }
}

/// One exact equal allocation of a citation pool.
///
/// The target count is supplied and validated by the caller. This value does
/// not carry target identities, establish eligibility, credit beneficiaries,
/// or mutate economic state. Its `u128` count is an in-memory reference
/// capacity, not a canonical encoding or protocol target-count bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CitationPoolAllocation {
    citation_pool: NaoAtoms,
    distinct_eligible_target_count: u128,
    per_target_reward: NaoAtoms,
    burned_remainder: NaoAtoms,
}

impl CitationPoolAllocation {
    /// Returns the complete source citation pool.
    pub const fn citation_pool(self) -> NaoAtoms {
        self.citation_pool
    }

    /// Returns the caller-validated distinct eligible-target count.
    pub const fn distinct_eligible_target_count(self) -> u128 {
        self.distinct_eligible_target_count
    }

    /// Returns the equal reward assigned to every eligible target.
    pub const fn per_target_reward(self) -> NaoAtoms {
        self.per_target_reward
    }

    /// Returns the citation-pool division remainder assigned to burn.
    pub const fn burned_remainder(self) -> NaoAtoms {
        self.burned_remainder
    }
}

/// Exact Knowledge Weight units in the reference economy kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct KnowledgeWeight(u128);

impl KnowledgeWeight {
    /// Zero Knowledge Weight.
    pub const ZERO: Self = Self(0);

    /// Constructs an exact Knowledge Weight value.
    pub const fn new(units: u128) -> Self {
        Self(units)
    }

    /// Returns the exact Knowledge Weight units.
    pub const fn units(self) -> u128 {
        self.0
    }

    /// Returns whether this value is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// One immutable Knowledge Weight origin batch.
///
/// Construction accepts citation-reward atoms only after the caller has
/// established their maturity. The batch contains no clock, beneficiary, or
/// lifecycle authority; callers supply its integer age when evaluating it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct KnowledgeWeightBatch {
    original_weight: KnowledgeWeight,
}

impl KnowledgeWeightBatch {
    /// Creates one origin batch at one initial Knowledge Weight unit per
    /// already-matured citation-reward atom.
    pub const fn from_matured_citation_atoms(atoms: u128) -> Self {
        Self {
            original_weight: KnowledgeWeight::new(atoms),
        }
    }

    /// Returns the batch's immutable initial Knowledge Weight.
    pub const fn original_weight(self) -> KnowledgeWeight {
        self.original_weight
    }

    /// Returns the batch's live weight at the caller-supplied integer age.
    ///
    /// For ages below 730 epochs this evaluates
    /// `floor(original_weight * (730 - age) / 730)`. At age 730 and later the
    /// result is zero. Quotient/remainder decomposition avoids overflowing the
    /// full `u128` input range.
    pub const fn live_weight_at_age(self, age_epochs: u64) -> KnowledgeWeight {
        if age_epochs >= BATCH_LIFETIME_EPOCHS {
            return KnowledgeWeight::ZERO;
        }

        let remaining_epochs = (BATCH_LIFETIME_EPOCHS - age_epochs) as u128;
        let original_units = self.original_weight.units();
        let quotient = original_units / BATCH_LIFETIME_UNITS;
        let remainder = original_units % BATCH_LIFETIME_UNITS;
        let live_units =
            quotient * remaining_epochs + (remainder * remaining_epochs) / BATCH_LIFETIME_UNITS;

        KnowledgeWeight::new(live_units)
    }
}

#[cfg(test)]
mod tests;
