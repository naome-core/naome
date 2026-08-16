//! Exact fee-partition and Knowledge Weight origin-batch arithmetic for NAOME.
//!
//! This crate partitions caller-supplied fee atoms and converts
//! already-matured citation-reward atoms into initial Knowledge Weight with
//! exact 730-epoch origin-batch decay. Callers remain responsible for fee
//! calculation and classification, payment authorization, balances, reward
//! eligibility and settlement, maturity, ownership, persistence, delegation,
//! penalties, and consensus use.

const BATCH_LIFETIME_EPOCHS: u64 = 730;
const BATCH_LIFETIME_UNITS: u128 = BATCH_LIFETIME_EPOCHS as u128;
const FEE_PARTS: u128 = 5;

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
    /// remainder arithmetic avoids doubling the full `u128` fee.
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
