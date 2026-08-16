//! Exact Knowledge Weight origin-batch arithmetic for NAOME.
//!
//! This crate converts already-matured citation-reward atoms into initial
//! Knowledge Weight and evaluates one immutable batch's 730-epoch linear
//! decay. Callers remain responsible for reward maturity, activation age,
//! ownership, persistence, delegation, penalties, and consensus use.

const BATCH_LIFETIME_EPOCHS: u64 = 730;
const BATCH_LIFETIME_UNITS: u128 = BATCH_LIFETIME_EPOCHS as u128;

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
