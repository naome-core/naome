//! Numeric validator-bond floor and agreement-weight cap integration.
//!
//! This module bridges caller-supplied economy [`NaoAtoms`] with a
//! caller-supplied consensus [`AgreementWeight`]. Meeting the numeric floor
//! does not establish an account balance, escrow, validator registration,
//! authorization, protocol eligibility, liability, or state transition. The
//! capped result does not compose delegation, bootstrap weight, decay,
//! penalties, active-set selection, proposer weight, or consensus authority.

use std::error::Error;
use std::fmt;

use naome_consensus::AgreementWeight;
use naome_economy::{NAO_ATOMS_PER_NAO, NaoAtoms};

/// Exact caller-supplied bond amount that meets the numeric validator floor.
pub const MINIMUM_VALIDATOR_BOND: NaoAtoms = NaoAtoms::new(10_000 * NAO_ATOMS_PER_NAO);

/// Maximum agreement-weight units supported by one caller-supplied bond atom.
pub const AGREEMENT_WEIGHT_UNITS_PER_BOND_ATOM: u128 = 20;

/// One caller-supplied bond amount that meets the exact numeric floor.
///
/// This value proves only the integer comparison performed by
/// [`Self::try_from_bond_atoms`]. It does not prove that the atoms exist in an
/// account, are escrowed, are offense-liable, or authorize a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FloorQualifiedValidatorBond {
    bond_atoms: NaoAtoms,
}

impl FloorQualifiedValidatorBond {
    /// Qualifies one caller-supplied atom amount against the numeric floor.
    pub const fn try_from_bond_atoms(
        bond_atoms: NaoAtoms,
    ) -> Result<Self, ValidatorBondFloorError> {
        if bond_atoms.atoms() < MINIMUM_VALIDATOR_BOND.atoms() {
            return Err(ValidatorBondFloorError::BelowMinimum {
                actual: bond_atoms,
                minimum: MINIMUM_VALIDATOR_BOND,
            });
        }

        Ok(Self { bond_atoms })
    }

    /// Returns the exact caller-supplied bond amount.
    pub const fn bond_atoms(self) -> NaoAtoms {
        self.bond_atoms
    }

    /// Caps caller-supplied requested agreement weight by this bond amount.
    ///
    /// The result is exactly `min(requested_weight, 20 * bond_atoms)` over
    /// mathematical integers. Saturating the supported weight at `u128::MAX`
    /// is exact because every representable requested weight is at most that
    /// value.
    pub const fn cap_requested_agreement_weight(
        self,
        requested_weight: AgreementWeight,
    ) -> AgreementWeight {
        let requested_units = requested_weight.units();
        let supported_units = self
            .bond_atoms
            .atoms()
            .saturating_mul(AGREEMENT_WEIGHT_UNITS_PER_BOND_ATOM);

        if requested_units <= supported_units {
            requested_weight
        } else {
            AgreementWeight::new(supported_units)
        }
    }
}

/// A numeric validator-bond floor qualification error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidatorBondFloorError {
    /// The caller-supplied atom amount is below the exact numeric floor.
    BelowMinimum { actual: NaoAtoms, minimum: NaoAtoms },
}

impl fmt::Display for ValidatorBondFloorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowMinimum { actual, minimum } => write!(
                formatter,
                "validator bond has {} atoms, below numeric minimum {}",
                actual.atoms(),
                minimum.atoms()
            ),
        }
    }
}

impl Error for ValidatorBondFloorError {}

#[cfg(test)]
mod tests;
