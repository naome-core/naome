use naome_consensus::AgreementWeight;
use naome_economy::{NAO_ATOMS_PER_NAO, NaoAtoms};

use super::{
    AGREEMENT_WEIGHT_UNITS_PER_BOND_ATOM, FloorQualifiedValidatorBond, MINIMUM_VALIDATOR_BOND,
    ValidatorBondFloorError,
};

const REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM: u128 = 20;
const CONSTANT_BOND: FloorQualifiedValidatorBond =
    match FloorQualifiedValidatorBond::try_from_bond_atoms(MINIMUM_VALIDATOR_BOND) {
        Ok(bond) => bond,
        Err(_) => panic!("minimum validator bond must qualify"),
    };
const CONSTANT_BOND_ATOMS: NaoAtoms = CONSTANT_BOND.bond_atoms();
const CONSTANT_CAPPED_WEIGHT: AgreementWeight =
    CONSTANT_BOND.cap_requested_agreement_weight(AgreementWeight::new(u128::MAX));

#[test]
fn exact_numeric_floor_qualifies_without_escrow_authority() {
    assert_eq!(NAO_ATOMS_PER_NAO, 1_000_000_000);
    assert_eq!(MINIMUM_VALIDATOR_BOND.atoms(), 10_000_000_000_000);

    let below = NaoAtoms::new(MINIMUM_VALIDATOR_BOND.atoms() - 1);
    assert_eq!(
        FloorQualifiedValidatorBond::try_from_bond_atoms(below),
        Err(ValidatorBondFloorError::BelowMinimum {
            actual: below,
            minimum: MINIMUM_VALIDATOR_BOND,
        })
    );

    for bond_atoms in [
        MINIMUM_VALIDATOR_BOND,
        NaoAtoms::new(MINIMUM_VALIDATOR_BOND.atoms() + 1),
    ] {
        let bond = FloorQualifiedValidatorBond::try_from_bond_atoms(bond_atoms).unwrap();
        assert_eq!(bond.bond_atoms(), bond_atoms);
    }
}

#[test]
fn minimum_bond_caps_weight_at_exact_twenty_to_one_ratio() {
    assert_eq!(
        AGREEMENT_WEIGHT_UNITS_PER_BOND_ATOM,
        REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM
    );
    let bond = FloorQualifiedValidatorBond::try_from_bond_atoms(MINIMUM_VALIDATOR_BOND).unwrap();
    let cap = MINIMUM_VALIDATOR_BOND.atoms() * REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM;

    for (requested, expected) in [(0, 0), (cap - 1, cap - 1), (cap, cap), (cap + 1, cap)] {
        assert_eq!(
            bond.cap_requested_agreement_weight(AgreementWeight::new(requested)),
            AgreementWeight::new(expected)
        );
    }
}

#[test]
fn one_additional_bond_atom_adds_exactly_twenty_weight_units() {
    let minimum = FloorQualifiedValidatorBond::try_from_bond_atoms(MINIMUM_VALIDATOR_BOND).unwrap();
    let plus_one = FloorQualifiedValidatorBond::try_from_bond_atoms(NaoAtoms::new(
        MINIMUM_VALIDATOR_BOND.atoms() + 1,
    ))
    .unwrap();

    let minimum_cap = minimum
        .cap_requested_agreement_weight(AgreementWeight::new(u128::MAX))
        .units();
    let plus_one_cap = plus_one
        .cap_requested_agreement_weight(AgreementWeight::new(u128::MAX))
        .units();
    assert_eq!(
        plus_one_cap - minimum_cap,
        REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM
    );
}

#[test]
fn safe_range_matches_independent_direct_multiplication_oracle() {
    for additional_atoms in 0_u128..=128 {
        let bond_atoms = MINIMUM_VALIDATOR_BOND.atoms() + additional_atoms;
        let bond =
            FloorQualifiedValidatorBond::try_from_bond_atoms(NaoAtoms::new(bond_atoms)).unwrap();
        let direct_cap = bond_atoms
            .checked_mul(REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM)
            .unwrap();

        for requested in [0, 1, direct_cap - 1, direct_cap, direct_cap + 1, u128::MAX] {
            let expected = requested.min(direct_cap);
            assert_eq!(
                bond.cap_requested_agreement_weight(AgreementWeight::new(requested)),
                AgreementWeight::new(expected),
                "bond_atoms={bond_atoms}, requested={requested}"
            );
        }
    }
}

#[test]
fn near_maximum_bonds_cap_without_overflow() {
    let maximum = u128::MAX;
    let largest_insufficient_atoms = maximum / REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM;
    let first_sufficient_atoms = largest_insufficient_atoms + 1;

    let largest_insufficient =
        FloorQualifiedValidatorBond::try_from_bond_atoms(NaoAtoms::new(largest_insufficient_atoms))
            .unwrap();
    assert_eq!(
        largest_insufficient.cap_requested_agreement_weight(AgreementWeight::new(maximum)),
        AgreementWeight::new(largest_insufficient_atoms * REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM)
    );

    for bond_atoms in [first_sufficient_atoms, maximum] {
        let bond =
            FloorQualifiedValidatorBond::try_from_bond_atoms(NaoAtoms::new(bond_atoms)).unwrap();
        assert_eq!(
            bond.cap_requested_agreement_weight(AgreementWeight::new(maximum)),
            AgreementWeight::new(maximum)
        );
    }
}

#[test]
fn public_const_api_is_usable_at_compile_time() {
    assert_eq!(CONSTANT_BOND_ATOMS, MINIMUM_VALIDATOR_BOND);
    assert_eq!(
        CONSTANT_CAPPED_WEIGHT,
        AgreementWeight::new(MINIMUM_VALIDATOR_BOND.atoms() * REFERENCE_WEIGHT_UNITS_PER_BOND_ATOM)
    );
}
