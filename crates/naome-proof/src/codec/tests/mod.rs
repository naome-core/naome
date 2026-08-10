use super::{
    Cursor, EQUALITY_REFLEXIVITY, FREGE, MODUS_PONENS, PROOF_REFERENCE, SIMPLIFICATION,
    VACUOUS_UNIVERSAL, ZFC_AXIOM, decode_step, encode_step, encode_step_with_formula_budget,
};
use crate::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS, ProofCertificate,
    ProofCertificateError, ProofId, ProofStep,
};
use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

mod golden;
mod limits;

fn framed_formula(formula: &[u8]) -> Vec<u8> {
    let mut framed = Vec::from(u32::try_from(formula.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(formula);
    framed
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    bytes
}

fn half_limit_formula() -> Formula {
    let variable = FreeVariable::new(1);
    let mut formula = Formula::equal(variable, variable);
    for _ in 0..14 {
        formula = Formula::implies(formula.clone(), formula);
    }
    Formula::negate(formula)
}

fn raw_formula_step(tag: u8, formulas: &[&[u8]]) -> Vec<u8> {
    let mut step = vec![tag];
    for formula in formulas {
        step.extend_from_slice(&u32::try_from(formula.len()).unwrap().to_be_bytes());
        step.extend_from_slice(formula);
    }
    step
}

fn raw_certificate(steps: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u32::try_from(steps.len()).unwrap().to_be_bytes());
    for step in steps {
        bytes.extend_from_slice(step);
    }
    bytes
}

fn assert_step_bytes(step: &ProofStep, expected: Vec<u8>) {
    let mut actual = Vec::new();
    encode_step(step, &mut actual).unwrap();
    assert_eq!(actual, expected);
}
