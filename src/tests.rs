use naome_foundation::ZfcAxiom;
use naome_proof::{ProofCertificate, ProofStep};

pub(crate) fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec()
}
