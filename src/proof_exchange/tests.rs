use naome_foundation::ZfcAxiom;
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofId};

use super::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofExchangeWireError, ProofRequest,
    ProofResponse,
};
use crate::tests::axiom_bytes;

fn response(bytes: Vec<u8>) -> ProofResponse {
    ProofResponse::from_wire_bytes(bytes).unwrap()
}

#[test]
fn request_and_response_wire_contract_is_exact_and_allocation_preserving() {
    let mut request_bytes = [0_u8; PROOF_REQUEST_BYTES];
    for (index, byte) in request_bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    let request = ProofRequest::new(ProofId::from_bytes(request_bytes));
    assert_eq!(request.to_wire_bytes(), request_bytes);
    assert_eq!(
        ProofRequest::from_wire_bytes(&request_bytes).unwrap(),
        request
    );

    for actual in 0..PROOF_REQUEST_BYTES {
        assert_eq!(
            ProofRequest::from_wire_bytes(&request_bytes[..actual]),
            Err(ProofExchangeWireError::InvalidRequestLength {
                actual,
                expected: PROOF_REQUEST_BYTES,
            })
        );
    }
    let mut extended_request = request_bytes.to_vec();
    extended_request.push(0xff);
    assert_eq!(
        ProofRequest::from_wire_bytes(&extended_request),
        Err(ProofExchangeWireError::InvalidRequestLength {
            actual: PROOF_REQUEST_BYTES + 1,
            expected: PROOF_REQUEST_BYTES,
        })
    );

    let unavailable = response(Vec::new());
    assert!(unavailable.is_unavailable());
    assert!(unavailable.into_wire_bytes().is_empty());

    let proof_bytes = axiom_bytes(ZfcAxiom::Pairing);
    assert_eq!(proof_bytes, [0x00, 0x00, 0x00, 0x01, 0x10, 0x01]);
    let proof_pointer = proof_bytes.as_ptr();
    let found = response(proof_bytes);
    assert!(!found.is_unavailable());
    let round_trip = found.into_wire_bytes();
    assert_eq!(round_trip.as_ptr(), proof_pointer);
    assert_eq!(round_trip, [0x00, 0x00, 0x00, 0x01, 0x10, 0x01]);
}

#[test]
fn response_limit_is_the_certificate_limit_and_precedes_proof_parsing() {
    assert_eq!(PROOF_RESPONSE_MAX_BYTES, CERTIFICATE_MAX_BYTES);

    let maximum = vec![0x5a; PROOF_RESPONSE_MAX_BYTES];
    let pointer = maximum.as_ptr();
    let maximum = ProofResponse::from_wire_bytes(maximum).unwrap();
    let maximum = maximum.into_wire_bytes();
    assert_eq!(maximum.len(), PROOF_RESPONSE_MAX_BYTES);
    assert_eq!(maximum.as_ptr(), pointer);

    assert_eq!(
        ProofResponse::from_wire_bytes(vec![0; PROOF_RESPONSE_MAX_BYTES + 1]).unwrap_err(),
        ProofExchangeWireError::ResponseTooLong {
            actual: PROOF_RESPONSE_MAX_BYTES + 1,
            maximum: PROOF_RESPONSE_MAX_BYTES,
        }
    );
}
