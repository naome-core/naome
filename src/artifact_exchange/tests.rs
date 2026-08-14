use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_proof::{
    ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate,
    ProofCertificate, ProofStep,
};

use super::{
    ARTIFACT_REQUEST_BYTES, ARTIFACT_RESPONSE_MAX_BYTES, ArtifactExchangeWireError,
    ArtifactRequest, ArtifactResponse,
};

fn response(bytes: Vec<u8>) -> ArtifactResponse {
    ArtifactResponse::from_wire_bytes(bytes).unwrap()
}

#[test]
fn request_is_one_exact_artifact_id() {
    let mut request_bytes = [0_u8; ARTIFACT_REQUEST_BYTES];
    for (index, byte) in request_bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    let request = ArtifactRequest::new(ArtifactId::from_bytes(request_bytes));
    assert_eq!(request.to_wire_bytes(), request_bytes);
    assert_eq!(
        ArtifactRequest::from_wire_bytes(&request_bytes).unwrap(),
        request
    );

    for actual in 0..ARTIFACT_REQUEST_BYTES {
        assert_eq!(
            ArtifactRequest::from_wire_bytes(&request_bytes[..actual]),
            Err(ArtifactExchangeWireError::InvalidRequestLength {
                actual,
                expected: ARTIFACT_REQUEST_BYTES,
            })
        );
    }
    let mut extended = request_bytes.to_vec();
    extended.push(0xff);
    assert_eq!(
        ArtifactRequest::from_wire_bytes(&extended),
        Err(ArtifactExchangeWireError::InvalidRequestLength {
            actual: ARTIFACT_REQUEST_BYTES + 1,
            expected: ARTIFACT_REQUEST_BYTES,
        })
    );
}

#[test]
fn unavailable_proof_and_definition_payloads_preserve_exact_wire_allocations() {
    let unavailable = response(Vec::new());
    assert!(unavailable.is_unavailable());
    assert!(unavailable.into_wire_bytes().is_empty());

    let proof = ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)]).unwrap();
    let definition = DefinitionCertificate::relation(
        1,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    for payload in [
        ArtifactPayload::Proof(proof),
        ArtifactPayload::Definition(definition),
    ] {
        let bytes = payload.to_canonical_bytes();
        let pointer = bytes.as_ptr();
        let found = response(bytes);
        assert!(!found.is_unavailable());
        let round_trip = found.into_wire_bytes();
        assert_eq!(round_trip.as_ptr(), pointer);
        assert_eq!(
            ArtifactPayload::from_canonical_bytes(&round_trip).unwrap(),
            payload
        );
    }
}

#[test]
fn response_limit_precedes_tagged_payload_parsing() {
    assert_eq!(ARTIFACT_RESPONSE_MAX_BYTES, ARTIFACT_PAYLOAD_MAX_BYTES);

    let maximum = vec![0x5a; ARTIFACT_RESPONSE_MAX_BYTES];
    let pointer = maximum.as_ptr();
    let maximum = ArtifactResponse::from_wire_bytes(maximum).unwrap();
    let maximum = maximum.into_wire_bytes();
    assert_eq!(maximum.len(), ARTIFACT_RESPONSE_MAX_BYTES);
    assert_eq!(maximum.as_ptr(), pointer);

    assert_eq!(
        ArtifactResponse::from_wire_bytes(vec![0; ARTIFACT_RESPONSE_MAX_BYTES + 1]).unwrap_err(),
        ArtifactExchangeWireError::ResponseTooLong {
            actual: ARTIFACT_RESPONSE_MAX_BYTES + 1,
            maximum: ARTIFACT_RESPONSE_MAX_BYTES,
        }
    );
}
