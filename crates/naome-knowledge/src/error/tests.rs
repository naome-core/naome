use super::*;
use crate::{Envelope, Graph, hex};
use naome_checker::diagnostics::{Failure, InputFormat, OperandRole};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofStep, StatementId};

#[test]
fn source_and_certificate_api_errors_preserve_the_report_through_json_serialization() {
    let mut graph = Graph::default();
    let before = graph.content_root();
    let source = "goal=all(x,eq(x,x)) proof: a=refl(x) b=mp(a,a) return b";
    let error = graph.author(source).unwrap_err();
    assert_eq!(
        error.diagnostic().unwrap().failure,
        Failure::ExpectedImplication {
            operand: OperandRole::Implication
        }
    );
    let source_json = serde_json::to_value(&error).unwrap();
    assert_eq!(source_json["code"], "source.compile");
    assert_eq!(
        source_json["diagnostic"]["failure"]["code"],
        "mp.expected_implication"
    );
    assert!(source_json["source_diagnostic"]["operand_span"].is_object());
    assert!(!error.retryable() && !error.fatal());
    let v = FreeVariable::new(0);
    let statement = StatementId::of_canonical_formula(
        &Formula::for_all(v, Formula::equal(v, v))
            .encode_canonical()
            .unwrap(),
    )
    .unwrap();
    let normal = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: v },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    let envelope = Envelope {
        compatibility: hex(&crate::compatibility()),
        artifact_id: hex(crate::object::content_id(statement, normal.canonical_bytes()).as_bytes()),
        statement_id: Some(hex(statement.as_bytes())),
        payload: format!("00{}", hex(normal.canonical_bytes())),
        obligation_proof: None,
    };
    let error = graph
        .ingest(envelope, std::time::Instant::now())
        .unwrap_err();
    assert_eq!(
        error.diagnostic().unwrap().input.format,
        InputFormat::Certificate
    );
    let binary_json = serde_json::to_value(&error).unwrap();
    assert_eq!(binary_json["code"], "proof.check");
    assert_eq!(
        binary_json["diagnostic"]["failure"],
        source_json["diagnostic"]["failure"]
    );
    assert_eq!(graph.content_root(), before);
    assert_eq!(graph.accepted_count(), 0);
}

#[test]
fn inspection_errors_keep_their_typed_retry_requirements_in_json() {
    let error = Error::from(naome_checker::program::Error::Inspection(
        naome_checker::diagnostics::InspectionError::ReplayRequired {
            checked_before: 3,
            required_before: 9,
        },
    ));
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(json["inspection_error"]["code"], "replay_required");
    assert_eq!(json["inspection_error"]["checked_before"], 3);
    assert_eq!(json["inspection_error"]["required_before"], 9);
}

#[test]
fn malformed_certificate_bytes_and_owned_storage_keep_distinct_typed_outcomes() {
    let bytes = [0_u8];
    let v = FreeVariable::new(0);
    let statement = StatementId::of_canonical_formula(
        &Formula::for_all(v, Formula::equal(v, v))
            .encode_canonical()
            .unwrap(),
    )
    .unwrap();
    let envelope = Envelope {
        compatibility: hex(&crate::compatibility()),
        artifact_id: hex(crate::object::content_id(statement, &bytes).as_bytes()),
        statement_id: Some(hex(statement.as_bytes())),
        payload: format!("00{}", hex(&bytes)),
        obligation_proof: None,
    };
    let error = Graph::default()
        .ingest(envelope, std::time::Instant::now())
        .unwrap_err();
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(json["code"], "certificate.format");
    assert_eq!(
        json["format_error"]["input_digest"],
        naome_checker::diagnostics::Digest::of(&bytes).to_string()
    );
    assert_eq!(json["format_error"]["reason"]["kind"], "unexpected_end");
    assert!(!error.fatal() && !error.retryable());
    let stored = error.storage();
    let stored_json = serde_json::to_value(&stored).unwrap();
    assert!(stored.fatal() && !stored.retryable());
    assert_eq!(stored_json["code"], "storage.invalid_record");
    assert_eq!(stored_json["format_error"], json["format_error"]);
    let source_error = Error::from(
        naome_authoring::compile("goal=all(x,eq(x,x)) proof: a=refl(x) b=mp(a,a) return b")
            .unwrap_err(),
    )
    .storage();
    assert!(source_error.fatal());
    assert!(source_error.diagnostic().is_some());
    assert!(source_error.compile_diagnostic().is_some());
}
