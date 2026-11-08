use super::*;
use crate::{Envelope, Graph, hex};
use naome_checker::diagnostics::{Failure, InputFormat, OperandRole};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofStep, StatementId};

#[test]
fn local_and_peer_certificate_errors_preserve_the_report_through_json_serialization() {
    let mut graph = Graph::default();
    let before = graph.content_root();
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
    let local_error = graph
        .author(&format!("00{}", hex(normal.canonical_bytes())))
        .unwrap_err();
    assert_eq!(
        local_error.diagnostic().unwrap().failure,
        Failure::ExpectedImplication {
            operand: OperandRole::Implication,
        }
    );
    assert!(!local_error.retryable() && !local_error.fatal());
    let local_json = serde_json::to_value(&local_error).unwrap();
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
    assert_eq!(binary_json["code"], u32::from(OperationCode::ProofCheck));
    assert_eq!(
        binary_json["diagnostic"]["failure"],
        local_json["diagnostic"]["failure"]
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
    assert_eq!(json["code"], u32::from(OperationCode::CertificateFormat));
    assert_eq!(
        json["format_error"]["input_digest"],
        naome_checker::diagnostics::Digest::of(&bytes).to_string()
    );
    assert_eq!(json["format_error"]["reason"]["code"], 0x002a_0004_u32);
    assert!(!error.fatal() && !error.retryable());
    let stored = error.storage();
    let stored_json = serde_json::to_value(&stored).unwrap();
    assert!(stored.fatal() && !stored.retryable());
    assert_eq!(
        stored_json["code"],
        u32::from(OperationCode::InvalidStoredRecord)
    );
    assert_eq!(stored_json["format_error"], json["format_error"]);
}

#[test]
fn checked_context_storage_cause_retains_its_native_code() {
    use naome_checker::ContextError;
    use naome_proof::ContextStorageFailure;

    let error = crate::Error::from(ContextError::Storage(ContextStorageFailure::Sqlite(Some(
        2067,
    ))));
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(value["code"], 0x0006_0013u32);
    assert_eq!(value["reason"], 1);
    assert_eq!(value["native_code"], 2067);
    assert_eq!(value["fatal"], true);
    assert_eq!(value["retryable"], false);
    assert!(value.get("message").is_none());
}

#[test]
fn formula_codec_failures_preserve_numeric_reason_and_context() {
    let error = Error::from(naome_foundation::FormulaCodecError::UnknownFormulaTag(42));
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(value["code"], u32::from(OperationCode::Formula));
    assert_eq!(value["formula"]["code"], 0x0028_0005_u32);
    assert_eq!(value["formula"]["tag"], 42);
    assert!(value["formula"].get("kind").is_none());
    let stored = serde_json::to_value(error.storage()).unwrap();
    assert_eq!(stored["cause_code"], u32::from(OperationCode::Formula));
    assert_eq!(stored["formula"], value["formula"]);
    assert_eq!(stored["fatal"], true);
}

#[test]
fn certificate_format_reasons_encode_domains_and_witnesses() {
    use naome_proof::ProofCertificateError;
    let limit = FormatFailure::from(&ProofCertificateError::TooManySteps {
        actual: 9,
        maximum: 8,
    });
    let value = serde_json::to_value(limit).unwrap();
    assert_eq!(value["code"], 0x002a_0002_u32);
    assert_eq!(value["resource"], 0x002b_0001_u32);
    assert_eq!(value["actual"], 9);
    assert_eq!(value["maximum"], 8);
    let tag = FormatFailure::from(&ProofCertificateError::UnknownZfcAxiomTag(42));
    let value = serde_json::to_value(tag).unwrap();
    assert_eq!(value["code"], 0x002a_0005_u32);
    assert_eq!(value["domain"], 0x002c_0002_u32);
    assert_eq!(value["tag"], 42);
    assert!(value.get("kind").is_none());
}
