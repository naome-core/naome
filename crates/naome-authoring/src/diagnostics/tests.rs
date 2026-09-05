use super::*;

#[test]
fn diagnostic_codes_and_source_positions_are_stable() {
    let proof_id = ProofId::from_bytes([0; ProofId::BYTE_LENGTH]);
    let errors = [
        CompileError::SourceTooLong {
            actual: 2,
            maximum: 1,
        },
        CompileError::Syntax {
            offset: 0,
            expected: "syntax",
        },
        CompileError::FoundationMismatch { offset: 0 },
        CompileError::DuplicateStep {
            offset: 0,
            name: "step".to_owned(),
        },
        CompileError::UnknownStep {
            offset: 0,
            name: "step".to_owned(),
        },
        CompileError::ReturnNotFinal { offset: 0 },
        CompileError::FormulaDepthLimitExceeded {
            offset: 0,
            maximum: FORMULA_MAX_DEPTH,
        },
        CompileError::Statement {
            offset: 0,
            source: FormulaCodecError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES,
            },
        },
        CompileError::Certificate {
            offset: 0,
            source: ProofCertificateError::EmptyCertificate,
        },
        CompileError::Check {
            span: SourceSpan::point(0),
            source: Box::new(CheckError::UnknownProofReference { step: 0, proof_id }),
        },
        CompileError::StatementMismatch {
            span: SourceSpan::point(0),
        },
        CompileError::DuplicateFormulaBinding {
            offset: 0,
            name: "formula".to_owned(),
        },
        CompileError::UnknownFormulaBinding {
            offset: 0,
            name: "formula".to_owned(),
        },
        CompileError::FormulaBindingNodeLimitExceeded {
            offset: 0,
            maximum: FORMULA_BINDING_MAX_NODES,
        },
    ];
    assert_eq!(
        errors
            .iter()
            .map(|error| error.diagnostic_code().as_str())
            .collect::<Vec<_>>(),
        vec![
            "NAO0001", "NAO0002", "NAO0003", "NAO0004", "NAO0005", "NAO0006", "NAO0007", "NAO0008",
            "NAO0009", "NAO0010", "NAO0011", "NAO0012", "NAO0013", "NAO0014",
        ]
    );
    assert_eq!(errors[0].source_offset(), None);
    assert_eq!(errors[1].source_offset(), Some(0));

    let source = "αβx\r\nq\rr\tz\n";
    assert_eq!(
        source_position(source, 4),
        Some(SourcePosition { line: 1, column: 3 })
    );
    assert_eq!(
        source_position(source, source.find('q').unwrap()),
        Some(SourcePosition { line: 2, column: 1 })
    );
    assert_eq!(
        source_position(source, source.find('r').unwrap()),
        Some(SourcePosition { line: 3, column: 1 })
    );
    assert_eq!(
        source_position(source, source.find('z').unwrap()),
        Some(SourcePosition { line: 3, column: 3 })
    );
    assert_eq!(
        source_position(source, source.len()),
        Some(SourcePosition { line: 4, column: 1 })
    );
}
