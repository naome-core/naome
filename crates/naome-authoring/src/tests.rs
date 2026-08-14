use naome_checker::{ProofState, ProofStateError, normalize_and_check};
use naome_foundation::{Replacement, SchemaError, Separation};
use naome_proof::{DerivationId, ProofCertificate, ProofId, StatementId};

use super::*;

const SOURCE: &str = r#"
# presentation-only comment
foundation "naome:zfc";
theorem equality_is_reflexive {
  statement (forall x (equal x x));
  proof {
    step reflexive = (equality-reflexivity x);
    step universally_reflexive = (generalization reflexive x);
    result universally_reflexive;
  }
}
"#;

const NORMAL_PROOF: &[u8] = &[
    0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

const SELF_EQUALITY_PROOF_ID_HEX: &str =
    "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const SELF_EQUALITY_STATEMENT_ID_HEX: &str =
    "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19";
const SELF_EQUALITY_DERIVATION_ID_HEX: &str =
    "59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb";
const SELF_EQUALITY_REFERENCE_PROOF_ID_HEX: &str =
    "bfd427b447e1514686cfa31b0b5aa1dd5036464cd8c5d73d0c3112cb46b0519b";
const SELF_EQUALITY_REFERENCE_PROOF_HEX: &str =
    "0000000130c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";

const QUANTIFIER_PROOF_ID_HEX: &str =
    "6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720";

const PROOF_ID_EXPECTED: &str = "a 64-digit lowercase hexadecimal ProofId";

fn proof_reference_source(proof_id: &str) -> String {
    format!(
        "foundation \"naome:zfc\"; theorem cited {{ statement (forall x (equal x x)); proof {{ step known = (proof-reference {proof_id}); result known; }} }}"
    )
}

fn checked_state(source: &str) -> (ProofState, CompiledProof) {
    let compiled = compile(source).unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    let checked = normalize_and_check(certificate).unwrap();
    let mut state = ProofState::new();
    state.register(checked).unwrap();
    (state, compiled)
}

const IMPLICATION_SOURCE: &str = include_str!("../../../examples/implication-identity.nao");

const QUANTIFIER_SOURCE: &str = include_str!("../../../examples/quantifier-instantiation.nao");

const EQUALITY_SUBSTITUTION_SOURCE: &str =
    include_str!("../../../examples/equality-substitution.nao");

const EXTENSIONALITY_SOURCE: &str = include_str!("../../../examples/extensionality.nao");

const SEPARATION_SOURCE: &str = include_str!("../../../examples/separation.nao");

const REPLACEMENT_SOURCE: &str = include_str!("../../../examples/replacement.nao");

const IMPLICATION_PROOF_HEX: &str = "00000006000000000b00000000000000000000000000000b0000000000000000000000000000000b0000000000000000000000000000170300000000000000000000000000000000000000000000010000000b00000000000000000000000000001703000000000000000000000000000000000000000000000000000b0000000000000000000000200000000100000002200000000000000003210000000400000000";

const QUANTIFIER_PROOF_HEX: &str = "0000000506000000002100000000000000000500000000000000010000000b0000000000000000000000200000000100000002210000000300000001";

const CLASSICAL_CONTRAPOSITION_PROOF_HEX: &str =
    "00000001020000000c0400010000000001000000000000000c040101000000000100000000";

const EQUALITY_SUBSTITUTION_PROOF_HEX: &str = "000000040700000000000000010000000b0100000000000000000002210000000000000002210000000100000001210000000200000000";

const EXTENSIONALITY_PROOF_HEX: &str = "000000011000";

const SEPARATION_PROOF_HEX: &str =
    "00000001110000000b01000000000000000000010000000000000002000000030000000100000001";

const REPLACEMENT_PROOF_HEX: &str =
    "00000001120000000b0000000000000000000001000000000000000100000002000000030000000400000000";

#[test]
fn every_derived_formula_lowers_to_the_existing_primitive_structure() {
    let pairs = [
        (
            "(and (equal x x) (member y z))",
            "(not (implies (equal x x) (not (member y z))))",
        ),
        (
            "(or (equal x x) (member y z))",
            "(implies (not (equal x x)) (member y z))",
        ),
        (
            "(iff (equal x x) (member y z))",
            "(not (implies (implies (equal x x) (member y z)) (not (implies (member y z) (equal x x)))))",
        ),
        (
            "(exists x (member x set))",
            "(not (forall x (not (member x set))))",
        ),
        ("(not-equal x y)", "(not (equal x y))"),
    ];

    for (derived, primitive) in pairs {
        let derived = parse_formula(derived, FormulaContext::Statement).unwrap();
        let primitive = parse_formula(primitive, FormulaContext::Statement).unwrap();
        assert_eq!(derived.formula, primitive.formula);
        assert_eq!(derived.expanded_nodes, primitive.expanded_nodes);
        assert_eq!(derived.expanded_depth, primitive.expanded_depth);
    }
}

#[test]
fn derived_and_primitive_sources_have_exactly_the_same_checked_artifact() {
    const A: &str = "(forall x (not-equal x x))";
    const B: &str = "(exists y (and (equal y y) (or (member y y) (iff (equal y y) (member y y)))))";
    const PRIMITIVE_A: &str = "(forall x (not (equal x x)))";
    const PRIMITIVE_B: &str = "(not (forall y (not (not (implies (equal y y) (not (implies (not (member y y)) (not (implies (implies (equal y y) (member y y)) (not (implies (member y y) (equal y y))))))))))))";
    let source = |a: &str, b: &str| {
        format!(
            "foundation \"naome:zfc\"; theorem t {{ statement (implies {a} (implies {b} {a})); proof {{ step result = (simplification {a} {b}); result result; }} }}"
        )
    };
    assert_eq!(
        parse_formula(A, FormulaContext::Statement).unwrap().formula,
        parse_formula(PRIMITIVE_A, FormulaContext::Statement)
            .unwrap()
            .formula
    );
    assert_eq!(
        parse_formula(B, FormulaContext::Statement).unwrap().formula,
        parse_formula(PRIMITIVE_B, FormulaContext::Statement)
            .unwrap()
            .formula
    );
    assert_eq!(
        compile(&source(A, B)).unwrap(),
        compile(&source(PRIMITIVE_A, PRIMITIVE_B)).unwrap()
    );
}

#[test]
fn derived_binary_operands_retain_source_order_and_exists_binds_capture_free() {
    let left = parse_formula(
        "(and (equal left left) (member right set))",
        FormulaContext::Certificate,
    )
    .unwrap();
    let swapped = parse_formula(
        "(and (member right set) (equal left left))",
        FormulaContext::Certificate,
    )
    .unwrap();
    assert_ne!(left.formula, swapped.formula);

    let exists = parse_formula(
        "(exists x (and (member x set) (forall x (member x x))))",
        FormulaContext::Certificate,
    )
    .unwrap();
    let x = FreeVariable::new(0);
    let set = FreeVariable::new(1);
    assert_eq!(
        exists.formula,
        Formula::exists(
            x,
            Formula::conjunction(
                Formula::member(x, set),
                Formula::for_all(x, Formula::member(x, x)),
            ),
        )
    );
}

#[test]
fn malformed_derived_formulas_fail_in_left_to_right_operand_order() {
    for (source, expected) in [
        ("(and broken (equal x x))", "`(`"),
        ("(and (equal x x) broken)", "`(`"),
        ("(or (equal x x))", "`(`"),
        ("(iff (equal x x) (equal y y) extra)", "`)`"),
        ("(exists 1bad (equal x x))", "a name"),
        ("(not-equal x)", "a name"),
    ] {
        assert!(matches!(
            parse_formula(source, FormulaContext::Statement),
            Err(CompileError::Syntax { expected: actual, .. }) if actual == expected
        ));
    }

    let mut prefix = String::new();
    for _ in 0..FORMULA_MAX_DEPTH - 1 {
        prefix.push_str("(not ");
    }
    let malformed = format!(
        "{prefix}(exists 1bad (equal x x)){}",
        ")".repeat(FORMULA_MAX_DEPTH as usize - 1)
    );
    assert!(matches!(
        parse_formula(&malformed, FormulaContext::Statement),
        Err(CompileError::Syntax {
            expected: "a name",
            ..
        })
    ));
}

#[test]
fn derived_formula_expansion_charges_exact_statement_and_certificate_node_limits() {
    const IFF: &str = "(iff (equal x x) (equal y y))";
    let expanded_nodes = 9;
    for (context, maximum) in [
        (FormulaContext::Statement, FORMULA_MAX_NODES),
        (FormulaContext::Certificate, CERTIFICATE_MAX_FORMULA_NODES),
    ] {
        let mut parser = Parser::new(IFF);
        match context {
            FormulaContext::Statement => parser.statement_nodes = maximum - expanded_nodes,
            FormulaContext::Certificate => {
                parser.certificate_formula_nodes = maximum - expanded_nodes
            }
        }
        let parsed = parser.parsed_formula(1, context).unwrap();
        assert_eq!(parsed.expanded_nodes, expanded_nodes);
        assert_eq!(
            match context {
                FormulaContext::Statement => parser.statement_nodes,
                FormulaContext::Certificate => parser.certificate_formula_nodes,
            },
            maximum
        );

        let mut parser = Parser::new(IFF);
        match context {
            FormulaContext::Statement => parser.statement_nodes = maximum - expanded_nodes + 1,
            FormulaContext::Certificate => {
                parser.certificate_formula_nodes = maximum - expanded_nodes + 1
            }
        }
        assert!(match (context, parser.parsed_formula(1, context)) {
            (
                FormulaContext::Statement,
                Err(CompileError::Statement {
                    source: FormulaCodecError::NodeLimitExceeded { maximum },
                }),
            ) => maximum == FORMULA_MAX_NODES,
            (
                FormulaContext::Certificate,
                Err(CompileError::Certificate {
                    source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                }),
            ) => maximum == CERTIFICATE_MAX_FORMULA_NODES,
            _ => false,
        });
    }
}

#[test]
fn derived_formula_expanded_depth_has_an_exact_boundary() {
    let wrapped = |wrappers: u32, body: &str| {
        format!(
            "{}{}{}",
            "(not ".repeat(wrappers as usize),
            body,
            ")".repeat(wrappers as usize)
        )
    };
    let iff = "(iff (equal x x) (equal y y))";
    let exists = "(exists x (equal x x))";

    assert!(
        parse_formula(
            &wrapped(FORMULA_MAX_DEPTH - 5, iff),
            FormulaContext::Statement
        )
        .is_ok()
    );
    assert!(
        parse_formula(
            &wrapped(FORMULA_MAX_DEPTH - 4, exists),
            FormulaContext::Statement
        )
        .is_ok()
    );
    for (wrappers, body, operator) in [
        (FORMULA_MAX_DEPTH - 4, iff, "iff"),
        (FORMULA_MAX_DEPTH - 3, exists, "exists"),
    ] {
        let source = wrapped(wrappers, body);
        let expected_offset = source.find(operator).unwrap();
        assert!(matches!(
            parse_formula(&source, FormulaContext::Statement),
            Err(CompileError::FormulaDepthLimitExceeded { offset, maximum })
                if offset == expected_offset && maximum == FORMULA_MAX_DEPTH
        ));
    }
}

#[test]
fn proof_reference_lowers_to_the_exact_checked_identity_vector_without_mutating_state() {
    let (state, direct) = checked_state(SOURCE);
    let source_proof_id = ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX));
    let source_derivation_id = DerivationId::from_bytes(hex32(SELF_EQUALITY_DERIVATION_ID_HEX));
    let reference =
        compile_with_state(&proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX), &state).unwrap();

    assert_eq!(
        reference.statement_id(),
        StatementId::from_bytes(hex32(SELF_EQUALITY_STATEMENT_ID_HEX))
    );
    assert_eq!(reference.statement_id(), direct.statement_id());
    assert_eq!(reference.derivation_id(), source_derivation_id);
    assert_eq!(reference.derivation_id(), direct.derivation_id());
    assert_eq!(
        reference.proof_id(),
        ProofId::from_bytes(hex32(SELF_EQUALITY_REFERENCE_PROOF_ID_HEX))
    );
    assert_ne!(reference.proof_id(), direct.proof_id());
    assert_eq!(
        reference.canonical_proof_bytes(),
        hex_bytes(SELF_EQUALITY_REFERENCE_PROOF_HEX)
    );

    let decoded =
        ProofCertificate::from_canonical_bytes(reference.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::ProofReference {
            proof_id: source_proof_id,
        }]
    );
    assert!(state.contains_proof(source_proof_id));
    assert!(!state.contains_proof(reference.proof_id()));
}

#[test]
fn referenced_theorem_participates_in_inference_and_remains_dependency_closed() {
    let monolithic = r#"foundation "naome:zfc"; theorem nested {
      statement (forall y (forall x (equal x x)));
      proof {
        step reflexive = (equality-reflexivity x);
        step for_x = (generalization reflexive x);
        step for_y = (generalization for_x y);
        result for_y;
      }
    }"#;
    let referenced = format!(
        "foundation \"naome:zfc\"; theorem nested {{ statement (forall y (forall x (equal x x))); proof {{ step known = (proof-reference {SELF_EQUALITY_PROOF_ID_HEX}); step for_y = (generalization known y); result for_y; }} }}"
    );
    let (mut state, _) = checked_state(SOURCE);
    let inline = compile(monolithic).unwrap();
    let cited = compile_with_state(&referenced, &state).unwrap();

    assert_eq!(cited.statement_id(), inline.statement_id());
    assert_eq!(cited.derivation_id(), inline.derivation_id());
    assert_ne!(cited.proof_id(), inline.proof_id());
    assert_ne!(
        cited.canonical_proof_bytes(),
        inline.canonical_proof_bytes()
    );

    let certificate =
        ProofCertificate::from_canonical_bytes(cited.canonical_proof_bytes()).unwrap();
    let checked = naome_checker::normalize_and_check_with_state(certificate, &state).unwrap();
    let cited_id = checked.proof_id();
    state.register(checked).unwrap();
    assert!(state.contains_proof(ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX))));
    assert!(state.contains_proof(cited_id));
}

#[test]
fn proof_reference_requires_the_exact_id_in_the_supplied_state() {
    let reference = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let expected = || CompileError::Check {
        source: CheckError::UnknownProofReference {
            step: 0,
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        },
    };

    assert_eq!(compile(&reference), Err(expected()));
    assert_eq!(
        compile_with_state(&reference, &ProofState::new()),
        Err(expected())
    );

    let (wrong_statement_state, _) = checked_state(EXTENSIONALITY_SOURCE);
    assert_eq!(
        compile_with_state(&reference, &wrong_statement_state),
        Err(expected())
    );

    // This state contains a different proof of the exact same statement. A
    // StatementId or mathematical conclusion is not an alias for ProofId.
    let (same_statement_state, _) = checked_state(QUANTIFIER_SOURCE);
    assert!(
        same_statement_state.contains_proof(ProofId::from_bytes(hex32(QUANTIFIER_PROOF_ID_HEX)))
    );
    assert_eq!(
        compile_with_state(&reference, &same_statement_state),
        Err(expected())
    );

    let (exact_state, _) = checked_state(SOURCE);
    assert!(compile_with_state(&reference, &exact_state).is_ok());
}

#[test]
fn proof_reference_is_identity_neutral_only_for_presentation_changes() {
    let (state, _) = checked_state(SOURCE);
    let baseline =
        compile_with_state(&proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX), &state).unwrap();
    let renamed = format!(
        "# presentation only\nfoundation \"naome:zfc\"; theorem renamed {{ statement (forall value (equal value value)); proof {{ step imported_theorem = (proof-reference {SELF_EQUALITY_PROOF_ID_HEX}); result imported_theorem; }} }}"
    );
    assert_eq!(compile_with_state(&renamed, &state).unwrap(), baseline);

    for alias in [
        SELF_EQUALITY_STATEMENT_ID_HEX,
        SELF_EQUALITY_DERIVATION_ID_HEX,
    ] {
        let alias_id = ProofId::from_bytes(hex32(alias));
        assert_eq!(
            compile_with_state(&proof_reference_source(alias), &state),
            Err(CompileError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: alias_id,
                },
            })
        );
    }

    let reference =
        compile_with_state(&proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX), &state).unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(reference.canonical_proof_bytes()).unwrap();
    let checked = naome_checker::normalize_and_check_with_state(certificate, &state).unwrap();
    let alias_id = checked.proof_id();
    assert_eq!(
        ProofState::new().register(checked),
        Err(ProofStateError::MissingProofDependency {
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        })
    );

    let certificate =
        ProofCertificate::from_canonical_bytes(reference.canonical_proof_bytes()).unwrap();
    let checked = naome_checker::normalize_and_check_with_state(certificate, &state).unwrap();
    let mut target = state;
    assert_eq!(
        target.register(checked),
        Err(ProofStateError::DuplicateDerivation {
            derivation_id: DerivationId::from_bytes(hex32(SELF_EQUALITY_DERIVATION_ID_HEX)),
        })
    );
    assert!(!target.contains_proof(alias_id));
}

#[test]
fn normalization_prunes_unreachable_references_after_complete_source_parsing() {
    let unknown = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let unreachable = SOURCE.replace(
        "step reflexive =",
        &format!("step unavailable = (proof-reference {unknown});\n    step reflexive ="),
    );
    assert_eq!(compile(&unreachable).unwrap(), compile(SOURCE).unwrap());

    let malformed = unreachable.replace(unknown, &unknown[..63]);
    let token_offset = malformed.find(&unknown[..63]).unwrap();
    assert_eq!(
        compile(&malformed),
        Err(CompileError::Syntax {
            offset: token_offset,
            expected: PROOF_ID_EXPECTED,
        })
    );
}

#[test]
fn proof_reference_hex_is_exact_lowercase_and_reports_precise_offsets() {
    let valid = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let token_offset = valid.find(SELF_EQUALITY_PROOF_ID_HEX).unwrap();
    assert!(matches!(
        parse_step(&format!("(proof-reference {SELF_EQUALITY_PROOF_ID_HEX})")),
        Ok(ProofStep::ProofReference { proof_id })
            if proof_id == ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX))
    ));
    assert!(matches!(
        parse_step(&format!(
            "(proof-reference # before\n {SELF_EQUALITY_PROOF_ID_HEX} # after\n)"
        )),
        Ok(ProofStep::ProofReference { .. })
    ));

    for malformed in [
        &SELF_EQUALITY_PROOF_ID_HEX[..63],
        "0x17c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7g",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7-",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7_",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7é",
    ] {
        let source = proof_reference_source(malformed);
        let start = source.find(malformed).unwrap();
        let first_invalid = malformed
            .bytes()
            .position(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte));
        let expected_offset = start + first_invalid.unwrap_or(0);
        assert_eq!(
            compile(&source),
            Err(CompileError::Syntax {
                offset: expected_offset,
                expected: PROOF_ID_EXPECTED,
            }),
            "misreported {malformed:?}"
        );
    }

    for (index, _) in SELF_EQUALITY_PROOF_ID_HEX
        .bytes()
        .enumerate()
        .filter(|(_, byte)| byte.is_ascii_alphabetic())
    {
        let mut uppercase = SELF_EQUALITY_PROOF_ID_HEX.as_bytes().to_vec();
        uppercase[index].make_ascii_uppercase();
        let uppercase = String::from_utf8(uppercase).unwrap();
        let source = proof_reference_source(&uppercase);
        assert_eq!(
            compile(&source),
            Err(CompileError::Syntax {
                offset: token_offset + index,
                expected: PROOF_ID_EXPECTED,
            })
        );
    }

    let overlong = format!("{SELF_EQUALITY_PROOF_ID_HEX}0");
    let source = proof_reference_source(&overlong);
    assert_eq!(
        compile(&source),
        Err(CompileError::Syntax {
            offset: token_offset + 64,
            expected: "`)`",
        })
    );
}

#[test]
fn complete_parsing_precedes_reachable_proof_reference_resolution_and_statement_matching() {
    let base = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let duplicate = base.replace(
        "result known;",
        "step known = (proof-reference ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff); result known;",
    );
    assert!(matches!(
        compile(&duplicate),
        Err(CompileError::DuplicateStep { name, .. }) if name == "known"
    ));

    let trailing = format!("{base} trailing");
    assert!(matches!(
        compile(&trailing),
        Err(CompileError::Syntax {
            expected: "end of source",
            ..
        })
    ));

    let mismatch = base.replace("(forall x (equal x x))", "(forall x (member x x))");
    assert!(matches!(
        compile(&mismatch),
        Err(CompileError::Check {
            source: CheckError::UnknownProofReference { .. }
        })
    ));
    let (state, _) = checked_state(SOURCE);
    assert_eq!(
        compile_with_state(&mismatch, &state),
        Err(CompileError::StatementMismatch)
    );
}

#[test]
fn extensionality_lowers_to_the_exact_checked_identity_vector() {
    let proof = compile(EXTENSIONALITY_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "d5badb94fde79367c1ee93516c9260d031335c23502e3fcf36513ac768cc9db9"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "5507c036519883b871a080036e5e9a5332784501f1982e17e4f9a363b7369b9c"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(EXTENSIONALITY_PROOF_HEX)
    );

    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::ZfcAxiom(ZfcAxiom::Extensionality)]
    );
}

#[test]
fn every_fixed_zfc_axiom_selector_maps_to_its_exact_variant() {
    for (selector, expected) in [
        ("extensionality", ZfcAxiom::Extensionality),
        ("pairing", ZfcAxiom::Pairing),
        ("union", ZfcAxiom::Union),
        ("power-set", ZfcAxiom::PowerSet),
        ("infinity", ZfcAxiom::Infinity),
        ("foundation", ZfcAxiom::Foundation),
        ("choice", ZfcAxiom::Choice),
    ] {
        let mut parser = Parser::new(selector);
        assert_eq!(parser.zfc_axiom(), Ok(expected));
        assert_eq!(parser.end(), Ok(()));
    }
}

#[test]
fn fixed_zfc_axiom_selector_is_exact_case_sensitive_syntax() {
    for selector in [
        "unknown",
        "Extensionality",
        "power_set",
        "extensionality-extra",
        "zfc-1",
        "0",
        "",
    ] {
        let source = EXTENSIONALITY_SOURCE.replace(
            "(zfc-axiom extensionality)",
            &format!("(zfc-axiom {selector})"),
        );
        let offset = source
            .find("(zfc-axiom ")
            .expect("the mutated source contains the rule")
            + "(zfc-axiom ".len();
        assert_eq!(
            compile(&source),
            Err(CompileError::Syntax {
                offset,
                expected: "a fixed ZFC axiom",
            }),
            "accepted or misreported selector {selector:?}"
        );
    }

    let extra_operand = EXTENSIONALITY_SOURCE.replace(
        "(zfc-axiom extensionality)",
        "(zfc-axiom extensionality pairing)",
    );
    let pairing_offset = extra_operand
        .find("extensionality pairing")
        .expect("the mutated source contains the extra operand")
        + "extensionality ".len();
    assert_eq!(
        compile(&extra_operand),
        Err(CompileError::Syntax {
            offset: pairing_offset,
            expected: "`)`",
        })
    );
}

#[test]
fn changing_the_fixed_axiom_changes_the_checked_statement() {
    let pairing =
        EXTENSIONALITY_SOURCE.replace("(zfc-axiom extensionality)", "(zfc-axiom pairing)");
    assert_eq!(compile(&pairing), Err(CompileError::StatementMismatch));
}

#[test]
fn fixed_zfc_axiom_presentation_is_identity_neutral() {
    let renamed = r#"# all names and layout are presentation-only
      foundation "naome:zfc"; theorem renamed { statement
      (forall first (forall second (implies (forall witness (not (implies
        (implies (member witness first) (member witness second))
        (not (implies (member witness second) (member witness first))))))
        (equal first second)))); proof {
      step result_step = (zfc-axiom extensionality); result result_step; } }"#;
    assert_eq!(
        compile(EXTENSIONALITY_SOURCE).unwrap(),
        compile(renamed).unwrap()
    );
}

#[test]
fn separation_lowers_to_the_exact_checked_identity_vector() {
    let proof = compile(SEPARATION_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "cdc8f561c1e6d36cb437da9cfce5f97ab9079f5985f769c02c67ab2ff803f9a3"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "073ae5f13c159cda79b6fe31ed033eb8bb1b79ffcd21fa617adc5aea139408a6"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "426fcca7bbf116adebfa819e0eaf7c465c0215d3b367d5446c3882b1f1a7697c"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(SEPARATION_PROOF_HEX)
    );

    let element = FreeVariable::new(0);
    let parameter = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::Separation(Separation {
            predicate: Formula::member(element, parameter),
            element,
            source,
            result,
            parameters: vec![parameter],
        })]
    );
}

#[test]
fn replacement_lowers_to_the_exact_checked_identity_vector() {
    let proof = compile(REPLACEMENT_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "4d12c8f960638ff317e561e8861808875f18dfd22910c38712e05112e26724f5"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "72d5c8f81af4a2bcbe1eb7ed9fc1963ecbc1fedf91edf20d85f55c84051c93ec"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "7c5a06a3e764c6b6e372334645050bd314f8a7e64c96633e3d3aff90ca2bd156"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(REPLACEMENT_PROOF_HEX)
    );

    let input = FreeVariable::new(0);
    let output = FreeVariable::new(1);
    let uniqueness_witness = FreeVariable::new(2);
    let source = FreeVariable::new(3);
    let result = FreeVariable::new(4);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::Replacement(Replacement {
            predicate: Formula::equal(input, output),
            input,
            output,
            uniqueness_witness,
            source,
            result,
            parameters: Vec::new(),
        })]
    );
}

#[test]
fn schema_presentation_renaming_preserves_every_identity() {
    let renamed_separation = SEPARATION_SOURCE
        .replace("intersection", "selection")
        .replace("filter", "criterion")
        .replace("source", "domain")
        .replace("element", "candidate");
    assert_eq!(
        compile(SEPARATION_SOURCE).unwrap(),
        compile(&renamed_separation).unwrap()
    );

    let renamed_replacement = REPLACEMENT_SOURCE
        .replace("image", "mapping")
        .replace("input", "argument")
        .replace("output", "value")
        .replace("witness", "alternate")
        .replace("source", "domain");
    assert_eq!(
        compile(REPLACEMENT_SOURCE).unwrap(),
        compile(&renamed_replacement).unwrap()
    );
}

#[test]
fn schema_source_order_maps_exactly_and_parameter_order_is_semantic() {
    let separation = parse_step(
        "(separation (implies (member element source) (equal first second)) element source result (parameters first second))",
    )
    .unwrap();
    assert_eq!(
        separation,
        ProofStep::Separation(Separation {
            predicate: Formula::implies(
                Formula::member(FreeVariable::new(0), FreeVariable::new(1)),
                Formula::equal(FreeVariable::new(2), FreeVariable::new(3)),
            ),
            element: FreeVariable::new(0),
            source: FreeVariable::new(1),
            result: FreeVariable::new(4),
            parameters: vec![FreeVariable::new(2), FreeVariable::new(3)],
        })
    );

    let replacement = parse_step(
        "(replacement (implies (equal input output) (member input parameter)) input output witness source result (parameters parameter unused))",
    )
    .unwrap();
    assert_eq!(
        replacement,
        ProofStep::Replacement(Replacement {
            predicate: Formula::implies(
                Formula::equal(FreeVariable::new(0), FreeVariable::new(1)),
                Formula::member(FreeVariable::new(0), FreeVariable::new(2)),
            ),
            input: FreeVariable::new(0),
            output: FreeVariable::new(1),
            uniqueness_witness: FreeVariable::new(3),
            source: FreeVariable::new(4),
            result: FreeVariable::new(5),
            parameters: vec![FreeVariable::new(2), FreeVariable::new(6)],
        })
    );

    let first_then_second = parse_step(
        "(separation (equal first second) element source result (parameters first second))",
    )
    .unwrap();
    let second_then_first = parse_step(
        "(separation (equal first second) element source result (parameters second first))",
    )
    .unwrap();
    let checked = |step| {
        normalize_and_check(ProofCertificate::new(vec![step]).unwrap())
            .unwrap()
            .statement_id()
    };
    assert_ne!(checked(first_then_second), checked(second_then_first));
}

#[test]
fn schema_parameter_list_is_mandatory_exact_and_arity_delimited() {
    for (source, expected) in [
        (
            "(separation (equal element element) element source result)",
            "`(`",
        ),
        (
            "(separation (equal element element) element source (parameters))",
            "a name",
        ),
        (
            "(separation (equal element element) element source result (parameter))",
            "parameters",
        ),
        (
            "(replacement (equal input output) input output witness source result extra (parameters))",
            "`(`",
        ),
        (
            "(replacement (equal input output) input output witness source result (parameters) extra)",
            "`)`",
        ),
    ] {
        assert!(
            matches!(
                parse_step(source),
                Err(CompileError::Syntax { expected: actual, .. }) if actual == expected
            ),
            "accepted or misreported {source:?}"
        );
    }

    assert!(matches!(
        parse_step("(separation (equal element element) element source result (parameters"),
        Err(CompileError::Syntax {
            expected: "a name",
            ..
        })
    ));
}

#[test]
fn every_schema_side_condition_remains_checker_owned() {
    for (step, expected) in [
        (
            "(separation (equal shared shared) shared shared result (parameters))",
            SchemaError::RoleVariableCollision(FreeVariable::new(0)),
        ),
        (
            "(separation (equal element element) element source result (parameters source))",
            SchemaError::ParameterCollidesWithRole(FreeVariable::new(1)),
        ),
        (
            "(separation (equal element element) element source result (parameters parameter parameter))",
            SchemaError::DuplicateParameter(FreeVariable::new(3)),
        ),
        (
            "(separation (equal result result) element source result (parameters))",
            SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        ),
        (
            "(separation (equal undeclared undeclared) element source result (parameters))",
            SchemaError::UndeclaredPredicateVariable(FreeVariable::new(0)),
        ),
        (
            "(replacement (equal witness output) input output witness source result (parameters))",
            SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        ),
    ] {
        assert_eq!(
            compile_schema_step(step),
            Err(CompileError::Check {
                source: CheckError::Schema {
                    step: 0,
                    source: expected,
                },
            }),
            "schema authority changed for {step:?}"
        );
    }
}

#[test]
fn schema_error_precedence_follows_foundation_validation_order() {
    for (step, expected) in [
        (
            "(separation (equal result result) shared shared result (parameters shared shared))",
            SchemaError::RoleVariableCollision(FreeVariable::new(1)),
        ),
        (
            "(separation (equal result result) element source result (parameters source source))",
            SchemaError::ParameterCollidesWithRole(FreeVariable::new(2)),
        ),
        (
            "(separation (equal result result) element source result (parameters parameter parameter))",
            SchemaError::DuplicateParameter(FreeVariable::new(3)),
        ),
        (
            "(separation (implies (equal result result) (equal undeclared undeclared)) element source result (parameters))",
            SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        ),
        (
            "(separation (implies (equal undeclared undeclared) (equal result result)) element source result (parameters))",
            SchemaError::UndeclaredPredicateVariable(FreeVariable::new(0)),
        ),
    ] {
        assert_eq!(
            compile_schema_step(step),
            Err(CompileError::Check {
                source: CheckError::Schema {
                    step: 0,
                    source: expected,
                },
            })
        );
    }
}

#[test]
fn bound_occurrences_of_fresh_role_names_are_not_free_schema_uses() {
    for step in [
        "(separation (forall result (equal result result)) element source result (parameters))",
        "(replacement (forall witness (forall result (equal witness result))) input output witness source result (parameters))",
    ] {
        assert_eq!(
            compile_schema_step(step),
            Err(CompileError::StatementMismatch)
        );
    }
}

#[test]
fn normalization_removes_an_unreachable_invalid_schema() {
    let with_invalid_schema = SOURCE.replace(
        "step reflexive =",
        "step invalid = (separation (equal result result) element source result (parameters));\n    step reflexive =",
    );
    assert_eq!(
        compile(&with_invalid_schema).unwrap(),
        compile(SOURCE).unwrap()
    );
}

#[test]
fn schema_parameter_depth_preflight_precedes_side_conditions_at_its_boundary() {
    let parameters = (0..FORMULA_MAX_DEPTH)
        .map(|index| format!("p{index}"))
        .collect::<Vec<_>>();
    let step = |parameters: &[String]| {
        format!(
            "(separation (equal result result) element source result (parameters {}))",
            parameters.join(" ")
        )
    };

    assert_eq!(
        compile_schema_step(&step(&parameters[..parameters.len() - 1])),
        Err(CompileError::Check {
            source: CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
            },
        })
    );
    assert_eq!(
        compile_schema_step(&step(&parameters)),
        Err(CompileError::Check {
            source: CheckError::DerivedFormula {
                step: 0,
                source: FormulaCodecError::DepthLimitExceeded {
                    maximum: FORMULA_MAX_DEPTH,
                },
            },
        })
    );
}

#[test]
fn schema_parameter_names_add_bytes_but_no_formula_nodes() {
    const WITHOUT: &str = "(separation (equal element element) element source result (parameters))";
    const WITH: &str =
        "(separation (equal element element) element source result (parameters first second))";
    let without_parameters = parse_step(WITHOUT).unwrap();
    let with_parameters = parse_step(WITH).unwrap();
    let with_trivia = parse_step(
        "(separation (equal element element) element source result
         (parameters first second # the close may follow trivia
         ))",
    )
    .unwrap();
    assert_eq!(with_trivia, with_parameters);

    let encoded_without = ProofCertificate::new(vec![without_parameters])
        .unwrap()
        .to_canonical_bytes();
    let encoded_with = ProofCertificate::new(vec![with_parameters])
        .unwrap()
        .to_canonical_bytes();
    assert_eq!(encoded_with.len() - encoded_without.len(), 8);

    for source in [WITHOUT, WITH] {
        let mut parser = Parser::new(source);
        parser.proof_step().unwrap();
        assert_eq!(parser.certificate_formula_nodes, 1);
    }
}

#[test]
fn example_compiles_to_the_existing_checked_identity_vector() {
    let proof = compile(SOURCE).unwrap();
    assert_eq!(proof.canonical_proof_bytes(), NORMAL_PROOF);
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"
        ))
    );
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        normalize_and_check(decoded).unwrap().proof_id(),
        proof.proof_id()
    );
}

#[test]
fn presentation_renaming_and_trivia_do_not_change_output() {
    let renamed = r#"foundation "naome:zfc"; theorem t { statement
      (forall element (equal element element)); proof {
      step a=(equality-reflexivity element); # comment
      step b=(generalization a element); result b; } }"#;
    assert_eq!(compile(SOURCE).unwrap(), compile(renamed).unwrap());
}

#[test]
fn implication_identity_lowers_every_formula_and_operand_role_exactly() {
    let proof = compile(IMPLICATION_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "6c7296d3c7adb7ee99b71caec2e6851c31360e2811bd1335b526c7b74525a48b"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "fd46e6233815bd4cb5188f5358b8afb852179c62b7fb512b798302b0f01fdd94"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(IMPLICATION_PROOF_HEX)
    );

    let x = FreeVariable::new(0);
    let a = Formula::equal(x, x);
    let a_implies_a = Formula::implies(a.clone(), a.clone());
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[
            ProofStep::Simplification {
                antecedent: a.clone(),
                consequent: a.clone(),
            },
            ProofStep::Simplification {
                antecedent: a.clone(),
                consequent: a_implies_a.clone(),
            },
            ProofStep::Frege {
                first: a.clone(),
                second: a_implies_a,
                third: a,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 3,
            },
            ProofStep::Generalization {
                premise: 4,
                variable: x,
            },
        ]
    );
}

#[test]
fn implication_proof_presentation_is_identity_neutral() {
    let renamed = r#"# same proof with presentation-only changes
      foundation "naome:zfc"; theorem renamed {
      statement (forall element (implies (equal element element) (equal element element)));
      proof {
      step a=(simplification (equal element element) (equal element element));
      step b=(simplification (equal element element)
        (implies (equal element element) (equal element element)));
      step c=(frege (equal element element)
        (implies (equal element element) (equal element element))
        (equal element element));
      step d=(modus-ponens b c); step e=(modus-ponens a d);
      step f=(generalization e element); result f; } }"#;
    assert_eq!(
        compile(IMPLICATION_SOURCE).unwrap(),
        compile(renamed).unwrap()
    );
}

#[test]
fn quantifier_example_lowers_to_the_exact_checked_identity_vector() {
    let proof = compile(QUANTIFIER_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "a85928e52c4c2833d30640cb2eaba82602ccbc39b6afea340b5b0b8d06061972"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(QUANTIFIER_PROOF_HEX)
    );

    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStep::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: Formula::equal(x, x),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: y,
            },
        ]
    );
}

#[test]
fn quantifier_steps_preserve_source_operands_and_nameless_q2() {
    let q1 = r#"foundation "naome:zfc"; theorem q1 {
      statement (forall close (implies
        (forall x (implies (equal x x) (member x x)))
        (implies (forall x (equal x x)) (forall x (member x x)))));
      proof {
        step rule = (universal-distribution x (equal x x) (member x x));
        step closed = (generalization rule close); result closed;
      } }"#;
    let proof = compile(q1).unwrap();
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    let x = FreeVariable::new(0);
    assert_eq!(
        decoded.steps()[0],
        ProofStep::UniversalDistribution {
            variable: x,
            antecedent: Formula::equal(x, x),
            consequent: Formula::member(x, x),
        }
    );
    assert_eq!(
        compile(&q1.replace(
            "(universal-distribution x (equal x x) (member x x))",
            "(universal-distribution x (member x x) (equal x x))"
        )),
        Err(CompileError::StatementMismatch)
    );

    let q2 = r#"foundation "naome:zfc"; theorem q2 {
      statement (implies (forall x (equal x x)) (forall unused (forall x (equal x x))));
      proof { step rule = (vacuous-universal (forall x (equal x x))); result rule; } }"#;
    let proof = compile(q2).unwrap();
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::VacuousUniversal {
            formula: Formula::for_all(x, Formula::equal(x, x)),
        }]
    );
    assert_eq!(
        compile(q2).unwrap(),
        compile(&q2.replace("unused", "presentation_only")).unwrap()
    );

    let swapped_q3 = QUANTIFIER_SOURCE.replace(
        "(universal-instantiation x y (equal x x))",
        "(universal-instantiation y x (equal x x))",
    );
    assert!(matches!(
        compile(&swapped_q3),
        Err(CompileError::Check {
            source: CheckError::Logic {
                source: naome_foundation::LogicError::ModusPonensMismatch,
                ..
            }
        })
    ));
}

#[test]
fn quantifier_presentation_renaming_preserves_identity() {
    let renamed = QUANTIFIER_SOURCE
        .replace("universal_equality_is_usable", "renamed")
        .replace("reflexive_at_x", "a")
        .replace("universal_at_x", "b")
        .replace("instantiate_at_y", "c")
        .replace("reflexive_at_y", "d")
        .replace("universal_at_y", "e")
        .replace(" x", " source")
        .replace(" y", " target");
    assert_eq!(
        compile(QUANTIFIER_SOURCE).unwrap(),
        compile(&renamed).unwrap()
    );
}

#[test]
fn equality_substitution_example_lowers_to_the_exact_checked_identity_vector() {
    let proof = compile(EQUALITY_SUBSTITUTION_SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "0d6570e2a5031b6a1b3664fb990c1cdf4ff4079364ad9dd08e4f9123662c5772"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "107a35fa6ec1677c01560c743c627a5d231315d605fa50083e18dd529a8861b5"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(EQUALITY_SUBSTITUTION_PROOF_HEX)
    );

    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let set = FreeVariable::new(2);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[
            ProofStep::EqualitySubstitution {
                from: x,
                to: y,
                body: Formula::member(x, set),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: set,
            },
            ProofStep::Generalization {
                premise: 1,
                variable: y,
            },
            ProofStep::Generalization {
                premise: 2,
                variable: x,
            },
        ]
    );
}

#[test]
fn classical_contraposition_preserves_closed_formula_operand_order() {
    const A: &str = "(forall x (equal x x))";
    const B: &str = "(forall y (member y y))";
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement
         (implies (implies (not {B}) (not {A})) (implies {A} {B})); proof {{
         step result = (classical-contraposition {A} {B}); result result; }} }}"
    );
    let proof = compile(&source).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(
            "76605b895a10af62541fd18263816c5fff90e1334b7bb51d37dd46684a34fcba"
        ))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(
            "9306675268fe2542590ad0eab3971e8a3b8bac1419fa84bb9a2e44015f09143c"
        ))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(
            "3aece3d5182e832c33038fb9b123707ed6676379146e1cc6b880a20bc735ccb4"
        ))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(CLASSICAL_CONTRAPOSITION_PROOF_HEX)
    );
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let a = Formula::for_all(x, Formula::equal(x, x));
    let b = Formula::for_all(y, Formula::member(y, y));
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::ClassicalContraposition {
            antecedent: a,
            consequent: b,
        }]
    );

    let swapped = source.replace(
        &format!("(classical-contraposition {A} {B})"),
        &format!("(classical-contraposition {B} {A})"),
    );
    assert_eq!(compile(&swapped), Err(CompileError::StatementMismatch));
}

#[test]
fn equality_substitution_preserves_roles_and_cannot_capture_under_a_binder() {
    let source = r#"foundation "naome:zfc"; theorem t {
      statement (forall x (forall y
        (implies (equal x y)
          (implies (forall bound (member x bound))
            (forall bound (member y bound))))));
      proof {
        step substitute =
          (equality-substitution x y (forall y (member x y)));
        step for_y = (generalization substitute y);
        step for_x = (generalization for_y x);
        result for_x;
      } }"#;
    let proof = compile(source).unwrap();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps()[0],
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: Formula::for_all(y, Formula::member(x, y)),
        }
    );

    for mutated in [
        source.replace("equality-substitution x y", "equality-substitution y x"),
        source.replace("(forall y (member x y)));", "(forall y (member y y)));"),
    ] {
        assert_eq!(compile(&mutated), Err(CompileError::StatementMismatch));
    }
}

#[test]
fn equality_substitution_presentation_renaming_preserves_identity() {
    let renamed = EQUALITY_SUBSTITUTION_SOURCE
        .replace("substitute", "a")
        .replace("for_set", "b")
        .replace("for_y", "c")
        .replace("for_x", "d")
        .replace(" x", " source")
        .replace(" y", " target")
        .replace(" set", " collection");
    assert_eq!(
        compile(EQUALITY_SUBSTITUTION_SOURCE).unwrap(),
        compile(&renamed).unwrap()
    );
}

#[test]
fn modus_ponens_preserves_operand_roles_and_rejects_every_non_earlier_name() {
    let swapped = IMPLICATION_SOURCE.replace(
        "(modus-ponens keep_implication distribute)",
        "(modus-ponens distribute keep_implication)",
    );
    assert!(matches!(
        compile(&swapped),
        Err(CompileError::Check {
            source: CheckError::Logic {
                source: naome_foundation::LogicError::ModusPonensMismatch,
                ..
            }
        })
    ));

    for (needle, replacement, missing) in [
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens missing distribute",
            "missing",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens keep_implication missing",
            "missing",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens identity distribute",
            "identity",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens lifted_identity distribute",
            "lifted_identity",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens keep_implication identity",
            "identity",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens keep_implication lifted_identity",
            "lifted_identity",
        ),
        (
            "modus-ponens keep_implication distribute",
            "modus-ponens first_missing second_missing",
            "first_missing",
        ),
    ] {
        let source = IMPLICATION_SOURCE.replace(needle, replacement);
        assert!(matches!(
            compile(&source),
            Err(CompileError::UnknownStep { name, .. }) if name == missing
        ));
    }
}

#[test]
fn unreachable_invalid_inference_is_removed_without_changing_identity() {
    let with_dead_step = IMPLICATION_SOURCE.replace(
        "step keep_implication =",
        "step invalid_but_unreachable = (modus-ponens keep_left keep_left);\n    step keep_implication =",
    );
    assert_eq!(
        compile(IMPLICATION_SOURCE).unwrap(),
        compile(&with_dead_step).unwrap()
    );
}

#[test]
fn logical_axiom_formula_operands_keep_source_order() {
    const A: &str = "(forall x (equal x x))";
    const B: &str = "(forall y (member y y))";
    const C: &str = "(not (forall z (equal z z)))";

    let simplification = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement (implies {A} (implies {B} {A})); proof {{ step result = (simplification {A} {B}); result result; }} }}"
    );
    let proof = compile(&simplification).unwrap();
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let a = Formula::for_all(x, Formula::equal(x, x));
    let b = Formula::for_all(y, Formula::member(y, y));
    assert_eq!(
        decoded.steps(),
        &[ProofStep::Simplification {
            antecedent: a,
            consequent: b,
        }]
    );
    let swapped = simplification.replace(
        &format!("(simplification {A} {B})"),
        &format!("(simplification {B} {A})"),
    );
    assert_eq!(compile(&swapped), Err(CompileError::StatementMismatch));

    let frege_statement = format!(
        "(implies (implies {A} (implies {B} {C})) (implies (implies {A} {B}) (implies {A} {C})))"
    );
    let frege = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement {frege_statement}; proof {{ step result = (frege {A} {B} {C}); result result; }} }}"
    );
    let proof = compile(&frege).unwrap();
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let z = FreeVariable::new(2);
    assert_eq!(
        decoded.steps(),
        &[ProofStep::Frege {
            first: Formula::for_all(x, Formula::equal(x, x)),
            second: Formula::for_all(y, Formula::member(y, y)),
            third: Formula::negate(Formula::for_all(z, Formula::equal(z, z))),
        }]
    );
    let swapped = frege.replace(
        &format!("(frege {A} {B} {C})"),
        &format!("(frege {A} {C} {B})"),
    );
    assert_eq!(compile(&swapped), Err(CompileError::StatementMismatch));
}

#[test]
fn proof_formula_limits_are_enforced_during_parsing() {
    let mut balanced = "(equal x x)".to_owned();
    for _ in 0..14 {
        balanced = format!("(implies {balanced} {balanced})");
    }
    let at_limit = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement (forall x (equal x x)); proof {{
         step separation = (separation {balanced} element source result (parameters));
         step replacement = (replacement {balanced} input output witness domain image (parameters));
         step edge_a = (separation (equal x x) element source result (parameters));
         step edge_b = (equality-substitution x x (equal x x));
         step ignored_axiom = (zfc-axiom extensionality);
         step reflexive = (equality-reflexivity x);
         step closed = (generalization reflexive x); result closed; }} }}"
    );
    assert_eq!(compile(&at_limit).unwrap(), compile(SOURCE).unwrap());

    let over_limit = at_limit.replace(
        "step reflexive =",
        "step excess = (separation (equal x x) malformed",
    );
    assert!(matches!(
        compile(&over_limit),
        Err(CompileError::Certificate {
            source: ProofCertificateError::FormulaNodeLimitExceeded {
                maximum: CERTIFICATE_MAX_FORMULA_NODES
            }
        })
    ));

    let mut too_deep = "(equal x x)".to_owned();
    for _ in 0..FORMULA_MAX_DEPTH {
        too_deep = format!("(not {too_deep})");
    }
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement (forall x (equal x x)); proof {{ step excessive = (separation {too_deep}; result excessive; }} }}"
    );
    assert!(matches!(
        compile(&source),
        Err(CompileError::FormulaDepthLimitExceeded { .. })
    ));
}

#[test]
fn all_formula_forms_parse_before_statement_comparison() {
    let sources = [
        "(member x y)",
        "(not (equal x x))",
        "(implies (equal x x) (member x y))",
        "(forall x (member x y))",
    ];
    for statement in sources {
        let source = format!(
            "foundation \"naome:zfc\"; theorem t {{ statement {statement}; proof {{ step a = (equality-reflexivity x); result a; }} }}"
        );
        assert!(matches!(
            compile(&source),
            Err(CompileError::StatementMismatch | CompileError::Check { .. })
        ));
    }
}

#[test]
fn foundation_and_name_failures_are_located_and_deterministic() {
    let wrong = SOURCE.replace("naome:zfc", "other");
    assert!(matches!(
        compile(&wrong),
        Err(CompileError::FoundationMismatch { .. })
    ));

    let duplicate = SOURCE.replace("step universally_reflexive", "step reflexive");
    assert!(matches!(
        compile(&duplicate),
        Err(CompileError::DuplicateStep { name, .. }) if name == "reflexive"
    ));

    let unknown = SOURCE.replace("generalization reflexive", "generalization later");
    assert!(matches!(
        compile(&unknown),
        Err(CompileError::UnknownStep { name, .. }) if name == "later"
    ));

    let self_reference = SOURCE.replace(
        "generalization reflexive",
        "generalization universally_reflexive",
    );
    assert!(matches!(
        compile(&self_reference),
        Err(CompileError::UnknownStep { name, .. }) if name == "universally_reflexive"
    ));
}

#[test]
fn result_must_name_the_final_step_and_input_must_be_complete() {
    let nonfinal = SOURCE.replace("result universally_reflexive", "result reflexive");
    assert!(matches!(
        compile(&nonfinal),
        Err(CompileError::ResultNotFinal { .. })
    ));

    let trailing = format!("{SOURCE} trailing");
    assert!(matches!(
        compile(&trailing),
        Err(CompileError::Syntax {
            expected: "end of source",
            ..
        })
    ));
}

#[test]
fn open_and_mismatched_conclusions_produce_no_output() {
    let open = r#"foundation "naome:zfc"; theorem t {
      statement (equal x x); proof { step a = (equality-reflexivity x); result a; } }"#;
    assert!(matches!(
        compile(open),
        Err(CompileError::Check {
            source: CheckError::OpenConclusion { .. }
        })
    ));

    let mismatch = SOURCE.replace("(equal x x)", "(member x x)");
    assert_eq!(compile(&mismatch), Err(CompileError::StatementMismatch));
}

#[test]
fn depth_and_source_limits_fail_closed() {
    let mut formula = "(equal x x)".to_owned();
    for _ in 0..FORMULA_MAX_DEPTH {
        formula = format!("(not {formula})");
    }
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement {formula}; proof {{ step a = (equality-reflexivity x); result a; }} }}"
    );
    assert!(matches!(
        compile(&source),
        Err(CompileError::FormulaDepthLimitExceeded { .. })
    ));

    let oversized = " ".repeat(AUTHORING_SOURCE_MAX_BYTES + 1);
    assert_eq!(
        compile(&oversized),
        Err(CompileError::SourceTooLong {
            actual: AUTHORING_SOURCE_MAX_BYTES + 1,
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        })
    );
}

#[test]
fn every_truncation_of_the_example_fails_without_output() {
    let complete_length = SOURCE.trim_end().len();
    for end in 0..complete_length {
        assert!(compile(&SOURCE[..end]).is_err(), "accepted prefix {end}");
    }
    assert!(compile(&SOURCE[..complete_length]).is_ok());
}

#[test]
fn declared_statement_obeys_the_formula_node_limit_before_proof_work() {
    let mut formula = "(equal x x)".to_owned();
    for _ in 0..16 {
        formula = format!("(implies {formula} {formula})");
    }
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement {formula}; proof {{ step a = (equality-reflexivity x); result a; }} }}"
    );
    assert!(matches!(
        compile(&source),
        Err(CompileError::Statement {
            source: naome_foundation::FormulaCodecError::NodeLimitExceeded { .. }
        })
    ));
}

#[test]
fn statement_node_limit_is_enforced_while_parsing_the_next_node() {
    let leaf = "(equal x x)";
    let mut formula = String::new();
    for _ in 0..FORMULA_MAX_NODES / 2 {
        formula.push_str("(not ");
    }
    formula.push_str(leaf);
    for _ in 0..FORMULA_MAX_NODES / 2 {
        formula.push(')');
    }
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement {formula}; proof {{ step a = (equality-reflexivity x); result a; }} }}"
    );
    assert!(matches!(
        compile(&source),
        Err(CompileError::FormulaDepthLimitExceeded { .. })
    ));

    let mut balanced = "(equal x x)".to_owned();
    for _ in 0..16 {
        balanced = format!("(implies {balanced} {balanced})");
    }
    let source = format!(
        "foundation \"naome:zfc\"; theorem t {{ statement {balanced}; proof {{ step a = (equality-reflexivity x); result a; }} }}"
    );
    assert!(matches!(
        compile(&source),
        Err(CompileError::Statement {
            source: naome_foundation::FormulaCodecError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES
            }
        })
    ));
}

#[test]
fn keywords_are_delimited_and_names_follow_the_ascii_grammar() {
    for source in [
        SOURCE.replace("foundation", "foundationx"),
        SOURCE.replace("theorem equality", "theorem 1equality"),
        SOURCE.replace("step reflexive", "step naïve"),
        SOURCE.replace("proof {", "proofx {"),
    ] {
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }
}

#[test]
fn comments_may_end_at_eof_but_cannot_split_tokens() {
    let mut with_eof_comment = SOURCE.trim_end().to_owned();
    with_eof_comment.push_str(" # final comment");
    assert!(compile(&with_eof_comment).is_ok());

    let split = SOURCE.replace("foundation", "found# split\nation");
    assert!(matches!(compile(&split), Err(CompileError::Syntax { .. })));
}

#[test]
fn step_limit_fails_when_the_first_excess_step_is_reached() {
    let mut source = String::from(
        "foundation \"naome:zfc\"; theorem t { statement (forall x (equal x x)); proof {",
    );
    source.push_str(" step s0 = (equality-reflexivity x);");
    for index in 1..CERTIFICATE_MAX_STEPS {
        source.push_str(" step s");
        source.push_str(&index.to_string());
        source.push_str(" = (generalization s");
        source.push_str(&(index - 1).to_string());
        source.push_str(" x);");
    }
    // The excess step is deliberately malformed. The step budget must reject
    // it before parsing or retaining any part of its expression.
    source.push_str(" step excess = (unsupported");

    assert!(matches!(
        compile(&source),
        Err(CompileError::Certificate {
            source: ProofCertificateError::TooManySteps {
                actual,
                maximum: CERTIFICATE_MAX_STEPS,
            }
        }) if actual == CERTIFICATE_MAX_STEPS + 1
    ));
}

#[test]
fn consuming_bytes_returns_the_exact_owned_output() {
    assert_eq!(
        compile(SOURCE)
            .unwrap()
            .into_canonical_proof_bytes()
            .as_ref(),
        NORMAL_PROOF
    );
}

fn parse_formula(source: &str, context: FormulaContext) -> Result<ParsedFormula, CompileError> {
    let mut parser = Parser::new(source);
    let formula = parser.parsed_formula(1, context)?;
    parser.end()?;
    Ok(formula)
}

fn parse_step(source: &str) -> Result<ProofStep, CompileError> {
    let mut parser = Parser::new(source);
    let step = parser.proof_step()?;
    parser.end()?;
    Ok(step)
}

fn compile_schema_step(step: &str) -> Result<CompiledProof, CompileError> {
    compile(&format!(
        "foundation \"naome:zfc\"; theorem schema {{ statement (forall closed (equal closed closed)); proof {{ step schema = {step}; result schema; }} }}"
    ))
}

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}
