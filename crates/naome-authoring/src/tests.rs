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

const IMPLICATION_SOURCE: &str = include_str!("../../../examples/implication-identity.nao");

const IMPLICATION_PROOF_HEX: &str = "00000006000000000b00000000000000000000000000000b0000000000000000000000000000000b0000000000000000000000000000170300000000000000000000000000000000000000000000010000000b00000000000000000000000000001703000000000000000000000000000000000000000000000000000b0000000000000000000000200000000100000002200000000000000003210000000400000000";

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
         step budget = (simplification {balanced} {balanced});
         step edge = (simplification (equal x x) (equal x x));
         step reflexive = (equality-reflexivity x);
         step closed = (generalization reflexive x); result closed; }} }}"
    );
    assert_eq!(compile(&at_limit).unwrap(), compile(SOURCE).unwrap());

    let over_limit = at_limit.replace(
        "step reflexive =",
        "step excess = (simplification (equal x x) (equal x x)); step reflexive =",
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
        "foundation \"naome:zfc\"; theorem t {{ statement (forall x (equal x x)); proof {{ step excessive = (simplification {too_deep} (equal x x)); result excessive; }} }}"
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
