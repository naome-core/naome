//! Offline mathematical authoring; these contexts establish no finalized publication.

#[path = "support/hex_decode.rs"]
mod hex_decode;
use hex_decode::hex32;

#[path = "support/hex_encode.rs"]
mod hex_encode;
use hex_encode::hex_string;

use naome_authoring::{
    CompileError, CompiledArtifact, CompiledProof, compile, compile_against_proof_context,
    compile_artifact, compile_artifact_against_proof_context,
};
use naome_checker::CheckError;
use naome_ledger::{ArtifactAdmissionError, ArtifactDag};
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinitionId, DerivationId, ProofCertificate, ProofId, ProofStep,
    StatementId,
};

const SELF_EQUALITY: &str = r#"
foundation = "naome:zfc"
statement = forall(x, equal(x, x))
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    return p1
"#;

const NESTED_SELF_EQUALITY: &str = r#"
foundation = "naome:zfc"
statement = forall(y, forall(x, equal(x, x)))
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    p2 = generalization(p1, y)
    return p2
"#;

const LONG_SELECTED_DEPENDENCY_PROOF: &str = r#"
foundation = "naome:zfc"
statement = forall(a, forall(set,
    implies(member(a, set), member(a, set))
))

proof:
    p0 = cite("c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73")
    p1 = cite("6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720")
    p2 = cite("dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285")
    p3 = cite("e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71")
    p4 = cite("7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d")

    p5 = simplification(
        forall(x, equal(x, x)),
        forall(y, equal(y, y)),
    )
    p6 = modus_ponens(p0, p5)
    p7 = modus_ponens(p1, p6)

    p8 = universal_instantiation(x, a, equal(x, x))
    p9 = modus_ponens(p7, p8)

    p10 = universal_instantiation(
        x,
        a,
        implies(equal(x, x), equal(x, x)),
    )
    p11 = modus_ponens(p2, p10)
    p12 = modus_ponens(p9, p11)

    p13 = simplification(
        equal(a, a),
        forall(x, forall(y,
            implies(
                forall(z, iff(member(z, x), member(z, y))),
                equal(x, y),
            ),
        )),
    )
    p14 = modus_ponens(p12, p13)
    p15 = modus_ponens(p4, p14)

    p16 = universal_instantiation(
        x,
        a,
        forall(y, forall(s,
            implies(
                equal(x, y),
                implies(member(x, s), member(y, s)),
            ),
        )),
    )
    p17 = modus_ponens(p3, p16)

    p18 = universal_instantiation(
        y,
        a,
        forall(s,
            implies(
                equal(a, y),
                implies(member(a, s), member(y, s)),
            ),
        ),
    )
    p19 = modus_ponens(p17, p18)

    p20 = universal_instantiation(
        s,
        set,
        implies(
            equal(a, a),
            implies(member(a, s), member(a, s)),
        ),
    )
    p21 = modus_ponens(p19, p20)

    p22 = modus_ponens(p15, p21)
    p23 = generalization(p22, set)
    p24 = generalization(p23, a)
    return p24
"#;

#[derive(Default)]
struct CheckedContext {
    dag: ArtifactDag,
    payloads: Vec<(ArtifactId, Vec<u8>)>,
}
impl CheckedContext {
    fn admit(&mut self, id: ArtifactId, bytes: Vec<u8>) -> Result<(), ArtifactAdmissionError> {
        self.dag
            .apply_canonical_artifact_bytes_with_expected_id(bytes.clone(), id)?;
        self.payloads.push((id, bytes));
        Ok(())
    }
    fn recheck(&self) -> Self {
        let mut fresh = Self::default();
        for (id, bytes) in &self.payloads {
            fresh.admit(*id, bytes.clone()).unwrap();
        }
        assert_eq!(fresh.dag.artifact_set_root(), self.dag.artifact_set_root());
        fresh
    }
}

fn reference_source(proof_id: ProofId) -> String {
    let mut encoded = String::with_capacity(ProofId::BYTE_LENGTH * 2);
    for byte in proof_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    format!(
        "foundation = \"naome:zfc\" statement = forall(y, forall(x, equal(x, x))) proof: p0 = cite(\"{encoded}\") p1 = generalization(p0, y) return p1"
    )
}

fn proof_artifact_bytes(proof: &CompiledProof) -> Vec<u8> {
    let certificate =
        ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn admit_source(context: &mut CheckedContext, source: &str) -> CompiledArtifact {
    let compiled =
        compile_artifact_against_proof_context(source, context.dag.artifact_state()).unwrap();
    admit_compiled(context, &compiled);
    compiled
}

fn admit_compiled(context: &mut CheckedContext, compiled: &CompiledArtifact) {
    context
        .admit(compiled.artifact_id(), compiled.canonical_artifact_bytes())
        .unwrap();
}

fn compiled_definition_id(compiled: &CompiledArtifact) -> DefinitionId {
    match compiled {
        CompiledArtifact::Definition(definition) => definition.definition_id(),
        CompiledArtifact::Proof(_) => panic!("expected a compiled definition"),
    }
}

fn compiled_proof(compiled: &CompiledArtifact) -> &CompiledProof {
    match compiled {
        CompiledArtifact::Proof(proof) => proof,
        CompiledArtifact::Definition(_) => panic!("expected a compiled proof"),
    }
}

fn assert_unknown_reference(result: Result<CompiledProof, CompileError>, expected: ProofId) {
    match result {
        Err(CompileError::Check { source, .. }) => assert!(matches!(
            source.as_ref(),
            CheckError::UnknownProofReference { step: 0, proof_id } if *proof_id == expected
        )),
        other => panic!("expected unknown proof reference, got {other:?}"),
    }
}

#[test]
fn long_agent_style_proof_uses_only_checked_exact_dependencies_without_mutation() {
    let mut context = CheckedContext::default();

    for source in [
        include_str!("../../../examples/self-equality.nao"),
        include_str!("../../../examples/quantifier-instantiation.nao"),
        include_str!("../../../examples/implication-identity.nao"),
        include_str!("../../../examples/equality-substitution.nao"),
        include_str!("../../../examples/extensionality.nao"),
    ] {
        let dependency = compile(source).unwrap();
        context
            .admit(
                ArtifactId::from_proof_id(dependency.proof_id()),
                proof_artifact_bytes(&dependency),
            )
            .unwrap();
    }

    let context_image = context.payloads.clone();
    let root = context.dag.artifact_set_root();
    let len = context.dag.len();

    let compiled =
        compile_against_proof_context(LONG_SELECTED_DEPENDENCY_PROOF, context.dag.artifact_state())
            .unwrap();
    assert_eq!(
        compiled.statement_id(),
        StatementId::from_bytes(hex32(
            "82ee04b9082115a985aa3a669bccab902c6108da31cfba242dcb533334656dba"
        ))
    );
    assert_eq!(
        compiled.derivation_id(),
        DerivationId::from_bytes(hex32(
            "65664aa8ff799d4d82f7cf1dd88aa768fdb7e97f9f4b7c010e10e3813e2ad322"
        ))
    );
    assert_eq!(
        compiled.proof_id(),
        ProofId::from_bytes(hex32(
            "bc81051d252a5012e65369702e205541f3e3d660c7edd11cfb134859951ec10a"
        ))
    );
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    assert_eq!(certificate.steps().len(), 25);
    assert_eq!(
        certificate
            .steps()
            .iter()
            .filter(|step| matches!(step, ProofStep::ProofReference { .. }))
            .count(),
        5
    );
    assert_eq!(context.dag.artifact_set_root(), root);
    assert_eq!(context.dag.len(), len);
    assert_eq!(context.payloads.clone(), context_image);
}

#[test]
fn definitions_and_term_sugar_resolve_only_from_checked_ancestry() {
    let mut context = CheckedContext::default();

    let identity_obligation = admit_source(
        &mut context,
        include_str!("../../../examples/identity-function-obligation.nao"),
    );
    assert_eq!(
        compiled_proof(&identity_obligation).proof_id(),
        ProofId::from_bytes(hex32(
            "298a101556461ae89f891c928d4e5e0290709452d93dea6019c7568e89a10970"
        ))
    );
    for source in [
        include_str!("../../../examples/self-equality.nao"),
        include_str!("../../../examples/quantifier-instantiation.nao"),
        include_str!("../../../examples/implication-identity.nao"),
        include_str!("../../../examples/equality-substitution.nao"),
        include_str!("../../../examples/extensionality.nao"),
    ] {
        let _ = admit_source(&mut context, source);
    }

    let first = admit_source(
        &mut context,
        include_str!("../../../examples/reflexive-relation.nao"),
    );
    let first_id = compiled_definition_id(&first);
    assert_eq!(
        first_id,
        DefinitionId::from_bytes(hex32(
            "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
        ))
    );
    let colliding_name = r#"
foundation = "naome:zfc"
definitions:
    self_equal = "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
definition self_equal = relation(x):
    self_equal(x)
"#;
    let source =
        compile_artifact_against_proof_context(colliding_name, context.dag.artifact_state())
            .unwrap_err();
    assert!(matches!(
        &source,
        CompileError::DuplicateDefinitionAlias { name, .. } if name == "self_equal"
    ));
    let diagnostic = source.diagnostic(colliding_name);
    assert_eq!(diagnostic.code().as_str(), "NAO0016");
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&colliding_name[span.start()..span.end()], "self_equal");

    let second = admit_source(
        &mut context,
        include_str!("../../../examples/membership-relation.nao"),
    );
    let second_id = compiled_definition_id(&second);
    assert_eq!(
        second_id,
        DefinitionId::from_bytes(hex32(
            "4165ac271695531751ada582517549ab2e53d286a820b03de7ac3a0ddc372d19"
        ))
    );

    let third = admit_source(
        &mut context,
        include_str!("../../../examples/same-members-relation.nao"),
    );
    let third_id = compiled_definition_id(&third);
    assert_eq!(
        third_id,
        DefinitionId::from_bytes(hex32(
            "29b9cbdea19bdc3ee48f3f4cdebbd4deb07aaf4669564c4440163a857fcbf548"
        ))
    );
    let presentation_variant = r#"
foundation = "naome:zfc"
definitions:
    unused = "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
    membership = "4165ac271695531751ada582517549ab2e53d286a820b03de7ac3a0ddc372d19"
definition presentation_only = relation(a, b):
    forall(candidate, iff(membership(candidate, a), membership(candidate, b)))
"#;
    let presentation_variant =
        compile_artifact_against_proof_context(presentation_variant, context.dag.artifact_state())
            .unwrap();
    assert_eq!(presentation_variant, third);

    for source in [
        "foundation = \"naome:zfc\" definition recursive = relation(x): recursive(x)",
        "foundation = \"naome:zfc\" definitions: future = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" definition current = relation(x): future(x)",
    ] {
        assert!(matches!(
            compile_artifact_against_proof_context(source, context.dag.artifact_state()),
            Err(CompileError::UnknownDefinitionAlias { .. }
                | CompileError::DefinitionNotSelected { .. })
        ));
    }

    let identity = admit_source(
        &mut context,
        include_str!("../../../examples/identity-function.nao"),
    );
    let identity_id = compiled_definition_id(&identity);
    assert_eq!(
        identity_id,
        DefinitionId::from_bytes(hex32(
            "1b976399f4226292fdea6b89c496e976cbcd86eb1458bc265cdd14e04d1cf854"
        ))
    );

    let selected_image = context.payloads.clone();
    let selected_root = context.dag.artifact_set_root();
    let selected_len = context.dag.len();

    let long = compile_artifact_against_proof_context(
        include_str!("../../../examples/definitions-long-proof.nao"),
        context.dag.artifact_state(),
    )
    .unwrap();
    let long = compiled_proof(&long);
    assert_eq!(
        long.statement_id(),
        StatementId::from_bytes(hex32(
            "82ee04b9082115a985aa3a669bccab902c6108da31cfba242dcb533334656dba"
        ))
    );
    assert_eq!(
        long.derivation_id(),
        DerivationId::from_bytes(hex32(
            "65664aa8ff799d4d82f7cf1dd88aa768fdb7e97f9f4b7c010e10e3813e2ad322"
        ))
    );
    assert_eq!(
        long.proof_id(),
        ProofId::from_bytes(hex32(
            "5ae5159ffe11909977f7033ad5d7b9364a3182a207427faccc67b63d6effc099"
        ))
    );
    let certificate = ProofCertificate::from_canonical_bytes(long.canonical_proof_bytes()).unwrap();
    assert_eq!(certificate.steps().len(), 25);
    assert_eq!(
        certificate
            .steps()
            .iter()
            .flat_map(ProofStep::definition_references)
            .count(),
        12
    );

    let term = compile_artifact_against_proof_context(
        include_str!("../../../examples/identity-function-term-proof.nao"),
        context.dag.artifact_state(),
    )
    .unwrap();
    let term = compiled_proof(&term);
    assert_eq!(
        term.statement_id(),
        StatementId::from_bytes(hex32(
            "ef76edfd47f93627bf5ee586b0d4479e84de739b7e91368e53f01590f2e381c1"
        ))
    );
    assert_eq!(
        term.derivation_id(),
        DerivationId::from_bytes(hex32(
            "689c0e8d315c738778a7dd7c0234da35155b8f3d5614c7b3a2e7c72d60acf27c"
        ))
    );
    assert_eq!(
        term.proof_id(),
        ProofId::from_bytes(hex32(
            "4ac90b298802d2f4373d3df41b1107bd8fd21cf8dde35a122cc5637432fd65c7"
        ))
    );
    let certificate = ProofCertificate::from_canonical_bytes(term.canonical_proof_bytes()).unwrap();
    assert_eq!(certificate.steps().len(), 2);
    assert_eq!(
        certificate
            .steps()
            .iter()
            .flat_map(ProofStep::definition_references)
            .count(),
        2
    );

    assert_eq!(context.dag.artifact_set_root(), selected_root);
    assert_eq!(context.dag.len(), selected_len);
    assert_eq!(context.payloads.clone(), selected_image);

    let dependency_free =
        compile_artifact(include_str!("../../../examples/reflexive-relation.nao")).unwrap();
    assert_eq!(compiled_definition_id(&dependency_free), first_id);
    assert!(matches!(
        compile_artifact(include_str!(
            "../../../examples/reflexive-relation-alias.nao"
        )),
        Err(CompileError::DefinitionNotSelected { .. })
    ));

    let final_proof_id = long.proof_id();
    let final_artifact_id = ArtifactId::from_proof_id(final_proof_id);
    context
        .admit(final_artifact_id, proof_artifact_bytes(long))
        .unwrap();
    assert_eq!(context.dag.len(), selected_len + 1);
    assert_ne!(context.dag.artifact_set_root(), selected_root);
    let rebuilt = context.recheck();
    assert_eq!(rebuilt.dag.len(), selected_len + 1);
    let final_record = rebuilt
        .dag
        .artifact(final_artifact_id)
        .unwrap()
        .as_proof()
        .unwrap();
    assert_eq!(final_record.proof_id(), final_proof_id);
    let state = rebuilt.dag.artifact_state();
    for definition_id in [first_id, second_id, third_id, identity_id] {
        assert!(state.contains_definition(definition_id));
    }
    for proof_id in [
        ProofId::from_bytes(hex32(
            "298a101556461ae89f891c928d4e5e0290709452d93dea6019c7568e89a10970",
        )),
        ProofId::from_bytes(hex32(
            "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73",
        )),
        ProofId::from_bytes(hex32(
            "6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720",
        )),
        ProofId::from_bytes(hex32(
            "dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285",
        )),
        ProofId::from_bytes(hex32(
            "e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71",
        )),
        ProofId::from_bytes(hex32(
            "7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d",
        )),
        final_proof_id,
    ] {
        assert!(state.contains_proof(proof_id));
    }
}

#[test]
fn empty_set_existence_remains_a_standalone_checked_proof() {
    const SOURCE: &str = include_str!("../../../examples/empty-set-obligation.nao");

    let mut context = CheckedContext::default();

    assert_eq!(SOURCE.len(), 390_826);
    let standalone = compile_artifact(SOURCE).unwrap();
    let standalone = compiled_proof(&standalone);
    assert_eq!(standalone.canonical_proof_bytes().len(), 110_196);
    assert_eq!(
        standalone.statement_id(),
        StatementId::from_bytes(hex32(
            "31e258a893b84df8abbfc30b99d74e2a610b23145dbfd66de054dc91d6a3472e"
        ))
    );
    assert_eq!(
        standalone.derivation_id(),
        DerivationId::from_bytes(hex32(
            "06967b3b8f22d2424593ad3aa2b68cec5bff8f4e81f92b958b78703191fc0d6d"
        ))
    );
    assert_eq!(
        standalone.proof_id(),
        ProofId::from_bytes(hex32(
            "0919162ae0dc2bf2f95966473aba97f22a072e26074ab5f92b55d043d730bfde"
        ))
    );
    let selected = admit_source(&mut context, SOURCE);
    assert_eq!(compiled_proof(&selected), standalone);
    let artifact_id = selected.artifact_id();
    assert_eq!(context.dag.len(), 1);
    let rebuilt = context.recheck();
    assert_eq!(rebuilt.dag.len(), 1);
    assert!(
        rebuilt
            .dag
            .artifact_state()
            .contains_proof(standalone.proof_id())
    );
    assert_eq!(
        rebuilt
            .dag
            .artifact(artifact_id)
            .unwrap()
            .as_proof()
            .unwrap()
            .proof_id(),
        standalone.proof_id()
    );
}

#[test]
fn selected_definition_use_composes_through_a_cited_proof_and_dependent_inference() {
    let mut context = CheckedContext::default();
    let definition = admit_source(
        &mut context,
        include_str!("../../../examples/reflexive-relation.nao"),
    );
    let definition_id = compiled_definition_id(&definition);

    let proof_source = r#"
foundation = "naome:zfc"
definitions:
    self_equal = "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
statement = forall(x,
    implies(self_equal(x,), implies(self_equal(x), self_equal(x)))
)
proof:
    p0 = simplification(self_equal(x), self_equal(x))
    p1 = generalization(p0, x)
    return p1
"#;
    let proof =
        compile_artifact_against_proof_context(proof_source, context.dag.artifact_state()).unwrap();
    let proof_output = compiled_proof(&proof);
    assert_eq!(proof_output.canonical_proof_bytes().len(), 106);
    assert_eq!(
        proof_output.statement_id(),
        StatementId::from_bytes(hex32(
            "dcbc10a2953eca4bd0b43b493023b8501d2bc04bae94a634dd13b546301e2bff"
        ))
    );
    assert_eq!(
        proof_output.derivation_id(),
        DerivationId::from_bytes(hex32(
            "a235541e92c035c22a53f2d962989eb459a1c441d23c1344c27ddee6a556ffab"
        ))
    );
    assert_eq!(
        proof_output.proof_id(),
        ProofId::from_bytes(hex32(
            "c4f94a3296bb92551a6f6c74042565e1b1ed870338a4ccc039e7117c28aefbdd"
        ))
    );
    let proof_id = proof_output.proof_id();
    admit_compiled(&mut context, &proof);

    let cited_source = format!(
        r#"
foundation = "naome:zfc"
definitions:
    self_equal = "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
statement = forall(y,
    implies(self_equal(y), implies(self_equal(y), self_equal(y)))
)
proof:
    p0 = cite("{}")
    p1 = universal_instantiation(
        x,
        y,
        implies(self_equal(x), implies(self_equal(x), self_equal(x))),
    )
    p2 = modus_ponens(p0, p1)
    p3 = generalization(p2, y)
    return p3
"#,
        hex_string(proof_id.as_bytes())
    );
    let cited = compile_artifact_against_proof_context(&cited_source, context.dag.artifact_state())
        .unwrap();
    let cited_output = compiled_proof(&cited);
    assert_eq!(cited_output.canonical_proof_bytes().len(), 196);
    assert_eq!(cited_output.statement_id(), proof_output.statement_id());
    assert_eq!(
        cited_output.derivation_id(),
        DerivationId::from_bytes(hex32(
            "77bcb5660b69e4e08231d04c4b3438006e368f3cbf64461d95a2a576a1763137"
        ))
    );
    assert_eq!(
        cited_output.proof_id(),
        ProofId::from_bytes(hex32(
            "2f7195742ff24f09d4dc90a2366fbc5e3866c6637015e0293193b1a4fd293187"
        ))
    );
    let cited_id = cited_output.proof_id();
    let cited_artifact_id = cited.artifact_id();
    let cited_certificate =
        ProofCertificate::from_canonical_bytes(cited_output.canonical_proof_bytes()).unwrap();
    assert!(matches!(
        cited_certificate.steps(),
        [
            ProofStep::ProofReference {
                proof_id: referenced
            },
            ProofStep::UniversalInstantiation { .. },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1
            },
            ProofStep::Generalization { premise: 2, .. }
        ] if *referenced == proof_id
    ));
    admit_compiled(&mut context, &cited);
    let rebuilt = context.recheck();
    let state = rebuilt.dag.artifact_state();
    assert!(state.contains_definition(definition_id));
    assert!(state.contains_proof(proof_id));
    assert!(state.contains_proof(cited_id));
    let cited_record = rebuilt
        .dag
        .artifact(cited_artifact_id)
        .unwrap()
        .as_proof()
        .unwrap();
    assert_eq!(cited_record.direct_proof_dependencies(), &[proof_id]);
    assert_eq!(
        cited_record.direct_definition_dependencies(),
        &[definition_id]
    );
    let replayed =
        compile_artifact_against_proof_context(&cited_source, rebuilt.dag.artifact_state())
            .unwrap();
    assert_eq!(replayed, cited);
}

#[test]
fn exact_context_registration_is_required_and_compilation_is_read_only() {
    let dependency = compile(SELF_EQUALITY).unwrap();
    let source = reference_source(dependency.proof_id());
    let monolithic = compile(NESTED_SELF_EQUALITY).unwrap();
    let mut context = CheckedContext::default();
    // A checked certificate in another context does not resolve this reference.
    let mut other = CheckedContext::default();
    other
        .admit(
            ArtifactId::from_proof_id(dependency.proof_id()),
            proof_artifact_bytes(&dependency),
        )
        .unwrap();
    assert_unknown_reference(
        compile_against_proof_context(&source, context.dag.artifact_state()),
        dependency.proof_id(),
    );
    assert!(context.dag.is_empty());
    context
        .admit(
            ArtifactId::from_proof_id(dependency.proof_id()),
            proof_artifact_bytes(&dependency),
        )
        .unwrap();
    let before = context.payloads.clone();
    let root = context.dag.artifact_set_root();
    let compiled = compile_against_proof_context(&source, context.dag.artifact_state()).unwrap();
    assert_eq!(compiled.statement_id(), monolithic.statement_id());
    assert_eq!(compiled.derivation_id(), monolithic.derivation_id());
    assert_ne!(compiled.derivation_id(), dependency.derivation_id());
    assert_ne!(compiled.proof_id(), dependency.proof_id());
    assert_ne!(compiled.proof_id(), monolithic.proof_id());
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    assert!(
        matches!(certificate.steps(), [ProofStep::ProofReference { proof_id },
        ProofStep::Generalization { premise: 0, .. }] if *proof_id == dependency.proof_id())
    );
    // Neither matching statement nor matching derivation substitutes for an ID.
    for wrong in [monolithic.proof_id(), ProofId::from_bytes([0xff; 32])] {
        assert_unknown_reference(
            compile_against_proof_context(&reference_source(wrong), context.dag.artifact_state()),
            wrong,
        );
    }
    assert_eq!(context.payloads, before);
    assert_eq!(context.dag.artifact_set_root(), root);
    assert_eq!(context.dag.len(), 1);
    assert!(
        !context
            .dag
            .artifact_state()
            .contains_proof(compiled.proof_id())
    );
    let rebuilt = context.recheck();
    assert_eq!(
        compile_against_proof_context(&source, rebuilt.dag.artifact_state()).unwrap(),
        compiled
    );
}

#[test]
fn only_exact_checked_definition_registration_enables_aliases() {
    let definition =
        compile_artifact(include_str!("../../../examples/reflexive-relation.nao")).unwrap();
    let id = compiled_definition_id(&definition);
    let source = include_str!("../../../examples/reflexive-relation-alias.nao");
    let mut other = CheckedContext::default();
    admit_compiled(&mut other, &definition);
    let mut context = CheckedContext::default();
    assert!(
        matches!(compile_artifact_against_proof_context(source, context.dag.artifact_state()),
        Err(CompileError::DefinitionNotSelected { definition_id, .. }) if definition_id == id)
    );
    assert!(context.dag.is_empty());
    admit_compiled(&mut context, &definition);
    let before = context.payloads.clone();
    let root = context.dag.artifact_set_root();
    let compiled =
        compile_artifact_against_proof_context(source, context.dag.artifact_state()).unwrap();
    assert_eq!(compiled, definition);
    assert_eq!(compiled_definition_id(&compiled), id);
    assert!(
        context
            .admit(compiled.artifact_id(), compiled.canonical_artifact_bytes())
            .is_err()
    );
    assert_eq!(context.payloads, before);
    assert_eq!(context.dag.artifact_set_root(), root);
    assert_eq!(context.dag.len(), 1);
}
