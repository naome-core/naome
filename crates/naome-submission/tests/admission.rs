use ed25519_dalek::{Signer, SigningKey};
use naome_checker::normalize_and_check;
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactId, ProofCertificate, ProofStep};
use naome_submission::{Admission, Configuration, MAX_BYTES, SignedRequest, Submission, hex};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn certificate() -> ProofCertificate {
    ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(0),
        },
    ])
    .unwrap()
}
fn context(dependencies: Vec<String>) -> Admission {
    Admission::from_configuration(
        &serde_json::to_vec(&Configuration {
            session: "offline-test-1".into(),
            participants: vec![hex(key().verifying_key().as_bytes())],
            dependencies,
        })
        .unwrap(),
    )
    .unwrap()
}
fn signed(admission: &Admission, nonce: u64, submission: &Submission) -> Vec<u8> {
    let mut request = SignedRequest {
        context: admission.context().into(),
        key: hex(key().verifying_key().as_bytes()),
        nonce,
        payload: serde_json::to_string(submission).unwrap(),
        signature: String::new(),
    };
    request.signature = hex(&key().sign(&request.signing_bytes().unwrap()).to_bytes());
    serde_json::to_vec(&request).unwrap()
}
fn question(source: &str) -> Submission {
    Submission::Question {
        source: source.into(),
    }
}
fn reflexivity() -> Submission {
    question(include_str!("fixtures/question.nao"))
}
fn candidate(question: &str, certificate: String, dependencies: Vec<String>) -> Submission {
    Submission::ProofCandidate {
        question: question.into(),
        refutation: false,
        certificate,
        dependencies,
    }
}

#[test]
fn three_apis_and_authenticated_idempotency() {
    let mut admission = context(vec![]);
    let input = signed(&admission, 1, &reflexivity());
    let receipt = admission.submit(&input).unwrap();
    let mut duplicate = receipt.clone();
    duplicate.duplicate = true;
    assert_eq!(admission.submit(&input).unwrap(), duplicate);
    let evaluation = signed(
        &admission,
        2,
        &Submission::Evaluation {
            question: receipt.object.clone(),
            interested: true,
            rationale: "Human supplied interest".into(),
        },
    );
    assert_eq!(
        admission.submit(&evaluation).unwrap().kind,
        "advisory_evaluation_admitted"
    );
    let proof = signed(
        &admission,
        3,
        &candidate(
            &receipt.object,
            hex(&certificate().to_canonical_bytes()),
            vec![],
        ),
    );
    let checked = admission.submit(&proof).unwrap();
    assert_eq!(checked.kind, "checker_valid_candidate");
    assert_eq!(
        checked.proof.as_deref(),
        Some(
            hex(normalize_and_check(certificate())
                .unwrap()
                .proof_id()
                .as_bytes())
            .as_str()
        )
    );
    assert!(!checked.selected && !checked.finalized);
    assert_eq!(admission.submit(&proof).unwrap().proof, checked.proof);
}

#[test]
fn failures_leave_nonce_and_state_unchanged() {
    let mut admission = context(vec![]);
    assert_eq!(admission.submit(b"{}"), Err("request_schema"));
    assert_eq!(
        admission.submit(&vec![b' '; MAX_BYTES + 1]),
        Err("frame_limit")
    );
    assert_eq!(
        admission.submit(&signed(&admission, 1, &question("invalid"))),
        Err("question")
    );
    let input = signed(&admission, 1, &reflexivity());
    let mut request: SignedRequest = serde_json::from_slice(&input).unwrap();
    request.context = "00".repeat(32);
    assert_eq!(
        admission.submit(&serde_json::to_vec(&request).unwrap()),
        Err("context")
    );
    request = serde_json::from_slice(&input).unwrap();
    request.signature = "00".repeat(64);
    assert_eq!(
        admission.submit(&serde_json::to_vec(&request).unwrap()),
        Err("signature")
    );
    request = serde_json::from_slice(&input).unwrap();
    request.payload.push(' ');
    assert_eq!(
        admission.submit(&serde_json::to_vec(&request).unwrap()),
        Err("signature")
    );
    let q = admission.submit(&input).unwrap().object;
    assert_eq!(
        admission.submit(&signed(&admission, 3, &reflexivity())),
        Err("nonce")
    );
    assert_eq!(
        admission.submit(&signed(&admission, 2, &reflexivity())),
        Err("question_exists")
    );
    assert_eq!(
        admission.submit(&signed(&admission, 2, &candidate(&q, "00".into(), vec![]))),
        Err("certificate")
    );
    assert_eq!(
        admission.submit(&signed(
            &admission,
            2,
            &candidate(&q, "00".repeat(16385), vec![])
        )),
        Err("hex_limit")
    );
    let open = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0),
    }])
    .unwrap();
    assert_eq!(
        admission.submit(&signed(
            &admission,
            2,
            &candidate(&q, hex(&open.to_canonical_bytes()), vec![])
        )),
        Err("mathematical")
    );
    assert_eq!(
        admission.submit(&signed(
            &admission,
            2,
            &candidate(
                &q,
                hex(&certificate().to_canonical_bytes()),
                vec!["00".repeat(32)]
            )
        )),
        Err("dependencies")
    );
    let wrong = admission
        .submit(&signed(
            &admission,
            2,
            &question("foundation = \"naome:zfc\" statement = forall(x, forall(y, equal(x,x)))"),
        ))
        .unwrap()
        .object;
    assert_eq!(
        admission.submit(&signed(
            &admission,
            3,
            &candidate(&wrong, hex(&certificate().to_canonical_bytes()), vec![])
        )),
        Err("target")
    );
    admission
        .submit(&signed(
            &admission,
            3,
            &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![]),
        ))
        .unwrap();
    let mut unknown =
        serde_json::to_value(serde_json::from_slice::<SignedRequest>(&input).unwrap()).unwrap();
    unknown["model"] = serde_json::json!("forbidden-field");
    assert_eq!(
        admission.submit(&serde_json::to_vec(&unknown).unwrap()),
        Err("request_schema")
    );
}

#[test]
fn dependencies_are_exact_and_frozen() {
    let base = normalize_and_check(certificate()).unwrap();
    let id = base.proof_id();
    let dep = hex(ArtifactId::from_proof_id(id).as_bytes());
    let reference =
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: id }]).unwrap();
    let proof = hex(&reference.to_canonical_bytes());
    let mut empty = context(vec![]);
    let q = empty
        .submit(&signed(&empty, 1, &reflexivity()))
        .unwrap()
        .object;
    // Earlier accepted candidates do not acquire dependency authority.
    empty
        .submit(&signed(
            &empty,
            2,
            &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![]),
        ))
        .unwrap();
    assert_eq!(
        empty.submit(&signed(
            &empty,
            3,
            &candidate(&q, proof.clone(), vec![dep.clone()])
        )),
        Err("mathematical")
    );
    let mut populated = context(vec![hex(&certificate().to_canonical_bytes())]);
    assert_ne!(empty.context(), populated.context());
    let q = populated
        .submit(&signed(&populated, 1, &reflexivity()))
        .unwrap()
        .object;
    assert_eq!(
        populated.submit(&signed(
            &populated,
            2,
            &candidate(&q, proof.clone(), vec![])
        )),
        Err("dependencies")
    );
    populated
        .submit(&signed(
            &populated,
            2,
            &candidate(&q, proof.clone(), vec![dep.clone()]),
        ))
        .unwrap();
    assert_eq!(
        populated.submit(&signed(
            &populated,
            3,
            &candidate(&q, proof, vec![dep.clone(), dep])
        )),
        Err("dependencies_not_sorted_unique")
    );
}

#[test]
fn context_and_author_limits_and_advisory_semantics() {
    let mut admission = context(vec![]);
    let q = admission
        .submit(&signed(&admission, 1, &reflexivity()))
        .unwrap()
        .object;
    let negative = Submission::Evaluation {
        question: q.clone(),
        interested: false,
        rationale: "Not my interest".into(),
    };
    admission.submit(&signed(&admission, 2, &negative)).unwrap();
    assert_eq!(
        admission.submit(&signed(&admission, 3, &negative)),
        Err("evaluation_exists")
    );
    // A negative preference never prevents mathematical acceptance.
    admission
        .submit(&signed(
            &admission,
            3,
            &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![]),
        ))
        .unwrap();
    for nonce in 4..=32 {
        admission
            .submit(&signed(
                &admission,
                nonce,
                &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![]),
            ))
            .unwrap();
    }
    assert_eq!(
        admission.submit(&signed(
            &admission,
            33,
            &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![])
        )),
        Err("admission_limit")
    );
    assert!(
        Admission::from_configuration(br#"{"session":"x","participants":[],"dependencies":[]}"#)
            .is_err()
    );
    let mut cfg = Configuration {
        session: "x".into(),
        participants: vec![hex(key().verifying_key().as_bytes()); 2],
        dependencies: vec![],
    };
    assert!(Admission::from_configuration(&serde_json::to_vec(&cfg).unwrap()).is_err());
    cfg.participants.pop();
    cfg.dependencies.push("00".into());
    assert!(Admission::from_configuration(&serde_json::to_vec(&cfg).unwrap()).is_err());
}

#[test]
fn strict_sources_keys_and_normal_forms_are_required() {
    let mut admission = context(vec![]);
    assert_eq!(
        admission.submit(&signed(&admission, 1, &question(&" ".repeat(16385)))),
        Err("question")
    );
    assert_eq!(
        admission.submit(&signed(
            &admission,
            1,
            &question("foundation = \"naome:zfc\" statement = equal(x,x)")
        )),
        Err("question")
    );
    let q = admission
        .submit(&signed(&admission, 1, &reflexivity()))
        .unwrap()
        .object;
    let mut raw: SignedRequest =
        serde_json::from_slice(&signed(&admission, 2, &reflexivity())).unwrap();
    let outsider = SigningKey::from_bytes(&[9; 32]);
    raw.key = hex(outsider.verifying_key().as_bytes());
    raw.signature = hex(&outsider.sign(&raw.signing_bytes().unwrap()).to_bytes());
    assert_eq!(
        admission.submit(&serde_json::to_vec(&raw).unwrap()),
        Err("account")
    );
    let excessive = Submission::Evaluation {
        question: q.clone(),
        interested: true,
        rationale: " ".repeat(1025),
    };
    assert_eq!(
        admission.submit(&signed(&admission, 2, &excessive)),
        Err("rationale_limit")
    );
    let mut steps = certificate().steps().to_vec();
    steps.push(ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0),
    });
    steps.push(ProofStep::Generalization {
        premise: 2,
        variable: FreeVariable::new(0),
    });
    let duplicate = ProofCertificate::new(steps).unwrap();
    assert_eq!(
        admission.submit(&signed(
            &admission,
            2,
            &candidate(&q, hex(&duplicate.to_canonical_bytes()), vec![])
        )),
        Err("non_normal_certificate")
    );
    let mut malformed_payload: SignedRequest =
        serde_json::from_slice(&signed(&admission, 2, &reflexivity())).unwrap();
    malformed_payload.payload = "{\"command\":\"generate_proof\"}".into();
    malformed_payload.signature = hex(&key()
        .sign(&malformed_payload.signing_bytes().unwrap())
        .to_bytes());
    assert_eq!(
        admission.submit(&serde_json::to_vec(&malformed_payload).unwrap()),
        Err("submission_schema")
    );
    admission
        .submit(&signed(
            &admission,
            2,
            &candidate(&q, hex(&certificate().to_canonical_bytes()), vec![]),
        ))
        .unwrap();
}

#[test]
fn refutation_binds_one_exact_syntactic_negation() {
    let mut admission = context(vec![]);
    let q = admission
        .submit(&signed(
            &admission,
            1,
            &question("foundation = \"naome:zfc\" statement = not_(forall(x,equal(x,x)))"),
        ))
        .unwrap()
        .object;
    // A proof of reflexivity alone cannot refute its negation without proving
    // the exact double-negated target. No implicit classical reduction occurs.
    let body = Submission::ProofCandidate {
        question: q,
        refutation: true,
        certificate: hex(&certificate().to_canonical_bytes()),
        dependencies: vec![],
    };
    assert_eq!(
        admission.submit(&signed(&admission, 2, &body)),
        Err("target")
    );
}

#[test]
fn global_admission_ceiling_rejects_without_evicting_receipts() {
    let keys: Vec<_> = (7..=11)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let config = Configuration {
        session: "global-bound".into(),
        participants: keys
            .iter()
            .map(|key| hex(key.verifying_key().as_bytes()))
            .collect(),
        dependencies: vec![],
    };
    let mut admission =
        Admission::from_configuration(&serde_json::to_vec(&config).unwrap()).unwrap();
    let request = signed(&admission, 1, &reflexivity());
    let q = admission.submit(&request).unwrap().object;
    for (index, key) in keys[..4].iter().enumerate() {
        for nonce in (if index == 0 { 2 } else { 1 })..=32 {
            let mut request = SignedRequest {
                context: admission.context().into(),
                key: hex(key.verifying_key().as_bytes()),
                nonce,
                payload: serde_json::to_string(&candidate(
                    &q,
                    hex(&certificate().to_canonical_bytes()),
                    vec![],
                ))
                .unwrap(),
                signature: String::new(),
            };
            request.signature = hex(&key.sign(&request.signing_bytes().unwrap()).to_bytes());
            admission
                .submit(&serde_json::to_vec(&request).unwrap())
                .unwrap();
        }
    }
    let mut extra = SignedRequest {
        context: admission.context().into(),
        key: hex(keys[4].verifying_key().as_bytes()),
        nonce: 1,
        payload: serde_json::to_string(&candidate(
            &q,
            hex(&certificate().to_canonical_bytes()),
            vec![],
        ))
        .unwrap(),
        signature: String::new(),
    };
    extra.signature = hex(&keys[4].sign(&extra.signing_bytes().unwrap()).to_bytes());
    assert_eq!(
        admission.submit(&serde_json::to_vec(&extra).unwrap()),
        Err("admission_limit")
    );
    assert!(admission.submit(&request).unwrap().duplicate);
}
