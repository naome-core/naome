use anyhow::Result;
use naome_protocol::{
    evaluation::{self, Query, Standing, Status},
    executor::{Dispatch, Request},
    fixture::{self, put},
    kit,
    learning::{Example, TrainingRequest},
    profile::{self, Document, Kind, PUBLIC, READ_ONLY, link},
    store::Archive,
    wire::{Format, Id, Record, Term},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use tempfile::tempdir;

#[test]
fn both_kits_and_published_identifiers() -> Result<()> {
    for (f, len, digest) in [
        (
            Format::A,
            80,
            "48367bebac79d394b4e13f004988c1141c977b295574ceafd716f29e39732dab",
        ),
        (
            Format::B,
            237,
            "6e56a2da3546ca07d9e693089c0f240c72a754592e91abf7894a4cb413d7d390",
        ),
    ] {
        let cases = kit::test(kit::bytes(f), &kit::pin(f))?;
        assert_eq!(cases.len(), 6);
        assert!(cases.iter().all(|c| c.matches));
        assert!(kit::test(kit::bytes(f), "untrusted").is_err());
        let r = Record {
            kind: 0,
            profile: format!("1:1:{}", "00".repeat(32)).parse()?,
            body: Term::Uint(200),
            access: format!("1:1:{}", "00".repeat(32)).parse()?,
            edges: vec![],
            critical: vec![],
        };
        let bytes = r.encode(f);
        assert_eq!(bytes.len(), len);
        assert!(Id::record(f, &bytes).to_string().ends_with(digest));
        assert_eq!(Record::decode(&bytes, f)?, r);
        for n in [0, 23, 24, 255, 256, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let t = Term::Uint(n);
            assert_eq!(Term::decode(&t.encode(f), f)?, t);
        }
        let t = Term::Text("line\n\u{0001}ß😀\u{2028}".into());
        assert_eq!(Term::decode(&t.encode(f), f)?, t);
    }
    Ok(())
}
#[test]
fn full_exchange_is_reproducible_from_reopened_databases() -> Result<()> {
    let dir = tempdir()?;
    let results = fixture::trial(dir.path())?;
    let west = Archive::open(dir.path().join("west.sqlite"))?;
    let s1 = west.head(serde_json::from_value(results["S1"].clone())?)?;
    let qs: Vec<Query> = serde_json::from_value(results["native_queries"].clone())?;
    let r = evaluation::assess(&west, &s1, &qs[2])?;
    assert_eq!(r.result, Some(Standing::Refuted));
    assert_eq!(r.branches[0]["joint"], json!([150, 200]));
    let old = west.head(serde_json::from_value(results["fixture"]["s0"].clone())?)?;
    let original: Vec<Query> = serde_json::from_value(results["fixture"]["queries"].clone())?;
    assert_eq!(
        evaluation::assess(&west, &old, &original[2])?.result,
        Some(Standing::Supported)
    );
    let id: Id = serde_json::from_value(results["fixture"]["receipts"][2].clone())?;
    let mapping: Id = serde_json::from_value(results["mapping"].clone())?;
    let pairs = west.verify_mapping(&s1, mapping)?;
    let sig = west
        .discover(
            &s1,
            Some(Kind::Attestation),
            None,
            None,
            "read",
            10000,
            None,
        )?
        .ids
        .into_iter()
        .filter_map(|i| west.read(&s1, i, "read").ok())
        .find(|d| d.one("signed-original").ok() == Some(id))
        .expect("original signature");
    let trusted = [hex::encode(
        fixture::fixture_key(4).verifying_key().to_bytes(),
    )]
    .into();
    profile::verify_attestation(
        &sig,
        id,
        "transition-1",
        "assessor",
        "research-policy-1",
        &trusted,
    )?;
    assert!(
        profile::verify_attestation(
            &sig,
            pairs[&id],
            "transition-1",
            "assessor",
            "research-policy-1",
            &trusted
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn opaque_records_travel_partial_search_reports_frontier_and_withdrawal_survives_reimport()
-> Result<()> {
    let a = Archive::memory()?;
    let mut b = Archive::memory()?;
    let public = Id::blob(PUBLIC);
    let r = Record {
        kind: 42,
        profile: Id::blob(b"unpublished"),
        access: public,
        edges: vec![],
        critical: vec![99],
        body: Term::Uint(0),
    };
    let id = a.record(&r, Format::A)?;
    let blob = a.blob(b"retirable", public)?;
    let s = a.snapshot("archive", BTreeSet::new())?;
    let bundle = a.export(&s, "read")?;
    b.import(&bundle)?;
    assert_eq!(b.resolve(&s, id, "read")?, r.encode(Format::A));
    assert!(b.read(&s, id, "read").is_err());
    let limited = b.explain(&s, &[id], "read", 1, 10);
    assert!(limited.frontier.contains_key(&r.profile));
    let first = b.discover(&s, None, None, None, "read", 1, None)?;
    let second = b.discover(&s, None, None, None, "read", 1, first.after)?;
    assert_ne!(first.after, second.after);
    b.withdraw(blob)?;
    b.import(&bundle)?;
    assert!(b.resolve(&s, blob, "read").is_err());
    let mut broken = a.export(&s, "read")?;
    broken.packets.last_mut().unwrap().hex.push_str("01");
    let mut fresh = Archive::memory()?;
    assert!(fresh.import(&broken).is_err());
    assert!(fresh.head(s.id()?).is_err());
    assert!(
        !fresh
            .snapshot("empty", BTreeSet::new())?
            .objects
            .contains(&id)
    );
    Ok(())
}
#[test]
fn partition_rivals_scope_unknown_and_budget() -> Result<()> {
    let a = Archive::memory()?;
    let i = fixture::seed(&a, Format::A)?;
    let initial = a.head(i.s0)?;
    let mut q = i.queries[2].clone();
    q.current_at = Some(100);
    assert_eq!(
        evaluation::assess(&a, &initial, &q)?.result,
        Some(Standing::Unresolved)
    );
    q.current_at = None;
    q.budget = 1;
    assert!(!evaluation::assess(&a, &initial, &q)?.frontier.is_empty());
    q.budget = 10000;
    fixture::notice(&a, Format::A, i.calibration, 10, 2)?;
    let only_m = a.snapshot("east", [i.s0].into())?;
    assert_eq!(
        evaluation::assess(&a, &only_m, &q)?.branches[0]["joint"],
        json!([220, 270])
    );
    let n = fixture::notice(&a, Format::A, i.calibration, 80, 1)?;
    let both = a.snapshot("east", [only_m.id()?].into())?;
    let r = evaluation::assess(&a, &both, &q)?;
    assert_eq!(r.result, Some(Standing::Contested));
    assert_eq!(r.applicable_notices.len(), 2);
    assert!(!r.obligations.is_empty());
    let impact = a.impact(&both, n, &[], both.objects.len())?;
    assert_eq!(impact.by_kind["label"].len(), 4);
    assert!(
        i.labels
            .iter()
            .all(|id| impact.by_kind["label"].contains(id))
    );
    assert!(
        !impact
            .by_kind
            .values()
            .any(|v| v.contains(&i.control) || v.contains(&i.control_label))
    );
    Ok(())
}
#[test]
fn learning_cutoff_permissions_independence_and_false_labels() -> Result<()> {
    let a = Archive::memory()?;
    let f = Format::A;
    let i = fixture::seed(&a, f)?;
    let s = a.head(i.published)?;
    let plan = a.read(&s, i.queries[0].arguments[0], "read")?.one("plan")?;
    let req = TrainingRequest {
        feature_cutoff: i.feature_cutoff,
        forecast_plan: Some(plan),
        mappings: vec![],
        label_head: i.published,
        policy: i.policy,
        standing: Default::default(),
        project: None,
        examples: vec![
            Example {
                features: vec![plan],
                label: i.labels[0],
                partition: "train".into(),
            },
            Example {
                features: vec![plan],
                label: i.labels[1],
                partition: "test".into(),
            },
            Example {
                features: vec![i.control],
                label: i.labels[2],
                partition: "train".into(),
            },
        ],
        independent_roles: ["calibration".into()].into(),
        binary: true,
    };
    let m = a.training_manifest(&req, f)?;
    assert_eq!(m.included, vec![i.labels[0]]);
    assert_eq!(m.withheld.len(), 2);
    let mut d = a.read(&s, i.labels[0], "read")?;
    d.fields.insert("value".into(), json!("fail"));
    let wrong = a.document(&d, f, Id::blob(PUBLIC))?;
    let sealed = a.document(&a.read(&s, plan, "read")?, f, Id::blob(READ_ONLY))?;
    let head = a.snapshot("later", [s.id()?].into())?.id()?;
    let req = TrainingRequest {
        feature_cutoff: head,
        label_head: head,
        examples: vec![
            Example {
                features: vec![plan],
                label: wrong,
                partition: "train".into(),
            },
            Example {
                features: vec![sealed],
                label: i.labels[3],
                partition: "train".into(),
            },
        ],
        ..req
    };
    assert!(a.training_manifest(&req, f)?.included.is_empty());
    assert!(a.export(&a.head(head)?, "train")?.omitted.contains(&sealed));
    Ok(())
}

fn argument_case(
    method: &str,
    claim: Value,
    inputs: impl FnOnce(&Archive) -> Result<Vec<profile::Link>>,
    fields: Value,
) -> Result<evaluation::Receipt> {
    let a = Archive::memory()?;
    let f = Format::B;
    let policy = fixture::policy(&a, f)?;
    let c = put(&a, f, Kind::Claim, "subject", "scope", claim, vec![])?;
    let mut links = inputs(&a)?;
    links.push(link("claim", c));
    let mut body = fields;
    body["method"] = json!(method);
    let arg = put(&a, f, Kind::Argument, "subject", "scope", body, links)?;
    evaluation::assess(
        &a,
        &a.snapshot("case", BTreeSet::new())?,
        &Query {
            target: c,
            arguments: vec![arg],
            policy,
            budget: 1000,
            byte_limit: 64 * 1024 * 1024,
            mappings: vec![],
            previous_receipts: vec![],
            required_notices: vec![],
            current_at: None,
        },
    )
}
#[test]
fn unit_mapping_requires_definitions_and_distinguishing_evidence() -> Result<()> {
    for (functional, domain, known, expected) in [
        ("endpoint-change", 1000, true, Standing::Supported),
        ("endpoint-change", 200, true, Standing::Refuted),
        ("peak-to-peak", 1000, true, Standing::Refuted),
        ("endpoint-change", 1000, false, Standing::Unresolved),
    ] {
        let r = argument_case(
            "unit-grid-map",
            json!({"predicate":"exact-translation"}),
            |a| {
                let mut inputs = vec![];
                for (role, unit, m, max) in [
                    ("source-profile", "um", "endpoint-change", 1000),
                    ("target-profile", "mm", functional, domain),
                ] {
                    let mut fields = json!({"unit":unit,"functional":m,"max_um":max,"step_um":1});
                    if !known {
                        fields.as_object_mut().unwrap().remove("functional");
                    }
                    inputs.push(link(
                        role,
                        put(
                            a,
                            Format::B,
                            Kind::Profile,
                            "subject",
                            "scope",
                            fields,
                            vec![],
                        )?,
                    ));
                }
                for trace in [vec![0, 0], vec![0, 200], vec![0, 250], vec![0, 260, 180]] {
                    inputs.push(link(
                        "trace",
                        put(
                            a,
                            Format::B,
                            Kind::Occurrence,
                            "subject",
                            "scope",
                            json!({"positions_um":trace}),
                            vec![],
                        )?,
                    ));
                }
                Ok(inputs)
            },
            json!({}),
        )?;
        assert_eq!(r.result, Some(expected));
        if known && functional == "peak-to-peak" {
            assert_eq!(r.branches[1]["witness"]["target_um"], 260);
            assert_eq!(r.branches[1]["witness"]["source_um"], 180);
        }
    }
    Ok(())
}
#[test]
fn restricted_proof_does_not_promote_the_theorem() -> Result<()> {
    let r = argument_case(
        "least-zero",
        json!({"predicate":"least-element","domain":"finite-nat-sets-containing-zero"}),
        |a| {
            Ok(vec![link(
                "proof",
                put(
                    a,
                    Format::B,
                    Kind::Derivation,
                    "subject",
                    "scope",
                    json!({"kernel":"nat-order-zero-v1","steps":["member-zero","zero-le-every-nat","least-intro"]}),
                    vec![],
                )?,
            )])
        },
        json!({}),
    )?;
    assert_eq!(r.result, Some(Standing::Supported));
    let coverage = argument_case(
        "domain-inclusion",
        json!({"predicate":"covers-domain","domain":"nonempty-finite-nat-sets"}),
        |a| {
            Ok(vec![link(
                "restricted",
                put(
                    a,
                    Format::B,
                    Kind::Claim,
                    "subject",
                    "scope",
                    json!({"domain":"finite-nat-sets-containing-zero"}),
                    vec![],
                )?,
            )])
        },
        json!({"witness":[3]}),
    )?;
    assert_eq!(coverage.result, Some(Standing::Refuted));
    assert_eq!(coverage.branches[0]["counterexample"], json!([3]));
    Ok(())
}
#[test]
fn manuscript_and_survey_evidence_observes_shared_origins() -> Result<()> {
    let r = argument_case(
        "source-independence",
        json!({"predicate":"independent-witnesses"}),
        |a| {
            let m = put(
                a,
                Format::B,
                Kind::Occurrence,
                "subject",
                "scope",
                json!({"edition":"first"}),
                vec![],
            )?;
            (0..2)
                .map(|n| {
                    Ok(link(
                        "transcription",
                        put(
                            a,
                            Format::B,
                            Kind::Derivation,
                            "subject",
                            "scope",
                            json!({"edition":n}),
                            vec![link("manuscript", m)],
                        )?,
                    ))
                })
                .collect()
        },
        json!({}),
    )?;
    assert_eq!(r.result, Some(Standing::Refuted));
    for (method, pred, want) in [
        ("sample-description", "sample-reports", Standing::Supported),
        (
            "survey-identification",
            "population-effect",
            Standing::Unresolved,
        ),
    ] {
        let r = argument_case(
            method,
            json!({"predicate":pred,"count":2}),
            |a| {
                ["alice", "bob", "bob"]
                    .into_iter()
                    .enumerate()
                    .map(|(copy, unit)| {
                        Ok(link(
                            "response",
                            put(
                                a,
                                Format::B,
                                Kind::Occurrence,
                                "subject",
                                "scope",
                                json!({"population":"subject","respondent":unit,"copy":copy,"sampling_frame":"route-riders"}),
                                vec![],
                            )?,
                        ))
                    })
                    .collect()
            },
            json!({}),
        )?;
        assert_eq!(r.result, Some(want));
        assert_eq!(r.branches[0]["unique_reported_units"], 2);
    }
    Ok(())
}
#[test]
fn ambiguous_execution_survives_restart_and_shared_reservations() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("state");
    let a = Archive::open(&path)?;
    a.resource("samples", 1)?;
    let f = Format::A;
    let key = fixture::fixture_key(17);
    let trusted = BTreeSet::from([hex::encode(key.verifying_key().to_bytes())]);
    let auth = put(
        &a,
        f,
        Kind::Authority,
        "sample",
        "lab",
        json!({"actor":"station","operation":"observe","valid":[10,20],"ceilings":{"samples":1}}),
        vec![],
    )?;
    let sig = fixture::sign(&a, f, auth, "lab", "executor", 17)?;
    let decision = |name: &str| {
        put(
            &a,
            f,
            Kind::Decision,
            "sample",
            "lab",
            json!({"operation":"observe","attempt":name}),
            vec![link("authority", auth)],
        )
    };
    let mut req = Request {
        attempt: "1".into(),
        actor: "station".into(),
        subject: "sample".into(),
        operation: "observe".into(),
        decision: decision("1")?,
        authority: auth,
        signature: sig,
        costs: BTreeMap::from([("samples".into(), 1)]),
    };
    let second = decision("2")?;
    let s = a.snapshot("station", BTreeSet::new())?;
    drop(a);
    let mut a = Archive::open(&path)?;
    assert!(a.reserve(&s, &req, &trusted, 21).is_err());
    assert_eq!(a.reserve(&s, &req, &trusted, 12)?, Dispatch::Reserved);
    drop(a);
    let mut a = Archive::open(&path)?;
    assert_eq!(
        a.reserve(&s, &req, &trusted, 13)?,
        Dispatch::AlreadyRecorded {
            state: "execution-unknown".into(),
            witness: None
        }
    );
    let witness = put(
        &a,
        f,
        Kind::Occurrence,
        "sample",
        "lab",
        json!({"execution":"observed","attempt":"1"}),
        vec![link("decision", req.decision)],
    )?;
    let signed = fixture::sign(&a, f, witness, "lab", "readback", 17)?;
    let s = a.snapshot("station", [s.id()?].into())?;
    a.reconcile_attempt(&s, "1", witness, signed, &trusted)?;
    assert!(matches!(
        a.reserve(&s, &req, &trusted, 13)?,
        Dispatch::AlreadyRecorded {
            witness: Some(_),
            ..
        }
    ));
    req.decision = second;
    req.attempt = "2".into();
    assert!(a.reserve(&s, &req, &trusted, 13).is_err());
    Ok(())
}

#[test]
fn capture_compute_close_and_retry_without_redispatch() -> Result<()> {
    let mut a = Archive::memory()?;
    let f = Format::B;
    let public = Id::blob(PUBLIC);
    let bytes = b"abcabcab";
    let descriptor = a.capture(&bytes[..], "text/plain", 3, public, f)?;
    let question = put(
        &a,
        f,
        Kind::Question,
        "sample",
        "session",
        json!({"purpose":"verify retained bytes"}),
        vec![],
    )?;
    let plan = put(
        &a,
        f,
        Kind::Plan,
        "sample",
        "session",
        json!({"planned_count":1,"stopping":"one-payload","predicate":"exact-bytes"}),
        vec![link("descriptor", descriptor), link("question", question)],
    )?;
    let key = fixture::fixture_key(8);
    let keys = [hex::encode(key.verifying_key().to_bytes())].into();
    let auth = put(
        &a,
        f,
        Kind::Authority,
        "sample",
        "session",
        json!({"actor":"analyst","operation":"verify-payload","valid":[0,100],"ceilings":{"bytes":8}}),
        vec![],
    )?;
    let sig = fixture::sign(&a, f, auth, "session", "executor", 8)?;
    let d = put(
        &a,
        f,
        Kind::Decision,
        "sample",
        "session",
        json!({"attempt":"capture-1","operation":"verify-payload"}),
        vec![link("authority", auth), link("plan", plan)],
    )?;
    a.resource("bytes", 8)?;
    let s = a.snapshot("fixture", BTreeSet::new())?;
    let mut output = vec![];
    a.materialize(&s, descriptor, "read", 8, &mut output)?;
    assert_eq!(output, bytes);
    assert!(
        a.materialize(&s, descriptor, "read", 7, std::io::sink())
            .is_err()
    );
    let mut altered = a.read(&s, descriptor, "read")?;
    altered.inputs.swap(0, 1);
    let invalid = a.document(&altered, f, public)?;
    assert!(
        a.materialize(
            &a.snapshot("altered", BTreeSet::new())?,
            invalid,
            "read",
            8,
            std::io::sink()
        )
        .is_err()
    );
    let req = Request {
        attempt: "capture-1".into(),
        actor: "analyst".into(),
        subject: "sample".into(),
        operation: "verify-payload".into(),
        decision: d,
        authority: auth,
        signature: sig,
        costs: [("bytes".into(), 8)].into(),
    };
    let first = a.execute_payload_check(&s, &req, &keys, &key, 50, f)?;
    assert_eq!(first.state, "observed");
    let closed = first.closure.unwrap();
    let again = a.execute_payload_check(&s, &req, &keys, &key, 51, f)?;
    assert_eq!(again.closure, Some(closed));
    let head = a.snapshot("complete", [s.id()?].into())?;
    assert_eq!(
        a.read(&head, closed, "read")?.field::<String>("result")?,
        "success"
    );
    Ok(())
}

#[test]
fn controlled_test_exemptions_require_witness_and_a_scientific_pass() -> Result<()> {
    let a = Archive::memory()?;
    let f = Format::A;
    let public = Id::blob(PUBLIC);
    let key = hex::encode(fixture::fixture_key(22).verifying_key().to_bytes());
    let policy = put(
        &a,
        f,
        Kind::Policy,
        "board",
        "research-policy-1",
        json!({"keys":{"reviewer":[key]},"rules":{"attribution":{"predicate":"attributed","polarity":"pro","required":["attribution","read-content"],"scientific":["attribution"],"exemptions":{"read-content":"sealed-custody"},"role":"reviewer"}}}),
        vec![],
    )?;
    let claim = put(
        &a,
        f,
        Kind::Claim,
        "testimony",
        "edition",
        json!({"predicate":"attributed"}),
        vec![],
    )?;
    let mk = |name: &str, status: Status| -> Result<Id> {
        let id = put(
            &a,
            f,
            Kind::Assessment,
            "testimony",
            "edition",
            json!({"rule":"attribution","test":name,"status":status}),
            vec![link("claim", claim)],
        )?;
        fixture::sign(&a, f, id, "edition", "reviewer", 22)?;
        Ok(id)
    };
    let attribution = mk("attribution", Status::Pass)?;
    let sealed = mk("read-content", Status::NotApplicable)?;
    let evidence = mk("sealed-custody", Status::Pass)?;
    let mut links = vec![
        link("claim", claim),
        link("test", attribution),
        link("test", sealed),
    ];
    let partial = put(
        &a,
        f,
        Kind::Argument,
        "testimony",
        "edition",
        json!({"rule":"attribution","method":"signed-tests"}),
        links.clone(),
    )?;
    links.push(link("test", evidence));
    let complete = put(
        &a,
        f,
        Kind::Argument,
        "testimony",
        "edition",
        json!({"rule":"attribution","method":"signed-tests"}),
        links,
    )?;
    let secret = a.blob(b"confidential testimony", Id::blob(READ_ONLY))?;
    let d = Document::new(
        Kind::Derivation,
        "testimony",
        "edition",
        json!({"method":"sealed transcription"}),
        vec![link("source", secret)],
    )?;
    let transcript = a.document(&d, f, public)?;
    let s = a.snapshot("custodian", BTreeSet::new())?;
    let mut q = Query {
        target: claim,
        arguments: vec![partial],
        policy,
        budget: 1000,
        byte_limit: 1000000,
        mappings: vec![],
        previous_receipts: vec![],
        required_notices: vec![],
        current_at: None,
    };
    assert_eq!(
        evaluation::assess(&a, &s, &q)?.result,
        Some(Standing::Unresolved)
    );
    q.arguments.push(complete);
    assert_eq!(
        evaluation::assess(&a, &s, &q)?.result,
        Some(Standing::Supported)
    );
    assert!(a.export(&s, "train")?.omitted.contains(&transcript));
    q.byte_limit = 8;
    assert!(!evaluation::assess(&a, &s, &q)?.frontier.is_empty());
    Ok(())
}

#[test]
fn finite_observation_value_uses_posterior_best_decisions() -> Result<()> {
    use naome_protocol::investigation::ObservationModel;
    let m = ObservationModel {
        losses: vec![vec![0, 10], vec![10, 0]],
        joint_masses: vec![vec![1, 0], vec![0, 1]],
        loss_unit: "points".into(),
        acquisition_cost: 1,
    };
    let value = m.evaluate()?;
    assert_eq!(
        (
            value.prior_loss_numerator,
            value.posterior_loss_numerator,
            value.net_gain_numerator,
            value.denominator
        ),
        (10, 0, 8, 2)
    );
    let uninformative = ObservationModel {
        joint_masses: vec![vec![1, 1]],
        ..m
    };
    assert_eq!(uninformative.evaluate()?.net_gain_numerator, -2);
    Ok(())
}

#[test]
fn adoption_compares_frozen_arms_and_rejects_exposure() -> Result<()> {
    use naome_protocol::adoption::Adoption;
    let a = Archive::memory()?;
    let f = Format::B;
    let public = Id::blob(PUBLIC);
    let put = |k, body, edges| fixture::put(&a, f, k, "successor", "held-out trial", body, edges);
    let task = put(Kind::Question, json!({"question":"finite task"}), vec![])?;
    let protected = put(
        Kind::Manifest,
        json!({"distribution":"one task"}),
        vec![link("task", task)],
    )?;
    let training = put(Kind::Manifest, json!({"distribution":"other data"}), vec![])?;
    let parent = put(Kind::Model, json!({"controller":"parent owner"}), vec![])?;
    let candidate = put(
        Kind::Model,
        json!({"controller":"candidate owner"}),
        vec![link("parent", parent), link("training", training)],
    )?;
    let plan = put(
        Kind::Plan,
        json!({"rule":"paired-count-v1","per_arm_budget":{"steps":100},"minimum_gain":1,"use_range":"held-out family","reassess_when":"correction or regression"}),
        vec![
            link("parent", parent),
            link("candidate", candidate),
            link("protected", protected),
        ],
    )?;
    let sealed = a.snapshot("precommit", BTreeSet::new())?;
    let sealed_head = a.blob(&serde_json::to_vec(&sealed)?, public)?;
    for exposures in [0, 1] {
        let observation = put(
            Kind::Occurrence,
            json!({"concealed_until_test":true,"previous_exposures":exposures,"candidate_budget":{"steps":100},"parent_budget":{"steps":100},"completed_per_arm":1}),
            vec![
                link("parent", parent),
                link("candidate", candidate),
                link("protected", protected),
                link("plan", plan),
                link("sealed-head", sealed_head),
                link("candidate-success", task),
            ],
        )?;
        let sig = fixture::sign(&a, f, observation, "held-out trial", "trial-controller", 21)?;
        let head = a.snapshot("trial", [sealed_head].into())?;
        let request = Adoption {
            plan,
            sealed_head,
            observation,
            signature: sig,
        };
        let result = a.adoption(
            &head,
            &request,
            &[hex::encode(
                fixture::fixture_key(21).verifying_key().to_bytes(),
            )]
            .into(),
            f,
        );
        if exposures == 0 {
            let id = result?;
            let outcome = a.read(&a.snapshot("decision", [head.id()?].into())?, id, "read")?;
            assert!(outcome.field::<bool>("adopted")?);
            assert_eq!(outcome.one("rollback")?, parent);
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[test]
fn public_interchange_runs_through_cli_and_grades_external_output() -> Result<()> {
    use std::process::Command;
    let dir = tempdir()?;
    let rep = env!("CARGO_BIN_EXE_rep");
    let trial = Command::new(rep).arg("trial").arg(dir.path()).output()?;
    assert!(
        trial.status.success(),
        "{}",
        String::from_utf8_lossy(&trial.stderr)
    );
    let cases = dir.path().join("conformance");
    let run = Command::new(rep).arg("suite").arg(&cases).output()?;
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let submission = dir.path().join("actual.json");
    std::fs::write(&submission, &run.stdout)?;
    let grade = || {
        Command::new(rep)
            .arg("grade")
            .arg(cases.join("answers.json"))
            .arg(&submission)
            .output()
    };
    let good = grade()?;
    assert!(good.status.success());
    let score: Value = serde_json::from_slice(&good.stdout)?;
    assert_eq!(score["correct"], 24);
    assert_eq!(score["incorrect_acceptance"], 0);
    let mut wrong: Value = serde_json::from_slice(&run.stdout)?;
    wrong["restricted/above"] = json!("supported");
    std::fs::write(&submission, serde_json::to_vec(&wrong)?)?;
    let bad = grade()?;
    assert!(!bad.status.success());
    let score: Value = serde_json::from_slice(&bad.stdout)?;
    assert_eq!(score["incorrect_acceptance"], 1);
    Ok(())
}

#[test]
fn withdrawals_leave_historic_proofs_and_unaffected_arguments_available() -> Result<()> {
    let a = Archive::memory()?;
    let f = Format::A;
    let make = |k, b, e| put(&a, f, k, "theorem", "scope", b, e);
    let key = hex::encode(fixture::fixture_key(9).verifying_key().to_bytes());
    let policy = put(
        &a,
        f,
        Kind::Policy,
        "custodian",
        "research-policy-1",
        json!({"keys":{"notice":[key]}}),
        vec![],
    )?;
    let c = make(
        Kind::Claim,
        json!({"predicate":"least-element","domain":"finite-nat-sets-containing-zero"}),
        vec![],
    )?;
    let mut arguments = vec![];
    for version in [1, 2] {
        let proof = make(
            Kind::Derivation,
            json!({"kernel":"nat-order-zero-v1","steps":["member-zero","zero-le-every-nat","least-intro"],"edition":version}),
            vec![],
        )?;
        arguments.push(make(
            Kind::Argument,
            json!({"method":"least-zero"}),
            vec![link("claim", c), link("proof", proof)],
        )?);
    }
    let initial = a.snapshot("before", BTreeSet::new())?;
    let mut query = Query {
        target: c,
        policy,
        arguments: vec![arguments[0]],
        budget: 1000,
        byte_limit: 1000000,
        mappings: vec![],
        previous_receipts: vec![],
        required_notices: vec![],
        current_at: None,
    };
    let n = make(
        Kind::Notice,
        json!({"reason":"editor withdrew this edition","action":"withdraw"}),
        vec![link("target", arguments[0])],
    )?;
    fixture::sign(&a, f, n, "scope", "notice", 9)?;
    let current = a.snapshot("after", [initial.id()?].into())?;
    assert_eq!(
        evaluation::assess(&a, &initial, &query)?.result,
        Some(Standing::Supported)
    );
    assert_eq!(
        evaluation::assess(&a, &current, &query)?.result,
        Some(Standing::Unresolved)
    );
    query.arguments = arguments;
    assert_eq!(
        evaluation::assess(&a, &current, &query)?.result,
        Some(Standing::Supported)
    );
    Ok(())
}

#[test]
fn unavailable_dependencies_are_retained_without_blocking_other_translations() -> Result<()> {
    let a = Archive::memory()?;
    let public = Id::blob(PUBLIC);
    let private = a.blob(br#"{"purposes":["custody"],"version":1}"#, public)?;
    let sealed = a.blob(b"restricted raw bytes", private)?;
    let scoped = put(
        &a,
        Format::A,
        Kind::Claim,
        "sample",
        "scope",
        json!({"predicate":"sealed claim"}),
        vec![link("raw", sealed)],
    )?;
    let free = put(
        &a,
        Format::A,
        Kind::Question,
        "public",
        "scope",
        json!({"purpose":"discover"}),
        vec![],
    )?;
    let s = a.snapshot("local", BTreeSet::new())?;
    let migrated = a.migrate(&s, Format::B, "custodian")?;
    assert!(migrated.retained.contains(&scoped));
    assert!(migrated.pairs.contains_key(&free));
    let pairs = a.verify_mapping(&a.head(migrated.exchange_head)?, migrated.mapping)?;
    assert!(!pairs.contains_key(&scoped));
    Ok(())
}

#[test]
fn paged_exchange_converges_on_the_same_inventory() -> Result<()> {
    let a = Archive::memory()?;
    let mut b = Archive::memory()?;
    let public = Id::blob(PUBLIC);
    for i in 0..8 {
        a.blob(&[i], public)?;
    }
    let s = a.snapshot("shared", BTreeSet::new())?;
    let mut after = None;
    let mut transferred = BTreeSet::new();
    loop {
        let page = a.export_page(&s, "read", after, 2)?;
        assert!(page.packets.len() <= 2);
        assert!(page.packets.iter().all(|p| transferred.insert(p.id)));
        b.import(&page)?;
        after = page.continuation;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(transferred, s.objects);
    for &id in &s.objects {
        assert_eq!(a.resolve(&s, id, "read")?, b.resolve(&s, id, "read")?);
    }
    Ok(())
}
#[test]
fn planner_keeps_infeasible_and_uninformative_alternatives() -> Result<()> {
    use naome_protocol::investigation::Selection;
    let a = Archive::memory()?;
    let f = Format::A;
    let q = put(
        &a,
        f,
        Kind::Question,
        "reference",
        "one event",
        json!({"losses":[[0,10],[10,0]],"prior_masses":[1,1]}),
        vec![],
    )?;
    let plan = |cost: u64, joint: Value| {
        put(
            &a,
            f,
            Kind::Plan,
            "reference",
            "one event",
            json!({"action_type":"observation","objective":"decision loss","costs":{"samples":cost},"observation_model":{"losses":[[0,10],[10,0]],"joint_masses":joint,"loss_unit":"points","acquisition_cost":1}}),
            vec![link("question", q)],
        )
    };
    let chosen = plan(1, json!([[1, 0], [0, 1]]))?;
    let other = plan(1, json!([[1, 1]]))?;
    let costly = plan(3, json!([[1, 0], [0, 1]]))?;
    let s = a.snapshot("selection", BTreeSet::new())?;
    let selection = a.select(
        &s,
        &Selection {
            question: q,
            proposals: [chosen, other, costly].into(),
            ceilings: [("samples".into(), 1)].into(),
            objective: "decision loss".into(),
            loss_unit: "points".into(),
        },
        f,
    )?;
    let d = a.read(&a.snapshot("result", [s.id()?].into())?, selection, "read")?;
    assert_eq!(d.one("selected")?, chosen);
    assert_eq!(d.roles("proposal").count(), 3);
    Ok(())
}

#[test]
fn training_rejects_duplicate_targets_false_origins_and_superseded_labels() -> Result<()> {
    use naome_protocol::learning::LabelStanding;
    let a = Archive::memory()?;
    let f = Format::A;
    let i = fixture::seed(&a, f)?;
    let original = a.head(i.published)?;
    let plan = a
        .read(&original, i.queries[2].arguments[0], "read")?
        .one("plan")?;
    assert!(
        a.label(&original, i.receipts[2], "observed", None, None, f)
            .is_err()
    );

    let mut req = TrainingRequest {
        feature_cutoff: i.feature_cutoff,
        label_head: i.published,
        policy: i.policy,
        standing: LabelStanding::Current,
        forecast_plan: Some(plan),
        mappings: vec![],
        project: None,
        examples: ["train", "test"]
            .iter()
            .map(|part| Example {
                features: vec![plan],
                label: i.labels[2],
                partition: (*part).into(),
            })
            .collect(),
        independent_roles: BTreeSet::new(),
        binary: true,
    };
    let split = a.training_manifest(&req, f)?;
    assert_eq!(split.included, vec![i.labels[2]]);
    assert!(split.withheld[&i.labels[2]].contains("crosses declared partitions"));

    let mut incorrect = a.read(&original, i.labels[2], "read")?;
    incorrect.fields.insert("origin".into(), json!("observed"));
    let incorrect_id = a.document(&incorrect, f, Id::blob(PUBLIC))?;
    req.label_head = a.snapshot("incorrect origin", [i.published].into())?.id()?;
    req.examples = vec![Example {
        features: vec![plan],
        label: incorrect_id,
        partition: "train".into(),
    }];
    assert!(a.training_manifest(&req, f)?.withheld[&incorrect_id].contains("declared origin"));

    let notice = fixture::notice(&a, f, i.calibration, 80, 1)?;
    let corrected = a.snapshot("corrected", [i.published].into())?;
    req.label_head = corrected.id()?;
    req.examples[0].label = i.labels[2];
    assert!(a.training_manifest(&req, f)?.withheld[&i.labels[2]].contains("reassessment"));
    req.standing = LabelStanding::Historical;
    assert_eq!(a.training_manifest(&req, f)?.included, vec![i.labels[2]]);
    let rec = evaluation::assess(&a, &corrected, &i.queries[2])?;
    assert!(rec.applicable_notices.contains(&notice));
    assert_eq!(rec.result, Some(Standing::Refuted));
    let received = evaluation::deposit_receipt(&a, &corrected, &i.queries[2], &rec, f)?;
    let assessed = a.snapshot("corrected receipt", [corrected.id()?].into())?;
    let label = a.label(&assessed, received, "synthetic", None, None, f)?;
    req.label_head = a
        .snapshot("corrected label", [assessed.id()?].into())?
        .id()?;
    req.standing = LabelStanding::Current;
    req.examples[0].label = label;
    assert_eq!(a.training_manifest(&req, f)?.included, vec![label]);
    Ok(())
}

#[test]
fn prospective_training_requires_an_admitted_witness_and_concealed_outcomes() -> Result<()> {
    let f = Format::A;
    for signed in [false, true] {
        let a = Archive::memory()?;
        let i = fixture::seed(&a, f)?;
        let old = a.head(i.s0)?;
        let mut q = i.queries[2].clone();
        let mut arg = a.read(&old, q.arguments[0], "read")?;
        let plan = arg.one("plan")?;
        let outcome = arg.roles("reading").next().unwrap();
        let mut release = a.read(&old, arg.one("release")?, "read")?;
        let cutoff = if signed {
            a.blob(&serde_json::to_vec(&old)?, Id::blob(PUBLIC))?
        } else {
            i.feature_cutoff
        };
        release.inputs.retain(|e| e.role != "feature-cutoff");
        release.inputs.push(link("feature-cutoff", cutoff));
        release
            .fields
            .insert("source".into(), json!("replacement release declaration"));
        let witness = a.document(&release, f, Id::blob(PUBLIC))?;
        if signed {
            fixture::sign(&a, f, witness, &release.scope, "release", 6)?;
        }
        arg.inputs.retain(|e| e.role != "release");
        arg.inputs.push(link("release", witness));
        let revised = a.document(&arg, f, Id::blob(PUBLIC))?;
        fixture::sign(&a, f, revised, &release.scope, "data-origin", 7)?;
        q.arguments = vec![revised];
        let horizon = a.snapshot("assessment", [i.s0].into())?;
        let receipt = evaluation::assess(&a, &horizon, &q)?;
        assert_eq!(receipt.result, Some(Standing::Supported));
        let receipt_id = evaluation::deposit_receipt(&a, &horizon, &q, &receipt, f)?;
        let receipts = a.snapshot("receipts", [horizon.id()?].into())?;
        let label = a.label(&receipts, receipt_id, "synthetic", None, None, f)?;
        let labeled = a.snapshot("labeled", [receipts.id()?].into())?;
        let req = TrainingRequest {
            feature_cutoff: cutoff,
            label_head: labeled.id()?,
            policy: i.policy,
            standing: Default::default(),
            forecast_plan: Some(plan),
            mappings: vec![],
            project: None,
            independent_roles: BTreeSet::new(),
            binary: true,
            examples: vec![Example {
                features: vec![if signed { outcome } else { plan }],
                label,
                partition: "train".into(),
            }],
        };
        let result = a.training_manifest(&req, f)?;
        assert!(result.included.is_empty());
        assert_eq!(
            result.withheld[&label],
            if signed {
                "outcome evidence visible at the feature cutoff"
            } else {
                "no admitted release signature at the receipt horizon"
            }
        );
        let manifest = a.read(
            &a.snapshot("manifest", [labeled.id()?].into())?,
            result.manifest,
            "read",
        )?;
        assert_eq!(
            manifest.field::<String>("exposure")?,
            "no eligible examples"
        );
    }
    Ok(())
}

#[test]
fn signed_disciplinary_targets_survive_exchange_and_enforce_use_scope() -> Result<()> {
    let a = Archive::memory()?;
    let f = Format::A;
    let unrestricted = Id::blob(PUBLIC);
    let grant = |expires| {
        a.blob(
            &serde_json::to_vec(&json!({
                "version":1,"purposes":["read","train"],"training":{
                    "project":"methods-study","not_before":0,"expires":expires
                }
            }))?,
            unrestricted,
        )
    };
    let restricted = a.blob(b"synthetic baseline, one participant", grant(u64::MAX)?)?;
    let expired = a.blob(b"expired baseline", grant(1)?)?;
    let keys = |n| hex::encode(fixture::fixture_key(n).verifying_key().to_bytes());
    let policy = put(
        &a,
        f,
        Kind::Policy,
        "fixture policy",
        "research-policy-1",
        json!({"keys":{"data-origin":[keys(7)],"outcome":[keys(8)]}}),
        vec![],
    )?;
    let ready = a.snapshot("features", BTreeSet::new())?;
    let before = a.blob(&serde_json::to_vec(&ready)?, unrestricted)?;
    let cases = [
        (
            "clinical",
            "time_to_event",
            json!({"target_type":"time_to_event","unit":"day"}),
            json!({"kind":"time_to_event","time":30,"unit":"day","status":"right_censored"}),
        ),
        (
            "laboratory",
            "interval",
            json!({"target_type":"interval","unit":"mm","interval_meaning":"absolute_bound"}),
            json!({"kind":"interval","lower":150,"upper":200,"scale":3,"unit":"mm","interpretation":{"kind":"absolute_bound"}}),
        ),
        (
            "textual",
            "readings",
            json!({"target_type":"readings"}),
            json!({"kind":"readings","variants":[{"id":"A","text":"1480","selector":"#A-line-7"},{"id":"B","text":"1481","selector":"#B-line-7"}]}),
        ),
        (
            "missing",
            "time_to_event",
            json!({"target_type":"time_to_event","unit":"day"}),
            json!({"kind":"missing","reason":"not_sampled"}),
        ),
    ];
    let mut queries = vec![];
    for (subject, _, profile_fields, target) in &cases {
        let profile = put(
            &a,
            f,
            Kind::Profile,
            subject,
            "training-target-1",
            profile_fields.clone(),
            vec![],
        )?;
        let claim = put(
            &a,
            f,
            Kind::Claim,
            subject,
            "case",
            json!({"predicate":"training-target"}),
            vec![link("target-profile", profile)],
        )?;
        let mut sources = vec![link("target-profile", profile)];
        if *subject == "textual" {
            for (witness, bytes) in [("A", b"transcript A"), ("B", b"transcript B")] {
                let mut source = link("variant-source", a.blob(bytes, unrestricted)?);
                source.qualifier = witness.into();
                sources.push(source);
            }
        }
        let outcome = put(
            &a,
            f,
            Kind::Occurrence,
            subject,
            "case",
            json!({"target":target}),
            sources,
        )?;
        fixture::sign(&a, f, outcome, "case", "outcome", 8)?;
        let argument = put(
            &a,
            f,
            Kind::Argument,
            subject,
            "case",
            json!({"method":"typed-outcome","origin":"synthetic"}),
            vec![link("claim", claim), link("outcome", outcome)],
        )?;
        fixture::sign(&a, f, argument, "case", "data-origin", 7)?;
        queries.push(Query {
            target: claim,
            policy,
            arguments: vec![argument],
            budget: 1000,
            byte_limit: 1_048_576,
            mappings: vec![],
            previous_receipts: vec![],
            required_notices: vec![],
            current_at: None,
        });
    }
    let source = a.snapshot("typed source", [before].into())?;
    let migration = a.migrate(&source, Format::B, "fixture custodian")?;
    let mut b = Archive::memory()?;
    let exchange = a.export(&a.head(migration.exchange_head)?, "read")?;
    b.import(&exchange)?;
    let imported = b.head(migration.exchange_head)?;
    let mapping = b.verify_mapping(&imported, migration.mapping)?;
    let mut examples = vec![];
    for ((_, _, _, expected), q) in cases.iter().zip(&queries) {
        let query = Query {
            target: mapping[&q.target],
            policy: mapping[&policy],
            arguments: vec![mapping[&q.arguments[0]]],
            mappings: vec![migration.mapping],
            ..q.clone()
        };
        let receipt = evaluation::assess(&b, &imported, &query)?;
        assert_eq!(receipt.branches[0]["training_target"], *expected);
        assert_eq!(receipt.result, Some(Standing::Supported));
        let id = evaluation::deposit_receipt(&b, &imported, &query, &receipt, Format::B)?;
        let head = b.snapshot("typed receipts", [migration.exchange_head].into())?;
        let label = b.label(&head, id, "synthetic", None, None, Format::B)?;
        let labeled = b.snapshot("typed labels", [head.id()?].into())?;
        assert_eq!(b.read(&labeled, label, "read")?.fields["value"], *expected);
        examples.push(Example {
            features: vec![restricted],
            label,
            partition: "train".into(),
        });
    }
    let head = b.snapshot("ready", [migration.exchange_head].into())?;
    let mut req = TrainingRequest {
        feature_cutoff: before,
        label_head: head.id()?,
        policy: mapping[&policy],
        standing: Default::default(),
        forecast_plan: None,
        mappings: vec![migration.mapping],
        project: Some("methods-study".into()),
        examples,
        independent_roles: BTreeSet::new(),
        binary: false,
    };
    assert_eq!(b.training_manifest(&req, Format::B)?.included.len(), 4);
    req.binary = true;
    assert!(b.training_manifest(&req, Format::B)?.included.is_empty());
    req.binary = false;
    req.project = Some("different-study".into());
    assert!(b.training_manifest(&req, Format::B)?.included.is_empty());
    req.project = Some("methods-study".into());
    req.examples[0].features = vec![expired];
    assert_eq!(b.training_manifest(&req, Format::B)?.included.len(), 3);
    assert!(b.export(&head, "train")?.omitted.contains(&restricted));
    let query = &queries[1];
    let original_argument = a.read(&source, query.arguments[0], "read")?;
    let mut invalid_outcome = a.read(&source, original_argument.one("outcome")?, "read")?;
    invalid_outcome.fields.get_mut("target").unwrap()["interpretation"] =
        json!({"kind":"confidence","level_ppm":950000});
    let outcome = a.document(&invalid_outcome, f, unrestricted)?;
    fixture::sign(&a, f, outcome, "case", "outcome", 8)?;
    let mismatch = put(
        &a,
        f,
        Kind::Argument,
        "laboratory",
        "case",
        json!({"method":"typed-outcome","origin":"synthetic"}),
        vec![link("claim", query.target), link("outcome", outcome)],
    )?;
    let invalid = evaluation::assess(
        &a,
        &a.snapshot("mismatched semantics", [source.id()?].into())?,
        &Query {
            arguments: vec![mismatch],
            ..query.clone()
        },
    )?;
    assert_eq!(invalid.result, Some(Standing::Unresolved));
    assert!(
        invalid
            .obligations
            .contains("interval interpretation differs from profile")
    );

    Ok(())
}
