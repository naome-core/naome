use crate::{
    evaluation::{Query, Receipt, Standing, assess, deposit_receipt},
    learning::{Example, TrainingRequest},
    profile::{Document, Kind, Link, PUBLIC, attest, link},
    store::{Archive, Snapshot},
    wire::{Format, Id},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

const SUBJECT: &str = "bar-7";
const SCOPE: &str = "transition-1";
pub fn fixture_key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
pub fn put(
    store: &Archive,
    f: Format,
    kind: Kind,
    subject: &str,
    scope: &str,
    fields: Value,
    links: Vec<Link>,
) -> Result<Id> {
    store.document(
        &Document::new(kind, subject, scope, fields, links)?,
        f,
        Id::blob(PUBLIC),
    )
}
fn bar(store: &Archive, f: Format, kind: Kind, fields: Value, links: Vec<Link>) -> Result<Id> {
    put(store, f, kind, SUBJECT, SCOPE, fields, links)
}
pub fn sign(store: &Archive, f: Format, id: Id, scope: &str, role: &str, seed: u8) -> Result<Id> {
    store.document(
        &attest(id, scope, role, "research-policy-1", &fixture_key(seed))?,
        f,
        Id::blob(PUBLIC),
    )
}
pub fn policy(store: &Archive, f: Format) -> Result<Id> {
    let pk = |n| hex::encode(fixture_key(n).verifying_key().to_bytes());
    put(
        store,
        f,
        Kind::Policy,
        "synthetic-laboratories",
        "research-policy-1",
        json!({
            "acquisition_basis": "admitted-custody",
            "keys": {"calibration":[pk(1),pk(2)],"projection":[pk(3)],"assessor":[pk(4)],"horizon":[pk(5)],"release":[pk(6)],"data-origin":[pk(7)]},
            "max_age": 60,
            "required_sources": ["West"],
        }),
        vec![],
    )
}
#[derive(Serialize)]
pub struct Investigation {
    pub feature_cutoff: Id,
    pub s0: Id,
    pub published: Id,
    pub calibration: Id,
    pub policy: Id,
    pub queries: Vec<Query>,
    pub receipts: Vec<Id>,
    pub labels: Vec<Id>,
    pub training: Id,
    pub model: Id,
    pub control: Id,
    pub control_label: Id,
}
pub fn seed(store: &Archive, f: Format) -> Result<Investigation> {
    seed_measurements(store, f, false)
}

/// Recreate the published pre-measurement-profile calibration fixture.
pub fn seed_legacy(store: &Archive, f: Format) -> Result<Investigation> {
    seed_measurements(store, f, true)
}

fn seed_measurements(store: &Archive, f: Format, legacy: bool) -> Result<Investigation> {
    let policy = policy(store, f)?;
    let question = bar(
        store,
        f,
        Kind::Question,
        json!({"purpose":"test axial displacement","target":"change between fixed measurement windows"}),
        vec![],
    )?;
    let plan = bar(
        store,
        f,
        Kind::Plan,
        json!({
            "threshold": 200,
            "band": [210,300],
            "design": "two gauges, shared reference",
            "stopping": "one stable transition",
            "scores": ["strict-hull-lower","inclusive-hull-containment"],
            "unit": "um",
            "budget": {"transitions":1},
        }),
        vec![link("question", question)],
    )?;
    let features = store.snapshot("East", BTreeSet::new())?;
    let feature_cutoff = store.blob(&serde_json::to_vec(&features)?, Id::blob(PUBLIC))?;
    let release = bar(
        store,
        f,
        Kind::Occurrence,
        json!({"sealed":1,"released":2,"concealed":true,"source":"synthetic controlled release"}),
        vec![link("plan", plan), link("feature-cutoff", feature_cutoff)],
    )?;
    sign(store, f, release, SCOPE, "release", 6)?;
    let calibration = bar(
        store,
        f,
        Kind::Calibration,
        json!({"bias":0,"mode":"axial","interval":[1,8]}),
        vec![],
    )?;
    let guarantee = bar(
        store,
        f,
        Kind::Guarantee,
        json!({"type":"simultaneous-absolute","radius":30,"unit":"um"}),
        vec![link("calibration", calibration)],
    )?;
    let read = |g: &str, b: i64, e: i64, event: i64, scope: &str| {
        let document = Document::new(
            Kind::Occurrence,
            SUBJECT,
            scope,
            json!({"gauge":g,"positions":[b,e],"mode":"axial","event":event,"unit":"um","source":"synthetic"}),
            vec![link("calibration", calibration)],
        )?;
        let access = Id::blob(PUBLIC);
        if legacy {
            store.record(&document.encode_legacy(access)?, f)
        } else {
            store.document(&document, f, access)
        }
    };
    let a = read("A", 10000, 10260, 1, SCOPE)?;
    let b = read("B", 13000, 13250, 1, SCOPE)?;
    let control_scope = "transition-3";
    let control = read("Z", 800, 810, 3, control_scope)?;
    let control_claim = put(
        store,
        f,
        Kind::Claim,
        SUBJECT,
        control_scope,
        json!({"predicate":"raw-change-above","unit":"um","threshold":0}),
        vec![],
    )?;
    let control_arg = put(
        store,
        f,
        Kind::Argument,
        SUBJECT,
        control_scope,
        json!({"method":"recorded-difference","origin":"synthetic"}),
        vec![link("claim", control_claim), link("reading", control)],
    )?;
    sign(store, f, control_arg, control_scope, "data-origin", 7)?;
    let stability = bar(
        store,
        f,
        Kind::Occurrence,
        json!({"stable":true,"trace":"synthetic station readback"}),
        vec![],
    )?;
    let mut queries = vec![];
    for predicate in ["score-above", "score-within", "above", "within"] {
        let claim = bar(
            store,
            f,
            Kind::Claim,
            json!({"predicate":predicate,"threshold":200,"band":[210,300]}),
            vec![],
        )?;
        let argument = bar(
            store,
            f,
            Kind::Argument,
            json!({"method":"simultaneous-bounds","event":1,"mode":"axial","origin":"synthetic"}),
            vec![
                link("claim", claim),
                link("plan", plan),
                link("release", release),
                link("calibration", calibration),
                link("reading", a),
                link("reading", b),
                link("guarantee", guarantee),
                link("stability", stability),
            ],
        )?;
        sign(store, f, argument, SCOPE, "data-origin", 7)?;
        queries.push(Query {
            target: claim,
            arguments: vec![argument],
            policy,
            budget: 10000,
            byte_limit: 64 * 1024 * 1024,
            mappings: vec![],
            previous_receipts: vec![],
            required_notices: vec![],
            current_at: None,
        });
    }
    let s = store.snapshot("East", [feature_cutoff].into())?;
    let s0 = s.id()?;
    let mut receipts = vec![];
    let mut labels = vec![];
    for q in &queries {
        let receipt = assess(store, &s, q)?;
        let id = deposit_receipt(store, &s, q, &receipt, f)?;
        sign(store, f, id, SCOPE, "assessor", 4)?;
        receipts.push(id);
        let receipt_head = store.snapshot("East receipts", [s0].into())?;
        labels.push(store.label(&receipt_head, id, "synthetic", None, None, f)?);
        if labels.len() == 1 {
            store.label(
                &receipt_head,
                id,
                "synthetic",
                Some("arithmetic replay"),
                None,
                f,
            )?;
        }
    }
    let control_query = Query {
        target: control_claim,
        arguments: vec![control_arg],
        ..queries[0].clone()
    };
    let result = assess(store, &s, &control_query)?;
    ensure!(
        result.result == Some(Standing::Supported),
        "control readback mismatch"
    );
    let id = deposit_receipt(store, &s, &control_query, &result, f)?;
    let control_label = store.label(
        &store.snapshot("control readback", [s0].into())?,
        id,
        "synthetic",
        None,
        None,
        f,
    )?;
    let labeled = store.snapshot("East", [s0].into())?;
    let extraction = store.training_manifest(
        &TrainingRequest {
            feature_cutoff,
            forecast_plan: Some(plan),
            mappings: vec![],
            label_head: labeled.id()?,
            policy,
            standing: Default::default(),
            project: None,
            examples: labels
                .iter()
                .map(|id| Example {
                    label: *id,
                    features: vec![plan],
                    partition: "train".into(),
                })
                .collect(),
            independent_roles: ["calibration".into()].into(),
            binary: true,
        },
        f,
    )?;
    ensure!(
        extraction.included.len() == 4,
        "fixture training labels withheld: {:?}",
        extraction.withheld
    );
    let training = extraction.manifest;
    let mut positives = 0;
    for &id in &extraction.included {
        let label = store.read(&labeled, id, "train")?;
        if matches!(
            label.field::<String>("value")?.as_str(),
            "supported" | "pass"
        ) {
            positives += 1;
        }
    }
    let weights = store.blob(
        &serde_json::to_vec(&[positives + 1, extraction.included.len() + 2])?,
        Id::blob(PUBLIC),
    )?;
    let model = bar(
        store,
        f,
        Kind::Model,
        json!({"name":"synthetic label-frequency model","estimator":"Laplace-smoothed positive fraction","encoding":"integer numerator and denominator"}),
        vec![link("training", training), link("weights", weights)],
    )?;
    let published = store.snapshot("East", [labeled.id()?].into())?.id()?;
    Ok(Investigation {
        feature_cutoff,
        s0,
        published,
        calibration,
        policy,
        queries,
        receipts,
        labels,
        training,
        model,
        control,
        control_label,
    })
}
pub fn notice(store: &Archive, f: Format, calibration: Id, bias: i64, issuer: u8) -> Result<Id> {
    let lab = format!("lab-{issuer}");
    let report = put(
        store,
        f,
        Kind::Occurrence,
        &lab,
        SCOPE,
        json!({"bias":bias,"source":"synthetic reference comparison"}),
        vec![],
    )?;
    let id = put(
        store,
        f,
        Kind::Notice,
        &lab,
        SCOPE,
        json!({"bias":bias,"mode":"axial","interval":[1,1],"reason":"shared differential calibration bias"}),
        vec![link("calibration", calibration), link("evidence", report)],
    )?;
    sign(store, f, id, SCOPE, "calibration", issuer)?;
    Ok(id)
}
pub fn trial(directory: &Path) -> Result<Value> {
    std::fs::create_dir_all(directory)?;
    let a_path = directory.join("east.sqlite");
    let b_path = directory.join("west.sqlite");
    let p_path = directory.join("projection.sqlite");
    for path in [&a_path, &b_path, &p_path] {
        ensure!(!path.exists(), "trial requires fresh archive files")
    }
    let mut a = Archive::open(a_path)?;
    let mut b = Archive::open(b_path)?;
    let mut p = Archive::open(p_path)?;
    let i = seed(&a, Format::A)?;
    let s0 = a.head(i.s0)?;
    let published = a.head(i.published)?;
    b.import(&a.export(&published, "read")?)?;
    let migration = b.migrate(&published, Format::B, "fixture-custodian")?;
    let pairs = &migration.pairs;
    let native_queries: Vec<_> = i
        .queries
        .iter()
        .zip(&i.receipts)
        .map(|(q, prior)| Query {
            previous_receipts: vec![*prior],
            target: pairs[&q.target],
            arguments: q.arguments.iter().map(|id| pairs[id]).collect(),
            policy: pairs[&q.policy],
            mappings: vec![migration.mapping],
            ..q.clone()
        })
        .collect();
    let run = |store: &Archive,
               s: &Snapshot,
               qs: &[Query],
               expected: Standing,
               hulls: &[[i64; 2]],
               score: &[&str]|
     -> Result<Vec<Receipt>> {
        let mut results = vec![];
        for (idx, q) in qs.iter().enumerate() {
            let r = assess(store, s, q)?;
            ensure!(
                r.branches.len() == hulls.len()
                    && (idx < 2 && r.result.is_none() || idx >= 2 && r.result == Some(expected)),
                "unexpected assessment: {:?}",
                r
            );
            let mut branches: Vec<_> = r
                .branches
                .iter()
                .map(|row| (row["hull"].to_string(), row["score"].to_string()))
                .collect();
            branches.sort();
            let mut want: Vec<_> = hulls
                .iter()
                .zip(score)
                .map(|(h, s)| (json!(h).to_string(), json!(s).to_string()))
                .collect();
            want.sort();
            ensure!(branches == want, "branch disagreement");
            results.push(r);
        }
        Ok(results)
    };
    let full0 = b.head(migration.exchange_head)?;
    run(
        &b,
        &full0,
        &native_queries,
        Standing::Supported,
        &[[220, 290]],
        &["pass"],
    )?;
    let n = notice(&a, Format::A, i.calibration, 80, 1)?;
    let west = a.snapshot("West", [published.id()?].into())?;
    b.import(&a.export(&west, "read")?)?;
    let s1 = b.snapshot("reconciled-S1", [west.id()?, full0.id()?].into())?;
    let changed = run(
        &b,
        &s1,
        &native_queries,
        Standing::Refuted,
        &[[140, 210]],
        &["fail"],
    )?;
    let mut new_receipts = vec![];
    for (q, r) in native_queries.iter().zip(&changed) {
        new_receipts.push(deposit_receipt(&b, &s1, q, r, Format::B)?);
    }
    let scored = b.snapshot("West labels", [s1.id()?].into())?;
    for &id in &new_receipts {
        b.label(&scored, id, "synthetic", None, None, Format::B)?;
    }
    let without = Query {
        mappings: vec![],
        previous_receipts: vec![],
        required_notices: vec![n],
        ..native_queries[2].clone()
    };
    ensure!(
        assess(&b, &s1, &without)?.result == Some(Standing::Unresolved),
        "missing mapping was accepted"
    );
    let m = notice(&b, Format::B, pairs[&i.calibration], 10, 2)?;
    let s2 = b.snapshot("reconciled-S2", [s1.id()?].into())?;
    a.import(&b.export(&s2, "read")?)?;
    let original_queries: Vec<_> = i
        .queries
        .iter()
        .map(|q| Query {
            mappings: vec![migration.mapping],
            ..q.clone()
        })
        .collect();
    for (archive, queries) in [(&a, &original_queries), (&b, &native_queries)] {
        let conflicts = run(
            archive,
            &s2,
            queries,
            Standing::Contested,
            &[[140, 210], [210, 280]],
            &["fail", "pass"],
        )?;
        for (q, r) in queries.iter().zip(&conflicts) {
            let receipt = deposit_receipt(
                archive,
                &s2,
                q,
                r,
                q.target.format().context("invalid claim")?,
            )?;
            let head = archive.snapshot("conflict receipts", [s2.id()?].into())?;
            let f = q.target.format().context("expected claim")?;
            archive.label(&head, receipt, "synthetic", None, None, f)?;
            for branch in &r.branches {
                let condition: Id = serde_json::from_value(branch["notice"].clone())?;
                archive.label(&head, receipt, "synthetic", None, Some(condition), f)?;
            }
        }
    }
    let impact = a.impact(&s2, n, &[migration.mapping], 10000)?;
    for id in i.labels.iter().chain([&i.training, &i.model]) {
        ensure!(
            impact.by_kind.values().any(|ids| ids.contains(id)),
            "lost correction descendant"
        );
    }
    ensure!(
        !impact
            .by_kind
            .values()
            .any(|ids| ids.contains(&i.control) || ids.contains(&i.control_label)),
        "negative control flagged"
    );
    run(
        &a,
        &s0,
        &i.queries,
        Standing::Supported,
        &[[220, 290]],
        &["pass"],
    )?;
    let disclosure = b.project_hull(&s2, new_receipts[0], &fixture_key(3), Format::B)?;
    p.import(&disclosure.packet)?;
    let restricted = disclosure.packet.snapshot;
    let qs = disclosure.queries;
    run(
        &p,
        &restricted,
        &qs,
        Standing::Unresolved,
        &[[140, 210]],
        &["fail"],
    )?;
    let reverse = p.migrate(&restricted, Format::A, "projection-custodian")?;
    let roundtrip = p.head(reverse.native_head)?;
    let rq: Vec<_> = qs
        .iter()
        .map(|q| Query {
            target: reverse.pairs[&q.target],
            arguments: q.arguments.iter().map(|id| reverse.pairs[id]).collect(),
            policy: reverse.pairs[&q.policy],
            mappings: vec![reverse.mapping],
            ..q.clone()
        })
        .collect();
    run(
        &p,
        &p.head(reverse.exchange_head)?,
        &rq,
        Standing::Unresolved,
        &[[140, 210]],
        &["fail"],
    )?;
    let case_dir = directory.join("conformance");
    std::fs::create_dir(&case_dir)?;
    let mut cases = crate::conformance::Cases::new();
    let mut answers = crate::conformance::Answers::new();
    for (name, archive, view, qs, want) in [
        (
            "source",
            &a,
            &s0,
            i.queries.as_slice(),
            ["pass", "pass", "supported", "supported"],
        ),
        (
            "native",
            &b,
            &full0,
            native_queries.as_slice(),
            ["pass", "pass", "supported", "supported"],
        ),
        (
            "corrected",
            &b,
            &s1,
            native_queries.as_slice(),
            ["fail", "fail", "refuted", "refuted"],
        ),
        (
            "rivals",
            &a,
            &s2,
            original_queries.as_slice(),
            ["fail+pass", "fail+pass", "contested", "contested"],
        ),
        (
            "restricted",
            &p,
            &restricted,
            qs.as_slice(),
            ["fail", "fail", "unresolved", "unresolved"],
        ),
        (
            "returned",
            &p,
            &p.head(reverse.exchange_head)?,
            rq.as_slice(),
            ["fail", "fail", "unresolved", "unresolved"],
        ),
    ] {
        crate::conformance::add_cases(
            &case_dir,
            name,
            archive,
            view,
            qs,
            want,
            (&mut cases, &mut answers),
        )?;
    }
    crate::conformance::save_json(&case_dir.join("cases.json"), &cases)?;
    crate::conformance::save_json(&case_dir.join("answers.json"), &answers)?;
    Ok(json!({
        "fixture": i,
        "native_queries": native_queries,
        "mapping": migration.mapping,
        "N": n,
        "M": m,
        "S1": s1.id()?,
        "S2": s2.id()?,
        "corrected_receipts": new_receipts,
        "projection_return": roundtrip.id()?,
        "verified": ["S0","S1","S2","historic replay","correction impact","missing mapping","isolated projection","reverse projection"],
    }))
}
