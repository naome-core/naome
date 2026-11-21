use crate::{
    evaluation::{Receipt, Standing, Status},
    profile::{Document, Kind},
    wire::Id,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use std::collections::BTreeSet;

pub(crate) fn evaluate(
    method: &str,
    c: &Document,
    a: &Document,
    read: impl Fn(Id) -> Result<Document>,
    out: &mut Receipt,
) -> Result<Vec<Standing>> {
    let pred: String = c.field("predicate")?;
    let evidence = |role: &str, kind: Kind| -> Result<Document> {
        let d = read(a.one(role)?)?;
        ensure!(d.kind == kind, "wrong evidence kind");
        Ok(d)
    };
    let conclusion = match (method, pred.as_str()) {
        ("recorded-difference", "raw-change-above") => {
            let r = evidence("reading", Kind::Occurrence)?;
            ensure!(
                r.subject == c.subject
                    && r.scope == c.scope
                    && r.field::<String>("unit")? == c.field::<String>("unit")?,
                "reading outside scope"
            );
            let [before, after]: [i64; 2] = r.field("positions")?;
            let delta = i128::from(after) - i128::from(before);
            out.branches
                .push(json!({"raw_difference":delta.to_string()}));
            if delta > i128::from(c.field::<i64>("threshold")?) {
                Standing::Supported
            } else {
                Standing::Refuted
            }
        }
        ("least-zero", "least-element") => {
            let theorem = evidence("proof", Kind::Derivation)?;
            ensure!(
                theorem.field::<String>("kernel")? == "nat-order-zero-v1"
                    && theorem.field::<Vec<String>>("steps")?
                        == ["member-zero", "zero-le-every-nat", "least-intro"]
                    && c.field::<String>("domain")? == "finite-nat-sets-containing-zero"
                    && theorem.subject == c.subject
                    && theorem.scope == c.scope,
                "unsupported foundation, proof or domain"
            );
            Standing::Supported
        }
        ("domain-inclusion", "covers-domain") => {
            let narrow = evidence("restricted", Kind::Claim)?;
            ensure!(
                narrow.subject == c.subject
                    && narrow.scope == c.scope
                    && narrow.field::<String>("domain")? == "finite-nat-sets-containing-zero"
                    && c.field::<String>("domain")? == "nonempty-finite-nat-sets",
                "unknown domain inclusion"
            );
            let witness: Vec<u64> = a.field("witness")?;
            ensure!(
                !witness.is_empty() && !witness.contains(&0),
                "invalid coverage counterexample"
            );
            out.branches.push(json!({"counterexample":witness}));
            Standing::Refuted
        }
        ("source-independence", "independent-witnesses") => {
            let mut manuscripts = BTreeSet::new();
            let mut copies = 0;
            for id in a.roles("transcription") {
                let d = read(id)?;
                ensure!(
                    d.kind == Kind::Derivation && d.subject == c.subject && d.scope == c.scope,
                    "wrong transcription scope"
                );
                let ancestor = d.one("manuscript")?;
                read(ancestor)?;
                manuscripts.insert(ancestor);
                copies += 1;
            }
            ensure!(copies >= 2, "need more witnesses");
            out.branches
                .push(json!({"documents":copies,"distinct_source_records":manuscripts.len()}));
            if manuscripts.len() < copies {
                Standing::Refuted
            } else {
                out.obligations
                    .insert("independent custody and acquisition unknown".into());
                Standing::Unresolved
            }
        }
        ("sample-description", "sample-reports")
        | ("survey-identification", "population-effect") => {
            let mut units = BTreeSet::new();
            let mut rider_only = true;
            for id in a.roles("response") {
                let r = read(id)?;
                ensure!(
                    r.kind == Kind::Occurrence
                        && r.scope == c.scope
                        && r.field::<String>("population")? == c.subject,
                    "wrong population or study"
                );
                rider_only &=
                    r.fields.get("sampling_frame").and_then(|v| v.as_str()) == Some("route-riders");
                units.insert(r.field::<String>("respondent")?);
            }
            ensure!(!units.is_empty(), "empty sample");
            out.branches
                .push(json!({"unique_reported_units":units.len()}));
            if pred == "sample-reports" {
                ensure!(
                    c.field::<usize>("count")? == units.len(),
                    "claimed sample count disagrees"
                );
                Standing::Supported
            } else {
                if rider_only {
                    out.obligations.insert("missing non-rider coverage".into());
                } else {
                    out.obligations
                        .insert("population coverage not established".into());
                }
                if a.roles("comparison").next().is_none() {
                    out.obligations.insert("missing causal comparison".into());
                } else {
                    out.obligations
                        .insert("comparison requires a causal identification warrant".into());
                }
                Standing::Unresolved
            }
        }
        ("unit-grid-map", "exact-translation") => {
            let u = evidence("source-profile", Kind::Profile)?;
            let m = evidence("target-profile", Kind::Profile)?;
            ensure!(
                u.subject == m.subject
                    && u.scope == m.scope
                    && u.subject == c.subject
                    && c.scope == u.scope,
                "profile target or frame mismatch"
            );
            let uf: String = u.field("functional")?;
            let mf: String = m.field("functional")?;
            let ud: u64 = u.field("max_um")?;
            let md: u64 = m.field("max_um")?;
            ensure!(
                u.field::<String>("unit")? == "um"
                    && m.field::<String>("unit")? == "mm"
                    && u.field::<u64>("step_um")? == 1
                    && m.field::<u64>("step_um")? == 1,
                "unsupported grid"
            );
            let mut counter = None;
            let mut cases = vec![];
            for id in a.roles("trace") {
                let d = read(id)?;
                ensure!(
                    d.kind == Kind::Occurrence && d.scope == c.scope && d.subject == c.subject,
                    "trace scope mismatch"
                );
                let trace: Vec<i64> = d.field("positions_um")?;
                let eval = |f: &str| -> Result<i64> {
                    match f {
                        "endpoint-change" => trace
                            .last()
                            .zip(trace.first())
                            .and_then(|(l, h)| l.checked_sub(*h))
                            .context("invalid endpoint change"),
                        "peak-to-peak" => trace
                            .iter()
                            .max()
                            .zip(trace.iter().min())
                            .and_then(|(h, l)| h.checked_sub(*l))
                            .context("invalid excursion"),
                        _ => bail!("unrecognised quantity definition"),
                    }
                };
                let x = eval(&uf)?;
                let y = eval(&mf)?;
                ensure!(x >= 0 && x as u64 <= ud, "trace outside source domain");
                cases.push(json!({"source_um":x,"target_mm":format!("{}.{:03}",y/1000,y.unsigned_abs()%1000),"within_target_grid":y>=0 && y as u64<=md}));
                if x != y {
                    counter = Some(json!({"trace":trace,"source_um":x,"target_um":y}));
                }
            }
            out.branches.push(json!({"reference_cases":cases}));
            if let Some(w) = counter {
                out.branches
                    .push(json!({"mapping":"counterexample","witness":w}));
                Standing::Refuted
            } else if uf != "endpoint-change" || mf != uf {
                out.obligations
                    .insert("definitions do not establish equivalence".into());
                Standing::Unresolved
            } else if md < ud {
                out.branches
                    .push(json!({"mapping":"partial","domain_um":[0,md],"first_excluded_um":md+1}));
                Standing::Refuted
            } else {
                out.branches.push(json!({"mapping":"exact","domain_um":[0,ud],"inverse":"multiply millimetres by 1000 on the declared lattice"}));
                Standing::Supported
            }
        }
        _ => bail!("unknown predicate or scientific evaluator"),
    };
    out.checks.push(crate::evaluation::Check {
        test: method.into(),
        status: if conclusion == Standing::Unresolved {
            Status::Unknown
        } else {
            Status::Pass
        },
        basis: "executed pinned research profile rule".into(),
        inputs: a.inputs.iter().map(|i| i.target).collect(),
    });
    Ok(vec![conclusion])
}
