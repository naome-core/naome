use crate::wire::{Format, Id, MAX_BYTES, Record, Term};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn bytes(f: Format) -> &'static [u8] {
    match f {
        Format::A => include_bytes!("../kits/A.json"),
        Format::B => include_bytes!("../kits/B.json"),
    }
}
pub fn pin(f: Format) -> String {
    hex::encode(Sha256::digest(bytes(f)))
}
#[derive(Serialize)]
pub struct VectorResult {
    pub name: String,
    pub status: String,
    pub matches: bool,
}
type Kit = (
    String,
    Format,
    String,
    String,
    String,
    Vec<[String; 6]>,
    Vec<[String; 2]>,
);
pub fn test(input: &[u8], pin: &str) -> Result<Vec<VectorResult>> {
    ensure!(
        input.len() <= MAX_BYTES && hex::encode(Sha256::digest(input)) == pin,
        "bootstrap digest mismatch"
    );
    let k: Kit = serde_json::from_slice(input)?;
    ensure!(
        k.0 == "REP-kit-1" && serde_json::to_vec(&k)? == input,
        "noncanonical kit"
    );
    let mut res = BTreeMap::new();
    let mut previous = "";
    for [name, value] in &k.6 {
        ensure!(
            name.as_str() > previous
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "invalid resource name or order"
        );
        previous = name;
        let b = hex::decode(value)?;
        ensure!(hex::encode(&b) == *value, "noncanonical hex");
        res.insert(name, b);
    }
    let get = |key: &String| res.get(key).context("missing kit resource");
    for key in [&k.2, &k.3, &k.4] {
        get(key)?;
    }
    // External packages may express arbitrary semantics. Only claim execution of understood rules.
    let known: Kit = serde_json::from_slice(bytes(k.1))?;
    for (actual, expected) in [(&k.2, &known.2), (&k.3, &known.3), (&k.4, &known.4)] {
        ensure!(
            known.6.iter().any(
                |[n, v]| n == expected && res.get(actual).is_some_and(|b| hex::encode(b) == *v)
            ),
            "unknown kit notation or rules"
        );
    }
    let coverage: BTreeSet<_> = k.5.iter().map(|c| (c[1].as_str(), c[4].as_str())).collect();
    ensure!(
        [
            ("term", "pass"),
            ("record", "pass"),
            ("interpretation", "unknown"),
            ("budget", "unknown")
        ]
        .iter()
        .all(|case| coverage.contains(case))
            && k.5.iter().any(|c| c[4] == "fail"),
        "incomplete bootstrap vectors"
    );
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    for [name, phase, source, context, expected, answer] in k.5 {
        ensure!(
            names.insert(name.clone()) && !name.is_empty(),
            "ambiguous case name"
        );
        let b = get(&source)?;
        let ctx = get(&context)?;
        let want = get(&answer)?;
        ensure!(
            phase == "budget" || ctx == b"[]",
            "unsupported vector context"
        );
        let outcome: Result<(&str, Vec<u8>)> = (|| {
            Ok(match phase.as_str() {
                "term" => ("pass", Term::decode(b, k.1)?.encode(Format::B)),
                "record" => {
                    Record::decode(b, k.1)?;
                    (
                        "pass",
                        Id::record(k.1, b).to_string().as_bytes()[4..].to_vec(),
                    )
                }
                "interpretation" => {
                    let r = Record::decode(b, k.1)?;
                    ensure!(ctx == b"[]", "unsupported interpretation context");
                    if r.profile == Id::blob(crate::profile::PROFILE) && r.critical.is_empty() {
                        ("pass", b"known-profile".to_vec())
                    } else {
                        ("unknown", b"missing-profile".to_vec())
                    }
                }
                "budget" => {
                    let limit: usize = serde_json::from_slice(ctx)?;
                    if b.len() > limit {
                        ("unknown", b"byte-limit".to_vec())
                    } else {
                        ("pass", Term::decode(b, k.1)?.encode(Format::B))
                    }
                }
                _ => bail!("unknown vector phase"),
            })
        })();
        ensure!(
            matches!(
                phase.as_str(),
                "term" | "record" | "interpretation" | "budget"
            ),
            "unknown phase"
        );
        let (status, output) = match outcome {
            Ok(v) => v,
            Err(e) if e.to_string().contains("budget exhausted") => {
                ("unknown", b"decoder-limit".to_vec())
            }
            Err(_) => ("fail", b"invalid".to_vec()),
        };
        result.push(VectorResult {
            name,
            status: status.into(),
            matches: status == expected && output == *want,
        });
    }
    Ok(result)
}
