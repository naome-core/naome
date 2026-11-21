use crate::{
    evaluation::{Query, assess},
    store::{Archive, Bundle, Snapshot},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

#[derive(Serialize, Deserialize)]
pub struct Case {
    pub packet: String,
    pub query: Query,
}
pub type Cases = BTreeMap<String, Case>;
pub type Answers = BTreeMap<String, String>;
pub fn save_json(path: &Path, data: &impl Serialize) -> Result<()> {
    let file = File::create_new(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, data)?;
    writer.flush()?;
    Ok(())
}
pub fn add_cases(
    dir: &Path,
    name: &str,
    archive: &Archive,
    view: &Snapshot,
    queries: &[Query],
    expected: [&str; 4],
    output: (&mut Cases, &mut Answers),
) -> Result<()> {
    let (cases, answers) = output;
    ensure!(queries.len() == expected.len(), "wrong fixture size");
    let packet = format!("{name}.json");
    save_json(&dir.join(&packet), &archive.export(view, "read")?)?;
    for ((query, want), suffix) in
        queries
            .iter()
            .zip(expected)
            .zip(["score-above", "score-within", "above", "within"])
    {
        let key = format!("{name}/{suffix}");
        answers.insert(key.clone(), want.into());
        cases.insert(
            key,
            Case {
                packet: packet.clone(),
                query: query.clone(),
            },
        );
    }
    Ok(())
}
pub fn run(dir: &Path, cases: &Cases) -> Result<Answers> {
    let mut answers = Answers::new();
    let packets: BTreeSet<_> = cases.values().map(|c| &c.packet).collect();
    for name in packets {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
                && !name.starts_with('.'),
            "invalid packet name"
        );
        let mut bytes = vec![];
        File::open(dir.join(name))?
            .take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 256 * 1024 * 1024, "exchange byte limit");
        let bundle: Bundle = serde_json::from_slice(&bytes)?;
        let mut archive = Archive::memory()?;
        archive.import(&bundle)?;
        for (key, case) in cases.iter().filter(|(_, c)| &c.packet == name) {
            let r = assess(&archive, &bundle.snapshot, &case.query)?;
            let value = if let Some(standing) = r.result {
                serde_json::to_value(standing)?
                    .as_str()
                    .context("standing")?
                    .to_owned()
            } else if !r.horizon_complete {
                "unknown".into()
            } else {
                let scores: BTreeSet<_> = r
                    .branches
                    .iter()
                    .filter_map(|b| b["score"].as_str())
                    .collect();
                if scores.is_empty() {
                    "unknown".into()
                } else {
                    scores.into_iter().collect::<Vec<_>>().join("+")
                }
            };
            answers.insert(key.clone(), value);
        }
    }
    Ok(answers)
}
#[derive(Default, Serialize)]
pub struct Grade {
    pub total: usize,
    pub correct: usize,
    pub incorrect_acceptance: usize,
    pub incorrect_rejection: usize,
    pub incorrect_abstention: usize,
    pub other_disagreements: BTreeSet<String>,
    pub differences: BTreeMap<String, (String, String)>,
}
pub fn grade(answer_key: &Answers, submitted: &Answers) -> Result<Grade> {
    ensure!(
        !answer_key.is_empty() && answer_key.keys().eq(submitted.keys()),
        "case inventory mismatch"
    );
    let mut g = Grade {
        total: answer_key.len(),
        ..Grade::default()
    };
    let vocabulary = [
        "pass",
        "fail",
        "fail+pass",
        "supported",
        "refuted",
        "contested",
        "unresolved",
        "unknown",
    ];
    for (id, want) in answer_key {
        let got = &submitted[id];
        ensure!(
            vocabulary.contains(&want.as_str()) && vocabulary.contains(&got.as_str()),
            "unknown outcome"
        );
        if got == want {
            g.correct += 1;
            continue;
        }
        match got.as_str() {
            "pass" | "supported" => g.incorrect_acceptance += 1,
            "fail" | "refuted" => g.incorrect_rejection += 1,
            "unknown" | "unresolved" => g.incorrect_abstention += 1,
            _ => {
                g.other_disagreements.insert(id.clone());
            }
        }
        g.differences
            .insert(id.clone(), (want.clone(), got.clone()));
    }
    Ok(g)
}
