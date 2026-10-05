//! Ten checkpoints, complete receiver snapshots and only binary terminal decisions.
use super::{
    Config,
    dataset::{CheckedSnapshot, FEATURE_SCHEMA, POLICY, Snapshot, id, question},
    experiment::{Release, raw_approve},
};
use crate::{dataset::digest, write};
use naome_authoring::compile_against_proof_context;
use naome_foundation::{Formula, FreeVariable};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Instant};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub source: String,
    pub title: String,
    pub context: String,
    pub profile_id: String,
}
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub enum Decision {
    #[serde(rename = "APPROVE")]
    Approve,
    #[serde(rename = "DECLINE")]
    Decline,
}
#[derive(Deserialize, Serialize, Clone)]
pub struct Check {
    pub id: String,
    pub status: String,
    pub reason: Option<String>,
}
#[derive(Deserialize, Serialize)]
pub struct Receipt {
    pub schema: u32,
    pub decision: Decision,
    pub reason: String,
    pub checks: Vec<Check>,
    pub input_sha256: String,
    pub input_digest_kind: String,
    pub question_id: Option<String>,
    pub snapshot_sha256: Option<String>,
    pub profile_id: String,
    pub policy: String,
    pub feature_schema: String,
    pub source_tree: String,
    pub model_sha256: Option<String>,
    pub threshold: Option<f64>,
    pub scores: Option<[f64; 4]>,
    pub checked_witness: Option<String>,
    pub elapsed_millis: u128,
}
impl Receipt {
    fn new(submission: &Submission) -> Self {
        Self {
            schema: 1,
            decision: Decision::Decline,
            reason: "ASSESSMENT_UNAVAILABLE".into(),
            checks: (1..=10)
                .map(|n| Check {
                    id: format!("GF{n:02}"),
                    status: "NOT_RUN".into(),
                    reason: None,
                })
                .collect(),
            input_digest_kind: "canonical-submission-json-v1".into(),
            input_sha256: digest(
                &serde_json::to_vec(submission).expect("submission serialization"),
            ),
            question_id: None,
            snapshot_sha256: None,
            profile_id: submission.profile_id.clone(),
            policy: POLICY.into(),
            feature_schema: FEATURE_SCHEMA.into(),
            source_tree: env!("NAOME_LAB_SOURCE_TREE").into(),
            model_sha256: None,
            threshold: None,
            scores: None,
            checked_witness: None,
            elapsed_millis: 0,
        }
    }
    fn pass(&mut self, number: usize) {
        self.checks[number - 1].status = "PASS".into();
    }
    fn fail(mut self, number: usize, reason: &str, clock: Instant) -> Self {
        self.reason = reason.into();
        self.checks[number - 1].status = "FAIL".into();
        self.checks[number - 1].reason = Some(reason.into());
        self.elapsed_millis = clock.elapsed().as_millis();
        self
    }
}
fn deadline(clock: Instant, config: &Config) -> bool {
    clock.elapsed().as_millis() >= u128::from(config.decision_millis)
}
/// Construct an actual checked answer from the complete declared general-lemma context.
fn elementary(
    target: &Formula,
    context: &CheckedSnapshot,
    snapshot: &Snapshot,
) -> Result<Option<String>, String> {
    let target_bytes = target.encode_canonical().map_err(|e| e.to_string())?;
    for (known, source) in context.knowledge.iter().zip(&snapshot.proof_sources) {
        let compiled =
            compile_against_proof_context(source, &context.state).map_err(|e| e.to_string())?;
        let proof_id = crate::dataset::hex(compiled.proof_id().as_bytes());
        let steps = if target == &Formula::for_all(FreeVariable::new(u32::MAX), known.clone()) {
            Some(format!(
                "p0 = cite(\"{proof_id}\")\np1 = generalization(p0,unused)"
            ))
        } else {
            let known_bytes = known.encode_canonical().map_err(|e| e.to_string())?;
            if target_bytes.first() == Some(&3)
                && target_bytes.len() > known_bytes.len() + 1
                && target_bytes.ends_with(&known_bytes)
            {
                let left = &target_bytes[1..target_bytes.len() - known_bytes.len()];
                if let Ok(antecedent) = Formula::decode_canonical(left) {
                    if antecedent.is_closed()
                        && target == &Formula::implies(antecedent.clone(), known.clone())
                    {
                        Some(format!(
                            "p0 = cite(\"{proof_id}\")\np1 = simplification({}, {})\np2 = modus_ponens(p0,p1)",
                            known.to_source(),
                            antecedent.to_source()
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(steps) = steps {
            let root = if steps.contains("p2 =") { "p2" } else { "p1" };
            let witness = format!(
                "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n{steps}\nreturn {root}\n",
                target.to_source()
            );
            // Compile includes the real checker and exact conclusion comparison.
            let _ = compile_against_proof_context(&witness, &context.state)
                .map_err(|e| e.to_string())?;
            return Ok(Some(witness));
        }
    }
    Ok(None)
}
pub fn assess(
    submission: &Submission,
    snapshot: Result<&Snapshot, String>,
    release: Result<&Release, String>,
    config: &Config,
    clock: Instant,
) -> Receipt {
    let mut receipt = Receipt::new(submission);
    if deadline(clock, config) {
        return receipt.fail(8, "DECISION_DEADLINE", clock);
    }
    if submission.title.is_empty()
        || submission.title.len() > 256
        || submission.context.is_empty()
        || submission.context.len() > 4096
        || submission.profile_id.is_empty()
    {
        return receipt.fail(1, "CONTEXT_MISMATCH", clock);
    }
    if submission.source.len() > 65536 {
        return receipt.fail(8, "RESOURCE_LIMIT", clock);
    }
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(_) => return receipt.fail(2, "MISSING_REFERENCE", clock),
    };
    if serde_json::to_vec(snapshot).map_or(true, |b| b.len() > 2 * 1024 * 1024) {
        return receipt.fail(8, "RESOURCE_LIMIT", clock);
    }
    let context = match snapshot.checked() {
        Ok(c) => c,
        Err(_) => return receipt.fail(2, "INVALID_CONTEXT", clock),
    };
    receipt.snapshot_sha256 = Some(snapshot.digest());
    let target = match question(&submission.source, &context.state) {
        Ok(f) => f,
        Err(_) => return receipt.fail(1, "INVALID_TARGET", clock),
    };
    receipt.question_id = id(&target).ok();
    receipt.pass(1);
    receipt.pass(2);
    if deadline(clock, config) {
        return receipt.fail(8, "DECISION_DEADLINE", clock);
    }
    if context.registry.contains(&target) {
        return receipt.fail(3, "EXACT_DUPLICATE", clock);
    }
    receipt.pass(3);
    if context.knowledge.iter().any(|f| {
        f == &target
            || f == &Formula::negate(target.clone())
            || target == Formula::negate(f.clone())
    }) {
        return receipt.fail(4, "ALREADY_SETTLED", clock);
    }
    receipt.pass(4);
    // Boolean question inversion carries the same requested information.
    // This is a declared admission relation, not a newly certified proof.
    if context
        .registry
        .iter()
        .chain(&context.knowledge)
        .any(|f| target == Formula::negate(f.clone()))
    {
        return receipt.fail(5, "SEMANTIC_REFORMULATION", clock);
    }
    match elementary(&target, &context, snapshot) {
        Ok(Some(witness)) => {
            receipt.checked_witness = Some(witness);
            return receipt.fail(6, "KNOWN_ELEMENTARY_INSTANCE", clock);
        }
        Err(_) => return receipt.fail(2, "INVALID_CONTEXT", clock),
        _ => {}
    }
    if submission.profile_id != snapshot.profile_id {
        return receipt.fail(7, "OUTSIDE_PROFILE", clock);
    }
    if deadline(clock, config) {
        return receipt.fail(8, "DECISION_DEADLINE", clock);
    }
    receipt.pass(8);
    let release = match release {
        Ok(r) => r,
        Err(_) => return receipt.fail(10, "ASSESSMENT_UNAVAILABLE", clock),
    };
    if release.validate().is_err() || release.source_tree != env!("NAOME_LAB_SOURCE_TREE") {
        return receipt.fail(9, "INCOMPLETE_CONTEXT", clock);
    }
    receipt.model_sha256 = Some(release.model_sha256.clone());
    receipt.threshold = Some(release.threshold);
    receipt.pass(9);
    if !release.qualified {
        return receipt.fail(10, "MODEL_UNQUALIFIED", clock);
    }
    let graph = match crate::graph::Graph::question(&target) {
        Ok(g) => g,
        Err(_) => return receipt.fail(8, "RESOURCE_LIMIT", clock),
    };
    if graph.nodes.len() > release.max_question_nodes {
        return receipt.fail(10, "ASSESSMENT_OUT_OF_DISTRIBUTION", clock);
    }
    let scores = release.model.score(&graph, &context.graph);
    receipt.scores = Some(scores);
    if deadline(clock, config) {
        return receipt.fail(8, "DECISION_DEADLINE", clock);
    }
    if !raw_approve(&scores, release.threshold) {
        let class = (0..4)
            .max_by(|a, b| scores[*a].total_cmp(&scores[*b]))
            .expect("four classes");
        let (check, reason) = if class > 0 && scores[class] >= release.threshold {
            (
                class + 4,
                [
                    "",
                    "SEMANTIC_REFORMULATION",
                    "KNOWN_ELEMENTARY_INSTANCE",
                    "OUTSIDE_PROFILE",
                ][class],
            )
        } else {
            (10, "ASSESSMENT_INSUFFICIENT_EVIDENCE")
        };
        return receipt.fail(check, reason, clock);
    }
    receipt.pass(5);
    receipt.pass(6);
    receipt.pass(7);
    receipt.pass(10);
    if receipt.checks.iter().all(|c| c.status == "PASS") {
        receipt.decision = Decision::Approve;
        receipt.reason = "ALL_CHECKPOINTS_PASS".into();
    }
    receipt.elapsed_millis = clock.elapsed().as_millis();
    receipt
}
pub fn run(config: &Config, output: &Path) -> Result<(), String> {
    let clock = Instant::now();
    let raw = super::bytes(&output.join("question-request.json"), 2 * 1024 * 1024);
    let submission: Submission = match raw
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|b| serde_json::from_slice(b).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(_) => {
            let invalid = Submission {
                source: String::new(),
                title: String::new(),
                context: String::new(),
                profile_id: String::new(),
            };
            let mut receipt = Receipt::new(&invalid).fail(1, "INVALID_TARGET", clock);
            receipt.input_sha256 = raw
                .as_ref()
                .map_or_else(|_| "unavailable".into(), |b| digest(b));
            receipt.input_digest_kind = if raw.is_ok() {
                "raw-submission-json-v1"
            } else {
                "input-unavailable"
            }
            .into();
            return write(&output.join("question-decision.json"), &receipt);
        }
    };
    // Receiver-owned fixed filenames. Candidate input cannot choose a smaller corpus/model.
    let snapshot: Result<Snapshot, String> = super::read(&output.join("receiver-snapshot.json"));
    let release: Result<Release, String> = super::read(&output.join("receiver-release.json"));
    let mut receipt = assess(
        &submission,
        snapshot.as_ref().map_err(Clone::clone),
        release.as_ref().map_err(Clone::clone),
        config,
        clock,
    );
    receipt.input_sha256 = digest(raw.as_ref().expect("validated input bytes"));
    receipt.input_digest_kind = "raw-submission-json-v1".into();
    write(&output.join("question-decision.json"), &receipt)
}
