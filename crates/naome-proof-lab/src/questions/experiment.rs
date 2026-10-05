//! Fixed training and development-only calibration, with retained negative results.
use super::read;
use super::{
    Config,
    dataset::{Corpus, FEATURE_SCHEMA, Input, POLICY},
};
use crate::{
    dataset::digest,
    model::{Adam, Model, Random},
    write,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedEvidence {
    pub model: Model,
    pub threshold: f64,
    pub heldout: serde_json::Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema: u32,
    pub policy: String,
    pub feature_schema: String,
    pub model: Model,
    pub model_sha256: String,
    pub threshold: f64,
    pub corpus_sha256: String,
    pub label_review_sha256: String,
    pub label_review_receipt: String,
    pub seed_evidence: Vec<SeedEvidence>,
    pub source_tree: String,
    pub qualified: bool,
    pub qualification_reason: String,
    pub heldout: serde_json::Value,
    pub max_question_nodes: usize,
}
impl Release {
    pub fn validate(&self) -> Result<(), String> {
        self.model.validate_policy(POLICY)?;
        if self.schema != 1
            || self.policy != POLICY
            || self.feature_schema != FEATURE_SCHEMA
            || self.model_sha256
                != digest(&serde_json::to_vec(&self.model).map_err(|e| e.to_string())?)
            || self.model.corpus_digest != self.corpus_sha256
            || self.label_review_sha256 != digest(self.label_review_receipt.as_bytes())
            || self.source_tree.len() != 40
            || !self.threshold.is_finite()
            || !(0.90..=1.0).contains(&self.threshold)
            || self.max_question_nodes == 0
            || self.max_question_nodes > 8192
        {
            return Err("invalid question release binding".into());
        }
        if self.qualified {
            let review: serde_json::Value =
                serde_json::from_str(&self.label_review_receipt).map_err(|e| e.to_string())?;
            let corpus = super::dataset::generate()?;
            if review["accepted"] != true
                || review["corpus_sha256"] != corpus.digest()
                || review["fixtures_sha256"] != corpus.fixtures_sha256
                || review["reviewer"].as_str().is_none_or(str::is_empty)
                || self.corpus_sha256 != corpus.digest()
                || !qualified_metrics(&self.heldout)
                || self.seed_evidence.len() != 3
            {
                return Err(
                    "qualification metrics or independently reviewed corpus binding invalid".into(),
                );
            }
            let inputs = corpus.replay()?;
            let config: Config =
                serde_json::from_str(include_str!("../../fixtures/question-experiment.json"))
                    .map_err(|e| e.to_string())?;
            config.validate()?;
            for (evidence, seed) in self.seed_evidence.iter().zip(&config.seeds) {
                evidence.model.validate_policy(POLICY)?;
                if evidence.model.seed != *seed
                    || evidence.model.corpus_digest != self.corpus_sha256
                    || !qualified_metrics(&evidence.heldout)
                    || evidence.threshold.to_bits()
                        != calibration(&corpus, &inputs, &evidence.model, &config).to_bits()
                    || evidence.heldout
                        != evaluate(
                            &corpus,
                            &inputs,
                            &evidence.model,
                            "test",
                            evidence.threshold,
                        )
                {
                    return Err("three-seed qualification evidence does not reproduce".into());
                }
            }
            let own = self
                .seed_evidence
                .iter()
                .find(|e| e.model.seed == self.model.seed)
                .ok_or("release model is outside qualified seeds")?;
            if digest(&serde_json::to_vec(&own.model).map_err(|e| e.to_string())?)
                != self.model_sha256
                || own.threshold.to_bits() != self.threshold.to_bits()
                || own.heldout != self.heldout
            {
                return Err("release model differs from three-seed qualification evidence".into());
            }
        }
        Ok(())
    }
}
fn qualified_metrics(report: &serde_json::Value) -> bool {
    let Some(rows) = report["rows"].as_u64() else {
        return false;
    };
    let Some(positives) = report["positive_rows"].as_u64() else {
        return false;
    };
    let Some(negatives) = report["negative_rows"].as_u64() else {
        return false;
    };
    let Some(false_approve) = report["false_approve"].as_u64() else {
        return false;
    };
    let Some(false_decline) = report["false_decline"].as_u64() else {
        return false;
    };
    let Some(families) = report["independent_families"].as_u64() else {
        return false;
    };
    let Some(covered) = report["families_with_an_approved_positive"].as_u64() else {
        return false;
    };
    let Some(control_errors) = report["exact_profile_control_errors"].as_u64() else {
        return false;
    };
    rows == 32
        && positives == 8
        && negatives == 24
        && families == 4
        && false_approve == 0
        && false_decline <= 2
        && covered == families
        && false_approve + false_decline < control_errors
}
pub fn raw_approve(score: &[f64; 4], threshold: f64) -> bool {
    score.iter().all(|n| n.is_finite())
        && score[0] >= threshold
        && score[1..].iter().all(|v| score[0] > *v)
}
fn calibration(corpus: &Corpus, inputs: &[Input], model: &Model, config: &Config) -> f64 {
    // No test row participates. Strict tie refusal is preserved at 1.0.
    corpus
        .rows
        .iter()
        .zip(inputs)
        .filter(|(r, _)| r.split == "development" && r.label != 0)
        .map(|(_, i)| model.score(&i.graph, &i.context.graph)[0])
        .fold(config.threshold_floor, |floor, p| {
            floor.max((p + f64::EPSILON).min(1.0))
        })
}
fn wilson(success: usize, total: usize) -> [f64; 2] {
    if total == 0 {
        return [0.0, 1.0];
    }
    let n = total as f64;
    let p = success as f64 / n;
    let z2 = 1.96_f64.powi(2);
    let center = (p + z2 / (2.0 * n)) / (1.0 + z2 / n);
    let margin = 1.96 * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt() / (1.0 + z2 / n);
    [(center - margin).max(0.0), (center + margin).min(1.0)]
}
pub fn evaluate(
    corpus: &Corpus,
    inputs: &[Input],
    model: &Model,
    partition: &str,
    threshold: f64,
) -> serde_json::Value {
    let mut predictions = Vec::new();
    let mut matrix = [[0usize; 4]; 4];
    let mut false_approve = 0;
    let mut false_decline = 0;
    let mut positives = 0;
    let mut negatives = 0;
    let mut families = BTreeMap::<usize, (usize, usize)>::new();
    let mut deterministic_errors = 0;
    for (row, input) in corpus
        .rows
        .iter()
        .zip(inputs)
        .filter(|(r, _)| r.split == partition)
    {
        let scores = model.score(&input.graph, &input.context.graph);
        let predicted = (0..4)
            .max_by(|a, b| scores[*a].total_cmp(&scores[*b]))
            .expect("four outputs");
        let approve = raw_approve(&scores, threshold);
        matrix[row.label][predicted] += 1;
        let family = families.entry(row.family).or_default();
        if row.label == 0 {
            positives += 1;
            family.0 += 1;
            if approve {
                family.1 += 1;
            } else {
                false_decline += 1;
            }
        } else {
            negatives += 1;
            if approve {
                false_approve += 1;
            }
        }
        // An explicit exact-objective receiver profile is a transparent control.
        // It is not a semantic oracle or a hidden train label feature.
        let exact_profile = input.formula == input.context.objective
            && !input.context.registry.contains(&input.formula)
            && !input.context.knowledge.iter().any(|f| {
                f == &input.formula
                    || f == &naome_foundation::Formula::negate(input.formula.clone())
            });
        if exact_profile != (row.label == 0) {
            deterministic_errors += 1;
        }
        predictions.push(serde_json::json!({"question_id":row.question_id,"family":row.family,"variant":row.variant,"expected":row.decision,"scores":scores,"diagnostic_class":predicted,"raw_decision":if approve{"APPROVE"}else{"DECLINE"},"exact_profile_control":if exact_profile{"APPROVE"}else{"DECLINE"},"always_decline_control":"DECLINE"}));
    }
    let covered = families
        .values()
        .filter(|(_, approved)| *approved > 0)
        .count();
    let accepted = positives > 0
        && false_approve == 0
        && false_decline * 4 <= positives
        && covered == families.len();
    serde_json::json!({"partition":partition,"rows":predictions.len(),"independent_families":families.len(),"positive_rows":positives,"negative_rows":negatives,"false_approve":false_approve,"false_decline":false_decline,"positive_coverage":if positives==0{0.0}else{(positives-false_decline)as f64/positives as f64},"positive_coverage_row_wilson95":wilson(positives-false_decline,positives),"false_approve_row_wilson95":wilson(false_approve,negatives),"families_with_an_approved_positive":covered,"family_coverage_wilson95":wilson(covered,families.len()),"row_interval_limit":"Descriptive only: repeated source variants are dependent, family counts are the transfer unit.","four_class_confusion":matrix,"exact_profile_control_errors":deterministic_errors,"added_utility_demonstrated":false_approve+false_decline<deterministic_errors,"utility_contract":"A release needs strictly fewer binary mistakes than the transparent exact-objective deterministic control, in addition to every error/coverage target. Equal results do not demonstrate additional utility.","always_decline_false_declines":positives,"meets_predeclared_targets":accepted,"predictions":predictions})
}
pub fn run(
    command: &str,
    config: &Config,
    corpus: &Corpus,
    inputs: &[Input],
    output: &Path,
) -> Result<(), String> {
    let train = corpus
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.split == "train")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    let label_digest = digest(&super::bytes(
        &output.join("question-label-review.json"),
        1024 * 1024,
    )?);
    for &seed in &config.seeds {
        let trained = output.join(format!("question-model-{seed}.json"));
        if command == "questions-train" {
            let clock = Instant::now();
            let mut model = Model::new(seed, corpus.digest());
            model.policy = POLICY.into();
            model.validate_policy(POLICY)?;
            let initial = digest(&serde_json::to_vec(&model).map_err(|e| e.to_string())?);
            let mut optimizer = Adam::new(&model);
            let mut rng = Random(seed);
            let mut order = train.clone();
            let mut losses = Vec::new();
            for _ in 0..config.epochs {
                for i in (1..order.len()).rev() {
                    let j = rng.next() as usize % (i + 1);
                    order.swap(i, j);
                }
                let mut total = 0.0;
                for &i in &order {
                    let input = &inputs[i];
                    let (loss, gradient) =
                        model.gradient(&input.graph, &input.context.graph, corpus.rows[i].label);
                    if !loss.is_finite() {
                        return Err("nonfinite question training loss".into());
                    }
                    optimizer.update(&mut model, &gradient, config.learning_rate);
                    total += loss;
                }
                losses.push(total / train.len() as f64);
            }
            let threshold = calibration(corpus, inputs, &model, config);
            model.validate_policy(POLICY)?;
            write(&trained, &model)?;
            write(
                &output.join(format!("question-training-{seed}.json")),
                &serde_json::json!({"schema":1,"seed":seed,"corpus_sha256":corpus.digest(),"label_review_sha256":label_digest,"initial_model_sha256":initial,"model_sha256":digest(&serde_json::to_vec(&model).map_err(|e|e.to_string())?),"parameters":model.parameters(),"epochs":config.epochs,"loss_by_epoch":losses,"threshold":threshold,"train_rows":train.len(),"train_seconds":clock.elapsed().as_secs_f64(),"development":evaluate(corpus,inputs,&model,"development",threshold)}),
            )?;
        } else {
            let model: Model = read(&trained)?;
            model.validate_policy(POLICY)?;
            let report: serde_json::Value =
                read(&output.join(format!("question-training-{seed}.json")))?;
            let threshold = calibration(corpus, inputs, &model, config);
            if model.seed != seed
                || model.corpus_digest != corpus.digest()
                || report["model_sha256"]
                    != digest(&serde_json::to_vec(&model).map_err(|e| e.to_string())?)
                || report["corpus_sha256"] != corpus.digest()
                || report["label_review_sha256"] != label_digest
                || report["threshold"]
                    .as_f64()
                    .is_none_or(|v| v.to_bits() != threshold.to_bits())
                || report["development"]
                    != evaluate(corpus, inputs, &model, "development", threshold)
            {
                return Err("question model/calibration/report binding mismatch".into());
            }
            let heldout = evaluate(corpus, inputs, &model, "test", threshold);
            let path = output.join(format!("question-quality-{seed}.json"));
            if command == "questions-evaluate" {
                write(&path, &heldout)?;
            } else if read::<serde_json::Value>(&path)? != heldout {
                return Err("question held-out replay mismatch".into());
            }
        }
    }
    if command == "questions-evaluate" || command == "questions-replay" {
        let qualities = config
            .seeds
            .iter()
            .map(|seed| {
                read::<serde_json::Value>(&output.join(format!("question-quality-{seed}.json")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let qualified = qualities.iter().all(|q| {
            q["meets_predeclared_targets"] == true && q["added_utility_demonstrated"] == true
        });
        let seed_evidence = config
            .seeds
            .iter()
            .zip(&qualities)
            .map(|(&seed, heldout)| {
                let model: Model = read(&output.join(format!("question-model-{seed}.json")))?;
                Ok(SeedEvidence {
                    threshold: calibration(corpus, inputs, &model, config),
                    model,
                    heldout: heldout.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        for (&seed, heldout) in config.seeds.iter().zip(qualities) {
            let model: Model = read(&output.join(format!("question-model-{seed}.json")))?;
            let threshold = calibration(corpus, inputs, &model, config);
            let max_question_nodes = corpus
                .rows
                .iter()
                .zip(inputs)
                .filter(|(r, _)| r.split == "train")
                .map(|(_, i)| i.graph.nodes.len())
                .max()
                .ok_or("empty training range")?;
            let release = Release {
                schema: 1,
                policy: POLICY.into(),
                feature_schema: FEATURE_SCHEMA.into(),
                model_sha256: digest(&serde_json::to_vec(&model).map_err(|e| e.to_string())?),
                model,
                threshold,
                corpus_sha256: corpus.digest(),
                label_review_sha256: label_digest.clone(),
                seed_evidence: seed_evidence.clone(),
                label_review_receipt: String::from_utf8(super::bytes(
                    &output.join("question-label-review.json"),
                    1024 * 1024,
                )?)
                .map_err(|e| e.to_string())?,
                source_tree: env!("NAOME_LAB_SOURCE_TREE").into(),
                qualified,
                qualification_reason: if qualified {
                    "ALL_TARGETS_AND_ADDITIONAL_UTILITY_PASS"
                } else {
                    "PREDECLARED_TARGET_OR_ADDITIONAL_UTILITY_NOT_ESTABLISHED"
                }
                .into(),
                heldout,
                max_question_nodes,
            };
            release.validate()?;
            let path = output.join(format!("question-release-{seed}.json"));
            if command == "questions-evaluate" {
                write(&path, &release)?;
            } else {
                let saved: Release = read(&path)?;
                saved.validate()?;
                if serde_json::to_vec(&saved).map_err(|e| e.to_string())?
                    != serde_json::to_vec(&release).map_err(|e| e.to_string())?
                {
                    return Err("question release replay mismatch".into());
                }
            }
        }
    }
    Ok(())
}
