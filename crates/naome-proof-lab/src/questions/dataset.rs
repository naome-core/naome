//! Real authoring validation and receiver-owned, replayable experimental snapshots.
use crate::{
    dataset::{digest, hex},
    graph::Graph,
};
use naome_authoring::{compile_against_proof_context, validate_question_against_proof_context};
use naome_checker::{ArtifactState, normalize_and_check_with_state};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::ProofCertificate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const POLICY: &str = "question-catalog-experiment-v1";
pub const FEATURE_SCHEMA: &str = "closed-question-full-context-graph-v1";
pub const LABELS: [&str; 4] = [
    "APPROVE",
    "SEMANTIC_REFORMULATION",
    "KNOWN_ELEMENTARY_INSTANCE",
    "OUTSIDE_PROFILE",
];
pub const FIXTURES: &str = include_str!("../../fixtures/question-families.json");
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Families {
    pub schema: u32,
    pub policy: String,
    pub families: Vec<Family>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub name: String,
    pub split: String,
    pub target: String,
    pub registry: String,
    pub outside: [String; 2],
    pub objective: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub policy: String,
    pub profile_id: String,
    pub objective: String,
    pub objective_source: String,
    pub registry_sources: Vec<String>,
    pub proof_sources: Vec<String>,
}
pub struct CheckedSnapshot {
    pub state: ArtifactState,
    pub objective: Formula,
    pub registry: Vec<Formula>,
    pub knowledge: Vec<Formula>,
    pub graph: Graph,
}
impl Snapshot {
    pub fn digest(&self) -> String {
        digest(&serde_json::to_vec(self).expect("snapshot serialization"))
    }
    pub fn checked(&self) -> Result<CheckedSnapshot, String> {
        if self.schema != 1
            || self.policy != POLICY
            || self.profile_id.is_empty()
            || self.objective.is_empty()
            || self.objective.len() > 4096
            || self.proof_sources.is_empty()
            || self.proof_sources.len() + self.registry_sources.len() > 512
        {
            return Err("invalid receiver-owned snapshot".into());
        }
        let mut state = ArtifactState::new();
        let mut knowledge = Vec::new();
        for source in &self.proof_sources {
            if source.len() > 65536 {
                return Err("snapshot proof source ceiling".into());
            }
            let output =
                compile_against_proof_context(source, &state).map_err(|e| e.to_string())?;
            let certificate =
                ProofCertificate::from_canonical_bytes(output.canonical_proof_bytes())
                    .map_err(|e| e.to_string())?;
            let checked =
                normalize_and_check_with_state(certificate, &state).map_err(|e| e.to_string())?;
            knowledge.push(checked.conclusion().clone());
            state
                .register_proof_for_replication(checked)
                .map_err(|e| e.to_string())?;
        }
        let objective = question(&self.objective_source, &state)?;
        let registry = self
            .registry_sources
            .iter()
            .map(|s| question(s, &state))
            .collect::<Result<Vec<_>, _>>()?;
        let parts = std::iter::once((objective.clone(), 2))
            .chain(registry.iter().cloned().map(|f| (f, 1)))
            .chain(knowledge.iter().cloned().map(|f| (f, 0)))
            .collect::<Vec<_>>();
        let graph = Graph::question_context(&parts)?;
        Ok(CheckedSnapshot {
            state,
            objective,
            registry,
            knowledge,
            graph,
        })
    }
}
pub fn source(target: &str) -> String {
    format!("foundation = \"naome:zfc\"\nquestion = {target}\n")
}
pub fn question(source: &str, state: &ArtifactState) -> Result<Formula, String> {
    if source.len() > 65536 {
        return Err("question input ceiling".into());
    }
    validate_question_against_proof_context(source, state)
        .map(|q| q.formula().clone())
        .map_err(|e| e.to_string())
}
pub fn id(formula: &Formula) -> Result<String, String> {
    let bytes = formula.encode_canonical().map_err(|e| e.to_string())?;
    let mut bound = b"NAOME-LAB-QUESTION-V1\0naome:zfc\0".to_vec();
    bound.extend(bytes);
    Ok(digest(&bound))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub family: usize,
    pub variant: String,
    pub split: String,
    pub source: String,
    pub source_sha256: String,
    pub canonical: Vec<u8>,
    pub question_id: String,
    pub snapshot: Snapshot,
    pub snapshot_sha256: String,
    pub label: usize,
    pub decision: String,
    pub rules: BTreeMap<String, String>,
    pub rationale: String,
    /// Actual complete checker input, or empty when no mathematical witness is claimed.
    pub witness_source: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub schema: u32,
    pub policy: String,
    pub feature_schema: String,
    pub fixtures_sha256: String,
    pub rows: Vec<Row>,
}
pub struct Input {
    pub formula: Formula,
    pub graph: Graph,
    pub context: CheckedSnapshot,
}
impl Corpus {
    pub fn digest(&self) -> String {
        digest(&serde_json::to_vec(self).expect("corpus serialization"))
    }
    pub fn replay(&self) -> Result<Vec<Input>, String> {
        // The frozen authoring templates, labels, profile and split are authoritative inputs.
        let expected = generate()?;
        if serde_json::to_vec(self).map_err(|e| e.to_string())?
            != serde_json::to_vec(&expected).map_err(|e| e.to_string())?
        {
            return Err(
                "corpus differs from the consumed frozen schema/source/label fixtures".into(),
            );
        }
        let mut identities = BTreeMap::new();
        let mut out = Vec::new();
        for row in &self.rows {
            let context = row.snapshot.checked()?;
            let formula = question(&row.source, &context.state)?;
            if id(&formula)? != row.question_id
                || formula.encode_canonical().map_err(|e| e.to_string())? != row.canonical
                || digest(row.source.as_bytes()) != row.source_sha256
                || row.snapshot.digest() != row.snapshot_sha256
            {
                return Err("question replay binding mismatch".into());
            }
            if let Some(old) = identities.insert(row.question_id.clone(), row.split.clone())
                && old != row.split
            {
                return Err("canonical question crosses whole-family split".into());
            }
            if row.decision == "APPROVE"
                && (context.registry.contains(&formula)
                    || context
                        .knowledge
                        .iter()
                        .any(|f| f == &formula || f == &Formula::negate(formula.clone())))
            {
                return Err("APPROVE target already present or settled".into());
            }
            if let Some(witness) = &row.witness_source {
                let proof = compile_against_proof_context(witness, &context.state)
                    .map_err(|e| e.to_string())?;
                let certificate =
                    ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes())
                        .map_err(|e| e.to_string())?;
                let checked = normalize_and_check_with_state(certificate, &context.state)
                    .map_err(|e| e.to_string())?;
                if checked.conclusion() != &formula {
                    return Err("elementary witness does not answer the exact target".into());
                }
            }
            out.push(Input {
                graph: Graph::question(&formula)?,
                formula,
                context,
            });
        }
        Ok(out)
    }
}
fn proof_source(target: &str, steps: &str, root: &str) -> String {
    format!("foundation = \"naome:zfc\"\nstatement = {target}\nproof:\n{steps}\nreturn {root}\n")
}
pub fn generate() -> Result<Corpus, String> {
    let fixtures: Families = serde_json::from_str(FIXTURES).map_err(|e| e.to_string())?;
    if fixtures.schema != 1 || fixtures.policy != POLICY || fixtures.families.len() != 16 {
        return Err("unsupported question fixture set".into());
    }
    let mut rows = Vec::new();
    for (family, f) in fixtures.families.iter().enumerate() {
        let empty = ArtifactState::new();
        let a = question(&source(&f.target), &empty)?;
        let outside1 = question(&source(&f.outside[0]), &empty)?;
        let outside2 = question(&source(&f.outside[1]), &empty)?;
        let r = question(&source(&f.registry), &empty)?;
        let t = Formula::implies(a.clone(), Formula::implies(outside2.clone(), a.clone()));
        let known = proof_source(
            &t.to_source(),
            &format!(
                "p0 = simplification({}, {})",
                a.to_source(),
                outside2.to_source()
            ),
            "p0",
        );
        let compiled = compile_against_proof_context(&known, &empty).map_err(|e| e.to_string())?;
        let proof_id = hex(compiled.proof_id().as_bytes());
        let snapshot = Snapshot {
            schema: 1,
            policy: POLICY.into(),
            profile_id: format!("structural-obligation-v1:{}", f.name),
            objective: f.objective.clone(),
            objective_source: source(&f.target),
            registry_sources: vec![source(&r.to_source())],
            proof_sources: vec![known],
        };
        let context = snapshot.checked()?;
        let v = FreeVariable::new(u32::MAX);
        let elementary = [
            Formula::for_all(v, t.clone()),
            Formula::implies(outside2.clone(), t.clone()),
        ];
        let witnesses = [
            proof_source(
                &elementary[0].to_source(),
                &format!("p0 = cite(\"{proof_id}\")\np1 = generalization(p0, unused)"),
                "p1",
            ),
            proof_source(
                &elementary[1].to_source(),
                &format!(
                    "p0 = cite(\"{proof_id}\")\np1 = simplification({}, {})\np2 = modus_ponens(p0,p1)",
                    t.to_source(),
                    outside2.to_source()
                ),
                "p2",
            ),
        ];
        let targets = [
            a.clone(),
            a.clone(),
            Formula::negate(Formula::negate(r.clone())),
            Formula::conjunction(r.clone(), r),
            elementary[0].clone(),
            elementary[1].clone(),
            outside1,
            outside2,
        ];
        let variants = [
            "objective",
            "formula_binding",
            "double_negated_registry",
            "repeated_registry_conjunction",
            "vacuous_known_lemma",
            "known_lemma_consequent",
            "other_obligation_one",
            "other_obligation_two",
        ];
        for (variant, target) in targets.into_iter().enumerate() {
            let label = variant / 2;
            let src = if variant == 1 {
                format!(
                    "foundation = \"naome:zfc\"\nformulas:\n goal = {}\nquestion = goal\n",
                    target.to_source()
                )
            } else {
                source(&target.to_source())
            };
            let parsed = validate_question_against_proof_context(&src, &context.state)
                .map_err(|e| e.to_string())?;
            if parsed.formula() != &target {
                return Err("generated source changed the target".into());
            }
            let mut rules = (1..=9)
                .map(|n| (format!("GF{n:02}"), "PASS".to_owned()))
                .collect::<BTreeMap<_, _>>();
            // These are complete expected rule vectors, not only a primary class.
            // GF10 is intentionally external to the reviewed data truth labels.
            if label != 0 {
                for rule in ["GF05", "GF07"] {
                    rules.insert(rule.into(), "FAIL".into());
                }
            }
            if label == 2 {
                rules.insert("GF04".into(), "FAIL".into());
                rules.insert("GF06".into(), "FAIL".into());
            }
            if variant == 6 {
                rules.insert("GF03".into(), "FAIL".into());
            }
            // GF10 is a release condition, deliberately excluded from corpus truth labels.
            let rationale=match label {
                0=>format!("Finite structural proof-obligation profile: {} Neither this target nor its negation is in the complete checked snapshot; it is not a specialization of the supplied simplification lemma. This is a reviewed experimental contribution label, not a claim of worldwide novelty or difficult open mathematics.",f.objective),
                1=>"Classical double-negation/repeated-conjunction reformulation of the declared existing unanswered registry question, outside the selected different objective. GF05 and GF07 fail; GF06 passes because this target is neither a vacuous universal nor an antecedent weakening of any supplied checked lemma. The label is an offline policy judgment; no checker-equivalence witness is claimed and no deterministic proof guard uses it.".into(),
                2=>"Exact checker-valid proof uses the declared general checked lemma. A vacuous universal or a weakened antecedent supplies no new research information; its complete answer witness is retained. GF04 already-settled, GF05 reformulation, GF06 elementary and GF07 no extra contribution all fail.".into(),
                _=>"The independent declared registry question or its negation is outside this receiver's different single structural objective. The exact source also fails GF03; its negation fails GF05. GF05 and GF07 fail. GF06 passes because this target is neither a vacuous universal nor an antecedent weakening of any supplied checked lemma; no general knowledge beyond this complete checked snapshot is claimed. A narrow-profile label is not a universal judgment about scientific value.".into(),
            };
            rows.push(Row {
                family,
                variant: variants[variant].into(),
                split: f.split.clone(),
                source_sha256: digest(src.as_bytes()),
                source: src,
                canonical: parsed.canonical_bytes().to_vec(),
                question_id: id(parsed.formula())?,
                snapshot_sha256: snapshot.digest(),
                snapshot: snapshot.clone(),
                label,
                decision: if label == 0 { "APPROVE" } else { "DECLINE" }.into(),
                rules,
                rationale,
                witness_source: if label == 2 {
                    Some(witnesses[variant - 4].clone())
                } else {
                    None
                },
            });
        }
    }
    if rows
        .iter()
        .filter(|r| r.split == "train")
        .map(|r| r.family)
        .collect::<BTreeSet<_>>()
        .len()
        != 8
        || rows
            .iter()
            .filter(|r| r.split == "development")
            .map(|r| r.family)
            .collect::<BTreeSet<_>>()
            .len()
            != 4
        || rows
            .iter()
            .filter(|r| r.split == "test")
            .map(|r| r.family)
            .collect::<BTreeSet<_>>()
            .len()
            != 4
    {
        return Err("unexpected whole-family partition".into());
    }
    Ok(Corpus {
        schema: 1,
        policy: POLICY.into(),
        feature_schema: FEATURE_SCHEMA.into(),
        fixtures_sha256: digest(FIXTURES.as_bytes()),
        rows,
    })
}
