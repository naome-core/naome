//! Bounded authoring inputs and exact Foundation answer checking.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use naome_authoring::compile_artifact_against_proof_context;
use naome_checker::{
    ArtifactState, ArtifactStateError, CheckedDefinition, CheckedProof,
    check_definition_with_state, check_normal_form_with_state,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ArtifactId, ArtifactPayload, StatementId};
use serde::{Deserialize, Serialize};

/// Experimental question-input bounds, independent of Foundation codec limits.
pub const QUESTION_MAX_DEPTH: usize = 32;
pub const QUESTION_MAX_NODES: usize = 256;
/// Maximum supplied helper artifacts for one answer or question context.
pub const DEPENDENCY_MAX_COUNT: usize = 8;
/// Maximum combined UTF-8 authoring bytes for one answer or question context.
pub const AUTHORING_MAX_BYTES: usize = 65_536;
/// Maximum combined canonical helper and final artifact payload bytes.
pub const ARTIFACT_MAX_TOTAL_BYTES: usize = 65_536;

/// Named primitive syntax; binder names carry no canonical identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum FormulaInput {
    Equal { left: u32, right: u32 },
    Member { element: u32, set: u32 },
    Not { body: Box<Self> },
    Implies { left: Box<Self>, right: Box<Self> },
    Forall { variable: u32, body: Box<Self> },
}

impl FormulaInput {
    /// Constructs a closed formula after charging every node and nesting level.
    pub fn to_formula(&self) -> Result<Formula, String> {
        let mut nodes = 0;
        let formula = self.lower(1, &mut nodes)?;
        if !formula.is_closed() {
            return Err("research question must be a closed Foundation formula".into());
        }
        Ok(formula)
    }

    /// Returns the Foundation encoding used for exact question identity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.to_formula()?
            .encode_canonical()
            .map_err(|error| format!("question encoding failed: {error}"))
    }

    /// Renders checked primitive `.nao` syntax with names `x0`, `x1`, etc.
    pub fn to_nao(&self) -> Result<String, String> {
        self.to_formula()?;
        let mut source = String::new();
        self.render(&mut source);
        Ok(source)
    }

    fn lower(&self, depth: usize, nodes: &mut usize) -> Result<Formula, String> {
        if depth > QUESTION_MAX_DEPTH {
            return Err(format!("question exceeds depth limit {QUESTION_MAX_DEPTH}"));
        }
        *nodes += 1;
        if *nodes > QUESTION_MAX_NODES {
            return Err(format!("question exceeds node limit {QUESTION_MAX_NODES}"));
        }
        let variable = FreeVariable::new;
        Ok(match self {
            Self::Equal { left, right } => Formula::equal(variable(*left), variable(*right)),
            Self::Member { element, set } => Formula::member(variable(*element), variable(*set)),
            Self::Not { body } => Formula::negate(body.lower(depth + 1, nodes)?),
            Self::Implies { left, right } => Formula::implies(
                left.lower(depth + 1, nodes)?,
                right.lower(depth + 1, nodes)?,
            ),
            Self::Forall { variable: id, body } => {
                Formula::for_all(variable(*id), body.lower(depth + 1, nodes)?)
            }
        })
    }

    fn render(&self, out: &mut String) {
        match self {
            Self::Equal { left, right } => write!(out, "equal(x{left}, x{right})").unwrap(),
            Self::Member { element, set } => write!(out, "member(x{element}, x{set})").unwrap(),
            Self::Not { body } => {
                out.push_str("not_(");
                body.render(out);
                out.push(')');
            }
            Self::Implies { left, right } => {
                out.push_str("implies(");
                left.render(out);
                out.push_str(", ");
                right.render(out);
                out.push(')');
            }
            Self::Forall { variable, body } => {
                write!(out, "forall(x{variable}, ").unwrap();
                body.render(out);
                out.push(')');
            }
        }
    }
}

/// A refutation proves the single syntactic negation of the published formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Proof,
    Refutation,
}

impl Outcome {
    #[must_use]
    pub fn expected(self, question: &Formula) -> Formula {
        match self {
            Self::Proof => question.clone(),
            Self::Refutation => Formula::negate(question.clone()),
        }
    }
}

/// A final proof source and its ordered, necessary checked helper closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerFile {
    pub source: String,
    pub dependencies: Vec<String>,
}

/// A fully checked answer and its proposed state; callers select it atomically.
pub struct CheckedAnswer {
    /// Exact untagged canonical final proof-certificate bytes.
    pub canonical_bytes: Vec<u8>,
    pub conclusion: Formula,
    pub resulting_state: ArtifactState,
    /// Typed artifact IDs as lowercase hex, in helper order then final proof.
    pub artifact_ids: Vec<String>,
}

impl std::fmt::Debug for CheckedAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedAnswer")
            .field("canonical_bytes", &self.canonical_bytes)
            .field("conclusion", &self.conclusion)
            .field("artifact_ids", &self.artifact_ids)
            .finish_non_exhaustive()
    }
}

/// Checks the exact answer and its minimal supplied closure on a private clone.
///
/// An error leaves `base` untouched. Neither discovery text nor new axioms are
/// proof evidence. Every source compiles, decodes canonically, and rechecks.
/// New artifacts register through the checker; a final proof may reuse an
/// already checked proof or derivation. Unused supplied artifacts fail.
pub fn check_answer(
    answer: &AnswerFile,
    question: &Formula,
    outcome: Outcome,
    base: &ArtifactState,
) -> Result<CheckedAnswer, String> {
    if !question.is_closed() {
        return Err("research question must be closed".into());
    }
    bound_sources(&answer.dependencies, Some(&answer.source))?;
    let mut state = base.clone();
    let mut records = Vec::new();
    let mut canonical_total = 0;
    for source in &answer.dependencies {
        let artifact = compile_checked(source, &state)?;
        charge_artifact(&artifact, &mut canonical_total)?;
        let record = register(artifact, &mut state, &records, base)?;
        records.push(record);
    }

    let final_artifact = compile_checked(&answer.source, &state)?;
    charge_artifact(&final_artifact, &mut canonical_total)?;
    let CheckedArtifact::Proof(proof) = final_artifact else {
        return Err("final answer must be a proof, not a definition".into());
    };
    let conclusion = proof.conclusion().clone();
    if conclusion != outcome.expected(question) {
        return Err("answer conclusion does not exactly match the published target".into());
    }
    let canonical_bytes = proof.normal_form().canonical_bytes().to_vec();
    let final_record = register_final_proof(proof, &mut state)?;
    require_exact_closure(&records, &final_record)?;
    let artifact_ids = records
        .iter()
        .chain(std::iter::once(&final_record))
        .map(|record| hex(record.id.as_bytes()))
        .collect();
    Ok(CheckedAnswer {
        canonical_bytes,
        conclusion,
        resulting_state: state,
        artifact_ids,
    })
}

/// Publishes bounded conservative definitions without admitting proof claims.
/// Function definitions still require their exact checked existence/uniqueness
/// obligation in `base`; source text cannot invent that obligation.
pub fn check_definitions(
    sources: &[String],
    base: &ArtifactState,
) -> Result<ArtifactState, String> {
    bound_sources(sources, None)?;
    let mut state = base.clone();
    let mut canonical_total = 0;
    for source in sources {
        let artifact = compile_checked(source, &state)?;
        charge_artifact(&artifact, &mut canonical_total)?;
        let CheckedArtifact::Definition(definition) = artifact else {
            return Err("question context accepts only conservative definitions".into());
        };
        state
            .register_definition(definition)
            .map_err(|error| format!("definition registration failed: {error}"))?;
    }
    Ok(state)
}

fn bound_sources(dependencies: &[String], final_source: Option<&str>) -> Result<(), String> {
    if dependencies.len() > DEPENDENCY_MAX_COUNT {
        return Err(format!("helper count exceeds limit {DEPENDENCY_MAX_COUNT}"));
    }
    let mut total = final_source.map_or(0, str::len);
    for source in dependencies {
        total = total
            .checked_add(source.len())
            .ok_or("authoring byte count overflow")?;
    }
    if total > AUTHORING_MAX_BYTES {
        return Err(format!(
            "authoring bytes exceed limit {AUTHORING_MAX_BYTES}"
        ));
    }
    Ok(())
}

enum CheckedArtifact {
    Proof(CheckedProof),
    Definition(CheckedDefinition),
}

/// Only concrete identities present in the current resolver can be imported.
/// A valid duplicate derivation may answer a question without publishing an alias.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AvailableArtifact {
    Proof {
        proof_id: String,
        source: String,
    },
    Definition {
        definition_id: String,
        source: String,
    },
}

pub(crate) fn available_artifact(source: &str, state: &ArtifactState) -> Option<AvailableArtifact> {
    match compile_checked(source, state).ok()? {
        CheckedArtifact::Proof(proof) if state.contains_proof(proof.proof_id()) => {
            Some(AvailableArtifact::Proof {
                proof_id: hex(proof.proof_id().as_bytes()),
                source: source.into(),
            })
        }
        CheckedArtifact::Definition(definition)
            if state.contains_definition(definition.definition_id()) =>
        {
            Some(AvailableArtifact::Definition {
                definition_id: hex(definition.definition_id().as_bytes()),
                source: source.into(),
            })
        }
        _ => None,
    }
}

fn charge_artifact(artifact: &CheckedArtifact, total: &mut usize) -> Result<(), String> {
    let length = 1 + match artifact {
        CheckedArtifact::Proof(proof) => proof.normal_form().canonical_bytes().len(),
        CheckedArtifact::Definition(definition) => {
            definition.certificate().to_canonical_bytes().len()
        }
    };
    *total = total
        .checked_add(length)
        .ok_or("canonical artifact byte count overflow")?;
    if *total > ARTIFACT_MAX_TOTAL_BYTES {
        return Err(format!(
            "canonical artifact bytes exceed limit {ARTIFACT_MAX_TOTAL_BYTES}"
        ));
    }
    Ok(())
}

fn compile_checked(source: &str, state: &ArtifactState) -> Result<CheckedArtifact, String> {
    let compiled = compile_artifact_against_proof_context(source, state)
        .map_err(|error| format!("authoring failed: {error}"))?;
    let bytes = compiled.canonical_artifact_bytes();
    let payload = ArtifactPayload::from_canonical_bytes(&bytes)
        .map_err(|error| format!("canonical artifact decoding failed: {error}"))?;
    if payload.to_canonical_bytes() != bytes {
        return Err("artifact encoding is not canonical".into());
    }
    match payload {
        ArtifactPayload::Proof(certificate) => {
            let normal_form = certificate
                .into_unchecked_normal_form()
                .with_matching_canonical_bytes(bytes[1..].into())
                .ok_or("proof bytes differ from canonical normal form")?;
            check_normal_form_with_state(normal_form, state)
                .map(CheckedArtifact::Proof)
                .map_err(|error| format!("proof recheck failed: {error}"))
        }
        ArtifactPayload::Definition(certificate) => check_definition_with_state(certificate, state)
            .map(CheckedArtifact::Definition)
            .map_err(|error| format!("definition recheck failed: {error}")),
    }
}

struct ArtifactRecord {
    id: ArtifactId,
    dependencies: Vec<ArtifactId>,
    statement: Option<StatementId>,
}

fn proof_record(proof: &CheckedProof) -> ArtifactRecord {
    ArtifactRecord {
        id: ArtifactId::from_proof_id(proof.proof_id()),
        dependencies: proof.direct_artifact_dependencies().into_vec(),
        statement: Some(proof.statement_id()),
    }
}

fn register_final_proof(
    proof: CheckedProof,
    state: &mut ArtifactState,
) -> Result<ArtifactRecord, String> {
    let record = proof_record(&proof);
    // Full canonical checking above establishes this file's actual conclusion
    // and dependencies. Ordinary registration additionally checks identity
    // consistency. Reusing knowledge is permitted; duplicate derivations do
    // not publish new concrete aliases into the selected resolver.
    match state.register_proof(proof) {
        Ok(_)
        | Err(ArtifactStateError::DuplicateProof { .. })
        | Err(ArtifactStateError::DuplicateDerivation { .. }) => Ok(record),
        Err(error) => Err(format!("final proof registration failed: {error}")),
    }
}

fn register(
    artifact: CheckedArtifact,
    state: &mut ArtifactState,
    preceding: &[ArtifactRecord],
    base: &ArtifactState,
) -> Result<ArtifactRecord, String> {
    match artifact {
        CheckedArtifact::Proof(proof) => {
            let record = proof_record(&proof);
            state
                .register_proof(proof)
                .map_err(|error| format!("proof registration failed: {error}"))?;
            Ok(record)
        }
        CheckedArtifact::Definition(definition) => {
            // Expanded relation bodies need no authoring-only alias ancestors.
            // A function additionally needs one earlier checked obligation proof.
            let mut dependencies = Vec::new();
            if let Some(statement) = definition.obligation_statement_id()
                && !base.contains_statement(statement)
            {
                let witness = preceding
                    .iter()
                    .find(|record| record.statement == Some(statement))
                    .ok_or("function definition has no supplied obligation witness")?;
                dependencies.push(witness.id);
            }
            let record = ArtifactRecord {
                id: ArtifactId::from_definition_id(definition.definition_id()),
                dependencies,
                statement: None,
            };
            state
                .register_definition(definition)
                .map_err(|error| format!("definition registration failed: {error}"))?;
            Ok(record)
        }
    }
}

fn require_exact_closure(
    dependencies: &[ArtifactRecord],
    final_record: &ArtifactRecord,
) -> Result<(), String> {
    let by_id: BTreeMap<_, _> = dependencies
        .iter()
        .map(|record| (record.id, record))
        .collect();
    let mut needed = BTreeSet::new();
    let mut pending = final_record.dependencies.clone();
    while let Some(id) = pending.pop() {
        if let Some(record) = by_id.get(&id)
            && needed.insert(id)
        {
            pending.extend(&record.dependencies);
        }
    }
    if needed.len() != dependencies.len() {
        return Err(
            "answer contains unrelated helper artifacts outside its checked closure".into(),
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use naome_authoring::compile;
    use naome_foundation::ZfcAxiom;
    use naome_proof::{DefinitionId, ProofCertificate};

    const SELF_EQUAL: &str = "foundation = \"naome:zfc\"\nstatement = forall(x, equal(x, x))\nproof:\n p0 = equality_reflexivity(x)\n p1 = generalization(p0, x)\n return p1\n";
    const SELF_EQUAL_DEFINITION: &str =
        "foundation = \"naome:zfc\"\ndefinition self_equal = relation(x):\n equal(x, x)\n";

    fn self_equal_input(variable: u32) -> FormulaInput {
        FormulaInput::Forall {
            variable,
            body: Box::new(FormulaInput::Equal {
                left: variable,
                right: variable,
            }),
        }
    }

    fn answer(source: &str) -> AnswerFile {
        AnswerFile {
            source: source.into(),
            dependencies: Vec::new(),
        }
    }

    fn helper_chain() -> (AnswerFile, Formula) {
        let helper_id = hex(compile(SELF_EQUAL).unwrap().proof_id().as_bytes());
        let helper = format!(
            "foundation = \"naome:zfc\"\nformulas:\n h = forall(x, equal(x, x))\nstatement = implies(h, h)\nproof:\n p0 = cite(\"{helper_id}\")\n p1 = simplification(h, h)\n p2 = modus_ponens(p0, p1)\n return p2\n"
        );
        let mut context = ArtifactState::new();
        register(
            compile_checked(SELF_EQUAL, &context).unwrap(),
            &mut context,
            &[],
            &ArtifactState::new(),
        )
        .unwrap();
        let compiled = compile_artifact_against_proof_context(&helper, &context).unwrap();
        let naome_authoring::CompiledArtifact::Proof(proof) = compiled else {
            panic!("fixture is a proof");
        };
        let second_id = hex(proof.proof_id().as_bytes());
        let final_source = format!(
            "foundation = \"naome:zfc\"\nformulas:\n h = forall(x, equal(x, x))\n b = implies(h, h)\nstatement = implies(h, b)\nproof:\n p0 = cite(\"{second_id}\")\n p1 = simplification(b, h)\n p2 = modus_ponens(p0, p1)\n return p2\n"
        );
        let h = self_equal_input(0).to_formula().unwrap();
        let target = Formula::implies(h.clone(), Formula::implies(h.clone(), h));
        (
            AnswerFile {
                source: final_source,
                dependencies: vec![SELF_EQUAL.into(), helper],
            },
            target,
        )
    }

    #[test]
    fn strict_json_contracts_reject_extra_fields_and_unbound_variables() {
        assert!(
            serde_json::from_str::<FormulaInput>(
                r#"{"op":"equal","left":0,"right":0,"axiom":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AnswerFile>(r#"{"source":"","dependencies":[],"valid":true}"#)
                .is_err()
        );
        assert!(
            FormulaInput::Equal { left: 0, right: 0 }
                .to_formula()
                .is_err()
        );
        let input = self_equal_input(37);
        assert_eq!(input.to_nao().unwrap(), "forall(x37, equal(x37, x37))");
        assert_eq!(
            input.canonical_bytes().unwrap(),
            self_equal_input(0).canonical_bytes().unwrap()
        );
    }

    #[test]
    fn question_limits_cover_depth_and_branching() {
        let mut deep = self_equal_input(0);
        for _ in 0..QUESTION_MAX_DEPTH {
            deep = FormulaInput::Not {
                body: Box::new(deep),
            };
        }
        assert!(deep.to_formula().unwrap_err().contains("depth limit"));
        assert!(deep.to_nao().is_err());
        let mut wide = self_equal_input(0);
        for _ in 0..8 {
            wide = FormulaInput::Implies {
                left: Box::new(wide.clone()),
                right: Box::new(wide),
            };
        }
        assert!(wide.to_formula().unwrap_err().contains("node limit"));
    }

    #[test]
    fn closed_self_equality_answer_rechecks_canonical_bytes() {
        let base = ArtifactState::new();
        let target = self_equal_input(0).to_formula().unwrap();
        let checked = check_answer(&answer(SELF_EQUAL), &target, Outcome::Proof, &base).unwrap();
        assert_eq!(checked.conclusion, target);
        let certificate = ProofCertificate::from_canonical_bytes(&checked.canonical_bytes).unwrap();
        assert_eq!(certificate.to_canonical_bytes(), checked.canonical_bytes);
        let proof_id = compile(SELF_EQUAL).unwrap().proof_id();
        assert!(!base.contains_proof(proof_id));
        assert!(checked.resulting_state.contains_proof(proof_id));
        assert_eq!(checked.artifact_ids.len(), 1);
        let known = check_answer(
            &answer(SELF_EQUAL),
            &target,
            Outcome::Proof,
            &checked.resulting_state,
        )
        .unwrap();
        assert_eq!(known.canonical_bytes, checked.canonical_bytes);
        assert_eq!(known.artifact_ids, checked.artifact_ids);
    }

    #[test]
    fn exact_refutation_proves_single_syntactic_negation() {
        // Infinity is an existential, encoded as not_(forall(...)).
        let axiom = ZfcAxiom::Infinity.formula();
        let bytes = axiom.encode_canonical().unwrap();
        assert_eq!(bytes[0], 0x02);
        let target = Formula::decode_canonical(&bytes[1..]).unwrap();
        let source = format!(
            "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = zfc_axiom(\"infinity\")\n return p0\n",
            axiom.to_source()
        );
        let result = check_answer(
            &answer(&source),
            &target,
            Outcome::Refutation,
            &ArtifactState::new(),
        )
        .unwrap();
        assert_eq!(result.conclusion, Formula::negate(target.clone()));
        assert!(
            check_answer(
                &answer(&source),
                &target,
                Outcome::Proof,
                &ArtifactState::new()
            )
            .is_err()
        );
        // Even a valid proof of A does not prove the exact requested not_(not_(A)).
        let h = self_equal_input(0).to_formula().unwrap();
        assert!(
            check_answer(
                &answer(SELF_EQUAL),
                &Formula::negate(h),
                Outcome::Refutation,
                &ArtifactState::new()
            )
            .is_err()
        );
    }

    #[test]
    fn arbitrary_axioms_wrong_targets_and_definitions_are_not_answers() {
        let target = self_equal_input(0).to_formula().unwrap();
        let invented = SELF_EQUAL.replace("equality_reflexivity(x)", "axiom(equal(x, x))");
        assert!(
            check_answer(
                &answer(&invented),
                &target,
                Outcome::Proof,
                &ArtifactState::new()
            )
            .is_err()
        );
        assert!(
            check_answer(
                &answer(SELF_EQUAL_DEFINITION),
                &target,
                Outcome::Proof,
                &ArtifactState::new()
            )
            .unwrap_err()
            .contains("must be a proof")
        );
        assert!(
            check_answer(
                &answer(SELF_EQUAL),
                &Formula::negate(target),
                Outcome::Proof,
                &ArtifactState::new()
            )
            .is_err()
        );
    }

    #[test]
    fn transitive_ordered_closure_is_checked_and_preserved_only_on_success() {
        let (valid, target) = helper_chain();
        let base = ArtifactState::new();
        let result = check_answer(&valid, &target, Outcome::Proof, &base).unwrap();
        assert_eq!(result.artifact_ids.len(), 3);
        assert!(
            result
                .resulting_state
                .contains_proof(compile(SELF_EQUAL).unwrap().proof_id())
        );
        let mut missing = valid.clone();
        missing.dependencies.remove(0);
        assert!(check_answer(&missing, &target, Outcome::Proof, &base).is_err());
        let mut reordered = valid.clone();
        reordered.dependencies.reverse();
        assert!(check_answer(&reordered, &target, Outcome::Proof, &base).is_err());
        let mut duplicate = valid.clone();
        duplicate.dependencies.insert(0, SELF_EQUAL.into());
        assert!(check_answer(&duplicate, &target, Outcome::Proof, &base).is_err());
        let mut unrelated = valid;
        unrelated.dependencies.push(SELF_EQUAL_DEFINITION.into());
        assert!(
            check_answer(&unrelated, &target, Outcome::Proof, &base)
                .unwrap_err()
                .contains("unrelated")
        );
        assert!(!base.contains_proof(compile(SELF_EQUAL).unwrap().proof_id()));
    }

    #[test]
    fn previously_published_helper_can_answer_its_own_exact_question() {
        // An earlier answer published H as a necessary helper for another
        // conclusion. Possession of that known file still answers a later H
        // question; question availability is enforced by the caller.
        let (earlier_answer, earlier_target) = helper_chain();
        let earlier = check_answer(
            &earlier_answer,
            &earlier_target,
            Outcome::Proof,
            &ArtifactState::new(),
        )
        .unwrap();
        let target = self_equal_input(0).to_formula().unwrap();
        let known = check_answer(
            &answer(SELF_EQUAL),
            &target,
            Outcome::Proof,
            &earlier.resulting_state,
        )
        .unwrap();
        assert_eq!(known.conclusion, target);
        let helper = compile(SELF_EQUAL).unwrap();
        assert!(known.resulting_state.contains_proof(helper.proof_id()));

        // Reference-only packaging has the same checked derivation. It can
        // answer, while the resolver retains the original selected concrete
        // proof and gains no verification-only alias.
        let citation = format!(
            "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = cite(\"{}\")\n return p0\n",
            target.to_source(),
            hex(helper.proof_id().as_bytes())
        );
        let CheckedArtifact::Proof(cited) =
            compile_checked(&citation, &earlier.resulting_state).unwrap()
        else {
            panic!("fixture is a proof");
        };
        assert_eq!(cited.derivation_id(), helper.derivation_id());
        let citation_id = cited.proof_id();
        let cited_answer = check_answer(
            &answer(&citation),
            &target,
            Outcome::Proof,
            &earlier.resulting_state,
        )
        .unwrap();
        assert!(
            cited_answer
                .resulting_state
                .contains_proof(helper.proof_id())
        );
        assert!(!cited_answer.resulting_state.contains_proof(citation_id));
        assert!(available_artifact(SELF_EQUAL, &cited_answer.resulting_state).is_some());
        assert!(available_artifact(&citation, &cited_answer.resulting_state).is_none());
        let mut redundant = answer(&citation);
        redundant.dependencies.push(SELF_EQUAL.into());
        assert!(
            check_answer(
                &redundant,
                &target,
                Outcome::Proof,
                &earlier.resulting_state
            )
            .is_err()
        );
        assert!(
            check_answer(
                &answer(&citation),
                &earlier_target,
                Outcome::Proof,
                &earlier.resulting_state
            )
            .is_err()
        );
    }

    #[test]
    fn conservative_context_adds_no_proof_assumptions() {
        let base = ArtifactState::new();
        let compiled =
            compile_artifact_against_proof_context(SELF_EQUAL_DEFINITION, &base).unwrap();
        let naome_authoring::CompiledArtifact::Definition(definition) = compiled else {
            panic!("fixture is a definition");
        };
        let definition_id = definition.definition_id();
        let state = check_definitions(&[SELF_EQUAL_DEFINITION.into()], &base).unwrap();
        assert!(state.contains_definition(definition_id));
        assert!(!base.contains_definition(definition_id));
        assert!(check_definitions(&[SELF_EQUAL_DEFINITION.into()], &state).is_err());
        assert!(check_definitions(&[SELF_EQUAL.into()], &base).is_err());
        let function =
            "foundation = \"naome:zfc\"\ndefinition identity = function(x, y):\n equal(y, x)\n";
        assert!(check_definitions(&[function.into()], &base).is_err());

        let source = format!(
            "foundation = \"naome:zfc\"\ndefinitions:\n self_equal = \"{}\"\nstatement = forall(y, self_equal(y))\nproof:\n p0 = equality_reflexivity(x)\n p1 = generalization(p0, x)\n p2 = universal_instantiation(x, y, self_equal(x))\n p3 = modus_ponens(p1, p2)\n p4 = generalization(p3, y)\n return p4\n",
            hex(definition_id.as_bytes())
        );
        let target = self_equal_input(0).to_formula().unwrap();
        let mut submitted = answer(&source);
        submitted.dependencies.push(SELF_EQUAL_DEFINITION.into());
        assert_eq!(
            check_answer(&submitted, &target, Outcome::Proof, &base)
                .unwrap()
                .artifact_ids
                .len(),
            2
        );
        assert!(check_answer(&answer(&source), &target, Outcome::Proof, &state).is_ok());
        assert!(!state.contains_definition(DefinitionId::from_bytes([0; 32])));
    }

    #[test]
    fn function_dependency_keeps_its_exact_checked_obligation_in_the_closure() {
        let obligation = include_str!("../../../examples/identity-function-obligation.nao");
        let definition = include_str!("../../../examples/identity-function.nao");
        let final_source = include_str!("../../../examples/identity-function-term-proof.nao");
        let base = ArtifactState::new();
        let mut context = base.clone();
        let witness = register(
            compile_checked(obligation, &context).unwrap(),
            &mut context,
            &[],
            &base,
        )
        .unwrap();
        let definition_record = register(
            compile_checked(definition, &context).unwrap(),
            &mut context,
            &[witness],
            &base,
        )
        .unwrap();
        assert_eq!(definition_record.dependencies.len(), 1);
        let CheckedArtifact::Proof(proof) = compile_checked(final_source, &context).unwrap() else {
            panic!("fixture is a proof");
        };
        let target = proof.conclusion().clone();
        let supplied = AnswerFile {
            source: final_source.into(),
            dependencies: vec![obligation.into(), definition.into()],
        };
        let result = check_answer(&supplied, &target, Outcome::Proof, &base).unwrap();
        assert_eq!(result.artifact_ids.len(), 3);
        let mut missing = supplied.clone();
        missing.dependencies.remove(0);
        assert!(check_answer(&missing, &target, Outcome::Proof, &base).is_err());
        let mut out_of_order = supplied;
        out_of_order.dependencies.reverse();
        assert!(check_answer(&out_of_order, &target, Outcome::Proof, &base).is_err());
    }

    #[test]
    fn supplied_count_and_combined_bytes_are_bounded_before_compilation() {
        let target = self_equal_input(0).to_formula().unwrap();
        let mut too_many = answer(SELF_EQUAL);
        too_many.dependencies = vec![SELF_EQUAL_DEFINITION.into(); DEPENDENCY_MAX_COUNT + 1];
        assert!(
            check_answer(&too_many, &target, Outcome::Proof, &ArtifactState::new())
                .unwrap_err()
                .contains("count")
        );
        let too_large = answer(&"x".repeat(AUTHORING_MAX_BYTES + 1));
        assert!(
            check_answer(&too_large, &target, Outcome::Proof, &ArtifactState::new())
                .unwrap_err()
                .contains("bytes")
        );
        assert!(
            check_definitions(
                &["x".repeat(AUTHORING_MAX_BYTES + 1)],
                &ArtifactState::new()
            )
            .is_err()
        );
    }

    #[test]
    fn small_alias_sources_cannot_expand_past_the_combined_canonical_budget() {
        let mut body = "equal(x, x)".to_owned();
        for _ in 0..7 {
            body = format!("implies({body}, {body})");
        }
        let initial =
            format!("foundation = \"naome:zfc\"\ndefinition seed = relation(x):\n {body}\n");
        let empty = ArtifactState::new();
        let base = check_definitions(std::slice::from_ref(&initial), &empty).unwrap();
        let CheckedArtifact::Definition(first) = compile_checked(&initial, &empty).unwrap() else {
            panic!("fixture is a definition");
        };
        let mut id = first.definition_id();
        let mut context = base.clone();
        let mut sources = Vec::new();
        for _ in 0..6 {
            let source = format!(
                "foundation = \"naome:zfc\"\ndefinitions:\n prior = \"{}\"\ndefinition doubled = relation(x):\n implies(prior(x), prior(x))\n",
                hex(id.as_bytes())
            );
            let CheckedArtifact::Definition(definition) =
                compile_checked(&source, &context).unwrap()
            else {
                panic!("fixture is a definition");
            };
            id = definition.definition_id();
            context.register_definition(definition).unwrap();
            sources.push(source);
        }
        assert!(sources.iter().map(String::len).sum::<usize>() < AUTHORING_MAX_BYTES);
        assert!(
            check_definitions(&sources, &base)
                .err()
                .unwrap()
                .contains("canonical artifact bytes")
        );
        assert!(!base.contains_definition(id));
    }
}
