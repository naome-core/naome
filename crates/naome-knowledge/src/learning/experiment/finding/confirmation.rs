//! Source-only confirmation preparation. No solver, optimizer or model calls.
use super::*;

#[test]
#[ignore = "explicit source-only confirmation freeze; run before inference"]
fn freeze_disjoint_confirmation_questions() {
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_OUTPUT").unwrap());
    assert!(!output.exists());
    let bytes =
        include_bytes!("../../../../tests/fixtures/finder-repair-confirmation-candidates.json");
    let inputs: Value = serde_json::from_slice(bytes).unwrap();
    let mut known = curriculum::owned::original_exclusions().clone();
    for content in [
        include_str!("../../../../tests/fixtures/finder-feedback.json"),
        include_str!("../../../../tests/fixtures/recursive-lemma-loop.json"),
    ] {
        let prior: Value = serde_json::from_str(content).unwrap();
        for case in prior["cases"].as_array().unwrap() {
            let q = CompiledQuestion::compile(case["source"].as_str().unwrap()).unwrap();
            known.insert(curriculum::owned::family(q.proved_target()));
        }
    }
    let graph = crate::Graph::default();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut cases = Vec::new();
    let mut excluded = Vec::new();
    let mut identities = BTreeSet::new();
    for input in inputs["cases"].as_array().unwrap() {
        let q = CompiledQuestion::compile(input["source"].as_str().unwrap()).unwrap();
        let id = crate::hex(q.resolution_id());
        let family = curriculum::owned::family(q.proved_target());
        let assessment = owner.assess(&graph, &q);
        let reason = if known.contains(&family) || !State::eligible(q.source()) {
            Some("existing_or_reserved_structural_family")
        } else if !assessment.passed() {
            Some("formal_question_prefilter")
        } else if !identities.insert(id.clone()) {
            Some("duplicate_canonical_question")
        } else {
            None
        };
        let row = json!({"source":q.source(),"resolution":id,"family":family,"lineage":input["lineage"],"variant":input["variant"],"exclusion":reason});
        if reason.is_some() {
            excluded.push(row);
        } else {
            cases.push(row);
        }
    }
    let result = json!({"scope":"First source-only freeze. No model calls or truth labels. Structural families are excluded from training, utility, replay and promotion feedback in the confirmation consumer. Authored-lineage siblings remain correlated.","source_sha256":crate::hex(&Sha256::digest(bytes)),"seeds":[173,251,389],"search_expansions":128,"cases":cases,"excluded":excluded});
    write(&output, &result);
    assert!(
        cases.len() >= 8,
        "source-only bank has insufficient independent material; preserve exclusions"
    );
    assert!(
        cases
            .iter()
            .map(|c| c["lineage"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len()
            >= 3
    );
}
