//! Identical source overlaid on baseline and candidate for the matched comparison.
use super::*;
use crate::{ArtifactState, normalize_and_check_with_state};
use naome_foundation::FreeVariable;
use naome_proof::ProofCertificate;
use std::{hint::black_box, time::Instant};

struct Case {
    target: Formula,
    state: ArtifactState,
    registry: QuestionRegistry,
    policy: PrefilterPolicy,
}

fn atom(index: usize) -> Formula {
    let x = FreeVariable::new(0);
    let mut body = Formula::member(x, x);
    for _ in 0..index {
        body = Formula::negate(body);
    }
    Formula::for_all(x, body)
}

fn plain(target: Formula, related: Option<Formula>) -> Case {
    let mut registry = QuestionRegistry::new();
    if let Some(related) = related {
        registry
            .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
            .unwrap();
    }
    Case {
        target,
        state: ArtifactState::new(),
        registry,
        policy: PrefilterPolicy::default(),
    }
}

fn cases() -> Vec<(&'static str, Vec<Case>)> {
    let mut equivalent = Vec::new();
    let mut distinct = Vec::new();
    let mut empty = Vec::new();
    let mut registry_controls = Vec::new();
    let mut known = Vec::new();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let wrap = |formula| Formula::for_all(FreeVariable::new(17), formula);
    for index in 0..8 {
        let a = atom(index);
        let b = atom(index + 1);
        let forward = Formula::implies(a.clone(), Formula::negate(b.clone()));
        let backward = Formula::implies(b.clone(), Formula::negate(a.clone()));
        equivalent.push(plain(forward.clone(), Some(backward.clone())));
        equivalent.push(plain(a.clone(), Some(wrap(a.clone()))));
        equivalent.push(plain(wrap(forward), Some(wrap(wrap(backward)))));
        distinct.push(plain(a.clone(), Some(b.clone())));
        distinct.push(plain(
            Formula::implies(a.clone(), b.clone()),
            Some(Formula::implies(b, a.clone())),
        ));
        let mut body = Formula::member(x, y);
        for _ in 0..index {
            body = Formula::negate(body);
        }
        distinct.push(plain(
            Formula::for_all(x, Formula::exists(y, body.clone())),
            Some(Formula::exists(x, Formula::for_all(y, body))),
        ));
        empty.push(plain(a.clone(), None));
        let mut control = plain(a, None);
        for record in 0..32u8 {
            let related =
                Formula::implies(atom(record as usize % 8), wrap(atom(record as usize / 8)));
            let mut identity = [0; 32];
            identity[0] = record;
            control
                .registry
                .insert(RegisteredQuestion::new(identity, &related).unwrap())
                .unwrap();
        }
        registry_controls.push(control);
        let mut target = Formula::for_all(x, Formula::equal(x, x));
        for _ in 0..index {
            target = wrap(target);
        }
        known.push(plain(target, None));
    }
    let mut budget = Vec::new();
    for decoys in [64, 96, 128, 192] {
        for negative in [false, true] {
            let (state, target) = fixtures::budget_case(decoys, negative);
            let mut policy = PrefilterPolicy::default();
            policy.limits.operations = 512;
            budget.push(Case {
                target,
                state,
                registry: QuestionRegistry::new(),
                policy,
            });
        }
    }
    vec![
        ("elementary_equivalence", equivalent),
        ("distinct_controls", distinct),
        ("paired_budget", budget),
        ("unanswered_empty", empty),
        ("unanswered_registry", registry_controls),
        ("known_answers", known),
    ]
}

#[test]
#[ignore = "run tools/benchmarks/prefilter.py for a matched baseline comparison"]
fn measure_prefilter() {
    for (group, cases) in cases() {
        let repeats = 16;
        let mut pass = 0;
        let mut reject = 0;
        let mut inconclusive = 0;
        let mut answers = 0;
        let mut equivalent = 0;
        let started = Instant::now();
        for _ in 0..repeats {
            for case in &cases {
                let request = AssessmentQuestion::new(
                    FOUNDATION_ID,
                    &case.target,
                    b"fixed comparison input",
                    &[],
                    None,
                )
                .unwrap();
                let snapshot = KnowledgeSnapshot::new([19; 32], &case.state, &case.registry);
                let result = black_box(assess_question(&request, &snapshot, &case.policy));
                pass += usize::from(result.passed());
                inconclusive += usize::from(result.inconclusive());
                reject += usize::from(result.outcome == PrefilterOutcome::Reject);
                answers += usize::from(result.has_answer());
                equivalent += usize::from(result.reason == Some(RejectionReason::ProvenEquivalent));
                if matches!(
                    group,
                    "distinct_controls" | "unanswered_empty" | "unanswered_registry"
                ) {
                    assert!(result.passed(), "unexpected rejection: {group}: {result:?}");
                }
            }
        }
        let elapsed_ns = started.elapsed().as_nanos();
        // Verify observed answers independently outside the timing interval.
        for case in &cases {
            let request = AssessmentQuestion::new(
                FOUNDATION_ID,
                &case.target,
                b"fixed comparison input",
                &[],
                None,
            )
            .unwrap();
            let result = assess_question(
                &request,
                &KnowledgeSnapshot::new([19; 32], &case.state, &case.registry),
                &case.policy,
            );
            if let Some(witness) = &result.deduction {
                let checked = normalize_and_check_with_state(
                    ProofCertificate::from_canonical_bytes(witness.canonical_certificate())
                        .unwrap(),
                    &case.state,
                )
                .unwrap();
                let expected = if result.reason == Some(RejectionReason::KnownRefutation) {
                    Formula::negate(case.target.clone())
                } else {
                    case.target.clone()
                };
                assert_eq!(checked.conclusion(), &expected);
            }
        }
        println!(
            "PREFILTER_MEASUREMENT {}",
            serde_json::json!({"group":group,"unique_cases":cases.len(),"repeats":repeats,"evaluations":cases.len()*repeats,"pass":pass,"reject":reject,"inconclusive":inconclusive,"answers":answers,"equivalences":equivalent,"elapsed_ns":elapsed_ns})
        );
    }
}
