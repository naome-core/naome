use super::*;
use crate::learning::model::{Binding, Candidate, Rule};
use naome_foundation::{Formula, FreeVariable};

fn decision() -> Decision {
    let [a, b] = [0, 1].map(FreeVariable::new);
    let goal = Formula::member(a, b);
    let context = [Formula::equal(a, b), Formula::equal(b, a), goal.clone()];
    let candidates = [
        (Rule::UniversalInstance, 0, context[0].clone()),
        (Rule::UniversalInstance, 1, goal.clone()),
        (Rule::ModusPonens, 2, goal.clone()),
    ];
    Decision {
        goal,
        context: context
            .into_iter()
            .map(|formula| Binding { formula })
            .collect(),
        candidates: candidates
            .into_iter()
            .map(|(rule, operand, effect)| Candidate {
                rule,
                premises: vec![operand],
                replacement: None,
                consequences: vec![effect],
            })
            .collect(),
        expert: 1,
    }
}

#[test]
fn normalizes_over_legal_prefixes_and_learns_the_checked_branch() {
    let decision = decision();
    let graph = Graph::encode(&decision).unwrap();
    let mut policy = Policy::default();
    let initial = policy.scores(&decision).unwrap();
    let probabilities = initial.iter().map(|score| score.exp()).collect::<Vec<_>>();
    for (observed, expected) in probabilities.into_iter().zip([0.25, 0.25, 0.5]) {
        assert!((observed - expected).abs() < 1e-6);
    }
    let before = policy.update(&[&graph]).unwrap();
    for _ in 0..15 {
        assert!(policy.update(&[&graph]).unwrap() < before);
    }
    let after = policy.scores(&decision).unwrap();
    assert!(after[decision.expert] > after[0] && after[decision.expert] > after[2]);
    assert!((after.iter().map(|score| score.exp()).sum::<f32>() - 1.).abs() < 1e-6);
    let plan = policy.plan(&decision, &graph, "", None).unwrap();
    assert_eq!(plan.scores, after);
}

#[test]
fn identical_action_tokens_share_mass_and_keep_legal_local_addresses() {
    let mut decision = decision();
    decision.candidates[1] = Candidate {
        rule: Rule::UniversalInstance,
        premises: vec![0],
        replacement: None,
        consequences: decision.candidates[0].consequences.clone(),
    };
    let graph = Graph::encode(&decision).unwrap();
    assert_eq!(graph.successes, [0, 1]);
    let mut policy = Policy::default();
    let before = policy.update(&[&graph]).unwrap();
    assert!((before - std::f64::consts::LN_2).abs() < 1e-12);
    let scores = policy.scores_graph(&graph).unwrap();
    assert_eq!(scores[0], scores[1]);
    assert!(scores[0].exp() + scores[1].exp() > 0.5);
}
