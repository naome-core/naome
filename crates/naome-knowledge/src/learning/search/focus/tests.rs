use super::*;
use crate::learning::model::{Binding, Candidate};
use naome_foundation::FreeVariable;

#[test]
fn existential_search_prioritizes_executable_instances_over_splits() {
    let [a, b, witness] = [0, 1, 2].map(FreeVariable::new);
    let fact = Formula::member(a, witness);
    let pending = Formula::member(witness, b);
    let rule = Formula::implies(fact.clone(), pending.clone());
    let denied = Formula::negate(Formula::implies(pending, fact.clone()));
    let goal = Formula::exists(witness, Formula::member(witness, b));
    let candidate = |rule, consequences| Candidate {
        rule,
        premises: vec![0],
        replacement: None,
        consequences,
    };
    let mut decision = Decision {
        context: vec![Binding { formula: fact }],
        goal,
        candidates: vec![
            candidate(Rule::ImplicationBranch, vec![]),
            candidate(Rule::UniversalInstance, vec![rule.clone()]),
            candidate(Rule::UniversalInstance, vec![denied]),
            candidate(Rule::UniversalInstance, vec![rule]),
        ],
        expert: 0,
    };
    let adversarial = [40., 1., -10., 2.];
    let mut scores = adversarial;
    rank(&decision, &mut scores);
    assert_eq!(scores, [1., 2., 4., 3.]);

    decision.goal = Formula::equal(a, b);
    let mut scores = adversarial;
    rank(&decision, &mut scores);
    assert_eq!(scores, adversarial);
}
