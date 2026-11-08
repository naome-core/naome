use super::*;
use crate::learning::model::{Binding, Candidate};
use naome_foundation::{Formula, FreeVariable};

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

    decision.context.push(Binding {
        formula: decision.goal.clone(),
    });
    decision.goal = Formula::equal(a, b);
    let mut scores = adversarial;
    rank(&decision, &mut scores);
    assert_eq!(scores, adversarial);
}

#[test]
fn executable_existential_instances_survive_the_tableau_menu_limit() {
    use crate::learning::search::{Action, State, actions};

    let v = FreeVariable::new;
    let x = v(8);
    let target = Formula::member(x, v(0));
    let goal = Formula::exists(x, target.clone());
    let productive = Formula::for_all(
        x,
        Formula::implies(Formula::member(x, v(1)), Formula::member(x, v(2))),
    );
    let mut facts = [3, 4, 5]
        .map(|destination| {
            Formula::for_all(
                x,
                Formula::implies(target.clone(), Formula::member(x, v(destination))),
            )
        })
        .to_vec();
    let rule = facts.len();
    facts.extend([
        productive,
        Formula::member(v(7), v(1)),
        Formula::for_all(x, Formula::negate(target)),
    ]);
    let state = State {
        facts,
        goal,
        knowledge: Vec::new(),
        knowledge_context: Vec::new(),
        used: Default::default(),
        domain: (0..8).map(v).collect(),
    };
    let menu = actions(&state);
    assert_eq!(menu.len(), 16);
    assert!(menu.contains(&Action::Instantiate(rule, 7)));
}
