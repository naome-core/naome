use super::*;
use crate::learning::{
    graph::Field,
    model::{Binding, Candidate, Decision, Rule},
};
use naome_foundation::{Formula, FreeVariable};

fn decision() -> Decision {
    let [a, b] = [0, 1].map(FreeVariable::new);
    let goal = Formula::member(a, b);
    let context = [Formula::equal(a, b), Formula::equal(b, a), goal.clone()];
    let candidates = [
        (Rule::UniversalInstance, 0, context[0].clone()),
        (Rule::UniversalInstance, 1, goal.clone()),
        (Rule::ModusPonens, 2, goal.clone()),
        (Rule::UniversalInstance, 1, goal.clone()),
    ];
    Decision {
        goal,
        context: context
            .into_iter()
            .map(|formula| Binding { formula })
            .collect(),
        candidates: candidates
            .into_iter()
            .map(|(rule, premise, effect)| Candidate {
                rule,
                premises: vec![premise],
                replacement: None,
                consequences: vec![effect],
            })
            .collect(),
        expert: 1,
    }
}

#[test]
fn packs_only_ambiguous_legal_edges_and_shares_equivalent_leaf_mass() {
    let graph = Graph::encode(&decision()).unwrap();
    assert_eq!(graph.successes, [1, 3]);
    let menu = Menu::lower(&graph).unwrap();
    assert_eq!(menu.groups, [0..2, 2..4]);
    assert_eq!(menu.priors, [2f32.ln(), 0., 0., 0.]);
    assert_eq!(menu.paths, [vec![2, 0], vec![3, 0], vec![1], vec![3, 0]]);
    assert_eq!(menu.aliases, [0., 2f32.ln(), 0., 2f32.ln()]);
    let typed = Graph::encode_field(&decision(), Field::Premise).unwrap();
    assert_ne!(graph.key(), typed.key());
    let typed_menu = Menu::lower(&typed).unwrap();
    assert_eq!(menu.paths, typed_menu.paths);
    assert_ne!(menu.edges, typed_menu.edges);
}

#[test]
fn opposite_fact_features_preserve_variable_bindings() {
    let mut decision = decision();
    let [a, b] = [0, 1].map(FreeVariable::new);
    decision.context = vec![
        Binding {
            formula: Formula::negate(Formula::member(a, b)),
        },
        Binding {
            formula: Formula::negate(Formula::member(b, a)),
        },
        Binding {
            formula: Formula::member(a, b),
        },
    ];
    decision.candidates[0].consequences = vec![Formula::member(b, a)];
    let graph = Graph::encode(&decision).unwrap();
    let input = Input::new(&graph);
    let swapped = graph.nodes[graph.candidates[0]].right;
    assert!(input.opposites[graph.goal]);
    assert!(input.opposites[swapped]);
    assert!(input.opposites[graph.context[0]]);
    assert!(!input.opposites[graph.context[1]]);
}
