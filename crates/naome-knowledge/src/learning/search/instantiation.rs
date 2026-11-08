//! Match typed quantifier operands before constructing possible conclusions.
use super::*;
use naome_foundation::{
    FormulaView,
    graph::{Node, Variable},
};

pub(super) struct Universal {
    body: Formula,
    placeholder: FreeVariable,
}
impl Universal {
    pub(super) fn new(formula: &Formula) -> Option<Self> {
        if !matches!(formula.view().graph_node(), Node::ForAll(_)) {
            return None;
        }
        let placeholder = fresh(std::iter::once(formula.clone())).ok()?;
        Some(Self {
            body: formula.open_outer_universal(placeholder)?,
            placeholder,
        })
    }

    pub(super) fn instance(&self, replacement: FreeVariable) -> Formula {
        self.body
            .clone()
            .substitute_free(self.placeholder, replacement)
    }

    pub(super) fn wanted(&self, goal: &Formula, first: FreeVariable) -> Option<FreeVariable> {
        self.matching(self.body.view(), goal.view(), first)
    }

    pub(super) fn applications<'a>(
        &'a self,
        facts: &'a [Formula],
        first: FreeVariable,
    ) -> impl Iterator<Item = (usize, FreeVariable)> + 'a {
        let premise = self
            .body
            .view()
            .implication_parts()
            .map(|(premise, _)| premise);
        facts
            .iter()
            .enumerate()
            .filter_map(move |(position, fact)| {
                Some((position, self.matching(premise?, fact.view(), first)?))
            })
    }

    pub(super) fn consequence(&self, replacement: FreeVariable) -> Option<Formula> {
        Some(
            self.body
                .view()
                .implication_parts()?
                .1
                .to_owned()
                .substitute_free(self.placeholder, replacement),
        )
    }

    fn matching(
        &self,
        pattern: FormulaView<'_>,
        actual: FormulaView<'_>,
        first: FreeVariable,
    ) -> Option<FreeVariable> {
        fn walk(
            pattern: FormulaView<'_>,
            actual: FormulaView<'_>,
            placeholder: u32,
            replacement: &mut Option<u32>,
        ) -> bool {
            let mut variable = |pattern, actual| {
                if pattern != Variable::Free(placeholder) {
                    return pattern == actual;
                }
                let Variable::Free(actual) = actual else {
                    return false;
                };
                *replacement.get_or_insert(actual) == actual
            };
            match (pattern.graph_node(), actual.graph_node()) {
                (Node::Equal(a, b), Node::Equal(x, y))
                | (Node::Member(a, b), Node::Member(x, y)) => variable(a, x) && variable(b, y),
                (Node::Not(a), Node::Not(b)) | (Node::ForAll(a), Node::ForAll(b)) => {
                    walk(a, b, placeholder, replacement)
                }
                (Node::Implies(a, b), Node::Implies(x, y)) => {
                    walk(a, x, placeholder, replacement) && walk(b, y, placeholder, replacement)
                }
                _ => false,
            }
        }
        let mut replacement = None;
        walk(
            pattern,
            actual,
            self.placeholder.identifier(),
            &mut replacement,
        )
        .then(|| replacement.map_or(first, FreeVariable::new))
    }
}
