//! Conservative propositional simplification for research interest only.
//! No conclusion from this module grants mathematical admission.
use super::*;
use naome_foundation::{
    FormulaView,
    graph::{Node, Variable},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape {
    id: [u8; 32],
    negative: bool,
    truth: Option<bool>,
}
impl Shape {
    fn truth(value: bool) -> Self {
        Self {
            id: [0; 32],
            negative: false,
            truth: Some(value),
        }
    }
    fn negate(mut self) -> Self {
        if let Some(value) = self.truth {
            self.truth = Some(!value);
        } else {
            self.negative = !self.negative;
        }
        self
    }
    fn bytes(self) -> [u8; 34] {
        let mut bytes = [0; 34];
        bytes[..32].copy_from_slice(&self.id);
        bytes[32] = u8::from(self.negative);
        bytes[33] = self.truth.map_or(0, |v| 1 + u8::from(v));
        bytes
    }
}
fn hash(tag: u8, parts: &[&[u8]]) -> Shape {
    let mut hash = Sha256::new();
    hash.update([tag]);
    for part in parts {
        hash.update(part);
    }
    Shape {
        id: hash.finalize().into(),
        negative: false,
        truth: None,
    }
}
fn variable(value: Variable) -> [u8; 9] {
    let mut bytes = [0; 9];
    let (tag, number) = match value {
        Variable::Free(v) => (0, u64::from(v)),
        Variable::Bound(v) => (1, v),
    };
    bytes[0] = tag;
    bytes[1..].copy_from_slice(&number.to_be_bytes());
    bytes
}
fn shape(formula: FormulaView<'_>, assumption: Option<Shape>) -> Shape {
    let result = match formula.graph_node() {
        Node::Equal(a, b) if a == b => Shape::truth(true),
        Node::Equal(a, b) => hash(0, &[&variable(a), &variable(b)]),
        Node::Member(a, b) => hash(1, &[&variable(a), &variable(b)]),
        Node::Not(body) => shape(body, assumption).negate(),
        Node::Implies(a, b) => {
            let a = shape(a, assumption);
            let b = shape(b, assumption);
            if a == b || a.truth == Some(false) || b.truth == Some(true) {
                Shape::truth(true)
            } else if a.truth == Some(true) {
                b
            } else if b.truth == Some(false) {
                a.negate()
            } else if a.id == b.id && a.negative != b.negative {
                b
            } else {
                hash(3, &[&a.bytes(), &b.bytes()])
            }
        }
        Node::ForAll(body) => {
            let body = shape(body, assumption);
            if body.truth.is_some() {
                body
            } else {
                hash(4, &[&body.bytes()])
            }
        }
    };
    if assumption == Some(result) {
        Shape::truth(true)
    } else {
        result
    }
}
pub(in crate::frontier) fn key(question: &CompiledQuestion) -> [u8; 32] {
    Sha256::digest(shape(question.formula().view(), None).bytes()).into()
}
pub(in crate::frontier) fn meaningful(question: &CompiledQuestion) -> bool {
    shape(question.formula().view(), None).truth.is_none()
}
/// A pure Boolean wrapper around the cited lemma is not a new supported goal.
pub(in crate::frontier) fn independent_goal(
    lemma: &CompiledQuestion,
    goal: &CompiledQuestion,
) -> bool {
    meaningful(goal)
        && key(lemma) != key(goal)
        && shape(
            goal.formula().view(),
            Some(shape(lemma.formula().view(), None)),
        )
        .truth
            != Some(true)
}
/// Complete non-atomic fragments can motivate a helper; atomic overlap alone
/// does not establish a proof prerequisite or a useful observation.
pub(in crate::frontier) fn relevance(lemma: &CompiledQuestion, goal: &CompiledQuestion) -> u64 {
    use std::collections::BTreeSet;
    fn collect(f: &Formula, out: &mut BTreeSet<[u8; 32]>, left: &mut usize) {
        if *left == 0 {
            return;
        }
        *left -= 1;
        if f.view().node_count_and_depth().0 > 1 {
            let mut names = std::collections::BTreeMap::new();
            let canonical = f.clone().map_free_variables(|v| {
                let next = FreeVariable::new(names.len() as u32);
                *names.entry(v).or_insert(next)
            });
            let s = shape(canonical.view(), None);
            if s.truth.is_none() {
                out.insert(Sha256::digest(s.bytes()).into());
            }
        }
        match f.view().graph_node() {
            Node::ForAll(_) => {
                let next = f
                    .free_variables()
                    .last()
                    .map_or(0, |v| v.identifier().saturating_add(1));
                if let Some(body) = f.open_outer_universal(FreeVariable::new(next)) {
                    collect(&body, out, left);
                }
            }
            Node::Not(body) => collect(&body.to_owned(), out, left),
            Node::Implies(a, b) => {
                collect(&a.to_owned(), out, left);
                collect(&b.to_owned(), out, left);
            }
            _ => {}
        }
    }
    let mut a = BTreeSet::new();
    let mut b = BTreeSet::new();
    collect(lemma.formula(), &mut a, &mut 32);
    collect(goal.formula(), &mut b, &mut 32);
    a.intersection(&b).count() as u64
}
