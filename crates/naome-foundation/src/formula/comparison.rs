//! Bounded, presentation-only explanations of structural formula differences.

use super::{Formula, Node};
use std::fmt;

/// One edge in the first differing primitive formula path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormulaPathSegment {
    Negated,
    Antecedent,
    Consequent,
    Quantified,
    LeftVariable,
    RightVariable,
}

impl FormulaPathSegment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Negated => "negated",
            Self::Antecedent => "antecedent",
            Self::Consequent => "consequent",
            Self::Quantified => "quantified",
            Self::LeftVariable => "left_variable",
            Self::RightVariable => "right_variable",
        }
    }
}

/// Diagnostic previews and the exact first structural difference. Previews
/// are bounded independently of formula size and never establish an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormulaMismatch {
    expected: Box<str>,
    actual: Box<str>,
    path: Box<[FormulaPathSegment]>,
}

impl FormulaMismatch {
    pub fn between(expected: &Formula, actual: &Formula) -> Option<Self> {
        let mut path = Vec::new();
        different(&expected.0, &actual.0, &mut path).then(|| Self {
            expected: expected.to_source_with_limit(256).into_boxed_str(),
            actual: actual.to_source_with_limit(256).into_boxed_str(),
            path: path.into_boxed_slice(),
        })
    }

    pub fn expected(&self) -> &str {
        &self.expected
    }

    pub fn actual(&self) -> &str {
        &self.actual
    }

    pub fn path(&self) -> &[FormulaPathSegment] {
        &self.path
    }
}

impl fmt::Display for FormulaMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected {}; actual {}; first difference at root",
            self.expected, self.actual
        )?;
        for segment in &self.path {
            write!(f, ".{}", segment.as_str())?;
        }
        Ok(())
    }
}

fn different(expected: &Node, actual: &Node, path: &mut Vec<FormulaPathSegment>) -> bool {
    use FormulaPathSegment as Edge;
    let children: &[(&Node, &Node, Edge)] = match (expected, actual) {
        (Node::Equal(a, b), Node::Equal(c, d)) | (Node::Member(a, b), Node::Member(c, d)) => {
            if a != c {
                path.push(Edge::LeftVariable);
                return true;
            }
            if b != d {
                path.push(Edge::RightVariable);
                return true;
            }
            return false;
        }
        (Node::Not(a), Node::Not(b)) => &[(a, b, Edge::Negated)],
        (Node::ForAll(a), Node::ForAll(b)) => &[(a, b, Edge::Quantified)],
        (Node::Implies(a, b), Node::Implies(c, d)) => {
            &[(a, c, Edge::Antecedent), (b, d, Edge::Consequent)]
        }
        _ => return true,
    };
    for (expected, actual, edge) in children {
        path.push(*edge);
        if different(expected, actual, path) {
            return true;
        }
        path.pop();
    }
    false
}

#[cfg(test)]
mod tests;
