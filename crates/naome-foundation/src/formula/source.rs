use super::{Formula, Node, Variable};
use std::fmt::Write;

impl Formula {
    /// Renders primitive `.nao` formula syntax without changing logical shape.
    /// Bound variables use capture-free names `b0`, `b1`, ...; free variables
    /// retain their numeric identity in names `f0`, `f1`, ... . Closed formulas
    /// round-trip through `.nao` parsing exactly. For open formulas, parsers may
    /// assign different numeric free-variable IDs to these presentation names;
    /// canonical bytes remain the identity-preserving serialization.
    #[must_use]
    pub fn to_source(&self) -> String {
        let mut output = String::new();
        render(&self.0, 0, &mut output);
        output
    }
}

fn variable(value: Variable, depth: u32, out: &mut String) {
    match value {
        Variable::Free(value) => write!(out, "f{}", value.identifier()),
        Variable::Bound(index) => write!(out, "b{}", depth - 1 - index),
    }
    .expect("writing a string cannot fail");
}
fn render(node: &Node, depth: u32, out: &mut String) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            out.push_str(if matches!(node, Node::Equal(..)) {
                "equal("
            } else {
                "member("
            });
            variable(*left, depth, out);
            out.push_str(", ");
            variable(*right, depth, out);
            out.push(')');
        }
        Node::Not(body) => {
            out.push_str("not_(");
            render(body, depth, out);
            out.push(')');
        }
        Node::Implies(left, right) => {
            out.push_str("implies(");
            render(left, depth, out);
            out.push_str(", ");
            render(right, depth, out);
            out.push(')');
        }
        Node::ForAll(body) => {
            write!(out, "forall(b{depth}, ").expect("string write");
            render(body, depth + 1, out);
            out.push(')');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FreeVariable;
    #[test]
    fn source_keeps_nested_binders_vacuous_quantifiers_and_free_ids_distinct() {
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let free = FreeVariable::new(u32::MAX);
        let formula = Formula::for_all(
            x,
            Formula::for_all(
                y,
                Formula::implies(
                    Formula::member(x, y),
                    Formula::negate(Formula::equal(x, free)),
                ),
            ),
        );
        assert_eq!(
            formula.to_source(),
            "forall(b0, forall(b1, implies(member(b0, b1), not_(equal(b0, f4294967295)))))"
        );
        let vacuous = Formula::for_all(y, Formula::for_all(x, Formula::equal(x, x)));
        assert_eq!(vacuous.to_source(), "forall(b0, forall(b1, equal(b1, b1)))");
    }
}
