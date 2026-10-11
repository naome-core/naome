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

    /// Renders the exact primitive tree as controlled English for derived
    /// retrieval text. Parentheses retain every operator's scope; binder names
    /// and free-variable IDs follow `to_source`. Consecutive universal binders
    /// form an ordered complete list; other operators keep separate scopes.
    /// This establishes no validity.
    #[must_use]
    pub fn to_controlled_english(&self) -> String {
        let mut output = String::new();
        english(&self.0, 0, &mut output);
        output
    }
}

fn english(node: &Node, depth: u32, out: &mut String) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            variable(*left, depth, out);
            out.push_str(if matches!(node, Node::Equal(..)) {
                " equals "
            } else {
                " is an element of "
            });
            variable(*right, depth, out);
        }
        Node::Not(body) => {
            out.push_str("it is not the case that (");
            english(body, depth, out);
            out.push(')');
        }
        Node::Implies(left, right) => {
            out.push_str("if (");
            english(left, depth, out);
            out.push_str("), then (");
            english(right, depth, out);
            out.push(')');
        }
        Node::ForAll(body) => {
            let mut end = depth + 1;
            let mut matrix = body.as_ref();
            while let Node::ForAll(next) = matrix {
                end += 1;
                matrix = next.as_ref();
            }
            if end == depth + 1 {
                write!(out, "for every set b{depth}, (").expect("string write");
            } else {
                out.push_str("for every choice of sets [");
                for binder in depth..end {
                    if binder != depth {
                        out.push_str(", ");
                    }
                    write!(out, "b{binder}").expect("string write");
                }
                out.push_str("], (");
            }
            english(matrix, end, out);
            out.push(')');
        }
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
                "eq("
            } else {
                "mem("
            });
            variable(*left, depth, out);
            out.push_str(", ");
            variable(*right, depth, out);
            out.push(')');
        }
        Node::Not(body) => {
            out.push_str("not(");
            render(body, depth, out);
            out.push(')');
        }
        Node::Implies(left, right) => {
            out.push_str("imp(");
            render(left, depth, out);
            out.push_str(", ");
            render(right, depth, out);
            out.push(')');
        }
        Node::ForAll(body) => {
            write!(out, "all(b{depth}, ").expect("string write");
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
            "all(b0, all(b1, imp(mem(b0, b1), not(eq(b0, f4294967295)))))"
        );
        let vacuous = Formula::for_all(y, Formula::for_all(x, Formula::equal(x, x)));
        assert_eq!(vacuous.to_source(), "all(b0, all(b1, eq(b1, b1)))");
    }

    #[test]
    fn english_retains_scope_shadowing_vacuous_binders_and_free_identity() {
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let formula = Formula::for_all(
            x,
            Formula::for_all(
                y,
                Formula::implies(
                    Formula::member(x, y),
                    Formula::negate(Formula::equal(y, FreeVariable::new(u32::MAX))),
                ),
            ),
        );
        let bytes = formula.encode_canonical().unwrap();
        assert_eq!(
            formula.to_controlled_english(),
            "for every choice of sets [b0, b1], (if (b0 is an element of b1), then (it is not the case that (b1 equals f4294967295)))"
        );
        assert_eq!(formula.encode_canonical().unwrap(), bytes);
        let vacuous = Formula::for_all(y, Formula::for_all(x, Formula::equal(x, x)));
        assert_eq!(
            vacuous.to_controlled_english(),
            "for every choice of sets [b0, b1], (b1 equals b1)"
        );
        let shadowed = Formula::for_all(x, Formula::for_all(x, Formula::equal(x, x)));
        assert_eq!(
            shadowed.to_controlled_english(),
            vacuous.to_controlled_english()
        );
    }

    #[test]
    fn english_quantifier_blocks_preserve_every_binder_and_operator_boundary() {
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let z = FreeVariable::new(2);
        let mut long = Formula::member(x, y);
        for id in (0..83).rev() {
            long = Formula::for_all(FreeVariable::new(id), long);
        }
        let bytes = long.encode_canonical().unwrap();
        let text = long.to_controlled_english();
        let binders = (0..83)
            .map(|i| format!("b{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            text,
            format!("for every choice of sets [{binders}], (b0 is an element of b1)")
        );
        assert_eq!(long.encode_canonical().unwrap(), bytes);

        let separated = Formula::for_all(
            x,
            Formula::implies(
                Formula::for_all(y, Formula::member(x, y)),
                Formula::negate(Formula::for_all(z, Formula::equal(x, z))),
            ),
        );
        assert_eq!(
            separated.to_controlled_english(),
            "for every set b0, (if (for every set b1, (b0 is an element of b1)), then (it is not the case that (for every set b1, (b0 equals b1))))"
        );
        let existential = Formula::for_all(x, Formula::exists(y, Formula::member(x, y)));
        assert_eq!(
            existential.to_controlled_english(),
            "for every set b0, (it is not the case that (for every set b1, (it is not the case that (b0 is an element of b1))))"
        );
    }
}
