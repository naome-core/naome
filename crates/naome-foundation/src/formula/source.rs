use super::{Formula, Node, Variable};
use std::fmt::{self, Write};

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
        render(&self.0, 0, &mut output).expect("writing a string cannot fail");
        output
    }

    /// Renders a bounded diagnostic preview, adding `...` when truncated.
    /// This preview is presentation data, never a formula serialization.
    #[must_use]
    pub fn to_source_with_limit(&self, maximum_bytes: usize) -> String {
        let mut output = LimitedSource {
            text: String::new(),
            maximum: maximum_bytes,
        };
        if render(&self.0, 0, &mut output).is_err() {
            let end = output.text.len().min(maximum_bytes.saturating_sub(3));
            output.text.truncate(end);
            output.text.push_str(&"..."[..maximum_bytes.min(3)]);
        }
        output.text
    }
}

struct LimitedSource {
    text: String,
    maximum: usize,
}
impl Write for LimitedSource {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = self.maximum.saturating_sub(self.text.len());
        if value.len() > available {
            // Primitive source rendering emits ASCII only.
            self.text.push_str(&value[..available]);
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

fn variable(value: Variable, depth: u32, out: &mut impl Write) -> fmt::Result {
    match value {
        Variable::Free(value) => write!(out, "f{}", value.identifier()),
        Variable::Bound(index) => write!(out, "b{}", depth - 1 - index),
    }
}
fn render(node: &Node, depth: u32, out: &mut impl Write) -> fmt::Result {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            out.write_str(if matches!(node, Node::Equal(..)) {
                "eq("
            } else {
                "mem("
            })?;
            variable(*left, depth, out)?;
            out.write_str(", ")?;
            variable(*right, depth, out)?;
            out.write_char(')')?;
        }
        Node::Not(body) => {
            out.write_str("not(")?;
            render(body, depth, out)?;
            out.write_char(')')?;
        }
        Node::Implies(left, right) => {
            out.write_str("imp(")?;
            render(left, depth, out)?;
            out.write_str(", ")?;
            render(right, depth, out)?;
            out.write_char(')')?;
        }
        Node::ForAll(body) => {
            write!(out, "all(b{depth}, ")?;
            render(body, depth + 1, out)?;
            out.write_char(')')?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
