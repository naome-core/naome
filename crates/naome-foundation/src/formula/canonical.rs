//! Canonical formula bytes used by Proof Certificate.
//!
//! This module stays beside the private formula tree so decoding cannot bypass
//! [`Formula`]'s well-formedness invariant. The byte format belongs to the
//! proof protocol, not to the abstract Foundation identity.

use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt;

use super::{Formula, FreeVariable, Node, Variable};

/// Maximum encoded byte length admitted by the formula codec.
///
/// This follows from the node limit: every node has one tag and at most half
/// the nodes can be binary leaves containing ten variable bytes.
pub const FORMULA_MAX_BYTES: usize = 393_216;

/// Maximum number of nested formula nodes admitted by the codec.
///
/// This deterministic protocol limit bounds recursive processing. It is not a
/// limit of the abstract Foundation language.
pub const FORMULA_MAX_DEPTH: u32 = 256;

/// Maximum number of formula nodes admitted by the codec.
pub const FORMULA_MAX_NODES: usize = 65_536;

const EQUAL: u8 = 0x00;
const MEMBER: u8 = 0x01;
const NOT: u8 = 0x02;
const IMPLIES: u8 = 0x03;
const FOR_ALL: u8 = 0x04;

const FREE_VARIABLE: u8 = 0x00;
const BOUND_VARIABLE: u8 = 0x01;

impl Formula {
    /// Encodes this formula using the canonical Proof Certificate format.
    ///
    /// Binder names are absent from the encoding. Bound variables retain the
    /// De Bruijn indices already stored by [`Formula`].
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FormulaCodecError> {
        self.encode_canonical_with_node_limit(FORMULA_MAX_NODES)
            .map(|(bytes, _)| bytes)
    }

    /// Encodes this formula within a caller-supplied node limit.
    ///
    /// The effective limit never exceeds [`FORMULA_MAX_NODES`]. The returned
    /// node count lets a containing canonical format enforce one cumulative
    /// budget across multiple formulas without inspecting the private tree.
    pub fn encode_canonical_with_node_limit(
        &self,
        maximum_nodes: usize,
    ) -> Result<(Vec<u8>, usize), FormulaCodecError> {
        self.encode_with_node_limit(maximum_nodes, FreeVariableEncoding::Preserve)
    }

    /// Encodes this formula after canonicalizing its free-variable identifiers.
    ///
    /// Free variables are renumbered to `0, 1, ...` by first occurrence in the
    /// existing canonical traversal order. Bound De Bruijn indices remain
    /// unchanged. This representation is used for proof-fragment identities;
    /// it does not replace [`Self::encode_canonical`] on the certificate wire.
    pub fn encode_free_variable_normalized(&self) -> Result<Vec<u8>, FormulaCodecError> {
        self.encode_with_node_limit(
            FORMULA_MAX_NODES,
            FreeVariableEncoding::Normalize {
                identifiers: BTreeMap::new(),
                next_identifier: 0,
            },
        )
        .map(|(bytes, _)| bytes)
    }

    /// Decodes one complete canonical Proof Certificate formula.
    ///
    /// The decoder rejects dangling De Bruijn indices, unknown tags, excessive
    /// nesting, truncated values, and trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FormulaCodecError> {
        Self::decode_canonical_with_node_limit(bytes, FORMULA_MAX_NODES).map(|(formula, _)| formula)
    }

    /// Decodes one complete formula within a caller-supplied node limit.
    ///
    /// The effective limit never exceeds [`FORMULA_MAX_NODES`]. Node
    /// exhaustion is checked before the next node is decoded or allocated.
    /// The returned count lets a containing canonical format share one
    /// cumulative budget across multiple formulas.
    pub fn decode_canonical_with_node_limit(
        bytes: &[u8],
        maximum_nodes: usize,
    ) -> Result<(Self, usize), FormulaCodecError> {
        if bytes.len() > FORMULA_MAX_BYTES {
            return Err(FormulaCodecError::InputTooLong {
                actual: bytes.len(),
                maximum: FORMULA_MAX_BYTES,
            });
        }

        let mut cursor = Cursor::new(bytes);
        let mut nodes = NodeBudget::new(maximum_nodes);
        let node = decode_node(&mut cursor, 0, 0, &mut nodes)?;

        if cursor.remaining() != 0 {
            return Err(FormulaCodecError::TrailingBytes {
                remaining: cursor.remaining(),
            });
        }

        Ok((Self(node), nodes.used()))
    }

    fn encode_with_node_limit(
        &self,
        maximum_nodes: usize,
        mut variables: FreeVariableEncoding,
    ) -> Result<(Vec<u8>, usize), FormulaCodecError> {
        let mut output = Vec::new();
        let mut nodes = NodeBudget::new(maximum_nodes);
        encode_node(&self.0, 0, &mut nodes, &mut variables, &mut output)?;
        Ok((output, nodes.used()))
    }
}

fn encode_node(
    node: &Node,
    depth: u32,
    nodes: &mut NodeBudget,
    variables: &mut FreeVariableEncoding,
    output: &mut Vec<u8>,
) -> Result<(), FormulaCodecError> {
    check_depth(depth)?;
    nodes.charge()?;

    match node {
        Node::Equal(left, right) => {
            output.push(EQUAL);
            encode_variable(*left, variables, output);
            encode_variable(*right, variables, output);
        }
        Node::Member(element, set) => {
            output.push(MEMBER);
            encode_variable(*element, variables, output);
            encode_variable(*set, variables, output);
        }
        Node::Not(formula) => {
            output.push(NOT);
            encode_node(formula, depth + 1, nodes, variables, output)?;
        }
        Node::Implies(antecedent, consequent) => {
            output.push(IMPLIES);
            encode_node(antecedent, depth + 1, nodes, variables, output)?;
            encode_node(consequent, depth + 1, nodes, variables, output)?;
        }
        Node::ForAll(body) => {
            output.push(FOR_ALL);
            encode_node(body, depth + 1, nodes, variables, output)?;
        }
    }

    Ok(())
}

fn encode_variable(variable: Variable, variables: &mut FreeVariableEncoding, output: &mut Vec<u8>) {
    let (tag, value) = match variable {
        Variable::Free(variable) => (FREE_VARIABLE, variables.identifier(variable)),
        Variable::Bound(index) => (BOUND_VARIABLE, index),
    };

    output.push(tag);
    output.extend_from_slice(&value.to_be_bytes());
}

enum FreeVariableEncoding {
    Preserve,
    Normalize {
        identifiers: BTreeMap<FreeVariable, u32>,
        next_identifier: u32,
    },
}

impl FreeVariableEncoding {
    fn identifier(&mut self, variable: FreeVariable) -> u32 {
        match self {
            Self::Preserve => variable.identifier(),
            Self::Normalize {
                identifiers,
                next_identifier,
            } => match identifiers.entry(variable) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => {
                    let identifier = *next_identifier;
                    *next_identifier = next_identifier
                        .checked_add(1)
                        .expect("the node limit bounds distinct free variables");
                    entry.insert(identifier);
                    identifier
                }
            },
        }
    }
}

fn decode_node(
    cursor: &mut Cursor<'_>,
    depth: u32,
    binder_depth: u32,
    nodes: &mut NodeBudget,
) -> Result<Node, FormulaCodecError> {
    check_depth(depth)?;
    nodes.charge()?;

    match cursor.read_u8()? {
        EQUAL => Ok(Node::Equal(
            decode_variable(cursor, binder_depth)?,
            decode_variable(cursor, binder_depth)?,
        )),
        MEMBER => Ok(Node::Member(
            decode_variable(cursor, binder_depth)?,
            decode_variable(cursor, binder_depth)?,
        )),
        NOT => Ok(Node::Not(Box::new(decode_node(
            cursor,
            depth + 1,
            binder_depth,
            nodes,
        )?))),
        IMPLIES => Ok(Node::Implies(
            Box::new(decode_node(cursor, depth + 1, binder_depth, nodes)?),
            Box::new(decode_node(cursor, depth + 1, binder_depth, nodes)?),
        )),
        FOR_ALL => Ok(Node::ForAll(Box::new(decode_node(
            cursor,
            depth + 1,
            binder_depth + 1,
            nodes,
        )?))),
        tag => Err(FormulaCodecError::UnknownFormulaTag(tag)),
    }
}

fn decode_variable(
    cursor: &mut Cursor<'_>,
    binder_depth: u32,
) -> Result<Variable, FormulaCodecError> {
    let tag = cursor.read_u8()?;
    let value = cursor.read_u32()?;

    match tag {
        FREE_VARIABLE => Ok(Variable::Free(FreeVariable::new(value))),
        BOUND_VARIABLE if value < binder_depth => Ok(Variable::Bound(value)),
        BOUND_VARIABLE => Err(FormulaCodecError::DanglingBoundVariable {
            index: value,
            binder_depth,
        }),
        tag => Err(FormulaCodecError::UnknownVariableTag(tag)),
    }
}

fn check_depth(depth: u32) -> Result<(), FormulaCodecError> {
    if depth >= FORMULA_MAX_DEPTH {
        return Err(FormulaCodecError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        });
    }

    Ok(())
}

struct NodeBudget {
    used: usize,
    maximum: usize,
}

impl NodeBudget {
    fn new(maximum: usize) -> Self {
        Self {
            used: 0,
            maximum: maximum.min(FORMULA_MAX_NODES),
        }
    }

    const fn used(&self) -> usize {
        self.used
    }

    fn charge(&mut self) -> Result<(), FormulaCodecError> {
        if self.used == self.maximum {
            return Err(FormulaCodecError::NodeLimitExceeded {
                maximum: self.maximum,
            });
        }
        self.used += 1;
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, FormulaCodecError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(FormulaCodecError::UnexpectedEnd)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, FormulaCodecError> {
        let end = self
            .position
            .checked_add(4)
            .ok_or(FormulaCodecError::UnexpectedEnd)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(FormulaCodecError::UnexpectedEnd)?;
        self.position = end;
        Ok(u32::from_be_bytes(
            bytes
                .try_into()
                .expect("the checked slice has exactly four bytes"),
        ))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

/// A failure while encoding or decoding a canonical formula.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormulaCodecError {
    /// The byte sequence is longer than any admitted formula.
    InputTooLong { actual: usize, maximum: usize },
    /// The formula contains more nodes than the effective node limit admits.
    NodeLimitExceeded { maximum: usize },
    /// Formula nesting exceeds the deterministic processing limit.
    DepthLimitExceeded { maximum: u32 },
    /// The byte sequence ended before the current value was complete.
    UnexpectedEnd,
    /// The byte sequence uses an unknown formula-node tag.
    UnknownFormulaTag(u8),
    /// The byte sequence uses an unknown variable tag.
    UnknownVariableTag(u8),
    /// A bound-variable index has no enclosing quantifier.
    DanglingBoundVariable { index: u32, binder_depth: u32 },
    /// A complete formula was followed by additional bytes.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for FormulaCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "canonical formula has {actual} bytes; the limit is {maximum}"
            ),
            Self::NodeLimitExceeded { maximum } => {
                write!(formatter, "formula exceeds the limit of {maximum} nodes")
            }
            Self::DepthLimitExceeded { maximum } => {
                write!(formatter, "formula nesting exceeds the limit of {maximum}")
            }
            Self::UnexpectedEnd => formatter.write_str("canonical formula ended unexpectedly"),
            Self::UnknownFormulaTag(tag) => {
                write!(formatter, "unknown canonical formula tag 0x{tag:02x}")
            }
            Self::UnknownVariableTag(tag) => {
                write!(formatter, "unknown canonical variable tag 0x{tag:02x}")
            }
            Self::DanglingBoundVariable {
                index,
                binder_depth,
            } => write!(
                formatter,
                "bound-variable index {index} is invalid at binder depth {binder_depth}"
            ),
            Self::TrailingBytes { remaining } => {
                write!(
                    formatter,
                    "canonical formula has {remaining} trailing bytes"
                )
            }
        }
    }
}

impl Error for FormulaCodecError {}

#[cfg(test)]
mod tests;
