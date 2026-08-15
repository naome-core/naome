//! Canonical proof formulas with eliminable selected-definition applications.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::error::Error;
use std::fmt;

use naome_foundation::{
    FORMULA_MAX_BYTES, FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, Formula, FormulaCodecError,
    FreeVariable,
};

use crate::DefinitionId;

const EQUAL: u8 = 0x00;
const MEMBER: u8 = 0x01;
const NOT: u8 = 0x02;
const IMPLIES: u8 = 0x03;
const FOR_ALL: u8 = 0x04;
const DEFINED_RELATION: u8 = 0x05;

const FREE_VARIABLE: u8 = 0x00;
const BOUND_VARIABLE: u8 = 0x01;

/// A well-formed proof formula that may cite selected graph definitions.
///
/// Equality and membership retain Foundation's variable-only term boundary.
/// A defined application is an eliminable relation atom whose arguments are
/// likewise variables. Constants and functions use unary and `(n + 1)`-ary
/// graph definitions rather than adding term constructors to Foundation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DefinedFormula(Node);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Node {
    Equal(Variable, Variable),
    Member(Variable, Variable),
    Not(Box<Self>),
    Implies(Box<Self>, Box<Self>),
    ForAll(Box<Self>),
    DefinedRelation {
        definition_id: DefinitionId,
        arguments: Box<[Variable]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Variable {
    Bound(u32),
    Free(FreeVariable),
}

impl DefinedFormula {
    /// Constructs equality between two free variables.
    #[must_use]
    pub const fn equal(left: FreeVariable, right: FreeVariable) -> Self {
        Self(Node::Equal(Variable::Free(left), Variable::Free(right)))
    }

    /// Constructs membership between two free variables.
    #[must_use]
    pub const fn member(element: FreeVariable, set: FreeVariable) -> Self {
        Self(Node::Member(Variable::Free(element), Variable::Free(set)))
    }

    /// Constructs one defined graph-relation application with free arguments.
    #[must_use]
    pub fn defined_relation(
        definition_id: DefinitionId,
        arguments: impl IntoIterator<Item = FreeVariable>,
    ) -> Self {
        let arguments = arguments
            .into_iter()
            .map(Variable::Free)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self(Node::DefinedRelation {
            definition_id,
            arguments,
        })
    }

    /// Constructs a negation.
    #[must_use]
    pub fn negate(formula: Self) -> Self {
        Self(Node::Not(Box::new(formula.into_node())))
    }

    /// Constructs an implication.
    #[must_use]
    pub fn implies(antecedent: Self, consequent: Self) -> Self {
        Self(Node::Implies(
            Box::new(antecedent.into_node()),
            Box::new(consequent.into_node()),
        ))
    }

    /// Constructs conjunction as `not(A -> not(B))`.
    #[must_use]
    pub fn conjunction(left: Self, right: Self) -> Self {
        Self::negate(Self::implies(left, Self::negate(right)))
    }

    /// Constructs disjunction as `not(A) -> B`.
    #[must_use]
    pub fn disjunction(left: Self, right: Self) -> Self {
        Self::implies(Self::negate(left), right)
    }

    /// Constructs a biconditional from conjunction and implication.
    #[must_use]
    pub fn biconditional(left: Self, right: Self) -> Self {
        Self::conjunction(
            Self::implies(left.clone(), right.clone()),
            Self::implies(right, left),
        )
    }

    /// Universally quantifies one free variable capture-safely.
    #[must_use]
    pub fn for_all(variable: FreeVariable, mut body: Self) -> Self {
        bind_free(&mut body.0, 0, variable);
        Self(Node::ForAll(Box::new(body.into_node())))
    }

    /// Existentially quantifies one free variable through Foundation syntax.
    #[must_use]
    pub fn exists(variable: FreeVariable, body: Self) -> Self {
        Self::negate(Self::for_all(variable, Self::negate(body)))
    }

    /// Replaces all occurrences of one free variable with another.
    #[must_use]
    pub fn substitute_free(self, from: FreeVariable, to: FreeVariable) -> Self {
        if from == to {
            return self;
        }
        self.map_free_variables(|candidate| if candidate == from { to } else { candidate })
    }

    /// Maps every free variable in canonical traversal order.
    #[must_use]
    pub fn map_free_variables(mut self, mut map: impl FnMut(FreeVariable) -> FreeVariable) -> Self {
        map_free_variables(&mut self.0, &mut map);
        self
    }

    /// Returns all free variables occurring in this formula.
    #[must_use]
    pub fn free_variables(&self) -> BTreeSet<FreeVariable> {
        let mut variables = BTreeSet::new();
        collect_free_variables(&self.0, &mut variables);
        variables
    }

    /// Returns definition references in canonical prefix order, including duplicates.
    #[must_use]
    pub fn definition_references(&self) -> Vec<DefinitionId> {
        let mut references = Vec::new();
        collect_definition_references(&self.0, &mut references);
        references
    }

    pub(crate) fn contains_definition(&self) -> bool {
        contains_definition(&self.0)
    }

    /// Returns whether the formula has no free variables.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.free_variables().is_empty()
    }

    /// Converts one primitive Foundation formula without changing its bytes.
    pub fn from_primitive(formula: &Formula) -> Result<Self, DefinedFormulaCodecError> {
        let bytes = formula
            .encode_canonical()
            .map_err(DefinedFormulaCodecError::Primitive)?;
        Self::decode_canonical(&bytes)
    }

    /// Converts this formula to Foundation syntax if every definition was eliminated.
    pub fn into_primitive(self) -> Result<Formula, DefinedFormulaCodecError> {
        let bytes = encode(&self.0, FreeVariableEncoding::Preserve, false)?.0;
        Formula::decode_canonical(&bytes).map_err(DefinedFormulaCodecError::Primitive)
    }

    /// Encodes this formula in the canonical definition-aware proof format.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DefinedFormulaCodecError> {
        encode(&self.0, FreeVariableEncoding::Preserve, true).map(|value| value.0)
    }

    /// Encodes this formula within one caller-supplied cumulative node budget.
    pub fn encode_canonical_with_node_limit(
        &self,
        maximum_nodes: usize,
    ) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
        encode_with_limit(&self.0, FreeVariableEncoding::Preserve, true, maximum_nodes)
    }

    /// Encodes after canonicalizing free-variable identifiers by first occurrence.
    pub fn encode_free_variable_normalized(&self) -> Result<Vec<u8>, DefinedFormulaCodecError> {
        encode(
            &self.0,
            FreeVariableEncoding::Normalize {
                identifiers: BTreeMap::new(),
                next_identifier: 0,
            },
            true,
        )
        .map(|value| value.0)
    }

    /// Decodes one complete canonical definition-aware formula.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DefinedFormulaCodecError> {
        Self::decode_canonical_with_node_limit(bytes, FORMULA_MAX_NODES).map(|value| value.0)
    }

    /// Decodes one formula within a caller-supplied cumulative node budget.
    pub fn decode_canonical_with_node_limit(
        bytes: &[u8],
        maximum_nodes: usize,
    ) -> Result<(Self, usize), DefinedFormulaCodecError> {
        if bytes.len() > FORMULA_MAX_BYTES {
            return Err(DefinedFormulaCodecError::InputTooLong {
                actual: bytes.len(),
                maximum: FORMULA_MAX_BYTES,
            });
        }
        let mut cursor = Cursor::new(bytes);
        let mut nodes = NodeBudget::new(maximum_nodes);
        let node = decode_node(&mut cursor, 0, 0, &mut nodes)?;
        if cursor.remaining() != 0 {
            return Err(DefinedFormulaCodecError::TrailingBytes {
                remaining: cursor.remaining(),
            });
        }
        Ok((Self(node), nodes.used()))
    }

    /// Eliminates selected definition applications into primitive Foundation syntax.
    pub fn expand_with<R: DefinitionResolver + ?Sized>(
        &self,
        resolver: &R,
    ) -> Result<Formula, DefinitionExpansionError> {
        self.expand_with_node_limit(resolver, FORMULA_MAX_NODES)
            .map(|value| value.0)
    }

    /// Eliminates definitions while bounding all visited expansion nodes.
    ///
    /// The returned count includes compact nodes visited through definition
    /// bodies, including definition applications that disappear from the
    /// primitive result. Charging happens before recursion or allocation.
    pub fn expand_with_node_limit<R: DefinitionResolver + ?Sized>(
        &self,
        resolver: &R,
        maximum_nodes: usize,
    ) -> Result<(Formula, usize), DefinitionExpansionError> {
        let mut budget = ExpansionBudget::new(maximum_nodes);
        let mut definitions = Vec::new();
        let expanded = expand_node(&self.0, resolver, None, 0, 0, &mut definitions, &mut budget)?;
        let formula = Self(expanded)
            .into_primitive()
            .map_err(DefinitionExpansionError::Formula)?;
        Ok((formula, budget.used))
    }

    fn into_node(mut self) -> Node {
        std::mem::replace(&mut self.0, placeholder_node())
    }
}

impl Drop for DefinedFormula {
    fn drop(&mut self) {
        let root = std::mem::replace(&mut self.0, placeholder_node());
        let mut pending = Vec::new();
        let mut current = Some(root);
        while let Some(node) = current {
            match node {
                Node::Not(child) | Node::ForAll(child) => {
                    current = Some(*child);
                }
                Node::Implies(left, right) => {
                    pending.push(*right);
                    current = Some(*left);
                }
                Node::Equal(..) | Node::Member(..) | Node::DefinedRelation { .. } => {
                    current = pending.pop();
                }
            }
        }
    }
}

fn placeholder_node() -> Node {
    let variable = Variable::Free(FreeVariable::new(0));
    Node::Equal(variable, variable)
}

/// A non-identity-bearing graph view used only for definition expansion.
///
/// This view deliberately exposes neither canonical certificate bytes nor a
/// [`DefinitionId`]. A resolver may cache an equivalent expanded body without
/// presenting that cache as the exact selected definition artifact.
#[derive(Clone, Copy, Debug)]
pub struct DefinitionResolution<'a> {
    relation_arity: u32,
    body: &'a DefinedFormula,
}

impl<'a> DefinitionResolution<'a> {
    /// Constructs one graph-expansion view.
    pub const fn new(relation_arity: u32, body: &'a DefinedFormula) -> Self {
        Self {
            relation_arity,
            body,
        }
    }

    /// Returns the number of graph arguments required at a call site.
    pub const fn relation_arity(self) -> u32 {
        self.relation_arity
    }

    /// Returns the body substituted during expansion.
    pub const fn body(self) -> &'a DefinedFormula {
        self.body
    }
}

/// Resolves only graph-expansion views authorized by already selected definitions.
pub trait DefinitionResolver {
    /// Returns an expansion-only view, or `None` when the definition is unavailable.
    fn resolve_definition(&self, definition_id: DefinitionId) -> Option<DefinitionResolution<'_>>;
}

fn bind_free(node: &mut Node, depth: u32, variable: FreeVariable) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            bind_variable(left, depth, variable);
            bind_variable(right, depth, variable);
        }
        Node::DefinedRelation { arguments, .. } => {
            for argument in arguments {
                bind_variable(argument, depth, variable);
            }
        }
        Node::Not(formula) => bind_free(formula, depth, variable),
        Node::Implies(antecedent, consequent) => {
            bind_free(antecedent, depth, variable);
            bind_free(consequent, depth, variable);
        }
        Node::ForAll(body) => bind_free(
            body,
            depth
                .checked_add(1)
                .expect("formula depth is checked before canonical admission"),
            variable,
        ),
    }
}

fn bind_variable(value: &mut Variable, depth: u32, variable: FreeVariable) {
    if *value == Variable::Free(variable) {
        *value = Variable::Bound(depth);
    }
}

fn map_free_variables(node: &mut Node, map: &mut impl FnMut(FreeVariable) -> FreeVariable) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            map_variable(left, map);
            map_variable(right, map);
        }
        Node::DefinedRelation { arguments, .. } => {
            for argument in arguments {
                map_variable(argument, map);
            }
        }
        Node::Not(formula) | Node::ForAll(formula) => map_free_variables(formula, map),
        Node::Implies(antecedent, consequent) => {
            map_free_variables(antecedent, map);
            map_free_variables(consequent, map);
        }
    }
}

fn map_variable(value: &mut Variable, map: &mut impl FnMut(FreeVariable) -> FreeVariable) {
    if let Variable::Free(variable) = value {
        *variable = map(*variable);
    }
}

fn collect_free_variables(node: &Node, variables: &mut BTreeSet<FreeVariable>) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            collect_free_variable(*left, variables);
            collect_free_variable(*right, variables);
        }
        Node::DefinedRelation { arguments, .. } => {
            for argument in arguments {
                collect_free_variable(*argument, variables);
            }
        }
        Node::Not(formula) | Node::ForAll(formula) => {
            collect_free_variables(formula, variables);
        }
        Node::Implies(antecedent, consequent) => {
            collect_free_variables(antecedent, variables);
            collect_free_variables(consequent, variables);
        }
    }
}

fn collect_free_variable(value: Variable, variables: &mut BTreeSet<FreeVariable>) {
    if let Variable::Free(variable) = value {
        variables.insert(variable);
    }
}

fn collect_definition_references(node: &Node, references: &mut Vec<DefinitionId>) {
    match node {
        Node::DefinedRelation { definition_id, .. } => references.push(*definition_id),
        Node::Not(formula) | Node::ForAll(formula) => {
            collect_definition_references(formula, references);
        }
        Node::Implies(antecedent, consequent) => {
            collect_definition_references(antecedent, references);
            collect_definition_references(consequent, references);
        }
        Node::Equal(..) | Node::Member(..) => {}
    }
}

fn contains_definition(node: &Node) -> bool {
    match node {
        Node::DefinedRelation { .. } => true,
        Node::Not(formula) | Node::ForAll(formula) => contains_definition(formula),
        Node::Implies(antecedent, consequent) => {
            contains_definition(antecedent) || contains_definition(consequent)
        }
        Node::Equal(..) | Node::Member(..) => false,
    }
}

fn encode(
    node: &Node,
    variables: FreeVariableEncoding,
    allow_definitions: bool,
) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
    encode_with_limit(node, variables, allow_definitions, FORMULA_MAX_NODES)
}

fn encode_with_limit(
    node: &Node,
    mut variables: FreeVariableEncoding,
    allow_definitions: bool,
    maximum_nodes: usize,
) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
    let mut output = Vec::new();
    let mut nodes = NodeBudget::new(maximum_nodes);
    encode_node(
        node,
        0,
        &mut nodes,
        &mut variables,
        allow_definitions,
        &mut output,
    )?;
    Ok((output, nodes.used()))
}

fn encode_node(
    node: &Node,
    depth: u32,
    nodes: &mut NodeBudget,
    variables: &mut FreeVariableEncoding,
    allow_definitions: bool,
    output: &mut Vec<u8>,
) -> Result<(), DefinedFormulaCodecError> {
    check_depth(depth)?;
    nodes.charge()?;
    match node {
        Node::Equal(left, right) => {
            output.push(EQUAL);
            encode_variable(*left, variables, output);
            encode_variable(*right, variables, output);
        }
        Node::Member(left, right) => {
            output.push(MEMBER);
            encode_variable(*left, variables, output);
            encode_variable(*right, variables, output);
        }
        Node::Not(formula) => {
            output.push(NOT);
            encode_node(
                formula,
                depth + 1,
                nodes,
                variables,
                allow_definitions,
                output,
            )?;
        }
        Node::Implies(antecedent, consequent) => {
            output.push(IMPLIES);
            encode_node(
                antecedent,
                depth + 1,
                nodes,
                variables,
                allow_definitions,
                output,
            )?;
            encode_node(
                consequent,
                depth + 1,
                nodes,
                variables,
                allow_definitions,
                output,
            )?;
        }
        Node::ForAll(body) => {
            output.push(FOR_ALL);
            encode_node(body, depth + 1, nodes, variables, allow_definitions, output)?;
        }
        Node::DefinedRelation {
            definition_id,
            arguments,
        } if allow_definitions => {
            output.push(DEFINED_RELATION);
            output.extend_from_slice(definition_id.as_bytes());
            let count = u32::try_from(arguments.len()).map_err(|_| {
                DefinedFormulaCodecError::TooManyDefinitionArguments {
                    actual: arguments.len(),
                }
            })?;
            output.extend_from_slice(&count.to_be_bytes());
            for argument in arguments {
                encode_variable(*argument, variables, output);
            }
        }
        Node::DefinedRelation { definition_id, .. } => {
            return Err(DefinedFormulaCodecError::UnexpandedDefinition {
                definition_id: *definition_id,
            });
        }
    }
    if output.len() > FORMULA_MAX_BYTES {
        return Err(DefinedFormulaCodecError::InputTooLong {
            actual: output.len(),
            maximum: FORMULA_MAX_BYTES,
        });
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
                        .expect("the formula node limit bounds distinct variables");
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
) -> Result<Node, DefinedFormulaCodecError> {
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
        DEFINED_RELATION => {
            let definition_id = DefinitionId::from_bytes(
                cursor
                    .take(DefinitionId::BYTE_LENGTH)?
                    .try_into()
                    .expect("the checked slice has one DefinitionId"),
            );
            let count = usize::try_from(cursor.read_u32()?)
                .expect("u32 is representable on supported targets");
            if count > cursor.remaining() / 5 {
                return Err(DefinedFormulaCodecError::UnexpectedEnd);
            }
            let mut arguments = Vec::with_capacity(count);
            for _ in 0..count {
                arguments.push(decode_variable(cursor, binder_depth)?);
            }
            Ok(Node::DefinedRelation {
                definition_id,
                arguments: arguments.into_boxed_slice(),
            })
        }
        tag => Err(DefinedFormulaCodecError::UnknownFormulaTag(tag)),
    }
}

fn decode_variable(
    cursor: &mut Cursor<'_>,
    binder_depth: u32,
) -> Result<Variable, DefinedFormulaCodecError> {
    let tag = cursor.read_u8()?;
    let value = cursor.read_u32()?;
    match tag {
        FREE_VARIABLE => Ok(Variable::Free(FreeVariable::new(value))),
        BOUND_VARIABLE if value < binder_depth => Ok(Variable::Bound(value)),
        BOUND_VARIABLE => Err(DefinedFormulaCodecError::DanglingBoundVariable {
            index: value,
            binder_depth,
        }),
        tag => Err(DefinedFormulaCodecError::UnknownVariableTag(tag)),
    }
}

fn check_depth(depth: u32) -> Result<(), DefinedFormulaCodecError> {
    if depth >= FORMULA_MAX_DEPTH {
        return Err(DefinedFormulaCodecError::DepthLimitExceeded {
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

    fn charge(&mut self) -> Result<(), DefinedFormulaCodecError> {
        if self.used == self.maximum {
            return Err(DefinedFormulaCodecError::NodeLimitExceeded {
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

    fn read_u8(&mut self) -> Result<u8, DefinedFormulaCodecError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(DefinedFormulaCodecError::UnexpectedEnd)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, DefinedFormulaCodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("the checked slice has four bytes"),
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DefinedFormulaCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DefinedFormulaCodecError::UnexpectedEnd)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(DefinedFormulaCodecError::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

fn expand_node<R: DefinitionResolver + ?Sized>(
    node: &Node,
    resolver: &R,
    substitution: Option<&[Variable]>,
    substitution_depth: u32,
    formula_depth: u32,
    definitions: &mut Vec<DefinitionId>,
    budget: &mut ExpansionBudget,
) -> Result<Node, DefinitionExpansionError> {
    budget.charge()?;
    if formula_depth >= FORMULA_MAX_DEPTH {
        return Err(DefinitionExpansionError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        });
    }
    match node {
        Node::Equal(left, right) => Ok(Node::Equal(
            instantiate_variable(*left, substitution, substitution_depth)?,
            instantiate_variable(*right, substitution, substitution_depth)?,
        )),
        Node::Member(left, right) => Ok(Node::Member(
            instantiate_variable(*left, substitution, substitution_depth)?,
            instantiate_variable(*right, substitution, substitution_depth)?,
        )),
        Node::Not(formula) => Ok(Node::Not(Box::new(expand_node(
            formula,
            resolver,
            substitution,
            substitution_depth,
            formula_depth + 1,
            definitions,
            budget,
        )?))),
        Node::Implies(antecedent, consequent) => Ok(Node::Implies(
            Box::new(expand_node(
                antecedent,
                resolver,
                substitution,
                substitution_depth,
                formula_depth + 1,
                definitions,
                budget,
            )?),
            Box::new(expand_node(
                consequent,
                resolver,
                substitution,
                substitution_depth,
                formula_depth + 1,
                definitions,
                budget,
            )?),
        )),
        Node::ForAll(body) => Ok(Node::ForAll(Box::new(expand_node(
            body,
            resolver,
            substitution,
            substitution_depth + u32::from(substitution.is_some()),
            formula_depth + 1,
            definitions,
            budget,
        )?))),
        Node::DefinedRelation {
            definition_id,
            arguments,
        } => {
            let definition = resolver.resolve_definition(*definition_id).ok_or(
                DefinitionExpansionError::UnknownDefinition {
                    definition_id: *definition_id,
                },
            )?;
            let actual = arguments.len();
            let expected = definition.relation_arity() as usize;
            if actual != expected {
                return Err(DefinitionExpansionError::ArityMismatch {
                    definition_id: *definition_id,
                    expected,
                    actual,
                });
            }
            if definitions.contains(definition_id) {
                return Err(DefinitionExpansionError::CyclicDefinition {
                    definition_id: *definition_id,
                });
            }
            if definitions.len() as u32 >= FORMULA_MAX_DEPTH - formula_depth {
                return Err(DefinitionExpansionError::DepthLimitExceeded {
                    maximum: FORMULA_MAX_DEPTH,
                });
            }
            let arguments = arguments
                .iter()
                .map(|argument| instantiate_variable(*argument, substitution, substitution_depth))
                .collect::<Result<Vec<_>, _>>()?;
            definitions.push(*definition_id);
            let expanded = expand_node(
                &definition.body().0,
                resolver,
                Some(&arguments),
                0,
                formula_depth,
                definitions,
                budget,
            );
            definitions.pop();
            expanded
        }
    }
}

fn instantiate_variable(
    variable: Variable,
    substitution: Option<&[Variable]>,
    depth: u32,
) -> Result<Variable, DefinitionExpansionError> {
    let Some(arguments) = substitution else {
        return Ok(variable);
    };
    match variable {
        Variable::Bound(_) => Ok(variable),
        Variable::Free(parameter) => {
            let argument = *arguments.get(parameter.identifier() as usize).ok_or(
                DefinitionExpansionError::UndeclaredFormalVariable {
                    identifier: parameter.identifier(),
                },
            )?;
            match argument {
                Variable::Bound(index) => index.checked_add(depth).map(Variable::Bound).ok_or(
                    DefinitionExpansionError::DepthLimitExceeded {
                        maximum: FORMULA_MAX_DEPTH,
                    },
                ),
                Variable::Free(_) => Ok(argument),
            }
        }
    }
}

struct ExpansionBudget {
    used: usize,
    maximum: usize,
}

impl ExpansionBudget {
    fn new(maximum: usize) -> Self {
        Self {
            used: 0,
            maximum: maximum.min(FORMULA_MAX_NODES),
        }
    }

    fn charge(&mut self) -> Result<(), DefinitionExpansionError> {
        if self.used == self.maximum {
            return Err(DefinitionExpansionError::NodeLimitExceeded {
                maximum: self.maximum,
            });
        }
        self.used += 1;
        Ok(())
    }
}

/// A canonical definition-aware formula encoding failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefinedFormulaCodecError {
    /// The encoded formula exceeds the byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The formula exceeds the effective node limit.
    NodeLimitExceeded { maximum: usize },
    /// Formula nesting exceeds the deterministic depth limit.
    DepthLimitExceeded { maximum: u32 },
    /// A defined relation has more arguments than the canonical count can encode.
    TooManyDefinitionArguments { actual: usize },
    /// Primitive encoding was requested before every definition was eliminated.
    UnexpandedDefinition { definition_id: DefinitionId },
    /// The byte sequence ended before the selected value was complete.
    UnexpectedEnd,
    /// The byte sequence uses an unknown formula tag.
    UnknownFormulaTag(u8),
    /// The byte sequence uses an unknown variable tag.
    UnknownVariableTag(u8),
    /// A bound variable has no enclosing quantifier.
    DanglingBoundVariable { index: u32, binder_depth: u32 },
    /// A complete formula was followed by additional bytes.
    TrailingBytes { remaining: usize },
    /// Conversion to or from the primitive Foundation codec failed.
    Primitive(FormulaCodecError),
}

impl fmt::Display for DefinedFormulaCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "formula has {actual} bytes; the limit is {maximum}"
                )
            }
            Self::NodeLimitExceeded { maximum } => {
                write!(formatter, "formula exceeds the {maximum}-node limit")
            }
            Self::DepthLimitExceeded { maximum } => {
                write!(formatter, "formula exceeds the depth limit {maximum}")
            }
            Self::TooManyDefinitionArguments { actual } => write!(
                formatter,
                "defined relation has {actual} arguments; the count must fit u32"
            ),
            Self::UnexpandedDefinition { .. } => {
                formatter.write_str("primitive formula encoding contains a definition")
            }
            Self::UnexpectedEnd => formatter.write_str("formula ended unexpectedly"),
            Self::UnknownFormulaTag(tag) => write!(formatter, "unknown formula tag {tag:#04x}"),
            Self::UnknownVariableTag(tag) => write!(formatter, "unknown variable tag {tag:#04x}"),
            Self::DanglingBoundVariable {
                index,
                binder_depth,
            } => write!(
                formatter,
                "bound variable {index} is invalid at binder depth {binder_depth}"
            ),
            Self::TrailingBytes { remaining } => {
                write!(formatter, "formula has {remaining} trailing bytes")
            }
            Self::Primitive(source) => write!(formatter, "primitive formula is invalid: {source}"),
        }
    }
}

impl Error for DefinedFormulaCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Primitive(source) => Some(source),
            _ => None,
        }
    }
}

/// A selected-definition resolution or bounded expansion failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefinitionExpansionError {
    /// A referenced definition is absent from the supplied selected state.
    UnknownDefinition { definition_id: DefinitionId },
    /// A selected definition was called with the wrong number of graph arguments.
    ArityMismatch {
        definition_id: DefinitionId,
        expected: usize,
        actual: usize,
    },
    /// A resolver exposed a cyclic definition dependency.
    CyclicDefinition { definition_id: DefinitionId },
    /// A definition body contains a free variable outside its formal interface.
    UndeclaredFormalVariable { identifier: u32 },
    /// Expansion exceeds the deterministic node-work limit.
    NodeLimitExceeded { maximum: usize },
    /// Expansion exceeds the deterministic formula/reference depth limit.
    DepthLimitExceeded { maximum: u32 },
    /// The expanded primitive formula is malformed or outside codec limits.
    Formula(DefinedFormulaCodecError),
}

impl fmt::Display for DefinitionExpansionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDefinition { .. } => {
                formatter.write_str("formula references an unknown definition")
            }
            Self::ArityMismatch {
                expected, actual, ..
            } => write!(
                formatter,
                "defined relation expects {expected} arguments but received {actual}"
            ),
            Self::CyclicDefinition { .. } => {
                formatter.write_str("definition expansion contains a dependency cycle")
            }
            Self::UndeclaredFormalVariable { identifier } => write!(
                formatter,
                "definition body uses undeclared formal variable {identifier}"
            ),
            Self::NodeLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "definition expansion exceeds {maximum} visited nodes"
                )
            }
            Self::DepthLimitExceeded { maximum } => {
                write!(formatter, "definition expansion exceeds depth {maximum}")
            }
            Self::Formula(source) => write!(formatter, "expanded formula is invalid: {source}"),
        }
    }
}

impl Error for DefinitionExpansionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Formula(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefinitionCertificate, ProofId};

    struct OneDefinition {
        id: DefinitionId,
        definition: DefinitionCertificate,
    }

    impl DefinitionResolver for OneDefinition {
        fn resolve_definition(
            &self,
            definition_id: DefinitionId,
        ) -> Option<DefinitionResolution<'_>> {
            (definition_id == self.id).then(|| {
                DefinitionResolution::new(self.definition.relation_arity(), self.definition.body())
            })
        }
    }

    #[test]
    fn primitive_subset_is_byte_identical_and_definition_tag_is_exact() {
        let x = FreeVariable::new(7);
        let primitive = Formula::for_all(x, Formula::equal(x, x));
        let defined = DefinedFormula::from_primitive(&primitive).unwrap();
        assert_eq!(
            defined.encode_canonical().unwrap(),
            primitive.encode_canonical().unwrap()
        );
        assert_eq!(defined.into_primitive().unwrap(), primitive);

        let id = DefinitionId::from_bytes([0x11; 32]);
        let application = DefinedFormula::for_all(x, DefinedFormula::defined_relation(id, [x]));
        let mut expected = vec![FOR_ALL, DEFINED_RELATION];
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.push(BOUND_VARIABLE);
        expected.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(application.encode_canonical().unwrap(), expected);
        assert_eq!(
            DefinedFormula::decode_canonical(&expected).unwrap(),
            application
        );
        assert!(matches!(
            Formula::decode_canonical(&expected),
            Err(FormulaCodecError::UnknownFormulaTag(DEFINED_RELATION))
        ));
    }

    #[test]
    fn expansion_shifts_an_outer_bound_argument_beneath_body_binders() {
        let formal = FreeVariable::new(0);
        let inner = FreeVariable::new(1);
        let outer = FreeVariable::new(7);
        let body = DefinedFormula::for_all(inner, DefinedFormula::member(formal, inner));
        let definition = DefinitionCertificate::relation(1, body).unwrap();
        let id = definition.definition_id();
        let resolver = OneDefinition { id, definition };
        let compact = DefinedFormula::for_all(outer, DefinedFormula::defined_relation(id, [outer]));
        let expanded = compact.expand_with(&resolver).unwrap();
        let expected = Formula::for_all(
            outer,
            Formula::for_all(inner, Formula::member(outer, inner)),
        );
        assert_eq!(expanded, expected);
    }

    #[test]
    fn expansion_rejects_unknown_wrong_arity_cycle_and_work_exhaustion() {
        let id = DefinitionId::from_bytes([0x22; 32]);
        let x = FreeVariable::new(0);
        let missing = DefinedFormula::defined_relation(id, [x]);
        struct Empty;
        impl DefinitionResolver for Empty {
            fn resolve_definition(&self, _: DefinitionId) -> Option<DefinitionResolution<'_>> {
                None
            }
        }
        assert_eq!(
            missing.expand_with(&Empty),
            Err(DefinitionExpansionError::UnknownDefinition { definition_id: id })
        );

        let definition = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
        let resolver = OneDefinition { id, definition };
        let wrong = DefinedFormula::defined_relation(id, []);
        assert_eq!(
            wrong.expand_with(&resolver),
            Err(DefinitionExpansionError::ArityMismatch {
                definition_id: id,
                expected: 1,
                actual: 0,
            })
        );
        assert_eq!(
            missing.expand_with_node_limit(&resolver, 1),
            Err(DefinitionExpansionError::NodeLimitExceeded { maximum: 1 })
        );

        let cyclic =
            DefinitionCertificate::relation(1, DefinedFormula::defined_relation(id, [x])).unwrap();
        let resolver = OneDefinition {
            id,
            definition: cyclic,
        };
        assert_eq!(
            missing.expand_with(&resolver),
            Err(DefinitionExpansionError::CyclicDefinition { definition_id: id })
        );
    }

    #[test]
    fn definition_applications_bind_normalize_and_round_trip_capture_safely() {
        let id = DefinitionId::from_bytes([0x33; 32]);
        let x = FreeVariable::new(99);
        let y = FreeVariable::new(7);
        let formula = DefinedFormula::for_all(
            x,
            DefinedFormula::implies(
                DefinedFormula::defined_relation(id, [x, y]),
                DefinedFormula::equal(y, y),
            ),
        );
        let renamed = formula.clone().map_free_variables(|_| FreeVariable::new(0));
        assert_eq!(
            formula.encode_free_variable_normalized().unwrap(),
            renamed.encode_free_variable_normalized().unwrap()
        );
        assert_eq!(formula.free_variables(), BTreeSet::from([y]));
        assert_eq!(formula.definition_references(), vec![id]);
        let bytes = formula.encode_canonical().unwrap();
        assert_eq!(DefinedFormula::decode_canonical(&bytes).unwrap(), formula);
    }

    #[test]
    fn proof_id_shaped_values_do_not_resolve_as_definitions() {
        let proof = ProofId::from_bytes([0x44; 32]);
        let id = DefinitionId::from_bytes(*proof.as_bytes());
        let formula = DefinedFormula::defined_relation(id, []);
        struct Empty;
        impl DefinitionResolver for Empty {
            fn resolve_definition(&self, _: DefinitionId) -> Option<DefinitionResolution<'_>> {
                None
            }
        }
        assert!(matches!(
            formula.expand_with(&Empty),
            Err(DefinitionExpansionError::UnknownDefinition { definition_id })
                if definition_id == id
        ));
    }
}
