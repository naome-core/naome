//! Canonical proof formulas with eliminable selected-definition applications.

use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map::Entry};
use std::error::Error;
use std::fmt;

use naome_foundation::{
    FORMULA_MAX_BYTES, FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, Formula, FormulaCodecError,
    FormulaView, FreeVariable,
    graph::{Node as PrimitiveNode, Variable as PrimitiveVariable},
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
/// likewise variables. Functions use `(n + 1)`-ary graph definitions rather
/// than adding term constructors to Foundation; standalone constants are not
/// represented.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DefinedFormula(Node);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Node {
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
pub enum Variable {
    /// A de Bruijn index into enclosing universal binders.
    Bound(u32),
    /// A free formal or source variable.
    Free(FreeVariable),
}

/// An immutable view of one compact formula node, retaining exact references.
#[derive(Clone, Copy, Debug)]
pub enum DefinedFormulaNode<'a> {
    /// Primitive equality operands.
    Equal(Variable, Variable),
    /// Primitive membership operands.
    Member(Variable, Variable),
    /// Negation body.
    Not(DefinedFormulaView<'a>),
    /// Ordered implication operands.
    Implies(DefinedFormulaView<'a>, DefinedFormulaView<'a>),
    /// Universally bound body, using de Bruijn variable indices.
    ForAll(DefinedFormulaView<'a>),
    /// Exact selected definition and ordered graph arguments.
    DefinedRelation {
        definition_id: DefinitionId,
        arguments: &'a [Variable],
    },
}

/// A borrowed compact subformula, including its existing binder indices.
#[derive(Clone, Copy, Debug)]
pub struct DefinedFormulaView<'a>(&'a Node);
impl<'a> DefinedFormulaView<'a> {
    /// Borrows one exact compact node without decoding or expanding it.
    pub fn node(self) -> DefinedFormulaNode<'a> {
        match self.0 {
            Node::Equal(a, b) => DefinedFormulaNode::Equal(*a, *b),
            Node::Member(a, b) => DefinedFormulaNode::Member(*a, *b),
            Node::Not(body) => DefinedFormulaNode::Not(Self(body)),
            Node::Implies(a, b) => DefinedFormulaNode::Implies(Self(a), Self(b)),
            Node::ForAll(body) => DefinedFormulaNode::ForAll(Self(body)),
            Node::DefinedRelation {
                definition_id,
                arguments,
            } => DefinedFormulaNode::DefinedRelation {
                definition_id: *definition_id,
                arguments,
            },
        }
    }
}

impl DefinedFormula {
    /// Borrows the exact compact structure without expanding or authorizing references.
    pub fn view(&self) -> DefinedFormulaView<'_> {
        DefinedFormulaView(&self.0)
    }
    pub(crate) fn graph_root(&self) -> &Node {
        &self.0
    }

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
        self.append_definition_references(&mut references);
        references
    }

    pub(crate) fn append_definition_references(&self, references: &mut Vec<DefinitionId>) {
        self.try_for_each_definition_reference(&mut |id| {
            references.push(id);
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap();
    }

    pub(crate) fn try_for_each_definition_reference<E>(
        &self,
        visit: &mut impl FnMut(DefinitionId) -> Result<(), E>,
    ) -> Result<(), E> {
        visit_definition_references(&self.0, visit)
    }

    pub(crate) fn definition_reference_count(&self) -> usize {
        fn count(node: &Node) -> usize {
            match node {
                Node::DefinedRelation { .. } => 1,
                Node::Not(formula) | Node::ForAll(formula) => count(formula),
                Node::Implies(antecedent, consequent) => count(antecedent) + count(consequent),
                Node::Equal(..) | Node::Member(..) => 0,
            }
        }
        count(&self.0)
    }

    pub(crate) fn first_definition_reference(&self) -> Option<DefinitionId> {
        first_definition_reference(&self.0)
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
        formula
            .encoded_length()
            .map_err(DefinedFormulaCodecError::Primitive)?;
        fn copy_node(
            view: FormulaView<'_>,
            binder_depth: u32,
        ) -> Result<Node, DefinedFormulaCodecError> {
            let variable = |value| match value {
                PrimitiveVariable::Free(id) => Ok(Variable::Free(FreeVariable::new(id))),
                PrimitiveVariable::Bound(index) => {
                    let index = u32::try_from(index).expect("Foundation binder indices fit u32");
                    if index >= binder_depth {
                        return Err(DefinedFormulaCodecError::DanglingBoundVariable {
                            index,
                            binder_depth,
                        });
                    }
                    Ok(Variable::Bound(index))
                }
            };
            Ok(match view.graph_node() {
                PrimitiveNode::Equal(left, right) => Node::Equal(variable(left)?, variable(right)?),
                PrimitiveNode::Member(left, right) => {
                    Node::Member(variable(left)?, variable(right)?)
                }
                PrimitiveNode::Not(body) => Node::Not(Box::new(copy_node(body, binder_depth)?)),
                PrimitiveNode::Implies(left, right) => Node::Implies(
                    Box::new(copy_node(left, binder_depth)?),
                    Box::new(copy_node(right, binder_depth)?),
                ),
                PrimitiveNode::ForAll(body) => {
                    Node::ForAll(Box::new(copy_node(body, binder_depth + 1)?))
                }
            })
        }
        copy_node(formula.view(), 0).map(Self)
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

    /// Encodes within caller-supplied cumulative node and depth limits.
    ///
    /// Both effective limits are capped by the canonical Formula limits. This
    /// lets a containing derived formula reserve its fixed structural headroom
    /// before duplicating this tree.
    pub fn encode_canonical_with_limits(
        &self,
        maximum_nodes: usize,
        maximum_depth: u32,
    ) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
        encode_with_limits(
            &self.0,
            FreeVariableEncoding::Preserve,
            true,
            maximum_nodes,
            maximum_depth,
        )
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
        let mut expansion = Expansion {
            resolver,
            active: Vec::new(),
            instances: HashMap::new(),
            graph: Vec::new(),
            interned: HashMap::new(),
            budget: ExpansionBudget::new(maximum_nodes),
        };
        let root = expansion.node(&self.0, None, 0, 0)?;
        let formula = Formula::from_graph(root, |position| {
            Ok::<_, std::convert::Infallible>(expansion.graph[position])
        })
        .map_err(|error| {
            DefinitionExpansionError::Formula(DefinedFormulaCodecError::Graph(error))
        })?;
        Ok((formula, expansion.budget.used))
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
#[derive(Clone, Debug)]
pub struct DefinitionResolution<'a> {
    relation_arity: u32,
    body: DefinitionBody<'a>,
}
#[derive(Clone, Debug)]
enum DefinitionBody<'a> {
    Borrowed(&'a DefinedFormula),
    Shared(std::sync::Arc<DefinedFormula>),
}

impl<'a> DefinitionResolution<'a> {
    /// Constructs one graph-expansion view.
    pub const fn new(relation_arity: u32, body: &'a DefinedFormula) -> Self {
        Self {
            relation_arity,
            body: DefinitionBody::Borrowed(body),
        }
    }

    /// Returns the number of graph arguments required at a call site.
    pub const fn relation_arity(&self) -> u32 {
        self.relation_arity
    }

    /// Returns the body substituted during expansion.
    pub fn body(&self) -> &DefinedFormula {
        match &self.body {
            DefinitionBody::Borrowed(body) => body,
            DefinitionBody::Shared(body) => body,
        }
    }

    /// Owns a bounded expansion read from authenticated cold storage.
    pub fn owned(relation_arity: u32, body: DefinedFormula) -> Self {
        Self::shared(relation_arity, std::sync::Arc::new(body))
    }
    /// Shares an immutable body without cloning its formula tree.
    pub fn shared(relation_arity: u32, body: std::sync::Arc<DefinedFormula>) -> Self {
        Self {
            relation_arity,
            body: DefinitionBody::Shared(body),
        }
    }
}

/// A bounded storage failure, independent of platform error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextStorageFailure {
    Sqlite(Option<i32>),
    System(Option<i32>),
    CacheLock,
    IndexLock,
    WriteGate,
    OwnerUnavailable,
    CopyRoute,
    StartupGeneration,
    StartupOwner,
    IncompleteCopy,
    ProgramRead,
    Injected,
}

impl ContextStorageFailure {
    /// Stable reason within the checked-context storage domain.
    pub fn code(self) -> u8 {
        match self {
            Self::Sqlite(_) => 1,
            Self::System(_) => 2,
            Self::CacheLock => 3,
            Self::IndexLock => 4,
            Self::WriteGate => 5,
            Self::OwnerUnavailable => 6,
            Self::CopyRoute => 7,
            Self::StartupGeneration => 8,
            Self::StartupOwner => 9,
            Self::IncompleteCopy => 10,
            Self::ProgramRead => 11,
            Self::Injected => 12,
        }
    }
    /// Original operating-system or SQLite code when the adapter supplied one.
    pub fn native_code(self) -> Option<i32> {
        match self {
            Self::Sqlite(code) | Self::System(code) => code,
            _ => None,
        }
    }
}

/// Failure to read an already selected definition. This is not absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefinitionAccessError {
    Storage(ContextStorageFailure),
    Corrupt,
    Limit,
}
impl fmt::Display for DefinitionAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(reason) => write!(f, "definition storage: {reason:?}"),
            Self::Corrupt => f.write_str("definition integrity failure"),
            Self::Limit => f.write_str("definition access limit"),
        }
    }
}
impl Error for DefinitionAccessError {}

/// Resolves only graph-expansion views authorized by already selected definitions.
pub trait DefinitionResolver {
    /// Returns an expansion-only view, or `None` when the definition is unavailable.
    fn resolve_definition(
        &self,
        definition_id: DefinitionId,
    ) -> Result<Option<DefinitionResolution<'_>>, DefinitionAccessError>;
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

fn visit_definition_references<E>(
    node: &Node,
    visit: &mut impl FnMut(DefinitionId) -> Result<(), E>,
) -> Result<(), E> {
    match node {
        Node::DefinedRelation { definition_id, .. } => visit(*definition_id),
        Node::Not(formula) | Node::ForAll(formula) => visit_definition_references(formula, visit),
        Node::Implies(antecedent, consequent) => {
            visit_definition_references(antecedent, visit)?;
            visit_definition_references(consequent, visit)
        }
        Node::Equal(..) | Node::Member(..) => Ok(()),
    }
}

fn first_definition_reference(node: &Node) -> Option<DefinitionId> {
    match node {
        Node::DefinedRelation { definition_id, .. } => Some(*definition_id),
        Node::Not(formula) | Node::ForAll(formula) => first_definition_reference(formula),
        Node::Implies(antecedent, consequent) => first_definition_reference(antecedent)
            .or_else(|| first_definition_reference(consequent)),
        Node::Equal(..) | Node::Member(..) => None,
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
    variables: FreeVariableEncoding,
    allow_definitions: bool,
    maximum_nodes: usize,
) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
    encode_with_limits(
        node,
        variables,
        allow_definitions,
        maximum_nodes,
        FORMULA_MAX_DEPTH,
    )
}

fn encode_with_limits(
    node: &Node,
    mut variables: FreeVariableEncoding,
    allow_definitions: bool,
    maximum_nodes: usize,
    maximum_depth: u32,
) -> Result<(Vec<u8>, usize), DefinedFormulaCodecError> {
    let mut output = Vec::new();
    let mut nodes = NodeBudget::new(maximum_nodes);
    encode_node(
        node,
        0,
        &mut nodes,
        &mut variables,
        allow_definitions,
        maximum_depth.min(FORMULA_MAX_DEPTH),
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
    maximum_depth: u32,
    output: &mut Vec<u8>,
) -> Result<(), DefinedFormulaCodecError> {
    check_depth_limit(depth, maximum_depth)?;
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
                maximum_depth,
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
                maximum_depth,
                output,
            )?;
            encode_node(
                consequent,
                depth + 1,
                nodes,
                variables,
                allow_definitions,
                maximum_depth,
                output,
            )?;
        }
        Node::ForAll(body) => {
            output.push(FOR_ALL);
            encode_node(
                body,
                depth + 1,
                nodes,
                variables,
                allow_definitions,
                maximum_depth,
                output,
            )?;
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

pub(crate) fn instantiate_prefix(
    bytes: &[u8],
    position: &mut usize,
    binders: u32,
    arguments: &[u32],
) -> Result<naome_foundation::graph::Node<()>, DefinitionExpansionError> {
    use naome_foundation::graph::{Node as Primitive, Variable as PrimitiveVariable};
    let corrupt = |_| DefinitionExpansionError::Access(DefinitionAccessError::Corrupt);
    let mut cursor = Cursor {
        bytes,
        position: *position,
    };
    let tag = cursor.read_u8().map_err(corrupt)?;
    let mut variable = || match decode_variable(&mut cursor, binders).map_err(corrupt)? {
        Variable::Bound(index) => Ok(PrimitiveVariable::Bound(u64::from(index))),
        Variable::Free(formal) => arguments
            .get(formal.identifier() as usize)
            .copied()
            .map(PrimitiveVariable::Free)
            .ok_or(DefinitionExpansionError::UndeclaredFormalVariable {
                identifier: formal.identifier(),
            }),
    };
    let node = match tag {
        EQUAL => Primitive::Equal(variable()?, variable()?),
        MEMBER => Primitive::Member(variable()?, variable()?),
        NOT => Primitive::Not(()),
        IMPLIES => Primitive::Implies((), ()),
        FOR_ALL => Primitive::ForAll(()),
        _ => {
            return Err(DefinitionExpansionError::Access(
                DefinitionAccessError::Corrupt,
            ));
        }
    };
    *position = cursor.position;
    Ok(node)
}

fn check_depth(depth: u32) -> Result<(), DefinedFormulaCodecError> {
    check_depth_limit(depth, FORMULA_MAX_DEPTH)
}

fn check_depth_limit(depth: u32, maximum: u32) -> Result<(), DefinedFormulaCodecError> {
    if depth >= maximum {
        return Err(DefinedFormulaCodecError::DepthLimitExceeded { maximum });
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

type Instance = (DefinitionId, Vec<Variable>, u32);

struct Expansion<'a, R: ?Sized> {
    resolver: &'a R,
    active: Vec<DefinitionId>,
    instances: HashMap<Instance, (usize, usize)>,
    graph: Vec<PrimitiveNode<usize>>,
    interned: HashMap<PrimitiveNode<usize>, usize>,
    budget: ExpansionBudget,
}

impl<R: DefinitionResolver + ?Sized> Expansion<'_, R> {
    fn node(
        &mut self,
        node: &Node,
        substitution: Option<&[Variable]>,
        substitution_depth: u32,
        formula_depth: u32,
    ) -> Result<usize, DefinitionExpansionError> {
        self.budget.charge(1)?;
        if formula_depth >= FORMULA_MAX_DEPTH {
            return Err(DefinitionExpansionError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        let variable = |value| {
            instantiate_variable(value, substitution, substitution_depth).map(|value| match value {
                Variable::Free(id) => PrimitiveVariable::Free(id.identifier()),
                Variable::Bound(index) => PrimitiveVariable::Bound(u64::from(index)),
            })
        };
        let next = formula_depth + 1;
        let primitive = match node {
            Node::Equal(left, right) => PrimitiveNode::Equal(variable(*left)?, variable(*right)?),
            Node::Member(left, right) => PrimitiveNode::Member(variable(*left)?, variable(*right)?),
            Node::Not(body) => {
                PrimitiveNode::Not(self.node(body, substitution, substitution_depth, next)?)
            }
            Node::Implies(left, right) => PrimitiveNode::Implies(
                self.node(left, substitution, substitution_depth, next)?,
                self.node(right, substitution, substitution_depth, next)?,
            ),
            Node::ForAll(body) => PrimitiveNode::ForAll(self.node(
                body,
                substitution,
                substitution_depth + u32::from(substitution.is_some()),
                next,
            )?),
            Node::DefinedRelation {
                definition_id,
                arguments,
            } => {
                let arguments = arguments
                    .iter()
                    .map(|argument| {
                        instantiate_variable(*argument, substitution, substitution_depth)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return self.application(*definition_id, arguments, formula_depth);
            }
        };
        Ok(*self.interned.entry(primitive).or_insert_with(|| {
            let position = self.graph.len();
            self.graph.push(primitive);
            position
        }))
    }

    fn application(
        &mut self,
        definition_id: DefinitionId,
        arguments: Vec<Variable>,
        depth: u32,
    ) -> Result<usize, DefinitionExpansionError> {
        // Reuse only complete applications from the same outer scope depth.
        // Nested applications must still check their active dependency path.
        let instance = (definition_id, arguments, depth);
        let reusable = self.active.is_empty();
        if reusable && let Some(&(root, nodes)) = self.instances.get(&instance) {
            self.budget.charge(nodes)?;
            return Ok(root);
        }
        let definition = self
            .resolver
            .resolve_definition(definition_id)
            .map_err(DefinitionExpansionError::Access)?
            .ok_or(DefinitionExpansionError::UnknownDefinition { definition_id })?;
        let expected = definition.relation_arity() as usize;
        let actual = instance.1.len();
        if actual != expected {
            return Err(DefinitionExpansionError::ArityMismatch {
                definition_id,
                expected,
                actual,
            });
        }
        if self.active.contains(&definition_id) {
            return Err(DefinitionExpansionError::CyclicDefinition { definition_id });
        }
        if self.active.len() as u32 >= FORMULA_MAX_DEPTH - depth {
            return Err(DefinitionExpansionError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        let before = self.budget.used;
        self.active.push(definition_id);
        let root = self.node(&definition.body().0, Some(&instance.1), 0, depth);
        self.active.pop();
        let root = root?;
        if reusable {
            self.instances
                .insert(instance, (root, self.budget.used - before));
        }
        Ok(root)
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

    fn charge(&mut self, nodes: usize) -> Result<(), DefinitionExpansionError> {
        if nodes > self.maximum - self.used {
            return Err(DefinitionExpansionError::NodeLimitExceeded {
                maximum: self.maximum,
            });
        }
        self.used += nodes;
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
    /// Materialization of a bounded primitive formula graph failed.
    Graph(naome_foundation::graph::MaterializationError<std::convert::Infallible>),
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
            Self::Graph(source) => {
                write!(formatter, "primitive formula graph is invalid: {source}")
            }
        }
    }
}

impl Error for DefinedFormulaCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Primitive(source) => Some(source),
            Self::Graph(source) => Some(source),
            _ => None,
        }
    }
}

/// A selected-definition resolution or bounded expansion failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefinitionExpansionError {
    /// Reading selected state failed; no mathematical rejection is established.
    Access(DefinitionAccessError),
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
            Self::Access(source) => source.fmt(formatter),
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
            Self::Access(source) => Some(source),
            Self::Formula(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
