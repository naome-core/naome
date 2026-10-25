use super::{Digest, InspectionError, MAX_INSPECTION_NODES, MAX_INSPECTION_PATH, OperandRole};
use naome_foundation::{
    FormulaView,
    graph::{Node, Properties, Variable as GraphVariable},
};
use naome_proof::program::graph_node_hash;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "identifier", rename_all = "snake_case")]
pub enum Variable {
    Free(u32),
    Bound(u64),
}
impl From<GraphVariable> for Variable {
    fn from(value: GraphVariable) -> Self {
        match value {
            GraphVariable::Free(v) => Self::Free(v),
            GraphVariable::Bound(v) => Self::Bound(v),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Equal,
    Member,
    Not,
    Implies,
    ForAll,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormulaNode {
    Equal {
        left: Variable,
        right: Variable,
    },
    Member {
        element: Variable,
        set: Variable,
    },
    Not {
        body: Digest,
    },
    Implies {
        antecedent: Digest,
        consequent: Digest,
    },
    ForAll {
        body: Digest,
    },
}
impl FormulaNode {
    pub fn children(&self) -> [Option<Digest>; 2] {
        match self {
            Self::Not { body } | Self::ForAll { body } => [Some(*body), None],
            Self::Implies {
                antecedent,
                consequent,
            } => [Some(*antecedent), Some(*consequent)],
            _ => [None, None],
        }
    }
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Equal { .. } => NodeKind::Equal,
            Self::Member { .. } => NodeKind::Member,
            Self::Not { .. } => NodeKind::Not,
            Self::Implies { .. } => NodeKind::Implies,
            Self::ForAll { .. } => NodeKind::ForAll,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeRecord {
    pub id: Digest,
    pub node: FormulaNode,
    pub has_free_variables: bool,
    pub required_binders: u64,
}
impl NodeRecord {
    pub(crate) fn new(node: Node<Digest>, id: Digest, properties: Properties) -> Self {
        let node = match node {
            Node::Equal(left, right) => FormulaNode::Equal {
                left: left.into(),
                right: right.into(),
            },
            Node::Member(element, set) => FormulaNode::Member {
                element: element.into(),
                set: set.into(),
            },
            Node::Not(body) => FormulaNode::Not { body },
            Node::Implies(antecedent, consequent) => FormulaNode::Implies {
                antecedent,
                consequent,
            },
            Node::ForAll(body) => FormulaNode::ForAll { body },
        };
        Self {
            id,
            node,
            has_free_variables: properties.has_free_variables,
            required_binders: properties.required_binders,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSegment {
    Negated,
    Antecedent,
    Consequent,
    Quantified,
    LeftVariable,
    RightVariable,
}
impl From<naome_foundation::FormulaPathSegment> for PathSegment {
    fn from(value: naome_foundation::FormulaPathSegment) -> Self {
        use naome_foundation::FormulaPathSegment as P;
        match value {
            P::Negated => Self::Negated,
            P::Antecedent => Self::Antecedent,
            P::Consequent => Self::Consequent,
            P::Quantified => Self::Quantified,
            P::LeftVariable => Self::LeftVariable,
            P::RightVariable => Self::RightVariable,
        }
    }
}

/// A structural fragment. Missing child IDs can be inspected separately. A
/// false completeness flag means absence of a node/variable is not evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FormulaFragment {
    /// Original operand root, retained across address-based continuation.
    pub anchor_root: Digest,
    /// Content-addressed starting node for this bounded path segment.
    pub start: Option<Digest>,
    pub root: Digest,
    pub variable_namespace: VariableNamespace,
    /// Absolute depth is unknown for address-based continuation. The reader
    /// must carry the binder context along authenticated child links.
    pub scope_depth: Option<u64>,
    pub path: Vec<PathSegment>,
    pub nodes: Vec<NodeRecord>,
    pub complete: bool,
    pub free_variables: Vec<u32>,
    pub free_variables_complete: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableNamespace {
    Input,
    Source,
    Supplied,
}
impl FormulaFragment {
    pub fn node(&self, id: Digest) -> Option<&NodeRecord> {
        self.nodes.iter().find(|node| node.id == id)
    }
    pub fn root_node(&self) -> Option<&NodeRecord> {
        self.node(self.root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Difference {
    pub path: Vec<PathSegment>,
    pub expected: NodeRecord,
    pub actual: NodeRecord,
    /// False when the search stopped at its bounded frontier. `path` then
    /// identifies where further inspection is needed, not a proved difference.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormulaQuery {
    pub operand: OperandRole,
    /// Must be an operand or target root in the bound diagnostic.
    pub root: Digest,
    /// Continue from a child hash returned by a preceding fragment. Program
    /// inspection authenticates this node in the replayed prefix but does not
    /// assert reachability from `root` or proofhood of the selected subtree.
    pub start: Option<Digest>,
    pub path: Vec<PathSegment>,
    pub maximum_nodes: usize,
}
impl FormulaQuery {
    pub fn validate(&self) -> Result<(), InspectionError> {
        if self.maximum_nodes == 0
            || self.maximum_nodes > MAX_INSPECTION_NODES
            || self.path.len() > MAX_INSPECTION_PATH
        {
            return Err(InspectionError::InvalidQuery);
        }
        Ok(())
    }
}

/// Hashes a codec-bounded tree once, retaining only a bounded preorder fragment
/// and at most 32 free variables. Open subtrees retain their binder context.
pub(crate) fn tree_fragment(
    view: FormulaView<'_>,
    maximum: usize,
    scope_depth: u64,
) -> FormulaFragment {
    struct Builder {
        nodes: Vec<Option<NodeRecord>>,
        maximum: usize,
        variables: BTreeSet<u32>,
        variables_complete: bool,
    }
    fn walk(view: FormulaView<'_>, b: &mut Builder) -> (Digest, Properties) {
        let slot = if b.nodes.len() < b.maximum {
            b.nodes.push(None);
            Some(b.nodes.len() - 1)
        } else {
            None
        };
        let node = view.graph_node();
        if let Node::Equal(a, c) | Node::Member(a, c) = node {
            for v in [a, c] {
                if let GraphVariable::Free(v) = v {
                    if b.variables.len() < 32 || b.variables.contains(&v) {
                        b.variables.insert(v);
                    } else {
                        b.variables_complete = false;
                    }
                }
            }
        }
        let mut properties = [None, None];
        let mut child = 0;
        let node = node.map(|view| {
            let (hash, p) = walk(view, b);
            properties[child] = Some(p);
            child += 1;
            hash
        });
        let p = node
            .properties(properties)
            .expect("tree variables have bounded indices");
        let hash = Digest(graph_node_hash(node.map(|id| id.0), p));
        if let Some(slot) = slot {
            b.nodes[slot] = Some(NodeRecord::new(node, hash, p));
        }
        (hash, p)
    }
    let mut b = Builder {
        nodes: Vec::new(),
        maximum: maximum.max(1),
        variables: BTreeSet::new(),
        variables_complete: true,
    };
    let (root, _) = walk(view, &mut b);
    let mut seen = BTreeSet::new();
    let nodes = b
        .nodes
        .into_iter()
        .flatten()
        .filter(|node| seen.insert(node.id))
        .collect::<Vec<_>>();
    let complete = nodes
        .iter()
        .flat_map(|node| node.node.children())
        .flatten()
        .all(|child| seen.contains(&child));
    FormulaFragment {
        anchor_root: root,
        start: None,
        root,
        variable_namespace: VariableNamespace::Input,
        scope_depth: Some(scope_depth),
        path: Vec::new(),
        nodes,
        complete,
        free_variables: b.variables.into_iter().collect(),
        free_variables_complete: b.variables_complete,
    }
}

pub(crate) fn tree_query(
    mut view: FormulaView<'_>,
    query: &FormulaQuery,
) -> Result<FormulaFragment, InspectionError> {
    query.validate()?;
    if let Some(start) = query.start {
        fn locate<'a>(
            view: FormulaView<'a>,
            target: Digest,
        ) -> (Digest, Properties, Option<FormulaView<'a>>) {
            let mut properties = [None, None];
            let mut index = 0;
            let mut found = None;
            let node = view.graph_node().map(|child| {
                let (hash, p, child_found) = locate(child, target);
                properties[index] = Some(p);
                index += 1;
                found = found.or(child_found);
                hash
            });
            let p = node.properties(properties).expect("bounded tree indices");
            let hash = Digest(graph_node_hash(node.map(|id| id.0), p));
            (hash, p, if hash == target { Some(view) } else { found })
        }
        view = locate(view, start)
            .2
            .ok_or(InspectionError::UnknownFormula)?;
    }
    let mut scope = 0;
    for (index, edge) in query.path.iter().enumerate() {
        let node = view.graph_node();
        view = match (node, edge) {
            (Node::Not(body), PathSegment::Negated) => body,
            (Node::ForAll(body), PathSegment::Quantified) => {
                scope += 1;
                body
            }
            (Node::Implies(a, _), PathSegment::Antecedent) => a,
            (Node::Implies(_, b), PathSegment::Consequent) => b,
            (
                Node::Equal(..) | Node::Member(..),
                PathSegment::LeftVariable | PathSegment::RightVariable,
            ) if index + 1 == query.path.len() => view,
            _ => return Err(InspectionError::InvalidPath),
        };
    }
    let mut fragment = tree_fragment(view, query.maximum_nodes, scope);
    fragment.anchor_root = query.root;
    fragment.start = query.start;
    if query.start.is_some() {
        fragment.scope_depth = None;
    }
    fragment.path = query.path.clone();
    Ok(fragment)
}

/// Inspects an explicitly supplied bounded formula while preserving exact
/// variable identities and binder scope. The query must name its actual root.
pub fn inspect_formula_value(
    formula: &naome_foundation::Formula,
    query: &FormulaQuery,
) -> Result<FormulaFragment, InspectionError> {
    query.validate()?;
    formula
        .encode_canonical()
        .map_err(|error| InspectionError::FormulaOutsideLimits {
            reason: super::FormulaFailure::from(&error),
        })?;
    if tree_fragment(formula.view(), 1, 0).root != query.root {
        return Err(InspectionError::UnknownFormula);
    }
    let mut fragment = tree_query(formula.view(), query)?;
    fragment.variable_namespace = VariableNamespace::Supplied;
    Ok(fragment)
}

pub(crate) type GraphRecord<H> = (Node<H>, Digest, Properties);
pub(crate) trait GraphRead {
    type Handle: Copy + Eq;
    type Error;
    fn read(&self, handle: Self::Handle) -> Result<GraphRecord<Self::Handle>, Self::Error>;
}

pub(crate) fn graph_fragment<R: GraphRead>(
    reader: &R,
    root: R::Handle,
    maximum: usize,
    scope_depth: u64,
) -> Result<FormulaFragment, R::Error> {
    let (_, root_hash, root_properties) = reader.read(root)?;
    let mut pending = VecDeque::from([root]);
    let mut nodes = Vec::new();
    let mut seen = BTreeSet::new();
    let mut variables = BTreeSet::new();
    let mut variable_overflow = false;
    // Every retained node has at most two child reads; no whole-DAG traversal.
    while nodes.len() < maximum.max(1) {
        let Some(handle) = pending.pop_front() else {
            break;
        };
        let (node, hash, properties) = reader.read(handle)?;
        if !seen.insert(hash) {
            continue;
        }
        if let Node::Equal(a, b) | Node::Member(a, b) = node {
            for variable in [a, b] {
                if let GraphVariable::Free(v) = variable {
                    if variables.len() < 32 || variables.contains(&v) {
                        variables.insert(v);
                    } else {
                        variable_overflow = true;
                    }
                }
            }
        }
        let mut child_hashes = [None, None];
        for (index, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let (_, hash, _) = reader.read(child)?;
                child_hashes[index] = Some(hash);
                if !seen.contains(&hash) {
                    pending.push_back(child);
                }
            }
        }
        let mut child = 0;
        let addressed = node.map(|_| {
            let hash = child_hashes[child].expect("child hash");
            child += 1;
            hash
        });
        nodes.push(NodeRecord::new(addressed, hash, properties));
    }
    let complete = nodes
        .iter()
        .flat_map(|node| node.node.children())
        .flatten()
        .all(|child| seen.contains(&child));
    Ok(FormulaFragment {
        anchor_root: root_hash,
        start: None,
        root: root_hash,
        variable_namespace: VariableNamespace::Input,
        scope_depth: Some(scope_depth),
        path: Vec::new(),
        nodes,
        complete,
        free_variables: variables.into_iter().collect(),
        free_variables_complete: !root_properties.has_free_variables
            || complete && !variable_overflow,
    })
}

pub(crate) fn graph_query<R: GraphRead>(
    reader: &R,
    mut root: R::Handle,
    query: &FormulaQuery,
) -> Result<Result<FormulaFragment, InspectionError>, R::Error> {
    if let Err(error) = query.validate() {
        return Ok(Err(error));
    }
    let mut scope = 0;
    for (index, edge) in query.path.iter().enumerate() {
        let node = reader.read(root)?.0;
        root = match (node, edge) {
            (Node::Not(body), PathSegment::Negated) => body,
            (Node::ForAll(body), PathSegment::Quantified) => {
                scope += 1;
                body
            }
            (Node::Implies(a, _), PathSegment::Antecedent) => a,
            (Node::Implies(_, b), PathSegment::Consequent) => b,
            (
                Node::Equal(..) | Node::Member(..),
                PathSegment::LeftVariable | PathSegment::RightVariable,
            ) if index + 1 == query.path.len() => root,
            _ => return Ok(Err(InspectionError::InvalidPath)),
        };
    }
    let mut fragment = graph_fragment(reader, root, query.maximum_nodes, scope)?;
    fragment.anchor_root = query.root;
    fragment.start = query.start;
    if query.start.is_some() {
        fragment.scope_depth = None;
    }
    fragment.path = query.path.clone();
    Ok(Ok(fragment))
}

pub(crate) fn graph_difference<R: GraphRead>(
    reader: &R,
    mut expected: R::Handle,
    mut actual: R::Handle,
) -> Result<Difference, R::Error> {
    let mut path = Vec::new();
    loop {
        let (en, eh, ep) = reader.read(expected)?;
        let (an, ah, ap) = reader.read(actual)?;
        let record = |node: Node<R::Handle>, hash, p| -> Result<NodeRecord, R::Error> {
            let mut children = Vec::new();
            for child in node.children().into_iter().flatten() {
                children.push(reader.read(child)?.1);
            }
            let mut children = children.into_iter();
            Ok(NodeRecord::new(
                node.map(|_| children.next().expect("child hash")),
                hash,
                p,
            ))
        };
        let finish = |path, complete| -> Result<Difference, R::Error> {
            Ok(Difference {
                path,
                expected: record(en, eh, ep)?,
                actual: record(an, ah, ap)?,
                complete,
            })
        };
        if path.len() >= MAX_INSPECTION_PATH {
            return finish(path, false);
        }
        let next = match (en, an) {
            (Node::Equal(a, b), Node::Equal(c, d)) | (Node::Member(a, b), Node::Member(c, d)) => {
                path.push(if a != c {
                    PathSegment::LeftVariable
                } else {
                    debug_assert_ne!(b, d);
                    PathSegment::RightVariable
                });
                return finish(path, true);
            }
            (Node::Not(a), Node::Not(b)) => (a, b, PathSegment::Negated),
            (Node::ForAll(a), Node::ForAll(b)) => (a, b, PathSegment::Quantified),
            (Node::Implies(a, b), Node::Implies(c, d)) => {
                if reader.read(a)?.1 != reader.read(c)?.1 {
                    (a, c, PathSegment::Antecedent)
                } else {
                    (b, d, PathSegment::Consequent)
                }
            }
            _ => return finish(path, true),
        };
        expected = next.0;
        actual = next.1;
        path.push(next.2);
    }
}
