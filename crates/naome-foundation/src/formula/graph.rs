//! Constant-size nodes for formulas whose trees do not fit in memory.
//!
//! Storage and scheduling belong to consumers. Foundation owns variable
//! binding, structural properties and representation-independent recipes.
use super::{Formula, FormulaView, Node as Tree, Variable as TreeVariable};
use std::{collections::HashMap, hash::Hash, sync::Arc};

/// Failure to materialize a formula graph, including errors from its reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterializationError<E> {
    /// The graph exceeds the maximum nesting depth.
    DepthLimit { maximum: u32 },
    /// The expanded graph exceeds the maximum number of nodes.
    NodeLimit { maximum: usize },
    /// A bound variable has no corresponding enclosing binder.
    DanglingBinder { index: u64, binder_depth: u32 },
    /// The graph reader rejected a node.
    Read(E),
}

impl<E: std::fmt::Display> std::fmt::Display for MaterializationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DepthLimit { maximum } => {
                write!(f, "formula graph exceeds depth limit {maximum}")
            }
            Self::NodeLimit { maximum } => write!(f, "formula graph exceeds node limit {maximum}"),
            Self::DanglingBinder {
                index,
                binder_depth,
            } => write!(
                f,
                "formula graph bound variable {index} is invalid at depth {binder_depth}"
            ),
            Self::Read(error) => write!(f, "formula graph read failed: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for MaterializationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variable {
    Free(u32),
    Bound(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Node<I> {
    Equal(Variable, Variable),
    Member(Variable, Variable),
    Not(I),
    Implies(I, I),
    ForAll(I),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Properties {
    pub has_free_variables: bool,
    /// Number of enclosing binders needed to make all bound indices valid.
    pub required_binders: u64,
}
impl Properties {
    pub const fn closed(self) -> bool {
        !self.has_free_variables && self.required_binders == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transform {
    Bind(u32),
    Substitute {
        from: u32,
        to: u32,
    },
    /// Remove the binder immediately outside this graph and replace its
    /// occurrences with a free variable. Inner binders keep their indices.
    Open(u32),
}
impl Transform {
    pub const fn affects(self, properties: Properties, depth: u64) -> bool {
        match self {
            Self::Bind(_) | Self::Substitute { .. } => properties.has_free_variables,
            Self::Open(_) => properties.required_binders > depth,
        }
    }

    pub fn variable(self, variable: Variable, depth: u64) -> Variable {
        match (self, variable) {
            (Self::Bind(target), Variable::Free(v)) if v == target => Variable::Bound(depth),
            (Self::Substitute { from, to }, Variable::Free(v)) if v == from => Variable::Free(to),
            (Self::Open(replacement), Variable::Bound(index)) if index == depth => {
                Variable::Free(replacement)
            }
            (Self::Open(_), Variable::Bound(index)) if index > depth => Variable::Bound(index - 1),
            _ => variable,
        }
    }
}
impl<I: Copy> Node<I> {
    pub fn map<J>(self, mut map: impl FnMut(I) -> J) -> Node<J> {
        match self {
            Self::Equal(a, b) => Node::Equal(a, b),
            Self::Member(a, b) => Node::Member(a, b),
            Self::Not(a) => Node::Not(map(a)),
            Self::Implies(a, b) => Node::Implies(map(a), map(b)),
            Self::ForAll(a) => Node::ForAll(map(a)),
        }
    }
    pub fn children(self) -> [Option<I>; 2] {
        match self {
            Self::Not(a) | Self::ForAll(a) => [Some(a), None],
            Self::Implies(a, b) => [Some(a), Some(b)],
            _ => [None, None],
        }
    }
    pub fn nested_depth(self, depth: u64) -> Option<u64> {
        if matches!(self, Self::ForAll(_)) {
            depth.checked_add(1)
        } else {
            Some(depth)
        }
    }
    pub fn transformed(self, transform: Transform, depth: u64, children: [Option<I>; 2]) -> Self {
        match self {
            Self::Equal(a, b) => {
                Self::Equal(transform.variable(a, depth), transform.variable(b, depth))
            }
            Self::Member(a, b) => {
                Self::Member(transform.variable(a, depth), transform.variable(b, depth))
            }
            Self::Not(_) => Self::Not(children[0].expect("transformed unary child")),
            Self::ForAll(_) => Self::ForAll(children[0].expect("transformed binder child")),
            Self::Implies(..) => Self::Implies(
                children[0].expect("transformed left child"),
                children[1].expect("transformed right child"),
            ),
        }
    }
    pub fn properties(self, children: [Option<Properties>; 2]) -> Option<Properties> {
        let variable = |v| match v {
            Variable::Free(_) => Some(Properties {
                has_free_variables: true,
                required_binders: 0,
            }),
            Variable::Bound(index) => index.checked_add(1).map(|required_binders| Properties {
                has_free_variables: false,
                required_binders,
            }),
        };
        let combine = |a: Properties, b: Properties| Properties {
            has_free_variables: a.has_free_variables || b.has_free_variables,
            required_binders: a.required_binders.max(b.required_binders),
        };
        match self {
            Self::Equal(a, b) | Self::Member(a, b) => Some(combine(variable(a)?, variable(b)?)),
            Self::Not(_) => children[0],
            Self::Implies(..) => Some(combine(children[0]?, children[1]?)),
            Self::ForAll(_) => children[0].map(|p| Properties {
                required_binders: p.required_binders.saturating_sub(1),
                ..p
            }),
        }
    }
}

impl Formula {
    /// Materializes a bounded primitive graph with its exact relative binders.
    /// The reader owns the graph and checks its reference identities.
    pub fn from_graph<I: Copy + Eq + Hash, E>(
        root: I,
        mut read: impl FnMut(I) -> Result<Node<I>, E>,
    ) -> Result<Self, MaterializationError<E>> {
        struct Materializer<I, R> {
            read: R,
            shared: HashMap<(I, u32, u32), (Arc<Tree>, usize)>,
            remaining: usize,
        }
        impl<I: Copy + Eq + Hash, E, R: FnMut(I) -> Result<Node<I>, E>> Materializer<I, R> {
            fn visit(
                &mut self,
                handle: I,
                depth: u32,
                binders: u32,
            ) -> Result<Arc<Tree>, MaterializationError<E>> {
                let capacity = || MaterializationError::NodeLimit {
                    maximum: super::canonical::FORMULA_MAX_NODES,
                };
                if depth >= super::canonical::FORMULA_MAX_DEPTH {
                    return Err(MaterializationError::DepthLimit {
                        maximum: super::canonical::FORMULA_MAX_DEPTH,
                    });
                }
                let key = (handle, depth, binders);
                if let Some((tree, nodes)) = self.shared.get(&key) {
                    self.remaining = self.remaining.checked_sub(*nodes).ok_or_else(capacity)?;
                    return Ok(Arc::clone(tree));
                }
                let before = self.remaining;
                self.remaining = before.checked_sub(1).ok_or_else(capacity)?;
                let variable = |variable| match variable {
                    Variable::Free(id) => Ok(TreeVariable::Free(super::FreeVariable::new(id))),
                    Variable::Bound(index) if index < u64::from(binders) => {
                        Ok(TreeVariable::Bound(index as u32))
                    }
                    Variable::Bound(index) => Err(MaterializationError::DanglingBinder {
                        index,
                        binder_depth: binders,
                    }),
                };
                let node = (self.read)(handle).map_err(MaterializationError::Read)?;
                let tree = Arc::new(match node {
                    Node::Equal(left, right) => Tree::Equal(variable(left)?, variable(right)?),
                    Node::Member(left, right) => Tree::Member(variable(left)?, variable(right)?),
                    Node::Not(body) => Tree::Not(self.visit(body, depth + 1, binders)?),
                    Node::Implies(left, right) => Tree::Implies(
                        self.visit(left, depth + 1, binders)?,
                        self.visit(right, depth + 1, binders)?,
                    ),
                    Node::ForAll(body) => Tree::ForAll(self.visit(body, depth + 1, binders + 1)?),
                });
                self.shared
                    .insert(key, (Arc::clone(&tree), before - self.remaining));
                Ok(tree)
            }
        }
        let mut materializer = Materializer {
            read: &mut read,
            shared: HashMap::new(),
            remaining: super::canonical::FORMULA_MAX_NODES,
        };
        materializer
            .visit(root, 0, 0)
            .map(|tree| Self(Arc::unwrap_or_clone(tree)))
    }

    /// Consumes a bounded tree as a sequence of postorder graph operations.
    pub fn into_graph_cursor<I: Copy>(self) -> FormulaGraphCursor<I> {
        FormulaGraphCursor {
            pending: vec![Pending::Tree(self.0)],
            results: Vec::new(),
        }
    }

    /// Projects a bounded tree through the same primitive node vocabulary used
    /// by disk processing. The callback may intern each node on disk.
    pub fn fold_graph<I: Copy, E>(
        &self,
        mut emit: impl FnMut(Node<I>) -> Result<I, E>,
    ) -> Result<I, E> {
        fn walk<I: Copy, E>(
            tree: &Tree,
            emit: &mut impl FnMut(Node<I>) -> Result<I, E>,
        ) -> Result<I, E> {
            let variable = |v| match v {
                TreeVariable::Free(v) => Variable::Free(v.identifier()),
                TreeVariable::Bound(v) => Variable::Bound(u64::from(v)),
            };
            let node = match tree {
                Tree::Equal(a, b) => Node::Equal(variable(*a), variable(*b)),
                Tree::Member(a, b) => Node::Member(variable(*a), variable(*b)),
                Tree::Not(a) => Node::Not(walk(a, emit)?),
                Tree::Implies(a, b) => Node::Implies(walk(a, emit)?, walk(b, emit)?),
                Tree::ForAll(a) => Node::ForAll(walk(a, emit)?),
            };
            emit(node)
        }
        walk(&self.0, &mut emit)
    }
}

enum Pending {
    Tree(Tree),
    Parent(Node<()>),
}

/// An owned, resumable traversal that retains only the unfinished tree and
/// the path to the current node. Each step visits or emits a single node.
pub struct FormulaGraphCursor<I> {
    pending: Vec<Pending>,
    results: Vec<I>,
}

impl<I: Copy> FormulaGraphCursor<I> {
    pub fn advance<E>(
        &mut self,
        emit: impl FnOnce(Node<I>) -> Result<I, E>,
    ) -> Result<Option<I>, E> {
        let variable = |v| match v {
            TreeVariable::Free(v) => Variable::Free(v.identifier()),
            TreeVariable::Bound(v) => Variable::Bound(u64::from(v)),
        };
        let node = match self.pending.pop() {
            None => return Ok(self.results.last().copied()),
            Some(Pending::Tree(Tree::Equal(a, b))) => Node::Equal(variable(a), variable(b)),
            Some(Pending::Tree(Tree::Member(a, b))) => Node::Member(variable(a), variable(b)),
            Some(Pending::Tree(Tree::Not(body))) => {
                self.pending.push(Pending::Parent(Node::Not(())));
                self.pending.push(Pending::Tree(Arc::unwrap_or_clone(body)));
                return Ok(None);
            }
            Some(Pending::Tree(Tree::ForAll(body))) => {
                self.pending.push(Pending::Parent(Node::ForAll(())));
                self.pending.push(Pending::Tree(Arc::unwrap_or_clone(body)));
                return Ok(None);
            }
            Some(Pending::Tree(Tree::Implies(left, right))) => {
                self.pending.push(Pending::Parent(Node::Implies((), ())));
                self.pending
                    .push(Pending::Tree(Arc::unwrap_or_clone(right)));
                self.pending.push(Pending::Tree(Arc::unwrap_or_clone(left)));
                return Ok(None);
            }
            Some(Pending::Parent(parent)) => {
                let base = self.results.len() - parent.children().into_iter().flatten().count();
                let mut children = self.results.drain(base..);
                parent.map(|()| children.next().expect("postorder child"))
            }
        };
        let id = emit(node)?;
        self.results.push(id);
        Ok(self.pending.is_empty().then_some(id))
    }
}

impl<'a> FormulaView<'a> {
    /// Borrows one primitive node without copying its children. Bound indices
    /// retain their enclosing scope; an inner view is not a standalone formula.
    pub fn graph_node(self) -> Node<Self> {
        let variable = |v| match v {
            TreeVariable::Free(v) => Variable::Free(v.identifier()),
            TreeVariable::Bound(v) => Variable::Bound(u64::from(v)),
        };
        match self.0 {
            Tree::Equal(a, b) => Node::Equal(variable(*a), variable(*b)),
            Tree::Member(a, b) => Node::Member(variable(*a), variable(*b)),
            Tree::Not(a) => Node::Not(Self(a)),
            Tree::Implies(a, b) => Node::Implies(Self(a), Self(b)),
            Tree::ForAll(a) => Node::ForAll(Self(a)),
        }
    }
}

#[cfg(test)]
mod materialization_tests {
    use super::*;

    #[test]
    fn preserves_reader_failure_and_invalid_binder() {
        let read = Formula::from_graph(0u32, |_| Err::<Node<u32>, _>(17u8));
        assert_eq!(read.unwrap_err(), MaterializationError::Read(17));
        let dangling = Formula::from_graph(0u32, |_| {
            Ok::<_, std::convert::Infallible>(Node::Equal(
                Variable::Bound(u64::MAX),
                Variable::Free(0),
            ))
        });
        assert_eq!(
            dangling.unwrap_err(),
            MaterializationError::DanglingBinder {
                index: u64::MAX,
                binder_depth: 0
            }
        );
    }

    #[test]
    fn distinguishes_depth_and_expanded_node_limits() {
        let depth = Formula::from_graph(0u32, |i| {
            Ok::<_, std::convert::Infallible>(Node::Not(i + 1))
        });
        assert_eq!(
            depth.unwrap_err(),
            MaterializationError::DepthLimit {
                maximum: super::super::canonical::FORMULA_MAX_DEPTH
            }
        );
        let nodes = Formula::from_graph(0u32, |i| {
            Ok::<_, std::convert::Infallible>(if i < 30 {
                Node::Implies(i + 1, i + 1)
            } else {
                Node::Equal(Variable::Free(0), Variable::Free(0))
            })
        });
        assert_eq!(
            nodes.unwrap_err(),
            MaterializationError::NodeLimit {
                maximum: super::super::canonical::FORMULA_MAX_NODES
            }
        );
    }
}
