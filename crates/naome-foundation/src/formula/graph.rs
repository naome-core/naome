//! Constant-size nodes for formulas whose trees do not fit in memory.
//!
//! Storage and scheduling belong to consumers. Foundation owns variable
//! binding, structural properties and representation-independent recipes.
use super::{Formula, FormulaView, Node as Tree, Variable as TreeVariable};

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
    pub fn from_graph<I: Copy>(
        root: I,
        mut read: impl FnMut(I) -> Result<Node<I>, String>,
    ) -> Result<Self, String> {
        fn visit<I: Copy>(
            handle: I,
            read: &mut impl FnMut(I) -> Result<Node<I>, String>,
            depth: u32,
            binders: u32,
            remaining: &mut usize,
        ) -> Result<Tree, String> {
            if depth > super::canonical::FORMULA_MAX_DEPTH || *remaining == 0 {
                return Err("materialized formula graph capacity".into());
            }
            *remaining -= 1;
            let variable = |variable| match variable {
                Variable::Free(id) => Ok(TreeVariable::Free(super::FreeVariable::new(id))),
                Variable::Bound(index) if index < u64::from(binders) => {
                    Ok(TreeVariable::Bound(index as u32))
                }
                Variable::Bound(_) => Err("formula graph has a dangling binder".to_owned()),
            };
            let node = read(handle)?;
            let mut child =
                |handle, binders| visit(handle, read, depth + 1, binders, remaining).map(Box::new);
            Ok(match node {
                Node::Equal(left, right) => Tree::Equal(variable(left)?, variable(right)?),
                Node::Member(left, right) => Tree::Member(variable(left)?, variable(right)?),
                Node::Not(body) => Tree::Not(child(body, binders)?),
                Node::Implies(left, right) => {
                    Tree::Implies(child(left, binders)?, child(right, binders)?)
                }
                Node::ForAll(body) => Tree::ForAll(child(body, binders + 1)?),
            })
        }
        let mut remaining = super::canonical::FORMULA_MAX_NODES;
        visit(root, &mut read, 0, 0, &mut remaining).map(Self)
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
                self.pending.push(Pending::Tree(*body));
                return Ok(None);
            }
            Some(Pending::Tree(Tree::ForAll(body))) => {
                self.pending.push(Pending::Parent(Node::ForAll(())));
                self.pending.push(Pending::Tree(*body));
                return Ok(None);
            }
            Some(Pending::Tree(Tree::Implies(left, right))) => {
                self.pending.push(Pending::Parent(Node::Implies((), ())));
                self.pending.push(Pending::Tree(*right));
                self.pending.push(Pending::Tree(*left));
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
