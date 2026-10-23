//! Constant-size nodes for formulas whose trees do not fit in memory.
//!
//! Storage and scheduling belong to consumers. Foundation owns variable
//! binding, structural properties and representation-independent recipes.
use super::{Formula, Node as Tree, Variable as TreeVariable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variable {
    Free(u32),
    Bound(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    Substitute { from: u32, to: u32 },
}
impl Transform {
    pub fn variable(self, variable: Variable, depth: u64) -> Variable {
        match (self, variable) {
            (Self::Bind(target), Variable::Free(v)) if v == target => Variable::Bound(depth),
            (Self::Substitute { from, to }, Variable::Free(v)) if v == from => Variable::Free(to),
            _ => variable,
        }
    }
}
impl<I: Copy> Node<I> {
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
