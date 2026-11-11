//! Replay-derived tree costs and bounded projection of an immutable formula DAG.
use super::*;
use naome_foundation::{FORMULA_MAX_BYTES, FORMULA_MAX_DEPTH, FORMULA_MAX_NODES};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Shape {
    pub nodes: u64,
    pub bytes: u64,
    pub depth: u64,
}
impl Shape {
    pub fn of(node: Node<u64>, children: [Option<Self>; 2]) -> Self {
        let mut shape = Self {
            nodes: 1,
            bytes: if matches!(node, Node::Equal(..) | Node::Member(..)) {
                11
            } else {
                1
            },
            depth: 1,
        };
        for child in children.into_iter().flatten() {
            shape.nodes = (shape.nodes + child.nodes).min(FORMULA_MAX_NODES as u64 + 1);
            shape.bytes = (shape.bytes + child.bytes).min(FORMULA_MAX_BYTES as u64 + 1);
            shape.depth = shape
                .depth
                .max((child.depth + 1).min(u64::from(FORMULA_MAX_DEPTH) + 1));
        }
        shape
    }
    pub fn fits(self) -> bool {
        self.nodes <= FORMULA_MAX_NODES as u64
            && self.bytes <= FORMULA_MAX_BYTES as u64
            && self.depth <= u64::from(FORMULA_MAX_DEPTH)
    }
}

pub(super) struct Tree {
    pending: Vec<u64>,
    bytes: Vec<u8>,
    cache: NodeCache<Node<u64>>,
}

pub(super) struct NodeCache<T> {
    nodes: BTreeMap<u64, T>,
    order: VecDeque<u64>,
    limit: usize,
}

impl<T: Copy> NodeCache<T> {
    // Conservative map-node, allocation and FIFO metadata charge per entry.
    fn entry_bytes() -> usize {
        std::mem::size_of::<(u64, T)>() + 128
    }
    pub fn new(bytes: u64) -> Self {
        Self {
            nodes: BTreeMap::new(),
            order: VecDeque::new(),
            limit: usize::try_from(bytes).unwrap_or(usize::MAX) / Self::entry_bytes(),
        }
    }
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.order.clear();
    }
    pub fn load(
        &mut self,
        id: u64,
        load: impl FnOnce(u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if let Some(node) = self.nodes.get(&id) {
            return Ok(*node);
        }
        let node = load(id)?;
        if self.limit > 0 {
            if self.nodes.len() >= self.limit
                && let Some(oldest) = self.order.pop_front()
            {
                self.nodes.remove(&oldest);
            }
            self.nodes.insert(id, node);
            self.order.push_back(id);
        }
        Ok(node)
    }
}

impl Tree {
    pub fn cache_bytes(budget: u64) -> u64 {
        budget / 4
    }
    pub fn new(root: u64, budget: u64) -> Self {
        Self {
            pending: vec![root],
            bytes: Vec::new(),
            cache: NodeCache::new(Self::cache_bytes(budget)),
        }
    }
    pub fn restrict_cache(&mut self, budget: u64) {
        self.cache = NodeCache::new(Self::cache_bytes(budget));
    }
    pub fn advance(
        &mut self,
        steps: usize,
        mut load: impl FnMut(u64) -> Result<Node<u64>, Error>,
    ) -> Result<bool, Error> {
        // Reauthenticate on every owner boundary; cached nodes never restore
        // trust across quanta, replay, or an observed external write.
        self.cache.clear();
        for _ in 0..steps {
            let Some(&id) = self.pending.last() else {
                return Ok(true);
            };
            // A failed cold read preserves this exact node for a later retry.
            let node = self.cache.load(id, &mut load)?;
            self.pending.pop();
            self.bytes.push(match node {
                Node::Equal(..) => 0,
                Node::Member(..) => 1,
                Node::Not(_) => 2,
                Node::Implies(..) => 3,
                Node::ForAll(_) => 4,
            });
            if let Node::Equal(a, b) | Node::Member(a, b) = node {
                for variable in [a, b] {
                    let (tag, value) = match variable {
                        Variable::Free(v) => (0, v),
                        Variable::Bound(v) => (
                            1,
                            u32::try_from(v).map_err(|_| ProgramFault::TreeVariableWidth)?,
                        ),
                    };
                    self.bytes.push(tag);
                    self.bytes.extend_from_slice(&value.to_be_bytes());
                }
            }
            self.pending
                .extend(node.children().into_iter().rev().flatten());
        }
        Ok(self.pending.is_empty())
    }
    pub fn finish(&self) -> Result<Formula, Error> {
        if !self.pending.is_empty() {
            return Err(ProgramFault::IncompleteProjection.into());
        }
        Formula::decode_canonical(&self.bytes).map_err(Error::from)
    }
}

pub(super) struct Finalization {
    pub reachable: u64,
    pub walk_complete: bool,
    pub tree: Option<Tree>,
    pub canonical: Option<Option<Formula>>,
}

impl Engine {
    pub(super) fn prepare_conclusion(&mut self, steps: usize) -> Result<bool, Error> {
        if steps == 0 {
            return Ok(false);
        }
        if self.finalization.is_none() {
            let root = self.accepted.ok_or(ProgramFault::UncheckedConclusion)?;
            self.load(root)?;
            let shape = self
                .authenticated(root)?
                .ok_or(ProgramFault::UnauthenticatedConclusion)?
                .2;
            sql(self.connection.execute(
                "INSERT OR IGNORE INTO export_pending VALUES(?1)",
                [number(root)?],
            ))?;
            self.finalization = Some(Finalization {
                reachable: 0,
                walk_complete: false,
                tree: shape
                    .fits()
                    .then(|| Tree::new(root, self.cache_budget.unwrap_or(0))),
                canonical: None,
            });
        }
        if !self
            .finalization
            .as_ref()
            .expect("finalization")
            .walk_complete
        {
            // Only disposable SQL state changes during this quantum. An aborted
            // write restores the frontier and leaves the volatile count intact.
            sql(self.connection.execute_batch("BEGIN IMMEDIATE"))?;
            let result = (|| {
                let mut added = 0;
                let mut complete = false;
                for _ in 0..steps {
                    let id: Option<u64> = sql(self
                        .query_cached(
                            "SELECT id FROM export_pending ORDER BY id DESC LIMIT 1",
                            [],
                            |row| unsigned(row, 0),
                        )
                        .optional())?;
                    let Some(id) = id else {
                        complete = true;
                        break;
                    };
                    let node = self.load(id)?.0;
                    added += self.execute_cached(
                        "INSERT OR IGNORE INTO export_node VALUES(?1)",
                        [number(id)?],
                    )? as u64;
                    self.execute_cached("DELETE FROM export_pending WHERE id=?1", [number(id)?])?;
                    for child in node.children().into_iter().flatten() {
                        self.execute_cached("INSERT OR IGNORE INTO export_pending SELECT ?1 WHERE NOT EXISTS(SELECT 1 FROM export_node WHERE id=?1)", [number(child)?])?;
                    }
                }
                sql(self.connection.execute_batch("COMMIT"))?;
                Ok::<_, Error>((added, complete))
            })();
            match result {
                Ok((added, complete)) => {
                    let state = self.finalization.as_mut().expect("finalization");
                    state.reachable += added;
                    state.walk_complete = complete;
                }
                Err(error) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(error);
                }
            }
            return Ok(false);
        }
        if self
            .finalization
            .as_ref()
            .expect("finalization")
            .canonical
            .is_some()
        {
            return Ok(true);
        }
        let tree = self
            .finalization
            .as_mut()
            .expect("finalization")
            .tree
            .take();
        let canonical = if let Some(mut tree) = tree {
            let result = tree.advance(steps, |id| self.load(id).map(|value| value.0));
            match result {
                Ok(true) => {
                    let result = tree.finish();
                    if result.is_err() {
                        self.finalization.as_mut().expect("finalization").tree = Some(tree);
                    }
                    Some(result?)
                }
                result => {
                    self.finalization.as_mut().expect("finalization").tree = Some(tree);
                    result?;
                    return Ok(false);
                }
            }
        } else {
            None
        };
        self.finalization.as_mut().expect("finalization").canonical = Some(canonical);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
