//! Bounded, immutable scheduling descriptors; never mathematical evidence.
use super::*;
use crate::structure::Features;
use naome_foundation::graph::{Node, Variable};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

pub(super) const BINDINGS: usize = 8;
const VISITS: usize = 128;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Descriptor {
    pub features: Features,
    pub bindings: [f32; BINDINGS],
}
impl Descriptor {
    pub fn validate(&self) -> Result<(), String> {
        if self.features.nodes == 0
            || self.features.depth == 0
            || self.features.depth > self.features.nodes
            || self
                .bindings
                .iter()
                .any(|v| !v.is_finite() || !(0.0..=2.0).contains(v))
        {
            return Err("finder descriptor bounds differ".into());
        }
        Ok(())
    }
    pub fn of(question: &CompiledQuestion) -> Self {
        Self {
            features: Features::of(question),
            bindings: bindings(question),
        }
    }
}

/// Names never enter this sketch. Each lexical binder has a separate identity,
/// including shadowed binders and independent quantifiers in sibling branches.
fn bindings(question: &CompiledQuestion) -> [f32; BINDINGS] {
    #[derive(Default)]
    struct Sketch {
        scopes: Vec<u64>,
        next: u64,
        variables: BTreeMap<(u8, u64), [u64; 3]>,
        edges: BTreeSet<((u8, u64), (u8, u64))>,
        left: usize,
    }
    impl Sketch {
        fn variable(&self, v: Variable) -> (u8, u64) {
            match v {
                Variable::Free(id) => (0, u64::from(id)),
                Variable::Bound(index) => (1, self.scopes[self.scopes.len() - 1 - index as usize]),
            }
        }
        fn visit(&mut self, formula: naome_foundation::FormulaView<'_>) {
            if self.left == 0 {
                return;
            }
            self.left -= 1;
            match formula.graph_node() {
                Node::Equal(a, b) | Node::Member(a, b) => {
                    let a = self.variable(a);
                    let b = self.variable(b);
                    if matches!(formula.graph_node(), Node::Member(..)) {
                        self.variables.entry(a).or_default()[0] += 1;
                        self.variables.entry(b).or_default()[1] += 1;
                        self.edges.insert((a, b));
                    } else {
                        self.variables.entry(a).or_default()[2] += 1;
                        self.variables.entry(b).or_default()[2] += 1;
                    }
                }
                Node::Not(a) => self.visit(a),
                Node::Implies(a, b) => {
                    self.visit(a);
                    self.visit(b);
                }
                Node::ForAll(a) => {
                    self.next += 1;
                    self.scopes.push(self.next);
                    self.visit(a);
                    self.scopes.pop();
                }
            }
        }
    }
    let mut sketch = Sketch {
        left: VISITS,
        ..Default::default()
    };
    sketch.visit(question.core().view());
    let mut values = [0u64; BINDINGS];
    values[0] = sketch.variables.len() as u64;
    for (key, [left, right, equal]) in &sketch.variables {
        values[1] += left * left.saturating_sub(1) / 2;
        values[2] += right * right.saturating_sub(1) / 2;
        values[3] += left * right;
        values[4] += equal * (left + right);
        values[5] += equal * equal.saturating_sub(1) / 2;
        if key.0 == 1 {
            values[7] += 1;
        }
    }
    values[6] = sketch
        .edges
        .iter()
        .filter(|(a, b)| a != b && sketch.edges.contains(&(*b, *a)))
        .count() as u64;
    values[7] = sketch.next.saturating_sub(values[7]);
    values.map(|v| (v as f32).ln_1p() / 8.)
}

pub(in crate::frontier) struct Analysis {
    question: CompiledQuestion,
    pub descriptor: Descriptor,
    interest: OnceLock<([u8; 32], bool)>,
    fragments: OnceLock<BTreeSet<[u8; 32]>>,
    bytes: usize,
    _memory: Arc<crate::resources::MemoryLease>,
}
impl Analysis {
    pub fn meaningful(&self) -> bool {
        self.interest
            .get_or_init(|| super::semantics::screen(&self.question))
            .1
    }
    pub fn relevance(&self, other: &Self) -> u64 {
        let a = self
            .fragments
            .get_or_init(|| super::semantics::fragments(&self.question));
        let b = other
            .fragments
            .get_or_init(|| super::semantics::fragments(&other.question));
        a.intersection(b).count() as u64
    }
}

#[derive(Default)]
pub(in crate::frontier) struct Cache {
    entries: VecDeque<Arc<Analysis>>,
    bytes: usize,
}
impl Cache {
    pub fn trim(&mut self) {
        let budget = crate::resources::adaptive::cache(
            crate::resources::active_limits().question_cache_bytes / 2,
        );
        while self.bytes > budget {
            self.bytes -= self.entries.pop_front().expect("charged analysis").bytes;
        }
    }
    pub fn descriptor(&self, question: &CompiledQuestion) -> Option<&Descriptor> {
        self.entries
            .iter()
            .find(|a| a.question.source_hash() == question.source_hash() && a.question == *question)
            .map(|a| &a.descriptor)
    }
    pub fn get(&mut self, question: &CompiledQuestion) -> Result<Arc<Analysis>, crate::Error> {
        self.trim();
        let budget = crate::resources::adaptive::cache(
            crate::resources::active_limits().question_cache_bytes / 2,
        );
        if let Some(index) = self.entries.iter().position(|a| {
            a.question.source_hash() == question.source_hash() && a.question == *question
        }) {
            let entry = self.entries.remove(index).expect("located analysis");
            self.entries.push_back(entry.clone());
            return Ok(entry);
        }
        // Includes the compiled source, at most 32 fragment keys, lazy-set
        // allocation overhead and the bounded transient binding sketch.
        let bytes =
            question.source().len().saturating_mul(8) + 4096 + std::mem::size_of::<Analysis>();
        while !self.entries.is_empty()
            && (self.bytes.saturating_add(bytes) > budget || self.entries.len() >= 128)
        {
            self.bytes -= self.entries.pop_front().expect("charged analysis").bytes;
        }
        let memory = crate::resources::MemoryLease::acquire(bytes)?;
        let entry = Arc::new(Analysis {
            question: question.clone(),
            descriptor: Descriptor::of(question),
            interest: OnceLock::new(),
            fragments: OnceLock::new(),
            bytes,
            _memory: memory,
        });
        if bytes <= budget {
            self.bytes += bytes;
            self.entries.push_back(entry.clone());
        }
        Ok(entry)
    }
}
