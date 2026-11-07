//! Immutable compiler DAG metadata. Fingerprints accelerate lookup only;
//! exact structural equality and the native checker remain authoritative.
use super::{Formula, FreeVariable, Kernel, ProofId};
use naome_foundation::Logic;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{Arc, OnceLock},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Lemma(
        Vec<Vec<u8>>,
        Vec<u8>,
        Formula,
        ProofId,
        Vec<super::super::definitions::Entry>,
    ),
    Variable(usize, Formula),
    Kernel(Kernel),
    Generalize(FreeVariable, Arc<Combinator>),
    K(Formula, Formula),
    S(Formula, Formula, Formula),
    Apply(Arc<Combinator>, Arc<Combinator>, Formula),
}

#[derive(Clone, Debug)]
pub(super) struct Combinator {
    kind: Kind,
    fingerprint: OnceLock<u64>,
    assumptions: u64,
}
impl Combinator {
    pub(super) fn kind(&self) -> &Kind {
        &self.kind
    }
    pub(super) fn new(kind: Kind) -> Arc<Self> {
        let assumptions = match &kind {
            Kind::Variable(id, _) => 1u64 << (id % 64),
            Kind::Generalize(_, body) => body.assumptions,
            Kind::Apply(a, b, _) => a.assumptions | b.assumptions,
            _ => 0,
        };
        Arc::new(Self {
            kind,
            fingerprint: OnceLock::new(),
            assumptions,
        })
    }
    fn fingerprint(&self) -> u64 {
        *self.fingerprint.get_or_init(|| {
            let mut hasher = DefaultHasher::new();
            self.kind.hash(&mut hasher);
            hasher.finish()
        })
    }
}
impl Hash for Combinator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fingerprint().hash(state);
    }
}
impl PartialEq for Combinator {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint() == other.fingerprint() && self.kind == other.kind
    }
}
impl Eq for Combinator {}

impl Combinator {
    pub(super) fn formula(&self) -> Formula {
        match &self.kind {
            Kind::Lemma(_, _, formula, _, _) => formula.clone(),
            Kind::Variable(_, formula) | Kind::Apply(_, _, formula) => formula.clone(),
            Kind::Kernel(k) => k.formula(),
            Kind::Generalize(v, b) => Formula::for_all(*v, b.formula()),
            Kind::K(a, b) => Logic::simplification(a.clone(), b.clone()),
            Kind::S(a, b, c) => Logic::frege(a.clone(), b.clone(), c.clone()),
        }
    }

    pub(super) fn contains(&self, variable: usize) -> bool {
        // Modulo collisions only require an exact walk; they never certify
        // that an assumption is present.
        if self.assumptions & (1u64 << (variable % 64)) == 0 {
            return false;
        }
        match &self.kind {
            Kind::Variable(id, _) => *id == variable,
            Kind::Apply(a, b, _) => a.contains(variable) || b.contains(variable),
            Kind::Generalize(_, body) => body.contains(variable),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
