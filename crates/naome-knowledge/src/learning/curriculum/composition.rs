//! Prospective composition questions. Inputs and structural siblings are split
//! without executing a solver or importing an answer certificate.
use super::Case;
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FreeVariable};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

pub struct Bank {
    #[cfg(test)]
    pub helpers: Vec<Case>,
    pub learning: Vec<Case>,
    pub development: Vec<Case>,
    #[cfg(test)]
    pub confirmation: Vec<Case>,
    pub reserved: BTreeSet<String>,
    pub reserved_families: BTreeSet<String>,
}
pub static BANK: LazyLock<Bank> = LazyLock::new(build);
fn atom(index: usize, variant: usize) -> Formula {
    let vars = [
        FreeVariable::new(30),
        FreeVariable::new(31),
        FreeVariable::new(32),
    ];
    let a = (index / 3 + variant) % 3;
    let b = (index % 3 + variant) % 3;
    Formula::member(vars[a], vars[b])
}
fn build() -> Bank {
    let mut choices = super::CORPUS
        .cases
        .iter()
        .filter(|q| !q.development && q.family.starts_with("logic-"))
        .collect::<Vec<_>>();
    choices.sort_by_key(|q| &q.id);
    let mut shapes = BTreeSet::new();
    let helpers = choices
        .into_iter()
        .filter(|q| {
            let q = CompiledQuestion::compile(&q.source).expect("sealed helper question");
            let (nodes, depth) = q.proved_target().view().node_count_and_depth();
            (10..=48).contains(&nodes)
                && depth <= 12
                && shapes.insert(super::owned::family(q.proved_target()))
        })
        .take(7)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(helpers.len(), 7);
    let mut grouped: BTreeMap<String, BTreeMap<String, Case>> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for (helper, h) in helpers.iter().enumerate() {
        let h = CompiledQuestion::compile(&h.source)
            .unwrap()
            .proved_target()
            .clone();
        for tail in 3..=7 {
            for dead in 4..=7 {
                for layout in 0..4 {
                    let mut variants = Vec::new();
                    for variant in 0..2 {
                        let mut premises = vec![Formula::implies(h.clone(), atom(0, variant))];
                        premises.extend(
                            (0..tail)
                                .map(|i| Formula::implies(atom(i, variant), atom(i + 1, variant))),
                        );
                        premises.extend((0..dead).map(|i| {
                            Formula::implies(
                                atom(5 + i % 3, variant),
                                atom(5 + (i + 1) % 3, variant),
                            )
                        }));
                        let count = premises.len();
                        premises.rotate_left((helper + layout) % count);
                        if layout % 2 == 1 {
                            premises.reverse();
                        }
                        let mut formula = atom(tail, variant);
                        for premise in premises.into_iter().rev() {
                            formula = Formula::implies(premise, formula);
                        }
                        for v in formula.free_variables().into_iter().rev() {
                            formula = Formula::for_all(v, formula);
                        }
                        let Ok(q) = CompiledQuestion::from_formula(formula) else {
                            continue;
                        };
                        let id = crate::hex(q.resolution_id());
                        if super::CORPUS.cases.iter().any(|q| q.id == id)
                            || super::CORPUS.reserved_ids.contains(&id)
                            || super::frontier::BANK.reserved.contains(&id)
                            || super::frontier::BANK.learning.iter().any(|q| q.id == id)
                            || !ids.insert(id.clone())
                        {
                            continue;
                        }
                        let structural = super::owned::family(q.proved_target());
                        if super::owned::sealed_family(&structural) {
                            continue;
                        }
                        variants.push((structural, id, q.source().to_owned()));
                    }
                    // Atom-renamed siblings have exactly the same conservative
                    // family. Grouping occurs before split or representative choice.
                    for (structural, id, source) in variants {
                        let dependency = format!("composition/{structural}");
                        grouped.entry(structural).or_default().insert(
                            id.clone(),
                            Case {
                                id,
                                source,
                                family: format!("composition-helper-{helper}"),
                                dependency,
                                development: false,
                            },
                        );
                    }
                }
            }
        }
    }
    let mut learning = Vec::new();
    let mut development = Vec::new();
    let mut confirmation = Vec::new();
    let mut reserved = BTreeSet::new();
    let mut reserved_families = BTreeSet::new();
    let mut dev_roots = 0;
    let mut confirmation_roots = 0;
    for (shape, group) in grouped {
        let hash = Sha256::digest(format!("naome:composition-partition:{shape}"));
        let bucket = u32::from_le_bytes(hash[..4].try_into().unwrap()) % 5;
        let mut rows = group.into_values().collect::<Vec<_>>();
        if bucket < 2 {
            reserved.extend(rows.iter().map(|q| q.id.clone()));
            reserved_families.insert(shape);
            if bucket == 0 && dev_roots < 16 {
                for q in rows.iter_mut().take(2) {
                    q.development = true;
                }
                development.extend(rows.into_iter().take(2));
                dev_roots += 1;
            } else if bucket == 1 && confirmation_roots < 32 {
                for q in rows.iter_mut().take(2) {
                    q.development = true;
                }
                confirmation.extend(rows.into_iter().take(2));
                confirmation_roots += 1;
            }
        } else {
            learning.extend(rows.into_iter().take(2));
        }
    }
    assert_eq!(development.len(), 32);
    assert_eq!(confirmation.len(), 64);
    Bank {
        #[cfg(test)]
        helpers,
        learning,
        development,
        #[cfg(test)]
        confirmation,
        reserved,
        reserved_families,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_composition_shapes_and_native_ids_never_cross_the_learning_boundary() {
        let bank = &*BANK;
        let train = bank
            .learning
            .iter()
            .map(|q| q.dependency.clone())
            .collect::<BTreeSet<_>>();
        let dev = bank
            .development
            .iter()
            .map(|q| q.dependency.clone())
            .collect::<BTreeSet<_>>();
        let test = bank
            .confirmation
            .iter()
            .map(|q| q.dependency.clone())
            .collect::<BTreeSet<_>>();
        assert!(train.is_disjoint(&dev) && train.is_disjoint(&test) && dev.is_disjoint(&test));
        assert_eq!(dev.len(), 16);
        assert_eq!(test.len(), 32);
        for q in bank
            .learning
            .iter()
            .chain(bank.development.iter())
            .chain(bank.confirmation.iter())
        {
            let compiled = CompiledQuestion::compile(&q.source).unwrap();
            assert_eq!(q.id, crate::hex(compiled.resolution_id()));
            assert_eq!(
                super::super::owned::case(&q.source).is_some(),
                !q.development
            );
            assert!(!bank.helpers.iter().any(|h| h.id == q.id));
        }
        eprintln!(
            "composition bank helpers={} train={} development={} confirmation={}",
            bank.helpers.len(),
            bank.learning.len(),
            bank.development.len(),
            bank.confirmation.len()
        );
    }
}
