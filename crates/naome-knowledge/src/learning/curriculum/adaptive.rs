//! Question-only combinations for the supported native operations. No proof,
//! continuation, success flag or solver is used to construct or partition them.
use super::Case;
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FreeVariable};
use std::{collections::BTreeSet, sync::LazyLock};

pub const DEVELOPMENT: usize = 24;
pub struct Bank {
    pub learning: Vec<Case>,
    pub development: Vec<Case>,
    pub transfer: Vec<Case>,
    #[cfg(test)]
    pub confirmation: Vec<Case>,
    #[cfg(test)]
    pub prior_confirmation: Vec<Case>,
    #[cfg(test)]
    pub excluded_roots: BTreeSet<String>,
    #[cfg(test)]
    pub confirmation_roots: BTreeSet<String>,
    pub reserved: BTreeSet<String>,
    pub reserved_families: BTreeSet<String>,
}
pub static BANK: LazyLock<Bank> = LazyLock::new(build);
fn atom(index: usize, variant: usize) -> Formula {
    let a = FreeVariable::new(((index / 4 + variant) % 4) as u32);
    let b = FreeVariable::new(((index % 4 + variant) % 4) as u32);
    Formula::member(a, b)
}
fn root_identity(premises: &[Formula], target: &Formula) -> String {
    let mut normalized = Vec::new();
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let map = [a, b, c, d];
                    if map.iter().copied().collect::<BTreeSet<_>>().len() != 4 {
                        continue;
                    }
                    let rename = |f: &Formula| {
                        f.clone()
                            .map_free_variables(|v| FreeVariable::new(map[v.identifier() as usize]))
                    };
                    let mut inputs = premises
                        .iter()
                        .map(|p| rename(p).encode_canonical().unwrap())
                        .collect::<Vec<_>>();
                    inputs.sort();
                    normalized.push(
                        serde_json::to_vec(&(inputs, rename(target).encode_canonical().unwrap()))
                            .unwrap(),
                    );
                }
            }
        }
    }
    use sha2::{Digest, Sha256};
    crate::hex(&Sha256::digest(normalized.into_iter().min().unwrap()))
}
fn question(seed: u64, variant: usize) -> Option<(CompiledQuestion, String)> {
    question_with_steps(seed, variant, 0)
}
fn question_with_steps(
    seed: u64,
    variant: usize,
    extra: usize,
) -> Option<(CompiledQuestion, String)> {
    let mut rng = crate::sampling::Random::new(seed.wrapping_mul(0x9e3779b97f4a7c15));
    let steps = 2 + (seed as usize / 4 % 6) + extra;
    let a = FreeVariable::new(variant as u32);
    let b = FreeVariable::new(((variant + 1) % 4) as u32);
    let c = FreeVariable::new(((variant + 2) % 4) as u32);
    let mut premises = Vec::new();
    let mut target = match seed % 4 {
        0 => {
            premises.push(atom(1, variant));
            premises.push(atom(2, variant));
            for i in 2..steps + 2 {
                let left = atom(1 + rng.below(i as u64) as usize, variant);
                let mut rule = Formula::implies(left, atom(i + 1, variant));
                if rng.below(2) == 0 {
                    rule = Formula::implies(atom(1 + rng.below(i as u64) as usize, variant), rule);
                }
                premises.push(rule);
            }
            atom(steps + 2, variant)
        }
        kind => {
            let start = match kind {
                1 => {
                    premises.push(Formula::member(c, a));
                    premises.push(Formula::for_all(
                        b,
                        Formula::implies(Formula::member(b, a), Formula::member(b, c)),
                    ));
                    Formula::member(c, c)
                }
                2 => {
                    premises.push(Formula::equal(a, b));
                    premises.push(Formula::member(a, c));
                    Formula::member(b, c)
                }
                _ => {
                    premises.push(Formula::equal(a, b));
                    premises.push(Formula::member(a, c));
                    Formula::member(b, c)
                }
            };
            let mut facts = vec![start, atom(1, variant)];
            premises.push(facts[1].clone());
            for _ in 0..steps {
                let left = facts[rng.below(facts.len() as u64) as usize].clone();
                let right = if kind == 3 {
                    Formula::member(b, c)
                } else {
                    atom(3 + rng.below(11) as usize, variant)
                };
                let mut rule = Formula::implies(left, right.clone());
                if rng.below(2) == 0 {
                    rule = Formula::implies(
                        facts[rng.below(facts.len() as u64) as usize].clone(),
                        rule,
                    );
                }
                premises.push(rule);
                facts.push(right);
            }
            if kind == 3 {
                let witness = FreeVariable::new(20);
                let body =
                    Formula::conjunction(Formula::equal(witness, b), Formula::member(witness, c));
                Formula::exists(witness, body)
            } else {
                facts.pop().unwrap()
            }
        }
    };
    let root = root_identity(&premises, &target);
    // Controlled unrelated premises, quantifier structure and conjunctions
    // produce genuinely different whole problems. Every variant of a source
    // construction is grouped together below, including argument renamings.
    for i in 0..2 + (seed as usize / 4 % 4) {
        let mut premise = Formula::implies(atom(8 + i, variant), atom(9 + i, variant));
        if rng.below(2) == 0 {
            premise = Formula::negate(Formula::negate(premise));
        }
        if rng.below(3) == 0 {
            let v = FreeVariable::new(20 + i as u32);
            premise = Formula::for_all(v, premise);
        }
        premises.push(premise);
    }
    if seed & 256 != 0 {
        target = Formula::negate(Formula::negate(target));
    }
    let length = premises.len();
    premises.rotate_left(seed as usize % length);
    for premise in premises.into_iter().rev() {
        target = Formula::implies(premise, target);
    }
    for variable in target.free_variables().into_iter().rev() {
        target = Formula::for_all(variable, target);
    }
    CompiledQuestion::from_formula(target)
        .ok()
        .map(|q| (q, root))
}
fn build() -> Bank {
    let mut bank = Bank {
        learning: Vec::new(),
        development: Vec::new(),
        transfer: Vec::new(),
        #[cfg(test)]
        confirmation: Vec::new(),
        #[cfg(test)]
        prior_confirmation: Vec::new(),
        #[cfg(test)]
        excluded_roots: BTreeSet::new(),
        #[cfg(test)]
        confirmation_roots: BTreeSet::new(),
        reserved: BTreeSet::new(),
        reserved_families: BTreeSet::new(),
    };
    let mut families = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut counts = [0usize; 3];
    for seed in 100_003..300_003 {
        let Some((first, root)) = question(seed, 0) else {
            continue;
        };
        if !roots.insert(root) {
            continue;
        }
        let family = super::owned::family(first.proved_target());
        if super::owned::sealed_family(&family)
            || super::composition::BANK.reserved_families.contains(&family)
            || !families.insert(family.clone())
        {
            continue;
        }
        let bytes = crate::object::id_bytes(&family).unwrap();
        let role = usize::from(bytes[0]) % 5;
        let part = if role == 0 {
            1
        } else if role == 1 {
            2
        } else {
            0
        };
        if counts[part] >= [48, 12, 24][part] {
            continue;
        }
        let mut cases = Vec::new();
        for variant in 0..2 {
            let Some((q, _)) = question(seed, variant) else {
                continue;
            };
            if super::owned::family(q.proved_target()) != family {
                continue;
            }
            let id = crate::hex(q.resolution_id());
            if super::CORPUS.reserved_ids.contains(&id) || !ids.insert(id.clone()) {
                continue;
            }
            cases.push(Case {
                id,
                source: q.source().into(),
                family: format!("adaptive-operation-{}", seed % 4),
                dependency: format!("adaptive/{family}"),
                development: part != 0,
            });
        }
        if cases.len() != 2 || cases[0].id == cases[1].id {
            continue;
        }
        counts[part] += 1;
        match part {
            0 => bank.learning.extend(cases),
            1 => {
                bank.reserved.extend(cases.iter().map(|q| q.id.clone()));
                bank.reserved_families.insert(family);
                bank.development.extend(cases);
            }
            _ => {
                bank.reserved.extend(cases.iter().map(|q| q.id.clone()));
                bank.reserved_families.insert(family);
                #[cfg(test)]
                bank.confirmation.extend(cases);
            }
        }
        if counts == [48, 12, 24] {
            break;
        }
    }
    assert_eq!(counts, [48, 12, 24], "question-only adaptive family supply");
    // The prior confirmation families stay reserved. Learning and all existing
    // development cases remain exactly the same; only independent final roots
    // are replenished. Selection uses syntax/identity only, never solve results.
    #[cfg(test)]
    {
        bank.prior_confirmation = std::mem::take(&mut bank.confirmation);
        bank.excluded_roots = roots.clone();
    }
    let retired = heldout(
        500_009,
        [5, 8, 7, 4],
        3,
        &mut bank,
        &mut roots,
        &mut families,
        &mut ids,
    );
    #[cfg(test)]
    bank.prior_confirmation.extend(retired);
    #[cfg(not(test))]
    drop(retired);
    bank.transfer = heldout(
        800_011,
        [3, 3, 3, 3],
        3,
        &mut bank,
        &mut roots,
        &mut families,
        &mut ids,
    );
    #[cfg(test)]
    {
        bank.excluded_roots = roots.clone();
    }
    let confirmation = heldout(
        1_100_017,
        [5, 8, 7, 4],
        3,
        &mut bank,
        &mut roots,
        &mut families,
        &mut ids,
    );
    #[cfg(test)]
    {
        bank.confirmation_roots = roots.difference(&bank.excluded_roots).cloned().collect();
        bank.confirmation = confirmation;
    }
    #[cfg(not(test))]
    drop(confirmation);
    bank
}

fn heldout(
    start: u64,
    targets: [usize; 4],
    extra: usize,
    bank: &mut Bank,
    roots: &mut BTreeSet<String>,
    families: &mut BTreeSet<String>,
    ids: &mut BTreeSet<String>,
) -> Vec<Case> {
    let mut selected = Vec::new();
    let mut fresh = [0usize; 4];
    for seed in start..start + 200_000 {
        let kind = (seed % 4) as usize;
        if fresh[kind] == targets[kind] {
            continue;
        }
        let Some((first, root)) = question_with_steps(seed, 0, extra) else {
            continue;
        };
        if roots.contains(&root) {
            continue;
        }
        let family = super::owned::family(first.proved_target());
        if families.contains(&family)
            || super::owned::sealed_family(&family)
            || super::composition::BANK.reserved_families.contains(&family)
        {
            continue;
        }
        let cases = (0..2)
            .filter_map(|variant| {
                let (q, _) = question_with_steps(seed, variant, extra)?;
                if super::owned::family(q.proved_target()) != family {
                    return None;
                }
                let id = crate::hex(q.resolution_id());
                if ids.contains(&id) || super::CORPUS.reserved_ids.contains(&id) {
                    return None;
                }
                Some(Case {
                    id,
                    source: q.source().into(),
                    family: format!("adaptive-operation-{kind}"),
                    dependency: format!("adaptive/{family}"),
                    development: true,
                })
            })
            .collect::<Vec<_>>();
        if cases.len() != 2 || cases[0].id == cases[1].id {
            continue;
        }
        roots.insert(root.clone());
        families.insert(family.clone());
        bank.reserved_families.insert(family);
        bank.reserved.extend(cases.iter().map(|q| q.id.clone()));
        ids.extend(cases.iter().map(|q| q.id.clone()));
        selected.extend(cases);
        fresh[kind] += 1;
        if fresh == targets {
            break;
        }
    }
    assert_eq!(fresh, targets, "independent family supply");
    selected
}

#[cfg(test)]
mod tests;
