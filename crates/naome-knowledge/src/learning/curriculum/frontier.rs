//! Question-only compositional roots, grouped before any model inference.
//! No reference answer, teacher proof or solver outcome participates in generation.
use super::Case;
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FreeVariable};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

pub struct Bank {
    pub learning: Vec<Case>,
    pub development: Vec<Case>,
    #[cfg(test)]
    pub confirmation: Vec<Case>,
    pub reserved: BTreeSet<String>,
    #[cfg(test)]
    pub roots: usize,
}
pub static BANK: LazyLock<Bank> = LazyLock::new(build);
fn random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
fn shuffle<T>(values: &mut [T], seed: &mut u64) {
    for i in (1..values.len()).rev() {
        let j = random(seed) as usize % (i + 1);
        values.swap(i, j);
    }
}
fn close(mut body: Formula) -> Formula {
    for variable in body.free_variables().into_iter().rev() {
        body = Formula::for_all(variable, body);
    }
    body
}
fn implication(premises: Vec<Formula>, mut goal: Formula) -> Formula {
    for premise in premises.into_iter().rev() {
        goal = Formula::implies(premise, goal);
    }
    close(goal)
}
fn atom(index: usize) -> Formula {
    let pairs = (0..4)
        .flat_map(|a| (0..4).filter(move |b| a != *b).map(move |b| (a, b)))
        .collect::<Vec<_>>();
    let (a, b) = pairs[index % pairs.len()];
    Formula::member(FreeVariable::new(a), FreeVariable::new(b))
}
fn root(family: usize, index: usize) -> (String, Vec<(String, String)>) {
    let mut seed = 0x66726f6e74696572u64 ^ ((family as u64) << 40) ^ index as u64;
    let nodes = if family == 3 {
        3 + random(&mut seed) as usize % 2
    } else {
        6 + random(&mut seed) as usize % 3
    };
    let mut intermediate = (1..nodes - 1).collect::<Vec<_>>();
    shuffle(&mut intermediate, &mut seed);
    let hops = if family == 3 {
        2
    } else {
        2 + random(&mut seed) as usize % 2
    };
    let mut path = vec![0];
    path.extend(intermediate.into_iter().take(hops - 1));
    path.push(nodes - 1);
    let route = path.windows(2).map(|p| (p[0], p[1])).collect::<Vec<_>>();
    let mut edges = route.iter().copied().collect::<BTreeSet<_>>();
    let extra = if family == 3 {
        1
    } else {
        4 + random(&mut seed) as usize % 3
    };
    while edges.len() < route.len() + extra {
        let a = random(&mut seed) as usize % nodes;
        let b = random(&mut seed) as usize % nodes;
        if a != b {
            edges.insert((a, b));
        }
    }
    let point = FreeVariable::new(nodes as u32);
    let predicates = (0..nodes)
        .map(|i| {
            let base = Formula::member(point, FreeVariable::new(i as u32));
            let other = Formula::member(FreeVariable::new(((i + 1) % nodes) as u32), point);
            if family != 3 || (index / 5 + i).is_multiple_of(3) {
                base
            } else {
                match index % 5 {
                    0 => Formula::negate(base),
                    1 => Formula::conjunction(base, other),
                    2 => Formula::disjunction(base, other),
                    3 => Formula::implies(base, other),
                    _ => Formula::implies(other, base),
                }
            }
        })
        .collect::<Vec<_>>();
    let signature = crate::hex(&Sha256::digest(
        serde_json::to_vec(&(
            family,
            nodes,
            &edges,
            predicates
                .iter()
                .map(|p| p.encode_canonical().unwrap())
                .collect::<Vec<_>>(),
        ))
        .unwrap(),
    ));
    let missing = route[random(&mut seed) as usize % route.len()];
    let mut variants = Vec::new();
    for incomplete in [false, true] {
        let mut selected = edges
            .iter()
            .copied()
            .filter(|e| !incomplete || *e != missing)
            .collect::<Vec<_>>();
        shuffle(&mut selected, &mut seed);
        let formula = match family {
            0 | 1 => {
                let mut premises = selected
                    .iter()
                    .map(|(a, b)| Formula::implies(atom(*a), atom(*b)))
                    .collect::<Vec<_>>();
                premises.push(atom(0));
                let goal = if family == 1 {
                    premises.push(Formula::negate(atom(nodes - 1)));
                    atom(nodes)
                } else {
                    atom(nodes - 1)
                };
                shuffle(&mut premises, &mut seed);
                implication(premises, goal)
            }
            2 => {
                let parameter = FreeVariable::new(nodes as u32);
                let mut premises = selected
                    .iter()
                    .map(|(a, b)| {
                        Formula::equal(FreeVariable::new(*a as u32), FreeVariable::new(*b as u32))
                    })
                    .collect::<Vec<_>>();
                premises.push(Formula::member(FreeVariable::new(0), parameter));
                shuffle(&mut premises, &mut seed);
                implication(
                    premises,
                    Formula::member(FreeVariable::new((nodes - 1) as u32), parameter),
                )
            }
            3 => {
                let predicate = |i: usize| predicates[i].clone();
                let mut premises = selected
                    .iter()
                    .map(|(a, b)| {
                        Formula::for_all(point, Formula::implies(predicate(*a), predicate(*b)))
                    })
                    .collect::<Vec<_>>();
                premises.push(Formula::negate(Formula::for_all(
                    point,
                    Formula::negate(predicate(0)),
                )));
                shuffle(&mut premises, &mut seed);
                implication(
                    premises,
                    Formula::negate(Formula::for_all(
                        point,
                        Formula::negate(predicate(nodes - 1)),
                    )),
                )
            }
            _ => unreachable!(),
        };
        let question =
            CompiledQuestion::from_formula(formula).expect("bounded closed frontier question");
        variants.push((
            crate::hex(question.resolution_id()),
            question.source().to_owned(),
        ));
    }
    (signature, variants)
}
fn representative(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        let next = parent[i];
        parent[i] = parent[next];
        i = parent[i];
    }
    i
}
fn build() -> Bank {
    let families = [
        "frontier-routing",
        "frontier-contradiction",
        "frontier-equality",
        "frontier-quantifiers",
    ];
    let mut rows = Vec::new();
    let mut signatures = Vec::new();
    for (family, name) in families.iter().enumerate() {
        for index in 0..80 {
            let (signature, variants) = root(family, index);
            let group = signatures.len();
            signatures.push(signature);
            for (id, source) in variants {
                rows.push((group, (*name).to_owned(), id, source));
            }
        }
    }
    // Canonical duplicates join their complete source roots before bucket selection.
    let mut parent = (0..signatures.len()).collect::<Vec<_>>();
    let mut identities = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (group, _, id, _) in &rows {
        if let Some(previous) = identities.insert(id.clone(), *group) {
            let a = representative(&mut parent, *group);
            let b = representative(&mut parent, previous);
            parent[a] = b;
        }
        if let Some(previous) = sources.insert(signatures[*group].clone(), *group) {
            let a = representative(&mut parent, *group);
            let b = representative(&mut parent, previous);
            parent[a] = b;
        }
    }
    let mut components: BTreeMap<usize, BTreeSet<&str>> = BTreeMap::new();
    for (i, signature) in signatures.iter().enumerate() {
        components
            .entry(representative(&mut parent, i))
            .or_default()
            .insert(signature);
    }
    let dependency = components
        .iter()
        .map(|(i, roots)| {
            (
                *i,
                format!(
                    "frontier/{}",
                    crate::hex(&Sha256::digest(serde_json::to_vec(roots).unwrap()))
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut groups: BTreeMap<(String, String), BTreeMap<String, Case>> = BTreeMap::new();
    for (group, family, id, source) in rows {
        let dep = dependency[&representative(&mut parent, group)].clone();
        groups
            .entry((family.clone(), dep.clone()))
            .or_default()
            .entry(id.clone())
            .or_insert(Case {
                id,
                source,
                family,
                dependency: dep,
                development: false,
            });
    }
    #[cfg(test)]
    let roots = groups.len();
    let mut learning = Vec::new();
    let mut development = Vec::new();
    let mut confirmation = Vec::new();
    let mut reserved = BTreeSet::new();
    let mut selected = BTreeMap::new();
    let mut confirmed = BTreeMap::new();
    for ((family, dependency), cases) in groups {
        let bucket = Sha256::digest(dependency.as_bytes())[0] % 5;
        if bucket >= 2 {
            learning.extend(cases.into_values());
            continue;
        }
        reserved.extend(cases.keys().cloned());
        let (counts, limit, output) = if bucket == 0 {
            (&mut selected, 4, &mut development)
        } else {
            (&mut confirmed, 8, &mut confirmation)
        };
        let count = counts.entry(family).or_insert(0usize);
        if *count < limit && cases.len() >= 2 {
            output.extend(cases.into_values().take(2).map(|mut case| {
                case.development = true;
                case
            }));
            *count += 1;
        }
    }
    assert_eq!(
        development.len(),
        32,
        "prospective selection construction coverage: {selected:?}"
    );
    assert_eq!(
        confirmation.len(),
        64,
        "prospective confirmation construction coverage"
    );
    Bank {
        learning,
        development,
        #[cfg(test)]
        confirmation,
        reserved,
        #[cfg(test)]
        roots,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_frontier_roots_are_closed_group_disjoint_and_exclude_the_original_corpus() {
        let bank = &*BANK;
        let mut identities = BTreeSet::new();
        let mut groups = BTreeMap::new();
        for (split, cases) in [
            ("learning", &bank.learning),
            ("development", &bank.development),
            ("confirmation", &bank.confirmation),
        ] {
            for case in cases {
                assert!(identities.insert(&case.id));
                let previous = groups.insert(&case.dependency, split);
                assert!(previous.is_none_or(|old| old == split));
                let question = CompiledQuestion::compile(&case.source).unwrap();
                assert_eq!(crate::hex(question.resolution_id()), case.id);
                assert!(question.formula().is_closed());
                assert!(!super::super::CORPUS.cases.iter().any(|c| c.id == case.id));
                assert!(!super::super::CORPUS.reserved_ids.contains(&case.id));
            }
        }
        if let Ok(path) = std::env::var("NAOME_FRONTIER_AUDIT_OUTPUT") {
            std::fs::write(path,serde_json::to_vec_pretty(&serde_json::json!({"learning":bank.learning,"development":bank.development,"confirmation":bank.confirmation,"reserved":bank.reserved,"roots":bank.roots})).unwrap()).unwrap();
        }
    }
}
