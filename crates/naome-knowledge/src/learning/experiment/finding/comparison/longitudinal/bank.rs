//! Question-only demands. No answer proof or learner outcome enters a split.
use super::*;
use naome_foundation::{Formula, FreeVariable};

fn v(n: usize) -> FreeVariable {
    FreeVariable::new(n as u32)
}
fn close(mut f: Formula) -> Formula {
    for name in f.free_variables().into_iter().rev() {
        f = Formula::for_all(name, f);
    }
    f
}
fn implication(premises: Vec<Formula>, mut goal: Formula) -> Formula {
    for premise in premises.into_iter().rev() {
        goal = Formula::implies(premise, goal);
    }
    close(goal)
}
fn conjunction(mut formulas: Vec<Formula>) -> Formula {
    let mut result = formulas.pop().expect("nonempty demand");
    while let Some(f) = formulas.pop() {
        result = Formula::conjunction(f, result);
    }
    result
}
fn atom(index: usize, style: usize) -> Formula {
    let a = Formula::member(v(index % 7 + 1), v(index % 5 + 9));
    let b = Formula::member(v(index % 5 + 9), v(index % 7 + 1));
    match style % 4 {
        0 => a,
        1 => Formula::negate(a),
        2 => Formula::conjunction(a, b),
        _ => Formula::disjunction(a, b),
    }
}
fn lemma(index: usize) -> Formula {
    let p = atom(0, 0);
    let q = atom(1, 0);
    let r = atom(2, 0);
    close(match index % 4 {
        0 => Formula::implies(p.clone(), Formula::implies(q, p)),
        1 => Formula::implies(
            Formula::implies(p.clone(), q.clone()),
            Formula::implies(Formula::implies(q, r.clone()), Formula::implies(p, r)),
        ),
        2 => Formula::implies(
            Formula::conjunction(p.clone(), q.clone()),
            Formula::conjunction(q, p),
        ),
        _ => Formula::implies(
            Formula::implies(p.clone(), q.clone()),
            Formula::implies(Formula::negate(q), Formula::negate(p)),
        ),
    })
}

fn composition(recipe: usize, root: usize) -> Formula {
    let obligations = 1 + (recipe - 1) / 2;
    let mut premises = Vec::new();
    let mut goals = Vec::new();
    for branch in 0..obligations {
        let begin = branch * 3;
        let length = 1 + (recipe - 1) % 2;
        let predicate = |i| atom(i, root >> (2 * (i % 5)));
        premises.push(Formula::implies(
            lemma((root / 256 + branch) % 4),
            predicate(begin),
        ));
        for i in begin..begin + length {
            premises.push(Formula::implies(predicate(i), predicate(i + 1)));
        }
        goals.push(predicate(begin + length));
    }
    implication(premises, conjunction(goals))
}

fn quantified(recipe: usize, root: usize) -> Formula {
    let point = v(0);
    let predicate = |index: usize| {
        let a = Formula::member(point, v(index + 1));
        let b = Formula::member(v(index + 1), point);
        let relation = Formula::member(v(20), v(index + 1));
        let neighbor = Formula::member(point, v(20));
        let every = |f| Formula::for_all(v(20), f);
        let some = |f| Formula::negate(Formula::for_all(v(20), Formula::negate(f)));
        match (root >> (4 * (index % 5))) % 16 {
            0 => a,
            1 => Formula::negate(a),
            2 => Formula::conjunction(a, b),
            3 => every(Formula::implies(neighbor, b)),
            4 => Formula::disjunction(a, b),
            5 => Formula::implies(a, b),
            6 => every(Formula::implies(relation, neighbor)),
            7 => some(Formula::conjunction(neighbor, relation)),
            8 => Formula::conjunction(a, Formula::negate(b)),
            9 => Formula::implies(Formula::negate(b), a),
            10 => Formula::disjunction(a, Formula::negate(b)),
            11 => Formula::negate(every(Formula::implies(relation, neighbor))),
            12 => Formula::conjunction(a, every(Formula::implies(neighbor, relation))),
            13 => Formula::implies(some(Formula::conjunction(neighbor, relation)), b),
            14 => every(Formula::implies(
                neighbor,
                Formula::conjunction(a, relation),
            )),
            _ => some(Formula::conjunction(
                relation,
                Formula::implies(neighbor, b),
            )),
        }
    };
    let exists = |f| Formula::negate(Formula::for_all(point, Formula::negate(f)));
    let length = 1 + (recipe - 1) % 3;
    let mut premises = vec![exists(predicate(0))];
    for i in 0..length {
        premises.push(Formula::for_all(
            point,
            Formula::implies(predicate(i), predicate(i + 1)),
        ));
    }
    let goal = if recipe > 3 {
        premises.push(Formula::for_all(
            point,
            Formula::implies(predicate(0), predicate(length + 1)),
        ));
        Formula::conjunction(exists(predicate(length)), exists(predicate(length + 1)))
    } else {
        exists(predicate(length))
    };
    implication(premises, goal)
}

fn equality(recipe: usize, root: usize) -> Formula {
    let length = 1 + (recipe - 1) % 3;
    let both = recipe > 3;
    let mut premises = (0..length)
        .map(|i| Formula::equal(v(i), v(i + 1)))
        .collect::<Vec<_>>();
    if both {
        premises.extend((0..length).map(|i| Formula::equal(v(8 + i), v(9 + i))));
    }
    let predicate = |a, b| {
        let p = Formula::member(v(a), v(b));
        let q = Formula::member(v(b), v(a));
        match root % 6 {
            0 => p,
            1 => Formula::negate(p),
            2 => Formula::conjunction(p, q),
            3 => Formula::disjunction(p, q),
            4 => Formula::for_all(v(24), Formula::implies(Formula::member(v(24), v(a)), q)),
            _ => Formula::implies(p, Formula::for_all(v(24), Formula::member(v(b), v(24)))),
        }
    };
    let first = 8;
    let last = if both { 8 + length } else { 8 };
    // Nest nonvacuous predicate contexts in both the source and target. They
    // change congruence demands; no irrelevant tautology is appended.
    let mut from = predicate(0, first);
    let mut to = predicate(length, last);
    for layer in 0..(root / 6) % 4 {
        let other = atom(20 + layer, root / 24 + layer);
        if (root / 96 + layer).is_multiple_of(2) {
            from = Formula::conjunction(from, other.clone());
            to = Formula::conjunction(to, other);
        } else {
            from = Formula::implies(other.clone(), from);
            to = Formula::implies(other, to);
        }
    }
    premises.push(from);
    implication(premises, to)
}

fn opened(mut formula: Formula) -> (usize, Vec<Formula>, Formula) {
    let mut binders = 0;
    while let Some(body) = formula.open_outer_universal(v(100 + binders)) {
        formula = body;
        binders += 1;
    }
    let mut premises = Vec::new();
    while let naome_foundation::graph::Node::Implies(a, b) = formula.view().graph_node() {
        premises.push(a.to_owned());
        formula = b.to_owned();
    }
    (binders, premises, formula)
}

/// Conservative shape grouping also removes outer premise order. It grants
/// no mathematical equivalence/admission and intentionally merges atom roles.
pub(super) fn near_family(question: &CompiledQuestion) -> String {
    lineage::normalized_family(question)
}

pub(super) fn cases(track: usize, recipe: usize, root: usize) -> Result<Vec<Case>, String> {
    let formula = match track {
        0 => composition(recipe, root),
        1 => quantified(recipe, root),
        2 => equality(recipe, root),
        _ => return Err("unknown capability track".into()),
    };
    let (_, mut premises, goal) = opened(formula.clone());
    premises.reverse();
    let variant = implication(premises, goal);
    let mut result = Vec::new();
    for (variant, formula) in [formula, variant].into_iter().enumerate() {
        let q = CompiledQuestion::from_formula(formula).map_err(|e| e.to_string())?;
        if !State::eligible(q.source()) {
            return Ok(Vec::new());
        }
        result.push(Case {
            source: q.source().into(),
            resolution: crate::hex(q.resolution_id()),
            family: curriculum::owned::family(q.proved_target()),
            construction: near_family(&q),
            track,
            recipe,
            variant,
        });
    }
    if result[0].construction != result[1].construction
        || result[0].resolution == result[1].resolution
    {
        return Ok(Vec::new());
    }
    Ok(result)
}

pub(super) fn build(historical: &[String]) -> Result<Bank, String> {
    let mut used_families = BTreeSet::new();
    let mut used_constructions = BTreeSet::new();
    let mut used_resolutions = BTreeSet::new();
    for source in historical {
        let q = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
        used_families.insert(curriculum::owned::family(q.proved_target()));
        used_constructions.insert(near_family(&q));
        used_resolutions.insert(crate::hex(q.resolution_id()));
    }
    let mut bank = Bank {
        acquisition: Vec::new(), calibration: Vec::new(), assessment: Vec::new(), pilot: Vec::new(),
        construction_notes: vec![
            "Operational tracks, not intrinsic difficulty or mathematical novelty.".into(),
            "Closed logical basis lemmas are shared foundations, not assessment targets or teacher proofs.".into(),
            "Whole normalized premise-order, conservative atomic-shape and authored-construction groups are disjoint before inference.".into(),
        ],
    };
    for (track, track_name) in TRACKS.iter().enumerate() {
        for recipe in 1..=6 {
            let mut counts = [0; 4];
            for root in 0..4096 {
                if counts == [8, 6, 12, 6] {
                    break;
                }
                let rows = cases(track, recipe, root)?;
                if rows.is_empty() {
                    continue;
                }
                if rows.iter().any(|q| {
                    used_families.contains(&q.family)
                        || used_resolutions.contains(&q.resolution)
                        || used_constructions.contains(&q.construction)
                }) {
                    continue;
                }
                let hash = Sha256::digest(rows[0].construction.as_bytes());
                let bucket = match hash[0] % 5 {
                    0 | 1 => 0,
                    2 => 1,
                    3 => 2,
                    _ => 3,
                };
                let limit = [8, 6, 12, 6][bucket];
                if counts[bucket] == limit {
                    continue;
                }
                used_constructions.insert(rows[0].construction.clone());
                for q in &rows {
                    used_families.insert(q.family.clone());
                    used_resolutions.insert(q.resolution.clone());
                }
                let target = match bucket {
                    0 => &mut bank.acquisition,
                    1 => &mut bank.calibration,
                    2 => &mut bank.assessment,
                    _ => &mut bank.pilot,
                };
                target.extend(rows);
                counts[bucket] += 1;
            }
            if counts != [8, 6, 12, 6] {
                return Err(format!(
                    "track {} recipe {recipe} lacks independent split families: {counts:?}",
                    track_name
                ));
            }
        }
    }
    Ok(bank)
}
