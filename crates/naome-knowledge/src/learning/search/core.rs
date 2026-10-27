//! Effect slicing of an owned successful trace, with exact context replay.
//! Formula identity, offered actions and branch arity remain authoritative.
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub original_steps: usize,
    pub useful_steps: usize,
    pub replay_work: usize,
}
pub fn steps(tree: &Tree) -> usize {
    match tree {
        Tree::Knowledge { proof, .. } | Tree::Definitions { proof, .. } => 1 + steps(proof),
        Tree::Step { children, .. } => 1 + children.iter().map(steps).sum::<usize>(),
        Tree::Certificate(bytes) => super::super::peer::step_count(bytes),
        Tree::Constructed { packet, .. } => super::super::evidence::steps(packet).unwrap_or(0),
        Tree::Stored { steps, .. } => *steps,
        _ => 0,
    }
}
fn position(index: usize, from: &State, to: &State) -> Result<usize, String> {
    let formula = from.facts.get(index).ok_or("core premise index")?;
    to.facts
        .iter()
        .position(|f| f == formula)
        .ok_or("core needs removed fact".into())
}
fn action(action: &Action, from: &State, to: &State) -> Result<Action, String> {
    Ok(match *action {
        Action::Cite(i) => Action::Cite(i),
        Action::Double(i) => Action::Double(position(i, from, to)?),
        Action::NotImp(i) => Action::NotImp(position(i, from, to)?),
        Action::Mp(i, j) => Action::Mp(position(i, from, to)?, position(j, from, to)?),
        Action::Beta(i) => Action::Beta(position(i, from, to)?),
        Action::Instantiate(i, v) => Action::Instantiate(position(i, from, to)?, v),
        Action::Witness(i, v) => Action::Witness(position(i, from, to)?, v),
        Action::Substitute(i, j) => {
            Action::Substitute(position(i, from, to)?, position(j, from, to)?)
        }
    })
}
fn spend(work: &mut usize) -> Result<(), String> {
    *work = work.checked_add(1).ok_or("core work overflow")?;
    if *work > 8192 {
        return Err("core work allowance".into());
    }
    Ok(())
}
fn rebase(
    tree: &Tree,
    from: &State,
    to: &State,
    work: &mut usize,
    depth: usize,
) -> Result<Tree, String> {
    spend(work)?;
    if depth > 40 {
        return Err("core replay depth".into());
    }
    if let Some((a, b)) = close(to) {
        return Ok(Tree::Close(a, b));
    }
    match tree {
        Tree::Close(a, b) => Ok(Tree::Close(
            position(*a, from, to)?,
            position(*b, from, to)?,
        )),
        Tree::Axiom(_)
        | Tree::Certificate(_)
        | Tree::Constructed { .. }
        | Tree::Stored { .. }
        | Tree::Knowledge { .. }
        | Tree::Definitions { .. } => Err("nested core axiom".into()),
        Tree::Step {
            action: old,
            children,
        } => {
            let before = next(from, old)?;
            if before.len() != children.len() {
                return Err("core branch arity".into());
            }
            if let Ok(selected) = action(old, from, to)
                && actions(to).contains(&selected)
            {
                let after = next(to, &selected)?;
                let children = children
                    .iter()
                    .zip(before.iter().zip(&after))
                    .map(|(tree, (from, to))| rebase(tree, from, to, work, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Tree::Step {
                    action: selected,
                    children,
                })
            } else if children.len() == 1 {
                rebase(&children[0], &before[0], to, work, depth + 1)
            } else {
                Err("core branching premise is absent".into())
            }
        }
    }
}
fn slice(tree: &Tree, state: &State, work: &mut usize, depth: usize) -> Result<Tree, String> {
    spend(work)?;
    if depth > 40 {
        return Err("core slice depth".into());
    }
    if let Some((a, b)) = close(state) {
        return Ok(Tree::Close(a, b));
    }
    let Tree::Step { action, children } = tree else {
        return Ok(tree.clone());
    };
    let states = next(state, action)?;
    if states.len() != children.len() {
        return Err("core source branch arity".into());
    }
    let children = children
        .iter()
        .zip(&states)
        .map(|(t, s)| slice(t, s, work, depth + 1))
        .collect::<Result<Vec<_>, _>>()?;
    let mut best = Tree::Step {
        action: action.clone(),
        children: children.clone(),
    };
    for (child, from) in children.iter().zip(&states) {
        if let Ok(candidate) = rebase(child, from, state, work, depth + 1)
            && steps(&candidate) < steps(&best)
        {
            best = candidate;
        }
        if *work >= 8192 {
            break;
        }
    }
    Ok(best)
}
/// A smaller trace is accepted only after complete native proof reconstruction
/// and checking. The returned identity is computed afresh by that checker.
pub fn checked(
    target: &Formula,
    tree: &Tree,
) -> Result<(Tree, Cost, super::super::proof::Verified), String> {
    let original_steps = steps(tree);
    let mut work = 0;
    let candidate = if let Tree::Definitions {
        entries,
        selected,
        available,
        proof,
    } = tree
    {
        Tree::Definitions {
            entries: entries.clone(),
            selected: *selected,
            available: *available,
            proof: Box::new(checked(target, proof)?.0),
        }
    } else if matches!(
        tree,
        Tree::Axiom(_) | Tree::Certificate(_) | Tree::Constructed { .. } | Tree::Knowledge { .. }
    ) {
        tree.clone()
    } else {
        slice(tree, &prepare(target)?.state, &mut work, 0).unwrap_or_else(|_| tree.clone())
    };
    let (term, _) = compile(target, &candidate)?;
    let verified = super::super::proof::verify(&term, target)?;
    Ok((
        candidate.clone(),
        Cost {
            original_steps,
            useful_steps: steps(&candidate),
            replay_work: work,
        },
        verified,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use naome_authoring::CompiledQuestion;
    #[test]
    fn irrelevant_effects_are_removed_and_all_fact_indices_are_replayed() {
        let q = CompiledQuestion::compile(
            "goal=all(x,all(y,imp(not(not(mem(x,x))),imp(not(not(mem(y,x))),imp(and(mem(x,x),mem(y,y)),mem(y,y))))))",
        )
        .unwrap();
        let target = q.proved_target();
        let state = prepare(target).unwrap().state;
        let dead = Action::Double(0);
        let after = next(&state, &dead).unwrap().remove(0);
        let productive = Action::NotImp(2);
        let done = next(&after, &productive).unwrap().remove(0);
        let (a, b) = close(&done).unwrap();
        let tree = Tree::Step {
            action: dead,
            children: vec![Tree::Step {
                action: productive,
                children: vec![Tree::Close(a, b)],
            }],
        };
        let original =
            super::super::super::proof::verify(&compile(target, &tree).unwrap().0, target).unwrap();
        let (core, cost, verified) = checked(target, &tree).unwrap();
        assert_eq!((cost.original_steps, cost.useful_steps), (2, 1));
        assert_eq!(
            verified.native_id, original.native_id,
            "an already pruned mathematical artifact keeps its identity; the operational trace is shorter"
        );
        assert!(compile(target, &core).unwrap().1.len() < compile(target, &tree).unwrap().1.len());
    }
}

#[cfg(test)]
mod alternatives {
    use super::*;
    use naome_authoring::CompiledQuestion;
    #[test]
    fn two_native_checked_completions_share_only_their_exact_initial_state() {
        let q = CompiledQuestion::compile("goal=all(x,all(y,all(z,imp(imp(mem(x,x),mem(y,y)),imp(mem(x,x),imp(imp(mem(z,z),mem(y,y)),imp(mem(z,z),imp(not(not(mem(x,z))),mem(y,y)))))))))").unwrap();
        let target = q.proved_target();
        let state = prepare(target).unwrap().state;
        let mut graphs = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for action in [Action::Mp(0, 1), Action::Mp(2, 3)] {
            let next = next(&state, &action).unwrap().remove(0);
            let (a, b) = close(&next).unwrap();
            let tree = Tree::Step {
                action,
                children: vec![Tree::Close(a, b)],
            };
            let (_, _, verified) = checked(target, &tree).unwrap();
            ids.insert(verified.native_id);
            graphs.extend(compile(target, &tree).unwrap().1);
        }
        assert_eq!(ids.len(), 2);
        assert_eq!(graphs.len(), 2);
        assert_eq!(graphs[0].key(), graphs[1].key());
        let pool = super::super::super::pool::Pool::from_graphs(&graphs);
        let graph = &pool.graphs()[0];
        assert_eq!(graph.candidates.len(), 3);
        assert_eq!(graph.successes, vec![0, 1]);
        assert_eq!(pool.graphs().len(), 1);
    }
}
