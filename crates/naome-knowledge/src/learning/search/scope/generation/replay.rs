//! Reconstruct teachable choices from the checker-sealed local deduction.
use super::*;
use naome_checker::program::CheckedProgram;

pub(in crate::learning) fn graphs(
    engine: &CheckedProgram,
    target: &Formula,
    commands: &[Command],
    used: &[bool],
) -> Result<Vec<Graph>, crate::Error> {
    let Some((position, assumptions, actions, result)) = commands
        .iter()
        .zip(used)
        .enumerate()
        .find_map(|(i, (command, used))| match command {
            Command::Deduce {
                assumptions,
                actions,
                result,
            } if *used => Some((i, assumptions.len(), actions, *result as usize)),
            _ => None,
        })
    else {
        return Ok(Vec::new());
    };
    if actions.is_empty()
        || actions.len() > ACTIONS
        || assumptions + actions.len() > FACTS
        || result + 1 != assumptions + actions.len()
        || !used_facts(assumptions, actions)
            .is_some_and(|used| used[assumptions..].iter().all(|&used| used))
    {
        return Ok(Vec::new());
    }

    let scope = Scope::decompose(target, None)?;
    if !supported_goal(&scope) {
        return Ok(Vec::new());
    }

    // The checked deduction result contains the expanded formulas of the
    // ordered inputs, including imported proofs and registered definitions.
    let Some(deduction) = engine.proved_formula(position as u64)? else {
        return Ok(Vec::new());
    };
    let mut tail = deduction.view();
    let mut facts = Vec::with_capacity(assumptions + actions.len());
    for _ in 0..assumptions {
        let Some((premise, rest)) = tail.implication_parts() else {
            return Ok(Vec::new());
        };
        facts.push(premise.to_owned());
        tail = rest;
    }
    if tail != scope.goal.view() || !facts.ends_with(&scope.assumptions) {
        return Ok(Vec::new());
    }
    let mut decoder = Decoder {
        goals: demand::goals(&scope, &facts),
        scope,
        facts,
        sources: Vec::new(),
        actions: Vec::new(),
        selection: Selection::Checked(Vec::new()),
        work: Work::default(),
    };
    let binding = &engine.manifest().program_hash;
    let mut replayed = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        if decoder.next(Some(action))?.as_ref() != Some(action) {
            return Ok(Vec::new());
        }
        let Some(effect) = decoder.scope.apply(&decoder.facts, action) else {
            return Ok(Vec::new());
        };
        let Selection::Checked(graphs) = &mut decoder.selection else {
            unreachable!("checked replay")
        };
        replayed.extend(graphs.drain(..).enumerate().map(|(slot, mut graph)| {
            graph.binding = crate::learning::digest(&(binding, position, index, slot));
            graph
        }));
        decoder.facts.push(effect);
    }
    Ok(replayed)
}
