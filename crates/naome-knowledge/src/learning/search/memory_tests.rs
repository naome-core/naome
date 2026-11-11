use super::*;
use crate::learning::{self as native, model};

struct Observed<'a> {
    runtime: &'a mut model::Runtime,
    calls: Vec<(String, Option<model::Memory>, model::Plan)>,
}
impl Ranker for Observed<'_> {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        self.runtime.scores(decision)
    }
    fn plan(
        &mut self,
        decision: &Decision,
        binding: &str,
        offered: &str,
        memory: Option<&model::Memory>,
    ) -> Result<model::Plan, crate::Error> {
        let mut plan = self.runtime.plan(decision, binding, offered, memory)?;
        // The fixture chooses the branching path explicitly. Neural working
        // state still follows every actual symbolic action and child.
        plan.scores = decision
            .candidates
            .iter()
            .map(|c| {
                if c.rule == Rule::ImplicationBranch {
                    1.
                } else {
                    0.
                }
            })
            .collect();
        self.calls
            .push((binding.to_owned(), memory.cloned(), plan.clone()));
        Ok(plan)
    }
    fn identity(&self) -> Option<String> {
        self.runtime.identity()
    }
}

#[test]
fn sibling_and_backtracked_alternatives_restore_their_actual_parent_memory() {
    let q = naome_checker::question::ResearchQuestion::from_hex("0404040403030101000000030100000003010100000002010000000203030101000000000100000000010100000003010000000303010100000000010000000003020201010000000201000000020101000000010100000001").unwrap();
    let state = prepare(q.proved_target()).unwrap().state;
    let root_actions = actions(&state);
    let mut io = native::tests::MemoryStore::default();
    let mut engine = native::Engine::default().with_recurrence(model::Recurrence::Carry);
    let saved = engine
        .snapshot(&model::Checkpoint::fresh(), &mut io)
        .unwrap();
    engine
        .with(&saved, &mut io, |runtime| {
            let mut ranker = Observed {
                runtime,
                calls: Vec::new(),
            };
            let result = solve(q.proved_target(), &mut ranker, 128)?;
            assert!(result.tree.is_none());
            let root = ranker
                .calls
                .iter()
                .find(|(key, _, _)| *key == trace::binding(&state).unwrap())
                .unwrap();
            assert!(root.1.is_none());
            let parent_plan = root.2.clone();
            let mut compared = 0;
            for (selected, action) in root_actions.iter().enumerate() {
                for child in next(&state, action)? {
                    if let Some((_, actual, _)) = ranker
                        .calls
                        .iter()
                        .find(|(key, _, _)| *key == trace::binding(&child).unwrap())
                    {
                        let expected = parent_plan.child(
                            selected,
                            trace::binding(&child)?,
                            native::digest(&actions(&child)),
                        )?;
                        assert_eq!(
                            native::digest(actual),
                            native::digest(&expected),
                            "sibling/backtrack memory crossed a different actual action"
                        );
                        compared += 1;
                    }
                }
            }
            assert!(
                compared >= 3,
                "both branch children and another root alternative must execute"
            );
            let previous = ranker.calls.len();
            let another =
                naome_checker::question::ResearchQuestion::from_hex(&native::tests::own_question())
                    .unwrap();
            solve(another.proved_target(), &mut ranker, 32)?;
            assert!(ranker.calls.len() > previous);
            assert!(
                ranker.calls[previous].1.is_none(),
                "a new goal starts without another search's memory"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(engine.snapshot(&saved, &mut io).unwrap(), saved);
    // Actual restart support remains at the whole native unit boundary.
    let mut restarted = native::Engine::default();
    let restored = restarted
        .with(&saved, &mut io, |runtime| {
            solve(q.proved_target(), runtime, 32).map_err(Into::into)
        })
        .unwrap();
    assert!(restored.execution.is_some());
    assert_eq!(restarted.snapshot(&saved, &mut io).unwrap(), saved);
}
