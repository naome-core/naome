//! Checked conditional cuts for transport beyond one local search scope.
use super::{
    ACTIONS, BTreeSet, Command, FACTS, Formula, FreeVariable, Projection, ProofFormula, Scope,
    ScopedAction, demand,
};
use crate::learning::proof;
use naome_checker::question::ResearchQuestion;
use naome_proof::{
    ProofId,
    program::{ACTION_PREMISES, SCOPE_ASSUMPTIONS},
};

mod witness;

const SEGMENT_ACTIONS: usize = if ACTIONS < ACTION_PREMISES - 1 {
    ACTIONS
} else {
    ACTION_PREMISES - 1
};
const SINGLE_PATH: usize = SEGMENT_ACTIONS + ACTIONS - 1;
const SERIAL_PATH: usize = 2 * SEGMENT_ACTIONS + ACTIONS - 2;

/// Each group is an alternative route. All questions in a group must be proved.
pub(crate) fn questions(target: &Formula) -> Vec<Vec<ResearchQuestion>> {
    let Some(scope) = Scope::open(target).ok().flatten() else {
        return Vec::new();
    };
    let cuts = witness::cuts(&scope);
    if !cuts.is_empty() {
        return cuts.into_iter().map(|cut| vec![cut.question]).collect();
    }
    route(scope).map_or_else(Vec::new, |route| {
        route
            .groups()
            .into_iter()
            .map(|segments| {
                segments
                    .into_iter()
                    .map(|segment| segment.question)
                    .collect()
            })
            .collect()
    })
}

pub(crate) fn plan(
    target: &Formula,
    count: usize,
    select: impl Fn(&Formula) -> Option<ProofId>,
) -> Option<Plan> {
    let scope = Scope::open(target).ok().flatten()?;
    if count == 1
        && let Some((cut, proof)) = witness::cuts(&scope).into_iter().find_map(|cut| {
            let proof = select(cut.question.proved_target())?;
            Some((cut, proof))
        })
    {
        // Charge each bound variable and used assumption, plus the reference,
        // vacuous generalization and discharge that connect the two proofs.
        let work = scope.binders.len() + cut.opened.free_variables().len() + cut.inputs.len() + 3;
        let replacement = unused(&cut.opened).identifier();
        return Some(Plan {
            scope,
            sources: vec![(proof, cut.opened)],
            actions: vec![ScopedAction::Instantiate {
                universal: 0,
                replacement,
                premises: cut.inputs.into_iter().map(|index| index + 1).collect(),
            }],
            work,
        });
    }
    let route = route(scope)?;
    let sources = route.groups().into_iter().find_map(|segments| {
        if segments.len() != count {
            return None;
        }
        segments
            .into_iter()
            .map(|segment| Some((select(segment.question.proved_target())?, segment)))
            .collect::<Option<Vec<_>>>()
    })?;
    Some(route.plan(sources))
}

struct Route {
    scope: Scope,
    path: Vec<Step>,
    facts: Vec<Formula>,
}

struct Step {
    universal: u32,
    replacement: u32,
    premise: u32,
}

pub(crate) struct Plan {
    scope: Scope,
    sources: Vec<(ProofId, Formula)>,
    actions: Vec<ScopedAction>,
    work: usize,
}

struct Segment {
    end: usize,
    inputs: Vec<u32>,
    opened: Formula,
    question: ResearchQuestion,
}

fn route(scope: Scope) -> Option<Route> {
    let mut facts = scope.assumptions.clone();
    let base = facts.len();
    let mut path = Vec::new();
    for i in 0..SERIAL_PATH.min(FACTS - base) {
        let (action, result) = demand::offers(&scope.goal, &facts).into_iter().next()?;
        let ScopedAction::Instantiate {
            universal,
            replacement,
            premises,
        } = action
        else {
            return None;
        };
        let [premise] = premises[..] else {
            return None;
        };
        if universal as usize >= base
            || (i == 0 && premise as usize >= base)
            || (i > 0 && premise as usize != base + i - 1)
        {
            return None;
        }
        path.push(Step {
            universal,
            replacement,
            premise,
        });
        let reached = result == scope.goal;
        facts.push(result);
        if reached {
            break;
        }
    }
    (path.len() > ACTIONS && facts.last() == Some(&scope.goal)).then_some(Route {
        scope,
        path,
        facts,
    })
}

impl Route {
    fn groups(&self) -> Vec<Vec<Segment>> {
        let length = self.path.len();
        let base = self.scope.assumptions.len();
        if length <= SINGLE_PATH && base < SCOPE_ASSUMPTIONS {
            // One local action applies a proved prefix. Keep the established
            // assumption order so previously checked prefixes remain reusable.
            let first = length - (ACTIONS - 1);
            let last = ACTIONS.min(length - 1);
            return (first..=last)
                .filter_map(|end| self.segment(0, end, true).map(|segment| vec![segment]))
                .collect();
        }
        if base + 2 > SCOPE_ASSUMPTIONS {
            return Vec::new();
        }
        // Two local actions apply the checked segments. Balance the three
        // runs while leaving at most six ordinary actions in the root.
        let suffix = length.div_ceil(3).min(ACTIONS - 2);
        let covered = length - suffix;
        let middle = covered.div_ceil(2);
        if let (Some(first), Some(second)) = (
            self.segment(0, middle, false),
            self.segment(middle, covered, false),
        ) && first.question.resolution_id() != second.question.resolution_id()
        {
            return vec![vec![first, second]];
        }
        Vec::new()
    }

    fn segment(&self, start: usize, end: usize, assumption_order: bool) -> Option<Segment> {
        if end - start > ACTIONS {
            return None;
        }
        let steps = &self.path[start..end];
        let mut seen = BTreeSet::new();
        let mut inputs = std::iter::once(steps[0].premise)
            .chain(steps.iter().map(|step| step.universal))
            .filter(|id| seen.insert(*id))
            .collect::<Vec<_>>();
        if inputs.len() > ACTION_PREMISES {
            return None;
        }
        if assumption_order {
            inputs.sort_unstable();
        }
        let result = self.facts[self.scope.assumptions.len() + end - 1].clone();
        let opened = inputs.iter().rev().fold(result, |body, &premise| {
            Formula::implies(self.facts[premise as usize].clone(), body)
        });
        let question = ResearchQuestion::from_formula(proof::close(opened.clone())).ok()?;
        Some(Segment {
            end,
            inputs,
            opened,
            question,
        })
    }
}

impl Route {
    fn plan(self, sources: Vec<(ProofId, Segment)>) -> Plan {
        let count = sources.len() as u32;
        let base = self.scope.assumptions.len() as u32;
        let end = sources.last().expect("nonempty cut sources").1.end;
        let mut actions = Vec::new();
        for (i, (_, segment)) in sources.iter().enumerate() {
            actions.push(ScopedAction::Instantiate {
                universal: i as u32,
                replacement: unused(&segment.opened).identifier(),
                premises: segment
                    .inputs
                    .iter()
                    .map(|&premise| {
                        if premise < base {
                            premise + count
                        } else {
                            base + count + i as u32 - 1
                        }
                    })
                    .collect(),
            });
        }
        for (offset, step) in self.path[end..].iter().enumerate() {
            actions.push(ScopedAction::Instantiate {
                universal: step.universal + count,
                replacement: step.replacement,
                premises: vec![base + 2 * count + offset as u32 - 1],
            });
        }
        let length = self.path.len();
        Plan {
            scope: self.scope,
            work: length + sources.len() + length - end,
            sources: sources
                .into_iter()
                .map(|(proof, segment)| (proof, segment.opened))
                .collect(),
            actions,
        }
    }
}

fn unused(formula: &Formula) -> FreeVariable {
    let used = formula.free_variables();
    (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|variable| !used.contains(variable))
        .expect("bounded cut variables")
}

impl Plan {
    pub(crate) fn work(&self) -> usize {
        self.work
    }

    pub(crate) fn commands(&self) -> Vec<Command> {
        let variables = self
            .sources
            .iter()
            .map(|(_, opened)| (opened.free_variables(), unused(opened)))
            .collect::<Vec<_>>();
        let assumptions = self
            .sources
            .iter()
            .zip(&variables)
            .map(|((_, opened), (_, unused))| Formula::for_all(*unused, opened.clone()))
            .chain(self.scope.assumptions.iter().cloned())
            .map(ProofFormula::from)
            .collect::<Vec<_>>();
        let mut commands = Projection::scoped(
            &assumptions,
            &self.actions,
            (assumptions.len() + self.actions.len() - 1) as u32,
            &[],
        );
        let Some(Command::Seal {
            proof: mut conclusion,
        }) = commands.pop()
        else {
            unreachable!()
        };
        for ((helper, _), (used, unused)) in self.sources.iter().zip(&variables) {
            let mut supplied = commands.len() as u64;
            commands.push(Command::ProofReference {
                proof_id: *helper.as_bytes(),
            });
            for variable in used {
                let index = commands.len() as u64;
                commands.push(Command::Instantiate {
                    premise: supplied,
                    replacement: variable.identifier(),
                });
                supplied = index;
            }
            let general = commands.len() as u64;
            commands.push(Command::Generalization {
                premise: supplied,
                variable: unused.identifier(),
            });
            let index = commands.len() as u64;
            commands.push(Command::ModusPonens {
                premise: general,
                implication: conclusion,
            });
            conclusion = index;
        }
        for variable in self.scope.binders.iter().rev() {
            let index = commands.len() as u64;
            commands.push(Command::Generalization {
                premise: conclusion,
                variable: variable.identifier(),
            });
            conclusion = index;
        }
        commands.push(Command::Seal { proof: conclusion });
        commands
    }
}
