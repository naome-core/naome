//! Checked prefix reuse for a transport that exceeds one local search scope.
use super::{
    ACTIONS, BTreeSet, Command, FACTS, Formula, FreeVariable, Projection, ProofFormula, Scope,
    ScopedAction, demand,
};
use crate::learning::proof;
use naome_checker::question::ResearchQuestion;

pub(crate) fn questions(target: &Formula) -> Vec<ResearchQuestion> {
    route(target).map_or_else(Vec::new, |route| {
        route.splits().map(|prefix| prefix.question).collect()
    })
}

pub(crate) fn plan(target: &Formula, helper: &Formula) -> Option<Plan> {
    let route = route(target)?;
    let prefix = route
        .splits()
        .find(|prefix| prefix.question.proved_target() == helper)?;
    Some(Plan { route, prefix })
}

struct Route {
    scope: Scope,
    path: Vec<ScopedAction>,
    facts: Vec<Formula>,
}

pub(crate) struct Plan {
    route: Route,
    prefix: Prefix,
}

struct Prefix {
    split: usize,
    inputs: Vec<u32>,
    variables: Vec<FreeVariable>,
    opened: Formula,
    question: ResearchQuestion,
}

fn route(target: &Formula) -> Option<Route> {
    let scope = Scope::open(target).ok().flatten()?;
    let mut facts = scope.assumptions.clone();
    let base = facts.len();
    if base >= naome_proof::program::SCOPE_ASSUMPTIONS {
        return None;
    }
    let mut path = Vec::new();
    let maximum = ACTIONS + naome_proof::program::ACTION_PREMISES - 2;
    for _ in 0..maximum.min(FACTS - base) {
        let (action, derived) = demand::offers(&scope.goal, &facts).into_iter().next()?;
        path.push(action);
        facts.push(derived.clone());
        if derived == scope.goal {
            break;
        }
    }
    if path.len() <= ACTIONS || facts.last() != Some(&scope.goal) {
        return None;
    }
    for (i, action) in path.iter().enumerate() {
        let ScopedAction::Instantiate {
            universal,
            premises,
            ..
        } = action
        else {
            return None;
        };
        if *universal as usize >= base
            || premises.len() != 1
            || (i == 0 && premises[0] as usize >= base)
            || (i > 0 && premises[0] as usize != base + i - 1)
        {
            return None;
        }
    }
    Some(Route { scope, path, facts })
}

impl Route {
    fn splits(&self) -> impl Iterator<Item = Prefix> + '_ {
        // Each admissible cut spends one action to apply the proved prefix.
        // Neither the helper nor the remaining local deduction exceeds its
        // existing scope allowance.
        let first = self.path.len() - (ACTIONS - 1);
        let last = ACTIONS.min(self.path.len() - 1);
        (first..=last).filter_map(|split| self.prefix(split))
    }

    fn prefix(&self, split: usize) -> Option<Prefix> {
        let base = self.scope.assumptions.len();
        let mut inputs = BTreeSet::new();
        for (index, action) in self.path[..split].iter().enumerate() {
            let ScopedAction::Instantiate {
                universal,
                premises,
                ..
            } = action
            else {
                unreachable!()
            };
            inputs.insert(*universal);
            if index == 0 {
                inputs.insert(premises[0]);
            }
        }
        let inputs = inputs.into_iter().collect::<Vec<_>>();
        if inputs.len() > naome_proof::program::ACTION_PREMISES {
            return None;
        }
        let opened =
            inputs
                .iter()
                .rev()
                .fold(self.facts[base + split - 1].clone(), |result, &premise| {
                    Formula::implies(self.scope.assumptions[premise as usize].clone(), result)
                });
        let variables = opened.free_variables().into_iter().collect::<Vec<_>>();
        let question = ResearchQuestion::from_formula(proof::close(opened.clone())).ok()?;

        Some(Prefix {
            split,
            inputs,
            variables,
            opened,
            question,
        })
    }
}

impl Plan {
    pub(crate) fn work(&self) -> usize {
        self.route.path.len() + self.route.path.len() - self.prefix.split + 1
    }

    pub(crate) fn commands(&self, helper: naome_proof::ProofId) -> Vec<Command> {
        let used = self.prefix.opened.free_variables();
        let unused = (0..=u32::MAX)
            .map(FreeVariable::new)
            .find(|variable| !used.contains(variable))
            .expect("bounded cut variables");
        let prefix = Formula::for_all(unused, self.prefix.opened.clone());
        let assumptions = std::iter::once(prefix)
            .chain(self.route.scope.assumptions.iter().cloned())
            .map(ProofFormula::from)
            .collect::<Vec<_>>();
        let mut actions = vec![ScopedAction::Instantiate {
            universal: 0,
            replacement: unused.identifier(),
            premises: self.prefix.inputs.iter().map(|x| x + 1).collect(),
        }];
        for (offset, action) in self.route.path[self.prefix.split..].iter().enumerate() {
            let ScopedAction::Instantiate {
                universal,
                replacement,
                ..
            } = action
            else {
                unreachable!()
            };
            actions.push(ScopedAction::Instantiate {
                universal: universal + 1,
                replacement: *replacement,
                premises: vec![(assumptions.len() + offset) as u32],
            });
        }
        // Deduce with the instantiated prefix as its first assumption.
        // Then discharge that exact assumption with the checked reference.
        let mut commands = Projection::scoped(
            &assumptions,
            &actions,
            (assumptions.len() + actions.len() - 1) as u32,
            &[],
        );
        let Some(Command::Seal { proof: conditional }) = commands.pop() else {
            unreachable!()
        };
        let mut supplied = commands.len() as u64;
        commands.push(Command::ProofReference {
            proof_id: *helper.as_bytes(),
        });
        for variable in &self.prefix.variables {
            let index = commands.len() as u64;
            commands.push(Command::Instantiate {
                premise: supplied,
                replacement: variable.identifier(),
            });
            supplied = index;
        }
        commands.push(Command::Generalization {
            premise: supplied,
            variable: unused.identifier(),
        });
        let mut conclusion = commands.len() as u64;
        commands.push(Command::ModusPonens {
            premise: conclusion - 1,
            implication: conditional,
        });
        for variable in self.route.scope.binders.iter().rev() {
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
