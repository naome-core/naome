//! Checked prefix reuse for a transport that exceeds one local search scope.
use super::{
    ACTIONS, BTreeSet, Command, FACTS, Formula, FreeVariable, Projection, ProofFormula, Scope,
    ScopedAction, demand,
};
use crate::learning::proof;
use naome_checker::question::ResearchQuestion;

pub(crate) fn question(target: &Formula) -> Option<ResearchQuestion> {
    plan(target).map(|cut| cut.question)
}

pub(crate) struct Plan {
    scope: Scope,
    path: Vec<ScopedAction>,
    split: usize,
    inputs: Vec<u32>,
    variables: Vec<FreeVariable>,
    opened: Formula,
    pub(crate) question: ResearchQuestion,
}

pub(crate) fn plan(target: &Formula) -> Option<Plan> {
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
    // One local action consumes the verified prefix; the suffix gets the
    // remaining actions of the existing scope allowance.
    let split = path.len() - (ACTIONS - 1);

    let mut inputs = BTreeSet::new();
    for (index, action) in path[..split].iter().enumerate() {
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
    let opened = inputs
        .iter()
        .rev()
        .fold(facts[base + split - 1].clone(), |result, &premise| {
            Formula::implies(scope.assumptions[premise as usize].clone(), result)
        });
    let variables = opened.free_variables().into_iter().collect::<Vec<_>>();
    let question = ResearchQuestion::from_formula(proof::close(opened.clone())).ok()?;
    Some(Plan {
        scope,
        path,
        split,
        inputs,
        variables,
        opened,
        question,
    })
}

impl Plan {
    pub(crate) fn work(&self) -> usize {
        self.path.len() + self.path.len() - self.split + 1
    }

    pub(crate) fn commands(&self, helper: naome_proof::ProofId) -> Vec<Command> {
        let used = self.opened.free_variables();
        let unused = (0..=u32::MAX)
            .map(FreeVariable::new)
            .find(|variable| !used.contains(variable))
            .expect("bounded cut variables");
        let prefix = Formula::for_all(unused, self.opened.clone());
        let assumptions = std::iter::once(prefix)
            .chain(self.scope.assumptions.iter().cloned())
            .map(ProofFormula::from)
            .collect::<Vec<_>>();
        let mut actions = vec![ScopedAction::Instantiate {
            universal: 0,
            replacement: unused.identifier(),
            premises: self.inputs.iter().map(|x| x + 1).collect(),
        }];
        for (offset, action) in self.path[self.split..].iter().enumerate() {
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
        for variable in &self.variables {
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
