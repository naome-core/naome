//! Generate a bounded native deduction one operation and operand at a time.
use super::*;
use crate::learning::{
    SolveContext, TypedGenerationCost as Work, construction::ProgramCandidate, definitions,
    knowledge, peer::Packet, prerequisites::ProgramInputs, proof,
};
use naome_checker::{ContextView, question::QUESTION_BYTES};

mod replay;
use naome_proof::{
    ProofId,
    program::{ACTION_PREMISES, Axiom, ScopedInput},
};
pub(in crate::learning) use replay::graphs;

#[derive(Clone, Copy)]
enum Source {
    Axiom(Axiom),
    Snapshot(usize, ProofId),
    Input(ProofId),
}
impl From<Source> for ScopedInput {
    fn from(source: Source) -> Self {
        match source {
            Source::Axiom(axiom) => Self::Axiom(axiom),
            Source::Snapshot(_, id) | Source::Input(id) => Self::Proof(id),
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Conjoin,
    Instantiate,
}

struct Choice<T> {
    value: T,
    rule: Rule,
    operand: usize,
    replacement: Option<FreeVariable>,
    effect: Formula,
}
impl<T> Choice<T> {
    fn new(value: T, rule: Rule, operand: usize, effect: &Formula) -> Self {
        Self {
            value,
            rule,
            operand,
            replacement: None,
            effect: effect.clone(),
        }
    }
}

struct ProjectionResult {
    commands: Vec<Command>,
    sources: Vec<Source>,
    helpers: Vec<String>,
}

enum Selection<'a> {
    Model {
        ranker: &'a mut dyn Ranker,
        started: Instant,
    },
    Checked(Vec<Graph>),
}

struct Decoder<'a> {
    scope: Scope,
    // Local assumptions, then external sources, then generated facts.
    facts: Vec<Formula>,
    sources: Vec<Source>,
    actions: Vec<ScopedAction>,
    goals: Vec<Formula>,
    selection: Selection<'a>,
    work: Work,
}

impl Decoder<'_> {
    fn within_time(&self) -> bool {
        match self.selection {
            Selection::Model { started, .. } => started.elapsed() < TIME_LIMIT,
            Selection::Checked(_) => true,
        }
    }

    fn pick<T>(
        &mut self,
        mut choices: Vec<Choice<T>>,
        checked: impl Fn(&T) -> bool,
    ) -> Result<Option<T>, crate::Error> {
        if !self.within_time() || choices.is_empty() {
            return Ok(None);
        }
        let replay = matches!(self.selection, Selection::Checked(_));
        if choices.len() == 1 {
            return Ok(choices
                .pop()
                .filter(|choice| !replay || checked(&choice.value))
                .map(|choice| choice.value));
        }
        // Prefer exact closure in the bounded view. The model selects from
        // typed fields of the current prefix, using decision-local addresses.
        choices.sort_by_key(|choice| choice.effect != self.scope.goal);
        choices.truncate(OFFERS);
        let expert = if replay {
            let Some(index) = choices.iter().position(|choice| checked(&choice.value)) else {
                return Ok(None);
            };
            index
        } else {
            0
        };
        let operands: Vec<_> = choices
            .iter()
            .map(|choice| choice.operand)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let decision = Decision {
            context: operands
                .iter()
                .map(|&i| Binding {
                    formula: self.facts[i].clone(),
                })
                .collect(),
            goal: self.scope.goal.clone(),
            candidates: choices
                .iter()
                .map(|choice| Candidate {
                    rule: choice.rule,
                    premises: vec![
                        operands
                            .binary_search(&choice.operand)
                            .expect("typed operand"),
                    ],
                    replacement: choice.replacement,
                    consequences: vec![choice.effect.clone()],
                })
                .collect(),
            expert,
        };
        let ranker = match &mut self.selection {
            Selection::Model { ranker, .. } => ranker,
            Selection::Checked(graphs) => {
                match Graph::encode(&decision) {
                    Ok(graph) => graphs.push(graph),
                    Err(crate::LearningGraphFailure::Capacity) => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
                return Ok(Some(choices.swap_remove(expert).value));
            }
        };
        let scores = match ranker.scores(&decision) {
            Ok(scores) => scores,
            Err(crate::Error::LearningGraph(crate::LearningGraphFailure::Capacity)) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        self.work.model_decisions += 1;
        if scores.len() != choices.len() || scores.iter().any(|score| !score.is_finite()) {
            return Err(crate::ResearchFailure::ScopeInvalidScores.into());
        }
        let index = (0..scores.len())
            .max_by(|&a, &b| scores[a].total_cmp(&scores[b]).then(b.cmp(&a)))
            .expect("nonempty choices");
        Ok(Some(choices.swap_remove(index).value))
    }

    fn needed(&self, formula: &Formula) -> bool {
        self.goals.contains(formula) && !self.facts.contains(formula)
    }

    /// Determine which replacements have a type-correct continuation to an
    /// open goal. Only types are tested here. Premise addresses are selected
    /// later, once the universal and its replacement have been chosen.
    fn replacements(&self, formula: &Formula) -> Vec<(FreeVariable, Formula)> {
        let Some(universal) = instantiation::Universal::new(formula) else {
            return Vec::new();
        };
        let variables = self.scope.binders.iter().copied().chain(
            self.scope
                .binders
                .is_empty()
                .then_some(FreeVariable::new(0)),
        );
        variables
            .filter_map(|variable| {
                let mut effect = universal.instance(variable);
                for consumed in 0..=ACTION_PREMISES {
                    if self.needed(&effect) {
                        return Some((variable, effect));
                    }
                    if consumed == ACTION_PREMISES {
                        break;
                    }
                    let (premise, result) = effect.view().implication_parts()?;
                    if !self.facts.iter().any(|fact| fact.view() == premise) {
                        break;
                    }
                    effect = result.to_owned();
                }
                None
            })
            .collect()
    }

    fn add_source(&mut self, source: Source, formula: Formula) {
        if self.facts.len() < FACTS - 1 && !self.facts.contains(&formula) {
            self.sources.push(source);
            self.facts.push(formula);
        }
    }

    fn next(
        &mut self,
        checked: Option<&ScopedAction>,
    ) -> Result<Option<ScopedAction>, crate::Error> {
        use crate::learning::construction::logic::conjunction;
        if !self.within_time() {
            return Ok(None);
        }
        let conjunctions: Vec<_> = self
            .goals
            .iter()
            .filter(|goal| self.needed(goal))
            .filter_map(|goal| conjunction(goal).map(|(left, right)| (left, right, goal.clone())))
            .filter(|(_, right, _)| self.facts.contains(right))
            .collect();
        let lefts: Vec<_> = self
            .facts
            .iter()
            .enumerate()
            .filter_map(|(index, fact)| {
                let (_, _, goal) = conjunctions.iter().find(|(left, _, _)| left == fact)?;
                Some(Choice::new(index, Rule::ConstructionPlan, index, goal))
            })
            .collect();
        let mut replacements = Vec::with_capacity(self.facts.len());
        let mut universals = Vec::new();
        for (index, formula) in self.facts.iter().enumerate() {
            let choices = self.replacements(formula);
            if let Some((_, effect)) = choices.first() {
                universals.push(Choice::new(index, Rule::UniversalInstance, index, effect));
            }
            replacements.push(choices);
        }
        let operations = [
            (Operation::Conjoin, lefts.first()),
            (Operation::Instantiate, universals.first()),
        ]
        .into_iter()
        .filter_map(|(operation, example)| {
            let example = example?;
            Some(Choice::new(
                operation,
                example.rule,
                example.operand,
                &example.effect,
            ))
        })
        .collect();
        match self.pick(operations, |operation| {
            matches!(
                (operation, checked),
                (Operation::Conjoin, Some(ScopedAction::Conjoin { .. }))
                    | (
                        Operation::Instantiate,
                        Some(ScopedAction::Instantiate { .. })
                    )
            )
        })? {
            Some(Operation::Conjoin) => {
                let Some(left) = self.pick(lefts, |index| matches!(checked, Some(ScopedAction::Conjoin { left, .. }) if *left as usize == *index))? else {
                    return Ok(None);
                };
                let rights = self
                    .facts
                    .iter()
                    .enumerate()
                    .filter_map(|(index, fact)| {
                        let (_, _, goal) = conjunctions
                            .iter()
                            .find(|(lhs, rhs, _)| lhs == &self.facts[left] && rhs == fact)?;
                        Some(Choice::new(index, Rule::ConstructionPlan, index, goal))
                    })
                    .collect();
                Ok(self.pick(rights, |index| matches!(checked, Some(ScopedAction::Conjoin { right, .. }) if *right as usize == *index))?.map(|right| ScopedAction::Conjoin {
                    left: left as u32,
                    right: right as u32,
                }))
            }
            Some(Operation::Instantiate) => {
                let Some(universal) = self.pick(universals, |index| matches!(checked, Some(ScopedAction::Instantiate { universal, .. }) if *universal as usize == *index))? else {
                    return Ok(None);
                };
                self.instantiate(
                    universal,
                    std::mem::take(&mut replacements[universal]),
                    checked,
                )
            }
            None => Ok(None),
        }
    }

    fn instantiate(
        &mut self,
        universal: usize,
        replacements: Vec<(FreeVariable, Formula)>,
        checked: Option<&ScopedAction>,
    ) -> Result<Option<ScopedAction>, crate::Error> {
        let choices = replacements
            .into_iter()
            .map(|(variable, effect)| Choice {
                replacement: Some(variable),
                rule: Rule::UniversalInstance,
                operand: universal,
                effect: effect.clone(),
                value: (variable, effect),
            })
            .collect();
        let checked_effect = checked.and_then(|action| self.scope.apply(&self.facts, action));
        let Some((replacement, wanted)) = self.pick(choices, |(variable, effect)| {
            matches!(checked, Some(ScopedAction::Instantiate { replacement, .. })
                if *replacement == variable.identifier() && checked_effect.as_ref() == Some(effect))
        })?
        else {
            return Ok(None);
        };
        let mut result = instantiation::Universal::new(&self.facts[universal])
            .expect("typed universal")
            .instance(replacement);
        let mut premises = Vec::new();
        while result != wanted {
            let Some((antecedent, consequent)) = result.view().implication_parts() else {
                return Ok(None);
            };
            if premises.len() == ACTION_PREMISES {
                return Ok(None);
            }
            let consequence = consequent.to_owned();
            let choices = self
                .facts
                .iter()
                .enumerate()
                .filter(|(_, fact)| fact.view() == antecedent)
                .map(|(index, _)| Choice::new(index, Rule::ModusPonens, index, &consequence))
                .collect();
            let Some(premise) = self.pick(choices, |index| {
                matches!(checked, Some(ScopedAction::Instantiate { premises: expected, .. })
                    if expected.get(premises.len()).copied() == Some(*index as u32))
            })?
            else {
                return Ok(None);
            };
            premises.push(premise as u32);
            result = consequence;
        }
        Ok(Some(ScopedAction::Instantiate {
            universal: universal as u32,
            replacement: replacement.identifier(),
            premises,
        }))
    }

    fn project(
        &mut self,
        entries: &[definitions::Entry],
    ) -> Result<Option<ProjectionResult>, crate::Error> {
        let locals = self.scope.assumptions.len();
        let inputs = locals + self.sources.len();
        let used = used_facts(inputs, &self.actions)
            .ok_or(crate::ResearchFailure::ScopeProgramOperands)?;
        let imports = (locals..inputs).filter(|&i| used[i]).collect::<Vec<_>>();
        let retained = imports.len() + locals;
        let mut positions = vec![None; inputs];
        let mut assumptions = Vec::with_capacity(retained);
        let mut helpers = Vec::new();
        for (position, index) in imports.iter().copied().chain(0..locals).enumerate() {
            positions[index] = Some(position as u32);
            let formula = self.facts[index].clone();
            let mut choices = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                if let Some(application) =
                    definitions::application(&formula, std::slice::from_ref(entry))?
                {
                    choices.push(Choice::new(
                        (i, ProofFormula::from_defined(application)?),
                        Rule::DefinitionReference,
                        index,
                        &entry.body()?,
                    ));
                }
            }
            if choices.is_empty() {
                assumptions.push(ProofFormula::from(formula));
            } else {
                let Some((selected, representation)) = self.pick(choices, |_| false)? else {
                    return Ok(None);
                };
                definitions::append_artifacts(&entries[selected..=selected], &mut helpers)?;
                assumptions.push(representation);
            }
        }
        let sources: Vec<_> = imports.iter().map(|&i| self.sources[i - locals]).collect();
        let actions = retain_actions(positions, retained, &self.actions, &used)
            .ok_or(crate::ResearchFailure::ScopeProgramOperands)?;
        let commands = Projection::scoped_with_inputs(
            &assumptions,
            &actions,
            (retained + actions.len() - 1) as u32,
            &self.scope.binders,
            sources.iter().copied().map(ScopedInput::from),
        );
        Ok(Some(ProjectionResult {
            commands,
            sources,
            helpers,
        }))
    }
}

fn supported_goal(scope: &Scope) -> bool {
    crate::learning::construction::logic::conjunction(&scope.goal).is_some()
        || demand::atomic(&scope.goal) && scope.supports_standard_search()
}

/// Exact checked statements that can serve as typed operands in this scope.
pub(crate) fn context_goals(target: &Formula) -> Result<Vec<Formula>, crate::Error> {
    let scope = Scope::decompose(target, None)?;
    if scope.assumptions.len() >= FACTS - 1 || !supported_goal(&scope) {
        return Ok(Vec::new());
    }
    let mut requested = Vec::new();
    for goal in demand::goals(&scope, &scope.assumptions)
        .into_iter()
        .skip(1)
    {
        if &goal != target && !requested.contains(&goal) {
            requested.push(goal);
        }
    }
    Ok(requested)
}

pub(in crate::learning) fn attempt(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
    context: &SolveContext<'_>,
) -> Result<(Option<ProgramCandidate>, Work), crate::Error> {
    if maximum == 0 || started.elapsed() >= TIME_LIMIT {
        return Ok((None, Work::default()));
    }
    let scope = Scope::decompose(target, None)?;
    if scope.assumptions.len() >= FACTS - 1 || !supported_goal(&scope) {
        return Ok((None, Work::default()));
    }
    let _memory = crate::resources::MemoryLease::acquire(8 * FACTS * QUESTION_BYTES)?;
    // Leave a closing action already supplied by the original scope search
    // on its fast path.
    if scope.supports_standard_search()
        && scope
            .offers(&scope.assumptions)
            .0
            .iter()
            .any(|(_, result)| result == &scope.goal)
    {
        return Ok((None, Work::default()));
    }
    let mut decoder = Decoder {
        facts: scope.assumptions.clone(),
        scope,
        sources: Vec::new(),
        actions: Vec::new(),
        goals: Vec::new(),
        selection: Selection::Model { ranker, started },
        work: Work::default(),
    };

    let proofs = knowledge::checked_entries(context.theorems)?;
    for (index, entry) in proofs.iter().enumerate() {
        decoder.add_source(Source::Snapshot(index, entry.id), entry.target.clone());
    }
    let inputs = context
        .prerequisites
        .filter(|inputs| !inputs.is_empty() && inputs.cut_certificate().is_none())
        .map(|inputs| inputs.checked_program_inputs())
        .transpose()?;
    if let Some(inputs) = &inputs {
        add_checked_inputs(&mut decoder, inputs)?;
    }
    for axiom in [
        Axiom::Extensionality,
        Axiom::Pairing,
        Axiom::Union,
        Axiom::PowerSet,
        Axiom::Infinity,
        Axiom::Foundation,
        Axiom::Choice,
    ] {
        decoder.add_source(
            Source::Axiom(axiom),
            naome_foundation::ZfcAxiom::from(axiom).formula(),
        );
    }

    decoder.goals = demand::goals(&decoder.scope, &decoder.facts);
    for _ in 0..maximum.min(ACTIONS).min(FACTS - decoder.facts.len()) {
        let Some(action) = decoder.next(None)? else {
            break;
        };
        decoder.work.actions += 1;
        let effect = decoder
            .scope
            .apply(&decoder.facts, &action)
            .ok_or(crate::ResearchFailure::ScopeProgramOperands)?;
        decoder.actions.push(action);
        if effect != decoder.scope.goal {
            decoder.facts.push(effect);
            continue;
        }
        let Some(ProjectionResult {
            commands,
            sources,
            mut helpers,
        }) = decoder.project(context.definitions)?
        else {
            break;
        };
        let mut used_inputs = false;
        for source in sources {
            match source {
                Source::Snapshot(index, _) => {
                    let verified = proofs[index].entry.verified()?;
                    for source in knowledge::helpers(&verified)?
                        .into_iter()
                        .chain([proof::source(&verified)])
                    {
                        if !helpers.contains(&source) {
                            helpers.push(source);
                        }
                    }
                }
                Source::Input(_) => used_inputs = true,
                Source::Axiom(_) => (),
            }
        }
        let artifacts = helpers
            .iter()
            .map(|source| crate::unhex(source).map(std::sync::Arc::from))
            .collect::<Result<Vec<_>, _>>()?;
        let (programs, input_artifacts) = inputs
            .filter(|_| used_inputs)
            .map_or((&[][..], Vec::new()), ProgramInputs::into_sources);
        let work = decoder.work;
        drop(decoder);
        drop(proofs);
        drop(_memory);
        let packet = Packet::compose(
            target,
            &commands,
            programs,
            input_artifacts
                .into_iter()
                .map(|input| input.bytes.clone())
                .chain(artifacts),
        )?;
        return Ok((Some(ProgramCandidate { packet, helpers }), work));
    }
    Ok((None, decoder.work))
}

fn add_checked_inputs(
    decoder: &mut Decoder<'_>,
    inputs: &ProgramInputs<'_>,
) -> Result<(), crate::Error> {
    for id in inputs.proof_ids() {
        if decoder.facts.len() == FACTS - 1 || !decoder.within_time() {
            break;
        }
        let id = id?;
        let Some(header) = inputs.context.proof_header(id)? else {
            return Err(crate::ResearchFailure::ScopeCitationMissing.into());
        };
        if header.canonical_length() > QUESTION_BYTES {
            continue;
        }
        let formula = inputs
            .context
            .proof_formula(header, header.canonical_length())?
            .ok_or(crate::ResearchFailure::ScopeCitationFormulaMissing)?;
        if formula.is_closed() {
            decoder.add_source(Source::Input(id), formula.into_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
