//! Exact local closure using one retained, checker-owned proof program.
use super::{FACTS, Formula, FreeVariable, Scope, ScopedAction};
use crate::{
    Error, Graph,
    jobs::CatalogSource,
    learning::{GenerationCost, Solution, peer, search::Tree},
};
use naome_checker::{ContextView, context::BucketKind, question};
use naome_proof::{ArtifactId, ProofId};
use std::time::Instant;

const BINDERS: usize = 4;
const PREMISES: usize = 4;
const CANDIDATES: usize = 4;

fn open_catalog_scope(target: &Formula) -> Result<Option<Scope>, Error> {
    Ok(Scope::open(target)?.filter(|scope| scope.assumptions.len() + BINDERS + 1 < FACTS))
}

fn exact_operands(
    lemma: &Formula,
    goal: &Formula,
    inputs: usize,
) -> Result<Option<Vec<FreeVariable>>, Error> {
    if !lemma.is_closed() {
        return Ok(None);
    }
    Ok(question::universal_operands(lemma, goal, BINDERS)?
        .filter(|operands| !operands.is_empty() && inputs + operands.len() < FACTS))
}

fn retained_program(graph: &Graph, proof: ProofId) -> Result<Option<CatalogSource>, Error> {
    let Some(manifest) = graph.program_manifest(ArtifactId::from(proof))? else {
        return Ok(None);
    };
    graph
        .peer_program(manifest)?
        .map(CatalogSource::new)
        .transpose()
}

fn indexed_program(
    graph: &Graph,
    goal: &Formula,
    matches: impl Fn(&Formula) -> Result<bool, Error>,
) -> Result<Option<CatalogSource>, Error> {
    let context = graph.checked_context();
    let key = question::universal_pattern(goal)?;
    for statement in context.bucket(BucketKind::Instances, key)?.take(CANDIDATES) {
        let statement = statement?;
        let Some(header) = context.statement_header(statement)? else {
            continue;
        };
        let length = header.canonical_length();
        if length > question::QUESTION_BYTES {
            continue;
        }
        let Some(lemma) = context.statement_formula_from_header(statement, header, length)? else {
            continue;
        };
        if matches(&lemma)?
            && let Some(source) = retained_program(graph, header.proof_id())?
        {
            return Ok(Some(source));
        }
    }
    Ok(None)
}

fn closing_premises(
    scope: &Scope,
    skip: usize,
) -> impl Iterator<Item = (u32, FreeVariable, Formula)> + '_ {
    scope
        .assumptions
        .iter()
        .enumerate()
        .skip(skip)
        .filter_map(|(index, rule)| {
            let mut used = rule.free_variables();
            used.extend(scope.goal.free_variables());
            let variable = (0..=u32::MAX)
                .map(FreeVariable::new)
                .find(|v| !used.contains(v))?;
            let opened = rule.open_outer_universal(variable)?;
            let (premise, conclusion) = opened.view().implication_parts()?;
            let pattern = Formula::for_all(variable, conclusion.to_owned());
            let operands = question::universal_operands(&pattern, &scope.goal, 1).ok()??;
            let replacement = operands[0];
            Some((
                index as u32,
                replacement,
                premise.to_owned().substitute_free(variable, replacement),
            ))
        })
        .take(PREMISES)
}

impl CatalogSource {
    /// Questions whose proved instances can discharge the catalog route's
    /// closing premises. A proposal contains no proof or claim of solvability.
    pub(crate) fn cut_questions(target: &Formula) -> Vec<question::ResearchQuestion> {
        let Ok(Some(scope)) = open_catalog_scope(target) else {
            return Vec::new();
        };
        closing_premises(&scope, 0)
            .filter_map(|(_, _, premise)| {
                let free = premise.free_variables();
                if free.len() > BINDERS || !free.iter().all(|name| scope.binders.contains(name)) {
                    return None;
                }
                let closed = scope
                    .binders
                    .iter()
                    .rev()
                    .filter(|name| free.contains(name))
                    .fold(premise.clone(), |body, name| Formula::for_all(*name, body));
                question::universal_operands(&closed, &premise, BINDERS).ok()??;
                question::ResearchQuestion::from_formula(closed).ok()
            })
            .collect()
    }

    /// A checked universal can close the opened consequent without using a
    /// local hypothesis. The worker reconstructs the same specialization from
    /// the retained program before publishing any proof.
    pub(crate) fn for_exact_local_scope(
        graph: &Graph,
        question: &question::ResearchQuestion,
    ) -> Result<Option<Self>, Error> {
        if crate::learning::curriculum::reserved(&crate::hex(question.resolution_id())) {
            return Ok(None);
        }
        let Ok(_memory) = crate::resources::MemoryLease::acquire(question::QUESTION_BYTES * 16)
        else {
            return Ok(None);
        };
        let scope = Scope::decompose(question.proved_target(), None)?;
        let inputs = scope.assumptions.len() + 1;
        if inputs >= FACTS {
            return Ok(None);
        }
        indexed_program(graph, &scope.goal, |lemma| {
            Ok(exact_operands(lemma, &scope.goal, inputs)?.is_some())
        })
    }

    pub(crate) fn for_local_scope(graph: &Graph, target: &Formula) -> Result<Option<Self>, Error> {
        let Ok(_memory) = crate::resources::MemoryLease::acquire(question::QUESTION_BYTES * 16)
        else {
            return Ok(None);
        };
        let Some(scope) = open_catalog_scope(target)? else {
            return Ok(None);
        };
        for (_, _, premise) in closing_premises(&scope, 0) {
            if let Some(source) = indexed_program(graph, &premise, |lemma| {
                Ok(question::universal_operands(lemma, &premise, BINDERS)?.is_some())
            })? {
                return Ok(Some(source));
            }
        }
        Ok(None)
    }

    /// Reuse exactly the program selected by a checked single-helper plan.
    pub(crate) fn for_planned_local_scope(
        graph: &Graph,
        target: &Formula,
        proof: ProofId,
    ) -> Result<Option<Self>, Error> {
        let Ok(_memory) = crate::resources::MemoryLease::acquire(question::QUESTION_BYTES * 16)
        else {
            return Ok(None);
        };
        let Some(scope) = open_catalog_scope(target)? else {
            return Ok(None);
        };
        let context = graph.checked_context();
        let Some(header) = context.proof_header(proof)? else {
            return Ok(None);
        };
        let bytes = header.canonical_length();
        if bytes > question::QUESTION_BYTES {
            return Ok(None);
        }
        let Some(lemma) = context.proof_formula(header, bytes)? else {
            return Ok(None);
        };
        for (_, _, premise) in closing_premises(&scope, 0) {
            if question::universal_operands(&lemma, &premise, BINDERS)?.is_some() {
                return retained_program(graph, proof);
            }
        }
        Ok(None)
    }

    pub(crate) fn supports(&self, solution: &Solution) -> Result<bool, Error> {
        let Tree::Program(packet) = &solution.tree else {
            return Ok(false);
        };
        Ok(!solution.refuted
            && peer::contributing_proofs(&packet.commands()?)?.contains(&self.proof_id()))
    }

    pub(crate) fn solve_local_scope(&self, source: &str) -> Result<Option<Solution>, Error> {
        let started = Instant::now();
        let question = question::ResearchQuestion::from_hex(source)?;
        if crate::learning::curriculum::reserved(&crate::hex(question.resolution_id())) {
            return Ok(None);
        }
        let target = question.proved_target();
        let lemma = self.packet().target()?;
        let scope = Scope::decompose(target, Some(&lemma))?;
        let inputs = scope.assumptions.len();
        let (operands, closing) =
            if let Some(operands) = exact_operands(&lemma, &scope.goal, inputs)? {
                (operands, None)
            } else {
                if !scope.supports_standard_search() {
                    return Err(crate::ResearchFailure::OfferedProofBinding.into());
                }
                let mut selected = None;
                for (universal, replacement, premise) in closing_premises(&scope, 1) {
                    let Some(operands) = question::universal_operands(&lemma, &premise, BINDERS)?
                    else {
                        continue;
                    };
                    if inputs + operands.len() < FACTS {
                        selected = Some((operands, Some((universal, replacement))));
                        break;
                    }
                }
                selected.ok_or(crate::ResearchFailure::OfferedProofBinding)?
            };
        let mut cited = 0;
        let mut actions = Vec::new();
        for operand in operands {
            actions.push(ScopedAction::Instantiate {
                universal: cited,
                replacement: operand.identifier(),
                premises: Vec::new(),
            });
            cited = (inputs + actions.len() - 1) as u32;
        }
        if let Some((universal, replacement)) = closing {
            actions.push(ScopedAction::Instantiate {
                universal,
                replacement: replacement.identifier(),
                premises: vec![cited],
            });
        }
        let commands = scope
            .program(&actions, &[self.proof_id()])
            .ok_or(crate::ResearchFailure::OfferedProofBinding)?;
        let packet =
            peer::Packet::compose(target, &commands, std::slice::from_ref(self.packet()), [])?;
        Ok(crate::learning::program_generation(
            packet,
            Vec::new(),
            target,
            false,
            GenerationCost {
                search_expansions: actions.len() + 1,
                retrieved_lemmas: 1,
                generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                ..GenerationCost::default()
            },
            Vec::new(),
        )?
        .solution)
    }
}
