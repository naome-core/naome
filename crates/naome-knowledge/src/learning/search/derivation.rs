//! Training structure reconstructed from independently checked complete proofs.
//! Observed search events are not inputs to this proof-producing boundary.
use super::*;

const STEPS: usize = 128;
const FRAGMENTS: usize = 2;
const FRAGMENT_BYTES: usize = trace::BYTES;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    pub graph: Graph,
    pub offered: String,
    /// A real preceding action and its selected symbolic child. A missing
    /// parent denotes the source root, never an inferred missing transition.
    pub parent: Option<(usize, usize)>,
    pub branch: Vec<usize>,
    pub action: Action,
    pub children: usize,
    pub remaining_steps: usize,
    pub witness: String,
    pub cited_proof: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Parent {
    Admitted {
        proof: String,
        tree: String,
    },
    Observed {
        job: u64,
        receipt: String,
        execution: String,
        event: usize,
        tree: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fragment {
    pub parent: Parent,
    pub source_target: String,
    pub branch: Vec<usize>,
    pub state: String,
    pub assumptions: Vec<String>,
    pub conclusion: String,
    pub closed_target: String,
    pub variables: Vec<u32>,
    pub proof_id: String,
    #[serde(with = "super::super::knowledge::packet")]
    pub packet: Vec<u8>,
}

fn encode(formula: &Formula) -> Result<String, crate::Error> {
    formula
        .encode_canonical()
        .map(|bytes| crate::hex(&bytes))
        .map_err(crate::Error::from)
}
fn decode(encoded: &str) -> Result<Formula, crate::Error> {
    let bytes = crate::object::unhex(encoded)?;
    if crate::hex(&bytes) != encoded {
        return Err(crate::ResearchFailure::FragmentFormulaEncoding.into());
    }
    Formula::decode_canonical(&bytes).map_err(crate::Error::from)
}

impl Fragment {
    fn within_capacity(&self) -> Result<bool, crate::Error> {
        // The canonical packet serializer enforces its own byte bound. Check
        // that bound first so an optional oversized derivation is omitted,
        // rather than aborting training from the valid complete source.
        Ok(self.packet.len() <= super::super::knowledge::BYTES
            && crate::checkpoint::encode(self)?.len() <= FRAGMENT_BYTES)
    }

    /// Verify the closed implication, including its complete native closure.
    /// The premises remain part of that implication, not globally true facts.
    pub fn verify(&self) -> Result<super::super::proof::Verified, crate::Error> {
        for id in [&self.source_target, &self.state, &self.proof_id] {
            crate::object::id_bytes(id)?;
        }
        match &self.parent {
            Parent::Admitted { proof, tree } => {
                crate::object::id_bytes(proof)?;
                crate::object::id_bytes(tree)?;
            }
            Parent::Observed {
                job,
                receipt,
                execution,
                tree,
                ..
            } => {
                if *job == 0 {
                    return Err(crate::ResearchFailure::FragmentObservedJob.into());
                }
                for id in [receipt, execution, tree] {
                    crate::object::id_bytes(id)?;
                }
            }
        }
        if self.branch.len() > 40
            || self.assumptions.len() > 32
            || !self.variables.windows(2).all(|w| w[0] < w[1])
            || !self.within_capacity()?
        {
            return Err(crate::ResearchFailure::FragmentCapacity.into());
        }
        let mut target = decode(&self.conclusion)?;
        for assumption in self.assumptions.iter().rev() {
            target = Formula::implies(decode(assumption)?, target);
        }
        if target
            .free_variables()
            .iter()
            .map(|v| v.identifier())
            .collect::<Vec<_>>()
            != self.variables
        {
            return Err(crate::ResearchFailure::FragmentVariableScope.into());
        }
        for variable in self.variables.iter().rev() {
            target = Formula::for_all(FreeVariable::new(*variable), target);
        }
        if decode(&self.closed_target)? != target {
            return Err(crate::ResearchFailure::FragmentClosedTarget.into());
        }
        let proof = super::super::evidence::checked(&self.packet)?;
        if proof.target != target || crate::hex(proof.native_id.as_bytes()) != self.proof_id {
            return Err(crate::ResearchFailure::FragmentIdentity.into());
        }
        Ok(proof)
    }

    /// Mathematical validity and source lineage are separate checks. A valid
    /// packet from another branch, scope or source cannot satisfy this binding.
    pub fn validate_source(
        &self,
        target: &Formula,
        tree: &Tree,
        native_id: &str,
    ) -> Result<(), crate::Error> {
        self.verify()?;
        if !matches!(&self.parent, Parent::Admitted { proof, tree: source } if proof == native_id && *source == super::super::digest(tree))
            || self.source_target != super::super::digest(&encode(target)?)
        {
            return Err(crate::ResearchFailure::FragmentSourceLineage.into());
        }
        let (source, mut node, mut state) = source(target, tree, native_id)?;
        for child in &self.branch {
            let Tree::Step { action, children } = node else {
                return Err(crate::ResearchFailure::FragmentBranchSource.into());
            };
            node = children
                .get(*child)
                .ok_or(crate::ResearchFailure::FragmentChild)?;
            state = next(&state, action)?
                .get(*child)
                .ok_or(crate::ResearchFailure::FragmentTransition)?
                .clone();
        }
        let expected = contextual(&source, node, &state, &self.branch)?;
        if super::super::digest(self) != super::super::digest(&expected) {
            return Err(crate::ResearchFailure::FragmentBranchBinding.into());
        }
        Ok(())
    }

    /// An observed parent supplies an exact context, not a complete root proof.
    /// Replay its stored transitions and check the conditional theorem afresh.
    pub fn validate_observation(
        &self,
        observation: &super::super::experience::Observation,
    ) -> Result<(), crate::Error> {
        self.verify()?;
        observation.validate()?;
        let Parent::Observed {
            job,
            receipt,
            execution,
            event,
            tree,
        } = &self.parent
        else {
            return Err(crate::ResearchFailure::FragmentObservedParent.into());
        };
        if *job != observation.summary.job
            || *receipt != observation.summary.receipt
            || !self.branch.is_empty()
        {
            return Err(crate::ResearchFailure::FragmentObservedReceipt.into());
        }
        let trace = observation
            .executions
            .iter()
            .find(|trace| super::super::digest(trace) == *execution)
            .ok_or(crate::ResearchFailure::FragmentExecutionMissing)?;
        let (_, state, subtree) = trace
            .closed_subtrees()?
            .into_iter()
            .find(|(index, _, _)| index == event)
            .ok_or(crate::ResearchFailure::FragmentClosedBranchMissing)?;
        if super::super::digest(&subtree) != *tree || trace.target != self.source_target {
            return Err(crate::ResearchFailure::FragmentObservedSubtree.into());
        }
        let question = naome_checker::question::ResearchQuestion::from_hex(&observation.question)
            .map_err(crate::Error::from)?;
        let target = observed_target(trace, &question)?;
        let knowledge = trace.context(&observation.knowledge)?;
        let source = Source {
            target,
            tree: &subtree,
            parent: self.parent.clone(),
            knowledge,
            citations: Vec::new(),
        };
        let expected = contextual(&source, &subtree, &state, &[])?;
        if super::super::digest(self) != super::super::digest(&expected) {
            return Err(crate::ResearchFailure::FragmentRecordedScope.into());
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Derivation {
    pub source_proof: Option<String>,
    pub source_tree: String,
    pub source_target: String,
    pub steps: Vec<Step>,
    pub fragments: Vec<Fragment>,
    pub omitted_steps: usize,
    pub fragment_attempts: usize,
    pub oversized_fragments: usize,
    pub rejected_fragments: Vec<u32>,
    /// Native certificates/constructions can remain valid without a supported
    /// tableau sequence. They keep their existing checked graph conversion.
    pub unsupported_sequence: bool,
}
impl Derivation {
    pub fn work_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.source_proof.as_ref().map_or(0, String::len)
            + self.source_tree.len()
            + self.source_target.len()
            + self
                .steps
                .iter()
                .map(|s| {
                    std::mem::size_of::<Step>()
                        + s.graph.work_bytes()
                        + s.witness.len()
                        + s.offered.len()
                        + s.branch.len() * std::mem::size_of::<usize>()
                        + s.cited_proof.as_ref().map_or(0, String::len)
                })
                .sum::<usize>()
            + self
                .fragments
                .iter()
                .map(|f| {
                    crate::checkpoint::encode(f)
                        .expect("finite checked fragment")
                        .len()
                })
                .sum::<usize>()
            + self.rejected_fragments.len() * std::mem::size_of::<u32>()
    }
}

struct Source<'a> {
    target: &'a Formula,
    tree: &'a Tree,
    parent: Parent,
    knowledge: Vec<Term>,
    citations: Vec<String>,
}

fn contextual(
    source: &Source<'_>,
    tree: &Tree,
    state: &State,
    branch: &[usize],
) -> Result<Fragment, crate::Error> {
    let mut names = Names::default();
    // The designated negated goal is discharged by RAA. Every other actual
    // fact remains an explicit antecedent, including branch assumptions.
    let negative = state
        .facts
        .iter()
        .rposition(|f| *f == c::not(state.goal.clone()))
        .ok_or(crate::ResearchFailure::FragmentNegatedGoal)?;
    let mut facts = Vec::new();
    let mut wrappers = Vec::new();
    let mut root = None;
    for (index, formula) in state.facts.iter().enumerate() {
        let (id, term) = names.assumption(formula.clone());
        facts.push(term);
        if index == negative {
            root = Some(id);
        } else {
            wrappers.push((id, formula.clone()));
        }
    }
    let (positive, negative) = replay(
        tree,
        state,
        &facts,
        &mut names,
        &mut Vec::new(),
        &source.knowledge,
        0,
    )?;
    let mut term = c::raa(
        state.goal.clone(),
        root.ok_or(crate::ResearchFailure::FragmentNegationBinding)?,
        positive,
        negative,
        &mut names,
    )?;
    for (id, formula) in wrappers.iter().rev() {
        term = Term::Lambda(*id, formula.clone(), Box::new(term));
    }
    let variables: Vec<_> = term.formula().free_variables().into_iter().collect();
    for variable in variables.iter().rev() {
        term = Term::Generalize(*variable, Box::new(term));
    }
    if !term.free_assumptions().is_empty() || !term.formula().free_variables().is_empty() {
        return Err(crate::ResearchFailure::FragmentOpenScope.into());
    }
    let checked = super::super::proof::verify(&term, &term.formula())?;
    let fragment = Fragment {
        parent: source.parent.clone(),
        source_target: super::super::digest(&encode(source.target)?),
        branch: branch.to_vec(),
        state: trace::binding(state)?,
        assumptions: wrappers
            .iter()
            .map(|(_, f)| encode(f))
            .collect::<Result<_, _>>()?,
        conclusion: encode(&state.goal)?,
        closed_target: encode(&checked.target)?,
        variables: variables.iter().map(|v| v.identifier()).collect(),
        proof_id: crate::hex(checked.native_id.as_bytes()),
        packet: super::super::evidence::pack(&checked)?,
    };
    Ok(fragment)
}

fn visit(
    source: &Source<'_>,
    tree: &Tree,
    state: &State,
    parent: Option<(usize, usize)>,
    branch: &mut Vec<usize>,
    out: &mut Derivation,
) -> Result<(), crate::Error> {
    if branch.len() > 40 {
        return Err(crate::ResearchFailure::DerivationDepth.into());
    }
    let Tree::Step { action, children } = tree else {
        return match tree {
            Tree::Close(..) => Ok(()),
            _ => Err(crate::ResearchFailure::DerivationNestedEvidence.into()),
        };
    };
    if out.steps.len() == STEPS {
        out.omitted_steps = out.omitted_steps.saturating_add(core::steps(tree));
        return Ok(());
    }
    let offered = actions(state);
    let selected = offered
        .iter()
        .position(|offered| offered == action)
        .ok_or(crate::ResearchFailure::DerivationAction)?;
    let next = next(state, action)?;
    if next.len() != children.len() {
        return Err(crate::ResearchFailure::DerivationArity.into());
    }
    let mut graph = Graph::encode(&decision(&state.goal, state, &offered, selected)?)?;
    graph.binding = trace::binding(state)?;
    let index = out.steps.len();
    out.steps.push(Step {
        graph,
        offered: super::super::digest(&offered),
        parent,
        branch: branch.clone(),
        action: action.clone(),
        children: children.len(),
        remaining_steps: core::steps(tree),
        witness: super::super::digest(&(source.tree, &*branch, tree)),
        cited_proof: match action {
            Action::Cite(i) => Some(
                source
                    .citations
                    .get(*i)
                    .ok_or(crate::ResearchFailure::DerivationCitationIndex)?
                    .clone(),
            ),
            _ => None,
        },
    });
    if !branch.is_empty()
        && out.fragment_attempts < FRAGMENTS
        && matches!(source.parent, Parent::Admitted { .. })
    {
        out.fragment_attempts += 1;
        // The complete source was checked first. A separately unsupported or
        // oversized contextual reconstruction contributes no fragment label.
        match contextual(source, tree, state, branch) {
            Ok(fragment) if fragment.within_capacity()? => {
                let Parent::Admitted { proof, .. } = &source.parent else {
                    unreachable!("admitted source above");
                };
                fragment.validate_source(source.target, source.tree, proof)?;
                out.fragments.push(fragment);
            }
            Ok(_) => out.oversized_fragments += 1,
            Err(reason) => out.rejected_fragments.push(reason.code()),
        }
    }
    for (child, (tree, state)) in children.iter().zip(next).enumerate() {
        branch.push(child);
        visit(source, tree, &state, Some((index, child)), branch, out)?;
        branch.pop();
    }
    Ok(())
}

/// Recheck the complete source before deriving any positive transition. The
/// bounded result is operational training material under that source lineage.
pub(crate) fn checked(
    target: &Formula,
    original: &Tree,
    native_id: &str,
) -> Result<Derivation, crate::Error> {
    let (source, tree, state) = source(target, original, native_id)?;
    let mut out = Derivation {
        source_proof: Some(native_id.to_owned()),
        source_tree: super::super::digest(original),
        source_target: super::super::digest(&encode(target)?),
        ..Derivation::default()
    };
    if !matches!(tree, Tree::Step { .. } | Tree::Close(..)) {
        out.unsupported_sequence = true;
        return Ok(out);
    }
    visit(&source, tree, &state, None, &mut Vec::new(), &mut out)?;
    Ok(out)
}

fn observed_target<'a>(
    trace: &trace::Trace,
    question: &'a naome_checker::question::ResearchQuestion,
) -> Result<&'a Formula, crate::Error> {
    for target in [question.proved_target(), question.refuted_target()] {
        if super::super::digest(&encode(target)?) == trace.target {
            return Ok(target);
        }
    }
    Err(crate::InputFault::ObservedTargetMismatch.into())
}

/// Closed branches may yield checked conditional proofs even when their root
/// search did not finish. No flag, timeout or missing transition is a label.
pub(crate) fn observed(
    observation: &super::super::experience::Observation,
) -> Result<Vec<Derivation>, crate::Error> {
    observation.validate()?;
    let question = naome_checker::question::ResearchQuestion::from_hex(&observation.question)
        .map_err(crate::Error::from)?;
    let mut result = Vec::new();
    let mut attempts = 0;
    for trace in &observation.executions {
        let target = observed_target(trace, &question)?;
        let knowledge = trace.context(&observation.knowledge)?;
        let citations = knowledge
            .iter()
            .map(|term| {
                super::super::proof::verify(term, &term.formula())
                    .map(|v| crate::hex(v.native_id.as_bytes()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (event, state, tree) in trace.closed_subtrees()? {
            if attempts == FRAGMENTS {
                return Ok(result);
            }
            attempts += 1;
            let source = Source {
                target,
                tree: &tree,
                knowledge: knowledge.clone(),
                citations: citations.clone(),
                parent: Parent::Observed {
                    job: observation.summary.job,
                    receipt: observation.summary.receipt.clone(),
                    execution: super::super::digest(trace),
                    event,
                    tree: super::super::digest(&tree),
                },
            };
            let mut derived = Derivation {
                source_target: trace.target.clone(),
                source_tree: super::super::digest(&tree),
                fragment_attempts: 1,
                ..Derivation::default()
            };
            match contextual(&source, &tree, &state, &[]) {
                Ok(fragment) if fragment.within_capacity()? => {
                    fragment.validate_observation(observation)?;
                    derived.fragments.push(fragment);
                    visit(&source, &tree, &state, None, &mut Vec::new(), &mut derived)?;
                }
                Ok(_) => derived.oversized_fragments += 1,
                Err(reason) => derived.rejected_fragments.push(reason.code()),
            }
            result.push(derived);
        }
    }
    Ok(result)
}

fn source<'a>(
    target: &'a Formula,
    original: &'a Tree,
    native_id: &'a str,
) -> Result<(Source<'a>, &'a Tree, State), crate::Error> {
    let (term, _) = compile(target, original)?;
    let verified = super::super::proof::verify(&term, target)?;
    if crate::hex(verified.native_id.as_bytes()) != native_id {
        return Err(crate::ResearchFailure::DerivationSourceIdentity.into());
    }
    let mut tree = original;
    while let Tree::Definitions { proof, .. } = tree {
        tree = proof;
    }
    let (tree, knowledge, knowledge_context) = if let Tree::Knowledge { proof, entries, .. } = tree
    {
        (
            proof.as_ref(),
            entries
                .iter()
                .map(super::super::knowledge::Entry::term)
                .collect::<Result<Vec<_>, _>>()?,
            entries.iter().map(super::super::digest).collect(),
        )
    } else {
        (tree, Vec::new(), Vec::new())
    };
    let citations = knowledge
        .iter()
        .map(|term| {
            super::super::proof::verify(term, &term.formula())
                .map(|v| crate::hex(v.native_id.as_bytes()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source = Source {
        target,
        tree: original,
        parent: Parent::Admitted {
            proof: native_id.to_owned(),
            tree: super::super::digest(original),
        },
        knowledge,
        citations,
    };
    let mut state = prepare(target)?.state;
    state.knowledge = source.knowledge.iter().map(Term::formula).collect();
    state.knowledge_context = knowledge_context;
    Ok((source, tree, state))
}

#[cfg(test)]
mod tests;
