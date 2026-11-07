//! A bounded prefix of actions actually attempted by the native search.
//! Replaying these transitions checks observation consistency, not provability.
use super::*;

pub(crate) const BYTES: usize = 2 * frontier::BYTES;

fn encode(formula: &Formula) -> Result<String, String> {
    formula
        .encode_canonical()
        .map(|b| crate::hex(&b))
        .map_err(|e| e.to_string())
}
fn decode(source: &str) -> Result<Formula, String> {
    let bytes = crate::object::unhex(source)?;
    if crate::hex(&bytes) != source {
        return Err("search observation formula encoding".into());
    }
    Formula::decode_canonical(&bytes).map_err(|e| e.to_string())
}

pub(super) fn binding(state: &State) -> Result<String, String> {
    Ok(super::super::digest(&(
        encode(&state.goal)?,
        state
            .facts
            .iter()
            .map(encode)
            .collect::<Result<Vec<_>, _>>()?,
        &state.used,
        &state.knowledge_context,
        state
            .domain
            .iter()
            .map(|v| v.identifier())
            .collect::<Vec<_>>(),
        state
            .knowledge
            .iter()
            .map(encode)
            .collect::<Result<Vec<_>, _>>()?,
    )))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Root {
    target: String,
    knowledge: Vec<Reference>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    formula: String,
    proof: String,
    packet: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Branch {
    pub event: usize,
    pub child: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    parent: Option<Branch>,
    state: String,
    offered: String,
    selected: usize,
    // Actual ranking outputs; these may include exploration or symbolic ranks.
    // A deterministic single-action transition has no inferred score to record.
    ranks: Option<Vec<u32>>,
    children_attempted: usize,
    // Inclusive subtree work and elapsed time; never sum across ancestors.
    start: usize,
    end: usize,
    elapsed_micros: u64,
    // A search tree closed. Native checking is a separate subsequent event.
    closed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trace {
    pub target: String,
    root: Option<Root>,
    events: Vec<Event>,
    pub attempts: usize,
    pub omitted: usize,
}
impl Trace {
    /// At most four actual observed transitions, cut at every missing match.
    /// A reconstructed proof supplies local checked labels, never chronology.
    pub(crate) fn windows(
        &self,
        checked: &[(usize, &super::derivation::Derivation)],
    ) -> Result<Vec<Vec<(usize, usize)>>, String> {
        self.validate()?;
        let matches: Vec<_> = self
            .events
            .iter()
            .map(|event| {
                checked.iter().find_map(|(source, derivation)| {
                    if derivation.source_target != self.target {
                        return None;
                    }
                    derivation
                        .steps
                        .iter()
                        .position(|step| {
                            step.graph.binding == event.state
                                && step.offered == event.offered
                                && step.graph.expert == event.selected
                        })
                        .map(|step| (*source, step))
                })
            })
            .collect();
        let mut result = Vec::new();
        for end in 0..self.events.len() {
            let mut window = Vec::new();
            let mut next = Some(end);
            while let Some(index) = next {
                let Some(step) = matches[index] else {
                    break;
                };
                window.push(step);
                if window.len() == 4 {
                    break;
                }
                // states() independently replays this exact parent action and
                // selected child before this edge is available to training.
                next = self.events[index].parent.map(|parent| parent.event);
            }
            window.reverse();
            if !window.is_empty() {
                result.push(window);
            }
        }
        Ok(result)
    }

    /// Match a separately checked completion to an actually observed state and
    /// action. This establishes available hindsight, not success of that past
    /// attempt. Unmatched and omitted events remain explicitly unassigned.
    pub(crate) fn reconcile(
        &self,
        checked: &super::derivation::Derivation,
    ) -> Result<Vec<(usize, String)>, String> {
        self.validate()?;
        if self.target != checked.source_target {
            return Ok(Vec::new());
        }
        Ok(self
            .events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                checked
                    .steps
                    .iter()
                    .find(|step| {
                        step.graph.binding == event.state
                            && step.offered == event.offered
                            && step.graph.expert == event.selected
                    })
                    .map(|step| (index, step.witness.clone()))
            })
            .collect())
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        self.states().map(drop)
    }

    fn states(&self) -> Result<Vec<State>, String> {
        crate::object::id_bytes(&self.target)?;
        if crate::checkpoint::encode(self)?.len() > BYTES
            || self.events.len() > self.attempts
            || self.omitted != self.attempts - self.events.len()
        {
            return Err("search observation capacity or coverage differs".into());
        }
        let Some(root) = &self.root else {
            return if self.events.is_empty() {
                Ok(Vec::new())
            } else {
                Err("search events lack their original context".into())
            };
        };
        let target = decode(&root.target)?;
        if self.target != super::super::digest(&root.target) {
            return Err("search observation target differs".into());
        }
        let mut initial = prepare(&target)?.state;
        for reference in &root.knowledge {
            crate::object::id_bytes(&reference.proof)?;
            crate::object::id_bytes(&reference.packet)?;
        }
        if root.knowledge.len() > super::super::knowledge::CAPACITY {
            return Err("search observation theorem capacity differs".into());
        }
        initial.knowledge_context = root
            .knowledge
            .iter()
            .map(|reference| reference.packet.clone())
            .collect();
        initial.knowledge = root
            .knowledge
            .iter()
            .map(|reference| decode(&reference.formula))
            .collect::<Result<_, _>>()?;
        let mut states: Vec<State> = Vec::new();
        let mut visits =
            std::collections::BTreeMap::<Option<Branch>, (usize, Option<Vec<u32>>)>::new();
        for (index, event) in self.events.iter().enumerate() {
            if event.start != index || event.end <= event.start || event.end > self.attempts {
                return Err("search observation expansion order differs".into());
            }
            let state = if let Some(parent) = event.parent {
                let previous = self
                    .events
                    .get(parent.event)
                    .filter(|_| parent.event < index)
                    .ok_or("search observation parent is not an earlier action")?;
                if parent.child >= previous.children_attempted || event.end > previous.end {
                    return Err("search observation branch ancestry differs".into());
                }
                let before = &states[parent.event];
                let offered = actions(before);
                next(before, &offered[previous.selected])?
                    .get(parent.child)
                    .ok_or("search observation branch is not offered")?
                    .clone()
            } else {
                initial.clone()
            };
            let offered = actions(&state);
            if event.state != binding(&state)?
                || event.offered != super::super::digest(&offered)
                || event.selected >= offered.len()
            {
                return Err("search observation state or action binding differs".into());
            }
            match &event.ranks {
                Some(ranks)
                    if offered.len() > 1
                        && ranks.len() == offered.len()
                        && ranks.iter().all(|bits| f32::from_bits(*bits).is_finite()) => {}
                None if offered.len() == 1 => {}
                _ => return Err("search observation ranking shape differs".into()),
            }
            let visit = visits
                .entry(event.parent)
                .or_insert((0, event.ranks.clone()));
            let mut order: Vec<_> = (0..offered.len()).collect();
            if let Some(ranks) = &event.ranks {
                order.sort_by(|a, b| {
                    f32::from_bits(ranks[*b])
                        .total_cmp(&f32::from_bits(ranks[*a]))
                        .then(a.cmp(b))
                });
            }
            if visit.1 != event.ranks || order.get(visit.0) != Some(&event.selected) {
                return Err("search observation differs from its attempted ranking order".into());
            }
            visit.0 += 1;
            let children = next(&state, &offered[event.selected])?;
            if event.children_attempted == 0
                || event.children_attempted > children.len()
                || event.closed && event.children_attempted != children.len()
            {
                return Err("search observation executed branch count differs".into());
            }
            states.push(state);
        }
        Ok(states)
    }

    pub(crate) fn validate_question(
        &self,
        question: &naome_authoring::CompiledQuestion,
    ) -> Result<(), String> {
        self.validate()?;
        let targets = [question.proved_target(), question.refuted_target()]
            .into_iter()
            .map(encode)
            .collect::<Result<Vec<_>, _>>()?;
        if !targets
            .iter()
            .any(|target| super::super::digest(target) == self.target)
        {
            return Err("search observation belongs to a different question".into());
        }
        Ok(())
    }

    pub(crate) fn validate_context(
        &self,
        question: &naome_authoring::CompiledQuestion,
        knowledge: &[super::super::knowledge::Entry],
    ) -> Result<(), String> {
        self.validate_question(question)?;
        self.context(knowledge)?;
        Ok(())
    }

    pub(super) fn context(
        &self,
        knowledge: &[super::super::knowledge::Entry],
    ) -> Result<Vec<Term>, String> {
        let Some(root) = &self.root else {
            return Ok(Vec::new());
        };
        let mut terms = Vec::new();
        for reference in &root.knowledge {
            let entry = knowledge
                .iter()
                .find(|entry| super::super::digest(entry) == reference.packet)
                .ok_or("search observation lacks its exact theorem snapshot")?;
            let checked = entry.verified()?;
            if encode(&checked.target)? != reference.formula
                || crate::hex(checked.native_id.as_bytes()) != reference.proof
            {
                return Err("search observation theorem identity differs".into());
            }
            terms.push(Term::Native {
                certificate: checked.certificate,
                lemmas: checked.lemmas,
                definitions: checked.definitions,
                target: checked.target,
            });
        }
        Ok(terms)
    }

    /// Reconstruct only closed subtrees whose actual required transitions all
    /// fit in the stored prefix. The caller must independently check each one.
    pub(super) fn closed_subtrees(&self) -> Result<Vec<(usize, State, Tree)>, String> {
        let states = self.states()?;
        fn rebuild(
            trace: &Trace,
            states: &[State],
            index: usize,
            depth: usize,
        ) -> Result<Option<Tree>, String> {
            if depth > 40 {
                return Err("observed closed branch depth differs".into());
            }
            let event = &trace.events[index];
            if !event.closed {
                return Ok(None);
            }
            let state = &states[index];
            let action = actions(state)[event.selected].clone();
            let mut children = Vec::new();
            for (child, next) in next(state, &action)?.into_iter().enumerate() {
                if let Some((a, b)) = close(&next) {
                    children.push(Tree::Close(a, b));
                    continue;
                }
                let matching: Vec<_> = trace
                    .events
                    .iter()
                    .enumerate()
                    .skip(index + 1)
                    .take_while(|(i, _)| *i < event.end)
                    .filter(|(_, e)| {
                        e.closed
                            && e.parent
                                == Some(Branch {
                                    event: index,
                                    child,
                                })
                    })
                    .map(|(i, _)| i)
                    .collect();
                if matching.len() > 1 {
                    return Err("observed branch has multiple terminal completions".into());
                }
                let Some(index) = matching.first() else {
                    return Ok(None);
                };
                let Some(tree) = rebuild(trace, states, *index, depth + 1)? else {
                    return Ok(None);
                };
                children.push(tree);
            }
            Ok(Some(Tree::Step { action, children }))
        }
        let mut result = Vec::new();
        for (index, state) in states.iter().enumerate() {
            if let Some(tree) = rebuild(self, &states, index, 0)? {
                result.push((index, state.clone(), tree));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;

pub(super) struct Recorder {
    trace: Trace,
    stopped: bool,
}
impl Recorder {
    pub fn new(
        target: &Formula,
        knowledge: &[super::super::knowledge::Entry],
    ) -> Result<Self, String> {
        let root = Root {
            target: encode(target)?,
            knowledge: knowledge
                .iter()
                .map(|entry| {
                    let checked = entry.verified()?;
                    Ok(Reference {
                        formula: encode(&checked.target)?,
                        proof: crate::hex(checked.native_id.as_bytes()),
                        packet: super::super::digest(entry),
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        let mut trace = Trace {
            target: super::super::digest(&root.target),
            root: Some(root),
            events: Vec::new(),
            attempts: usize::MAX,
            omitted: usize::MAX,
        };
        if crate::checkpoint::encode(&trace)?.len() > BYTES {
            trace.root = None;
        }
        let stopped = trace.root.is_none();
        trace.attempts = 0;
        trace.omitted = 0;
        Ok(Self { trace, stopped })
    }
    pub fn begin(
        &mut self,
        state: &State,
        offered: &[Action],
        selected: usize,
        ranks: Option<&[f32]>,
        parent: Option<Branch>,
        start: usize,
    ) -> Result<Option<usize>, String> {
        if start != self.trace.attempts {
            return Err("search observation skipped an attempted action".into());
        }
        self.trace.attempts += 1;
        self.trace.omitted += 1;
        if self.stopped {
            return Ok(None);
        }
        let index = self.trace.events.len();
        self.trace.events.push(Event {
            parent,
            state: binding(state)?,
            offered: super::super::digest(&offered),
            selected,
            ranks: ranks.map(|values| values.iter().map(|v| v.to_bits()).collect()),
            children_attempted: usize::MAX,
            start,
            end: usize::MAX,
            elapsed_micros: u64::MAX,
            closed: false,
        });
        // Reserve maximal widths for unfinished ancestors and final counters.
        // Once full, keep a genuine prefix and count every omitted attempt.
        if crate::checkpoint::encode(&self.trace)?.len() + 2 * 20 > BYTES {
            self.trace.events.pop();
            self.stopped = true;
            return Ok(None);
        }
        self.trace.omitted -= 1;
        Ok(Some(index))
    }
    pub fn finish(
        &mut self,
        event: Option<usize>,
        children: usize,
        end: usize,
        closed: bool,
        elapsed: Duration,
    ) {
        if let Some(index) = event {
            let event = &mut self.trace.events[index];
            event.children_attempted = children;
            event.end = end;
            event.closed = closed;
            event.elapsed_micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        }
    }
    pub fn into_trace(self) -> Trace {
        self.trace
    }
}
