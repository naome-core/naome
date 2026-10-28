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
    knowledge: Vec<String>,
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
        crate::object::id_bytes(&self.target)?;
        if crate::checkpoint::encode(self)?.len() > BYTES
            || self.events.len() > self.attempts
            || self.omitted != self.attempts - self.events.len()
        {
            return Err("search observation capacity or coverage differs".into());
        }
        let Some(root) = &self.root else {
            return if self.events.is_empty() {
                Ok(())
            } else {
                Err("search events lack their original context".into())
            };
        };
        let target = decode(&root.target)?;
        if self.target != super::super::digest(&root.target) {
            return Err("search observation target differs".into());
        }
        let mut initial = prepare(&target)?.state;
        initial.knowledge = root
            .knowledge
            .iter()
            .map(|s| decode(s))
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
        Ok(())
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
        if let Some(root) = &self.root {
            let allowed = knowledge
                .iter()
                .map(|entry| encode(&entry.verified()?.target))
                .collect::<Result<BTreeSet<_>, String>>()?;
            if root.knowledge.iter().any(|f| !allowed.contains(f)) {
                return Err("search observation uses an unowned theorem context".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) struct Recorder {
    trace: Trace,
    stopped: bool,
}
impl Recorder {
    pub fn new(target: &Formula, knowledge: &[Formula]) -> Result<Self, String> {
        let root = Root {
            target: encode(target)?,
            knowledge: knowledge.iter().map(encode).collect::<Result<_, _>>()?,
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
