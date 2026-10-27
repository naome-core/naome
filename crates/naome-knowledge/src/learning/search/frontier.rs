//! Bounded observations of open branches, never a proof or a falsity label.
use super::*;

pub(crate) const BYTES: usize = 4096;
const STATES: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frontier {
    target: String,
    states: Vec<Open>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    facts: Vec<String>,
    variables: Vec<u32>,
    depth: usize,
}
pub(crate) struct Context {
    pub assumptions: Vec<Formula>,
    pub facts: Vec<Formula>,
    pub goal: Formula,
}
fn encode(formula: &Formula) -> String {
    crate::hex(&formula.encode_canonical().expect("bounded native formula"))
}
fn decode(source: &str) -> Result<Formula, String> {
    if source.len() > 2 * BYTES {
        return Err("open branch formula capacity".into());
    }
    let bytes = crate::object::unhex(source)?;
    if crate::hex(&bytes) != source {
        return Err("open branch formula encoding".into());
    }
    Formula::decode_canonical(&bytes).map_err(|e| e.to_string())
}
impl Frontier {
    pub(super) fn new(target: &Formula) -> Option<Self> {
        let report = Self {
            target: encode(target),
            states: Vec::new(),
        };
        (serde_json::to_vec(&report).ok()?.len() <= BYTES).then_some(report)
    }
    pub(super) fn observe(&mut self, state: &State, depth: usize) {
        if state.facts.len() > 32 || depth > 32 || close(state).is_some() {
            return;
        }
        let open = Open {
            facts: state.facts.iter().map(encode).collect(),
            variables: state.domain.iter().map(|v| v.identifier()).collect(),
            depth,
        };
        if self.states.iter().any(|s| s.facts == open.facts) {
            return;
        }
        let mut next = self.clone();
        next.states.push(open);
        next.states.sort_by_key(|s| std::cmp::Reverse(s.depth));
        next.states.truncate(STATES);
        while !next.states.is_empty() && serde_json::to_vec(&next).map_or(true, |b| b.len() > BYTES)
        {
            next.states.pop();
        }
        if !next.states.is_empty() {
            *self = next;
        }
    }
    pub(crate) fn empty(&self) -> bool {
        self.states.is_empty()
    }
    pub(crate) fn validate(
        &self,
        question: &naome_authoring::CompiledQuestion,
    ) -> Result<(), String> {
        if self.states.is_empty()
            || self.states.len() > STATES
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > BYTES
        {
            return Err("open branch observation capacity".into());
        }
        let target = decode(&self.target)?;
        if target != *question.proved_target() && target != *question.refuted_target() {
            return Err("open branch target binding differs".into());
        }
        let prepared = prepare(&target)?;
        for open in &self.states {
            if open.facts.len() > 32 || open.variables.len() > 32 || open.depth > 32 {
                return Err("open branch state capacity".into());
            }
            let facts = open
                .facts
                .iter()
                .map(|f| decode(f))
                .collect::<Result<Vec<_>, _>>()?;
            let variables = open.variables.iter().copied().collect::<BTreeSet<_>>();
            if variables.len() != open.variables.len()
                || facts
                    .iter()
                    .flat_map(Formula::free_variables)
                    .any(|v| !variables.contains(&v.identifier()))
                || prepared.state.facts.iter().any(|f| !facts.contains(f))
            {
                return Err("open branch assumptions or variable binding differs".into());
            }
        }
        Ok(())
    }
    pub(crate) fn contexts(&self) -> Result<Vec<Context>, String> {
        let prepared = prepare(&decode(&self.target)?)?;
        let assumptions = prepared
            .wrap
            .iter()
            .filter_map(|w| match w {
                Wrap::Assumption(f) => Some(f.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        self.states
            .iter()
            .map(|s| {
                Ok(Context {
                    assumptions: assumptions.clone(),
                    facts: s
                        .facts
                        .iter()
                        .map(|f| decode(f))
                        .collect::<Result<_, _>>()?,
                    goal: prepared.body.clone(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    #[test]
    fn failed_branches_retain_the_target_assumptions_and_bound_witnesses() {
        let q = naome_authoring::CompiledQuestion::compile(
            "goal=all(a,all(b,imp(not(eq(a,b)),imp(all(x,mem(x,a)),mem(b,a)))))",
        )
        .unwrap();
        let result = solve(q.proved_target(), &mut Ordered, 1).unwrap();
        assert!(result.tree.is_none());
        let report = result.frontier.unwrap();
        report.validate(&q).unwrap();
        assert!(serde_json::to_vec(&report).unwrap().len() <= BYTES);
        let contexts = report.contexts().unwrap();
        assert!(
            contexts
                .iter()
                .all(|c| c.assumptions.len() == 2
                    && c.assumptions.iter().all(|a| c.facts.contains(a)))
        );
        let mut altered = report.clone();
        altered.states[0].variables.clear();
        assert!(altered.validate(&q).is_err());
        let mut altered = report.clone();
        altered.states[0].facts.remove(0);
        assert!(altered.validate(&q).is_err());
        let other = naome_authoring::CompiledQuestion::compile("goal=all(a,mem(a,a))").unwrap();
        assert!(report.validate(&other).is_err());
        let restored: Frontier =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(report, restored);
    }
}
