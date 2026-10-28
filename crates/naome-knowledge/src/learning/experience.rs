//! Bounded operational evidence, separate from mathematical admission.
use super::{GenerationCost, Origin, Solution, digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Budget {
    Expansions,
    Depth,
    Time,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Capacity {
    Facts,
    Graph,
    Certificate,
    Dependencies,
    PeerConversion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NoSearch {
    ReservedQuestion,
    TrainingOnly,
}

/// An observation about this execution, never a negative mathematical label.
/// A certified candidate still requires the ordinary graph admission path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum TerminalEvidence {
    CertifiedCandidate {
        proof_id: String,
        refuted: bool,
    },
    Budget(Budget),
    Unsupported(Capacity),
    CheckerRejected,
    TechnicalFailure,
    Interrupted,
    NoSearch(NoSearch),
    /// All offered branches of this restricted search policy were attempted.
    /// This does not establish semantic unprovability or calculus completeness.
    PolicyExhausted,
    Unknown,
}
impl TerminalEvidence {
    /// A later unresolved branch must not hide an earlier technical limitation.
    pub(super) fn include(&mut self, next: Self) {
        fn severity(value: &TerminalEvidence) -> u8 {
            match value {
                TerminalEvidence::NoSearch(_) => 0,
                TerminalEvidence::Unknown => 1,
                TerminalEvidence::PolicyExhausted => 2,
                TerminalEvidence::Budget(_) => 3,
                TerminalEvidence::Unsupported(_) => 4,
                TerminalEvidence::CheckerRejected => 5,
                TerminalEvidence::TechnicalFailure => 6,
                TerminalEvidence::Interrupted => 7,
                TerminalEvidence::CertifiedCandidate { .. } => 8,
            }
        }
        if severity(&next) >= severity(self) {
            *self = next;
        }
    }
    pub(crate) fn certified(solution: &Solution) -> Self {
        Self::CertifiedCandidate {
            proof_id: solution.proof_id.clone(),
            refuted: solution.refuted,
        }
    }

    pub(crate) fn validate(&self, solution: Option<&Solution>) -> Result<(), String> {
        match (self, solution) {
            (Self::CertifiedCandidate { proof_id, refuted }, Some(solution))
                if *proof_id == solution.proof_id && *refuted == solution.refuted =>
            {
                crate::object::id_bytes(proof_id)?;
                Ok(())
            }
            (Self::CertifiedCandidate { .. }, _) | (_, Some(_)) => {
                Err("terminal evidence differs from the checked candidate".into())
            }
            (_, None) => Ok(()),
        }
    }

    /// Only actual bounded search work can inform search difficulty. This is
    /// not evidence that the question or any unvisited action is false.
    pub(crate) fn observed_search_failure(&self, expansions: usize) -> bool {
        expansions > 0 && matches!(self, Self::Budget(_) | Self::PolicyExhausted)
    }
}

/// Exact bindings to existing journal evidence. A frontier is an observation,
/// not a checked contextual fragment or a complete search event trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceBinding {
    pub checked_trajectory: Option<String>,
    pub observed_branches: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExperienceSummary {
    pub job: u64,
    pub question: String,
    pub checkpoint: String,
    pub policy: String,
    pub request_binding: String,
    pub native_context: String,
    pub origin: Origin,
    pub terminal: TerminalEvidence,
    pub trace: TraceBinding,
    pub cost: Option<GenerationCost>,
    pub search_limit: u32,
    pub spent_ms: u64,
    pub reserved_units: u32,
    pub receipt: String,
}
impl ExperienceSummary {
    pub(crate) fn from_record(record: &crate::jobs::Record) -> Result<Option<Self>, String> {
        use crate::jobs::{Input, Output, State};
        let Some(native) = &record.native else {
            return Ok(None);
        };
        if digest(&native.base) != native.base_hash {
            return Err("experience native context differs from its retained snapshot".into());
        }
        let (question, origin) = match &record.input {
            Input::Solve { question } => (question, Origin::Local),
            Input::Peer {
                question,
                artifact,
                peer,
                ..
            } => (
                question,
                Origin::Peer {
                    artifact: artifact.clone(),
                    peer: peer.clone(),
                },
            ),
            _ => return Ok(None),
        };
        if matches!(
            record.state,
            State::Queued | State::Running | State::Suspended
        ) {
            return Ok(None);
        }
        let progress = native.progress.as_ref();
        let terminal = match record.state {
            State::Complete => {
                let Some(Output::Native {
                    solution,
                    terminal,
                    frontier,
                    ..
                }) = &record.result
                else {
                    return Err("complete native experience lacks its result".into());
                };
                terminal.validate(solution.as_ref())?;
                let p = progress.ok_or("complete native experience lacks its checkpoint")?;
                if &p.terminal != terminal.as_ref()
                    || digest(&p.result) != digest(solution)
                    || digest(&p.frontier) != digest(frontier)
                    || solution.as_ref().is_some_and(|s| {
                        p.cost
                            .as_ref()
                            .is_none_or(|cost| digest(cost) != digest(s.cost.as_ref()))
                    })
                {
                    return Err(
                        "native terminal evidence differs from its retained execution".into(),
                    );
                }
                terminal.as_ref().clone()
            }
            State::Failed => TerminalEvidence::TechnicalFailure,
            State::Cancelled | State::Expired | State::InDoubt => TerminalEvidence::Interrupted,
            _ => unreachable!("nonterminal records returned above"),
        };
        let q = naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
        let mut summary = Self {
            job: record.id,
            question: crate::hex(q.resolution_id()),
            checkpoint: native.model_checkpoint(),
            policy: progress
                .map_or(&native.base.model, |p| &p.model)
                .specification
                .clone(),
            request_binding: digest(&record.binding),
            native_context: digest(&(&native.base_hash, &native.required, &native.prerequisites)),
            origin,
            terminal,
            trace: TraceBinding {
                checked_trajectory: progress
                    .and_then(|p| p.result.as_ref())
                    .map(|s| digest(&s.tree)),
                observed_branches: progress.and_then(|p| p.frontier.as_ref()).map(digest),
            },
            cost: progress.and_then(|p| p.cost.clone()),
            search_limit: native.base.search_budget(),
            spent_ms: record.spent_ms,
            reserved_units: record.reserved_units,
            receipt: String::new(),
        };
        summary.receipt = summary.binding();
        summary.validate()?;
        Ok(Some(summary))
    }

    fn binding(&self) -> String {
        let mut value = self.clone();
        value.receipt.clear();
        digest(&value)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        for id in [
            &self.question,
            &self.checkpoint,
            &self.policy,
            &self.request_binding,
            &self.native_context,
            &self.receipt,
        ]
        .into_iter()
        .chain(self.trace.checked_trajectory.iter())
        .chain(self.trace.observed_branches.iter())
        {
            crate::object::id_bytes(id)?;
        }
        if let Origin::Peer { artifact, peer } = &self.origin {
            crate::object::id_bytes(artifact)?;
            let parsed: libp2p::PeerId = peer
                .parse()
                .map_err(|_| "experience peer identity syntax")?;
            if parsed.to_string() != *peer {
                return Err("experience peer identity encoding".into());
            }
        }
        if let TerminalEvidence::CertifiedCandidate { proof_id, .. } = &self.terminal {
            crate::object::id_bytes(proof_id)?;
        }
        if self.job == 0 || self.receipt != self.binding() {
            return Err("experience receipt identity differs".into());
        }
        let expansions = self.cost.as_ref().map_or(0, |c| c.search_expansions);
        if expansions > self.search_limit as usize
            || matches!(self.terminal, TerminalEvidence::NoSearch(_)) && expansions != 0
            || matches!(self.terminal, TerminalEvidence::PolicyExhausted)
                && !self.terminal.observed_search_failure(expansions)
            || matches!(self.terminal, TerminalEvidence::CertifiedCandidate { .. })
                && (self.trace.checked_trajectory.is_none()
                    || self.trace.observed_branches.is_some())
        {
            return Err("experience terminal, trace or measured work differs".into());
        }
        Ok(())
    }
}

/// A journal-owned operational observation. It carries no reusable proof;
/// positive training labels still require the admitted-source reconstruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub question: String,
    pub summary: ExperienceSummary,
    pub frontier: Option<super::SearchFrontier>,
}
impl Observation {
    pub(crate) fn from_record(record: &crate::jobs::Record) -> Result<Option<Self>, String> {
        let question = match &record.input {
            crate::jobs::Input::Solve { question } | crate::jobs::Input::Peer { question, .. }
                if super::State::eligible(question) =>
            {
                question
            }
            _ => return Ok(None),
        };
        let Some(summary) = ExperienceSummary::from_record(record)? else {
            return Ok(None);
        };
        let observation = Self {
            question: question.clone(),
            summary,
            frontier: record
                .native
                .as_ref()
                .and_then(|n| n.progress.as_ref())
                .and_then(|p| p.frontier.clone()),
        };
        observation.validate()?;
        Ok(Some(observation))
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.summary.validate()?;
        if !super::State::eligible(&self.question) {
            return Err("history observation is outside the eligible training lineage".into());
        }
        let question = naome_authoring::CompiledQuestion::compile(&self.question)
            .map_err(|e| e.to_string())?;
        if self.summary.question != crate::hex(question.resolution_id())
            || self.summary.trace.observed_branches != self.frontier.as_ref().map(digest)
        {
            return Err("history observation question or frontier binding differs".into());
        }
        if let Some(frontier) = &self.frontier {
            frontier.validate(&question)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertainty_and_technical_events_never_become_negative_search_labels() {
        for terminal in [
            TerminalEvidence::Unknown,
            TerminalEvidence::TechnicalFailure,
            TerminalEvidence::CheckerRejected,
            TerminalEvidence::Interrupted,
            TerminalEvidence::Unsupported(Capacity::Graph),
            TerminalEvidence::NoSearch(NoSearch::ReservedQuestion),
        ] {
            assert!(!terminal.observed_search_failure(128));
        }
        for terminal in [
            TerminalEvidence::Budget(Budget::Time),
            TerminalEvidence::PolicyExhausted,
        ] {
            assert!(!terminal.observed_search_failure(0));
            assert!(terminal.observed_search_failure(1));
        }
        let mut terminal = TerminalEvidence::Unsupported(Capacity::Graph);
        terminal.include(TerminalEvidence::PolicyExhausted);
        terminal.include(TerminalEvidence::Budget(Budget::Expansions));
        assert_eq!(terminal, TerminalEvidence::Unsupported(Capacity::Graph));
    }

    #[test]
    fn actual_budget_stop_and_zero_work_remain_distinct() {
        struct Ordered;
        impl super::super::model::Ranker for Ordered {
            fn scores(
                &mut self,
                decision: &super::super::model::Decision,
            ) -> Result<Vec<f32>, String> {
                Ok(vec![0.; decision.candidates.len()])
            }
        }
        let q = naome_authoring::CompiledQuestion::compile(
            "goal=all(a,all(b,imp(not(eq(a,b)),imp(all(x,all(y,mem(x,y))),mem(b,a)))))",
        )
        .unwrap();
        let empty = super::super::search::solve(q.proved_target(), &mut Ordered, 0).unwrap();
        assert!(!empty.terminal.observed_search_failure(empty.expansions));
        let searched = super::super::search::solve(q.proved_target(), &mut Ordered, 1).unwrap();
        assert!(searched.tree.is_none());
        assert_eq!(
            searched.terminal,
            TerminalEvidence::Budget(Budget::Expansions)
        );
        assert!(
            searched
                .terminal
                .observed_search_failure(searched.expansions)
        );
        assert!(searched.frontier.is_some());
    }
}
