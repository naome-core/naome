//! Sole live owner of state signing and selected-history transitions.
//!
//! Transport and clocks stay in runtime. This owner verifies bounded evidence,
//! orders finality before voting, and never releases a signature before the
//! signer journal has durably completed it.

use naome_consensus::state::{
    StateBranch, StateConsensusError, StateFinality, StateLockEvent, StatePhase, StateProposal,
    StatePublication, StateQuorum, StateVote, StateVoteSet,
};
use naome_consensus::{ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget};
use naome_ledger::{LedgerState, time::SignedTimeReport};
use naome_storage::state::{StateAppendOutcome, StateHistory, StateSigner, StateStorageError};
use std::{collections::BTreeMap, fmt};

/// Volatile evidence is bounded independently of the complete durable history.
const RETAINED_ROUNDS: usize = 8;
const MAX_PROPOSALS: usize = RETAINED_ROUNDS * 2;
const MAX_VOTES: usize = RETAINED_ROUNDS * 8;
const PROPOSALS_PER_SIGNER: usize = MAX_PROPOSALS / 4;
const VOTES_PER_SIGNER: usize = MAX_VOTES / 4;

#[derive(Debug)]
pub enum StateNodeError {
    Rejected(String),
    Storage(StateStorageError),
    Halted,
}
impl fmt::Display for StateNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(s) => write!(f, "state input rejected: {s}"),
            Self::Storage(e) => e.fmt(f),
            Self::Halted => f.write_str("state node halted on verified conflicting finality"),
        }
    }
}
impl std::error::Error for StateNodeError {}
impl From<StateConsensusError> for StateNodeError {
    fn from(e: StateConsensusError) -> Self {
        Self::Rejected(e.to_string())
    }
}
impl From<StateStorageError> for StateNodeError {
    fn from(e: StateStorageError) -> Self {
        Self::Storage(e)
    }
}
type Result<T> = std::result::Result<T, StateNodeError>;

/// Only this non-cloneable owner can move its live signer or selected history.
pub struct StateNode {
    history: StateHistory,
    signer: Option<StateSigner>,
    proposals: BTreeMap<(u64, [u8; 32]), StateProposal>,
    votes: BTreeMap<(u64, u8, ConsensusKey), StateVote>,
}
impl StateNode {
    pub fn new(mut history: StateHistory, mut signer: Option<StateSigner>) -> Result<Self> {
        if history.halted()? {
            if let Some(signer) = signer.as_mut() {
                let _ = signer.advance_to_history(&mut history);
            }
            return Err(StateNodeError::Halted);
        }
        let recovered = if let Some(signer) = signer.as_mut() {
            // Complete exactly the anchored intent before any height handoff.
            if signer.pending()? {
                let _ = signer.sign_prepared()?;
            }
            signer.advance_to_history(&mut history)?;
            signer.retry_publications()?
        } else {
            Vec::new()
        };
        let mut node = Self {
            history,
            signer,
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
        };
        for publication in recovered {
            node.retain(publication)?;
        }
        Ok(node)
    }
    pub fn state(&self) -> Result<&LedgerState> {
        Ok(self.history.head()?.state())
    }
    pub fn branch(&self) -> Result<&StateBranch> {
        Ok(self.history.head()?)
    }
    pub fn history(&self) -> &StateHistory {
        &self.history
    }
    pub fn signer_key(&self) -> Option<ConsensusKey> {
        self.signer.as_ref().map(StateSigner::signer)
    }
    pub fn position(&self) -> Result<Option<(u64, u64, StatePhase)>> {
        self.signer
            .as_ref()
            .map(|s| Ok((s.height()?, s.round()?, s.phase()?)))
            .transpose()
    }
    pub fn has_retained_value(&self) -> Result<bool> {
        match &self.signer {
            Some(s) => Ok(s.retained_record()?.is_some()),
            None => Ok(false),
        }
    }
    pub fn maximum_round(&self) -> u64 {
        self.history.maximum_round()
    }
    pub fn is_proposer(&self) -> Result<bool> {
        let Some(s) = &self.signer else {
            return Ok(false);
        };
        Ok(s.phase()? == StatePhase::Proposal
            && self.branch()?.proposer(s.round()?, self.maximum_round())? == s.signer())
    }
    pub fn already_authored(&self) -> Result<bool> {
        let Some(s) = &self.signer else {
            return Ok(false);
        };
        let round = s.round()?;
        Ok(self
            .proposals
            .values()
            .any(|p| p.round() == round && p.proposer() == s.signer()))
    }
    pub fn sign_time_report(&self, utc_seconds: u64) -> Result<Option<SignedTimeReport>> {
        self.signer
            .as_ref()
            .map(|s| s.sign_time_report(utc_seconds).map_err(Into::into))
            .transpose()
    }
    pub fn finality_bytes(&mut self, height: u64) -> Result<Vec<u8>> {
        Ok(self.history.finality_bytes(height)?)
    }
    pub fn publications(&self) -> Result<Vec<StatePublication>> {
        // Retry current proposals and this key's current/previous-round votes.
        // A sole advanced node must still let lagging peers finish the quorum
        // that advanced it; one future signer cannot trigger their round jump.
        let round = self.signer.as_ref().map(StateSigner::round).transpose()?;
        let signer = self.signer_key();
        Ok(self
            .proposals
            .values()
            .filter(|p| round.is_none_or(|r| p.round() == r))
            .cloned()
            .map(StatePublication::Proposal)
            .chain(
                self.votes
                    .values()
                    .filter(|v| {
                        round.is_none_or(|r| v.round() >= r.saturating_sub(1) && v.round() <= r)
                            && signer.is_none_or(|s| v.signer() == s)
                    })
                    .cloned()
                    .map(StatePublication::Vote),
            )
            .collect())
    }
    pub fn accept_proposal(&mut self, bytes: &[u8]) -> Result<()> {
        let p = self
            .branch()?
            .verify_proposal(bytes, self.maximum_round())?;
        self.retain(StatePublication::Proposal(p))
    }
    pub fn accept_vote(&mut self, bytes: &[u8]) -> Result<()> {
        let vote = StateVote::decode(bytes, self.state()?.genesis())?;
        if vote.height() != self.branch()?.next_height()? || vote.round() > self.maximum_round() {
            return Err(StateNodeError::Rejected("vote height or round".into()));
        }
        self.retain(StatePublication::Vote(vote))
    }
    fn retain(&mut self, publication: StatePublication) -> Result<()> {
        match publication {
            StatePublication::Proposal(p) => {
                let key = (p.round(), *p.value().signing_root().as_bytes());
                if let Some(old) = self.proposals.get_mut(&key) {
                    if p.valid_quorum().map(StateQuorum::round)
                        > old.valid_quorum().map(StateQuorum::round)
                    {
                        *old = p;
                    }
                    return Ok(());
                }
                self.reserve_proposal(p.round(), p.proposer())?;
                self.proposals.insert(key, p);
            }
            StatePublication::Vote(v) => {
                let key = (v.round(), role(v.role()), v.signer());
                if let Some(old) = self.votes.get(&key) {
                    if old != &v {
                        return Err(StateNodeError::Rejected("equivocating vote".into()));
                    }
                    return Ok(());
                }
                self.reserve_vote(v.round(), v.role(), v.signer())?;
                self.votes.insert(key, v);
            }
        }
        Ok(())
    }
    fn apply(&mut self, event: StateLockEvent) -> Result<()> {
        if let Some(signer) = &self.signer {
            let key = signer.signer();
            let round = signer.round()?;
            // Reserve volatile custody before any durable intent or signing-key
            // call. Each key has an independent budget and current slots win.
            match &event {
                StateLockEvent::Author { .. } => self.reserve_proposal(round, key)?,
                StateLockEvent::Prevote { .. } | StateLockEvent::ProposalTimeout => {
                    self.reserve_vote(round, ConsensusVoteRole::Prevote, key)?
                }
                StateLockEvent::Precommit { .. } | StateLockEvent::PrevoteTimeout { .. } => {
                    self.reserve_vote(round, ConsensusVoteRole::Precommit, key)?
                }
                _ => {}
            }
        }
        let Some(signer) = &mut self.signer else {
            return Ok(());
        };
        if let Some(publication) = signer.apply_and_sign(&event)? {
            self.retain(publication)?;
        }
        self.prune()?;
        Ok(())
    }
    fn reserve_vote(
        &mut self,
        round: u64,
        role_: ConsensusVoteRole,
        signer: ConsensusKey,
    ) -> Result<()> {
        if self.votes.contains_key(&(round, role(role_), signer)) {
            return Ok(());
        }
        let count = self.votes.values().filter(|v| v.signer() == signer).count();
        if count < VOTES_PER_SIGNER && self.votes.len() < MAX_VOTES {
            return Ok(());
        }
        let current = self.position()?.map_or(0, |p| p.1);
        let victim = self
            .votes
            .iter()
            .filter(|(_, v)| v.signer() == signer)
            .filter_map(|(key, _)| {
                eviction_priority(key.0, current, round).map(|priority| (priority, *key))
            })
            .min()
            .map(|(_, key)| key)
            .ok_or_else(|| StateNodeError::Rejected("signer vote retention limit".into()))?;
        self.votes.remove(&victim);
        Ok(())
    }
    fn reserve_proposal(&mut self, round: u64, signer: ConsensusKey) -> Result<()> {
        if self.proposals.keys().filter(|key| key.0 == round).count() >= 2 {
            return Err(StateNodeError::Rejected(
                "equivocating proposal retention limit".into(),
            ));
        }
        let count = self
            .proposals
            .values()
            .filter(|p| p.proposer() == signer)
            .count();
        if count < PROPOSALS_PER_SIGNER && self.proposals.len() < MAX_PROPOSALS {
            return Ok(());
        }
        let current = self.position()?.map_or(0, |p| p.1);
        let victim = self
            .proposals
            .iter()
            .filter(|(_, p)| p.proposer() == signer)
            .filter_map(|(key, _)| {
                eviction_priority(key.0, current, round).map(|priority| (priority, *key))
            })
            .min()
            .map(|(_, key)| key)
            .ok_or_else(|| StateNodeError::Rejected("proposer payload retention limit".into()))?;
        self.proposals.remove(&victim);
        Ok(())
    }
    fn prune(&mut self) -> Result<()> {
        if let Some((_, round, _)) = self.position()? {
            let minimum = round.saturating_sub(RETAINED_ROUNDS as u64 - 1);
            self.proposals.retain(|(r, _), _| *r >= minimum);
            self.votes.retain(|(r, _, _), _| *r >= minimum);
        }
        Ok(())
    }
    pub fn author(&mut self, record: Option<Vec<u8>>) -> Result<()> {
        if !self.is_proposer()? || self.already_authored()? {
            return Ok(());
        }
        self.apply(StateLockEvent::Author { record })
    }
    pub fn accept_finality(&mut self, bytes: &[u8]) -> Result<StateAppendOutcome> {
        let maximum = self
            .state()?
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let height = StateFinality::claimed_height(bytes, maximum)?;
        if height > self.state()?.height().saturating_add(1) {
            return Err(StateNodeError::Rejected("history gap".into()));
        }
        let result = self
            .history
            .receive_finality(height, bytes)
            .map_err(|error| match error {
                StateStorageError::Validation(message) => StateNodeError::Rejected(message),
                other => StateNodeError::Storage(other),
            })?;
        if let Some(signer) = self.signer.as_mut() {
            if result == StateAppendOutcome::ConflictHalt {
                // A verified conflict preempts even an anchored unsigned intent.
                let _ = signer.advance_to_history(&mut self.history);
                return Err(StateNodeError::Halted);
            }
            if signer.pending()? {
                let _ = signer.sign_prepared()?;
            }
            // This call also anchors the signer stop when history found a conflict.
            let advanced = signer.advance_to_history(&mut self.history);
            advanced?;
        }
        if result == StateAppendOutcome::ConflictHalt {
            return Err(StateNodeError::Halted);
        }
        if result == StateAppendOutcome::Finalized {
            self.proposals.clear();
            self.votes.clear();
        }
        Ok(result)
    }
    fn votes_at(&self, round: u64, role_: ConsensusVoteRole) -> Vec<StateVote> {
        self.votes
            .values()
            .filter(|v| v.round() == round && v.role() == role_)
            .cloned()
            .collect()
    }
    fn vote_set(&self, round: u64, role_: ConsensusVoteRole) -> Result<Option<StateVoteSet>> {
        let votes = self.votes_at(round, role_);
        if votes.is_empty() {
            return Ok(None);
        }
        Ok(Some(StateVoteSet::new(votes, self.state()?.genesis())?))
    }
    fn quorum(
        &self,
        round: u64,
        role_: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Result<Option<StateQuorum>> {
        let votes: Vec<_> = self
            .votes_at(round, role_)
            .into_iter()
            .filter(|v| v.target() == target)
            .collect();
        if votes.len() < 3 {
            return Ok(None);
        }
        Ok(Some(StateQuorum::from_votes(
            votes,
            self.state()?.genesis(),
        )?))
    }
    /// Drain bounded immediately actionable evidence. Finality always precedes
    /// new votes; runtime measures elapsed time separately via `timeout`.
    pub fn drive(&mut self) -> Result<bool> {
        let before = self.state()?.height();
        for _ in 0..16 {
            let mut finalities = Vec::new();
            for proposal in self.proposals.values() {
                let target = ConsensusVoteTarget::Proposal(proposal.value().signing_root());
                if let Some(qc) =
                    self.quorum(proposal.round(), ConsensusVoteRole::Precommit, target)?
                {
                    finalities.push(
                        self.branch()?
                            .verify_finality(proposal, &qc, self.maximum_round())?
                            .encode()?,
                    );
                }
            }
            if !finalities.is_empty() {
                for proof in finalities {
                    self.accept_finality(&proof)?;
                }
                return Ok(true);
            }
            let Some((_, round, phase)) = self.position()? else {
                break;
            };
            let mut higher = None;
            for ((r, _, _), _) in self.votes.iter().rev() {
                if *r <= round {
                    break;
                }
                for role_ in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
                    if let Some(votes) = self.vote_set(*r, role_)?
                        && votes.has_one_third(self.state()?.genesis())?
                    {
                        higher = Some(votes.encode());
                        break;
                    }
                }
                if higher.is_some() {
                    break;
                }
            }
            if let Some(votes) = higher {
                self.apply(StateLockEvent::HigherRound { votes })?;
                continue;
            }
            if let Some(qc) = self.quorum(
                round,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
            )? {
                self.apply(StateLockEvent::NilPrecommit {
                    quorum: qc.encode(),
                })?;
                continue;
            }
            let proposals: Vec<_> = self
                .proposals
                .values()
                .filter(|p| p.round() == round)
                .cloned()
                .collect();
            if phase == StatePhase::Proposal && proposals.len() == 1 {
                self.apply(StateLockEvent::Prevote {
                    proposal: Some(proposals[0].encode()?),
                })?;
                continue;
            }
            if phase == StatePhase::Prevote {
                let mut candidates = Vec::new();
                if let Some(qc) =
                    self.quorum(round, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil)?
                {
                    candidates.push((None, qc));
                }
                for proposal in &proposals {
                    if let Some(qc) = self.quorum(
                        round,
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Proposal(proposal.value().signing_root()),
                    )? {
                        candidates.push((Some(proposal.encode()?), qc));
                    }
                }
                if candidates.len() == 1 {
                    let (proposal, qc) = candidates.pop().expect("one candidate");
                    self.apply(StateLockEvent::Precommit {
                        proposal,
                        quorum: qc.encode(),
                    })?;
                    continue;
                }
            }
            break;
        }
        Ok(self.state()?.height() != before)
    }
    pub fn timeout(&mut self) -> Result<bool> {
        let Some((_, round, phase)) = self.position()? else {
            return Ok(false);
        };
        match phase {
            StatePhase::Proposal => self.apply(StateLockEvent::ProposalTimeout)?,
            StatePhase::Prevote => {
                let Some(votes) = self.vote_set(round, ConsensusVoteRole::Prevote)? else {
                    return Ok(false);
                };
                if !votes.has_supermajority(self.state()?.genesis())? {
                    return Ok(false);
                }
                self.apply(StateLockEvent::PrevoteTimeout {
                    votes: votes.encode(),
                })?;
            }
            StatePhase::Precommit => {
                let Some(votes) = self.vote_set(round, ConsensusVoteRole::Precommit)? else {
                    return Ok(false);
                };
                if !votes.has_supermajority(self.state()?.genesis())? {
                    return Ok(false);
                }
                self.apply(StateLockEvent::PrecommitTimeout {
                    votes: votes.encode(),
                })?;
            }
        }
        Ok(true)
    }
}
fn role(role: ConsensusVoteRole) -> u8 {
    match role {
        ConsensusVoteRole::Prevote => 0,
        ConsensusVoteRole::Precommit => 1,
    }
}

// Current-round custody is never displaced by another round. Keep recent
// future observations for catch-up, while one key cannot consume other keys'
// reserved slots. Historical certificates remain available through history.
fn eviction_priority(existing: u64, current: u64, incoming: u64) -> Option<(u8, u64)> {
    if existing == current {
        None
    } else if incoming < current {
        (existing < incoming).then_some((0, existing))
    } else if existing < current {
        Some((0, existing))
    } else {
        (incoming == current || existing < incoming).then_some((1, existing))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod safety_model;
