//! Sole live owner of state signing and selected-history transitions.
//!
//! Transport and clocks stay in runtime. This owner verifies bounded evidence,
//! orders finality before voting, and never releases a signature before the
//! signer journal has durably completed it.

use naome_consensus::state::{
    SealRole, SealSignature, StateAgreement, StateBranch, StateConsensusError, StateFinality,
    StateLockEvent, StatePhase, StateProposal, StatePublication, StateQuorum, StateSeal, StateVote,
    StateVoteSet,
};
use naome_consensus::{ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget};
use naome_ledger::{LedgerState, time::SignedTimeReport};
use naome_storage::state::{
    StateAppendOutcome, StateHandoffJournal, StateHistory, StatePeriodCustody, StateSigner,
    StateStorageError,
};
use std::{collections::BTreeMap, fmt, path::Path};

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
    handoff: Option<StateHandoffJournal>,
    ready: BTreeMap<ConsensusKey, SealSignature>,
    terminal: BTreeMap<ConsensusKey, SealSignature>,
}
impl StateNode {
    pub fn new(history: StateHistory, signer: Option<StateSigner>) -> Result<Self> {
        Self::new_with_handoff(history, signer, None)
    }
    pub fn new_with_handoff(
        mut history: StateHistory,
        mut signer: Option<StateSigner>,
        mut handoff: Option<StateHandoffJournal>,
    ) -> Result<Self> {
        if history.halted()? {
            if let Some(signer) = signer.as_mut() {
                let _ = signer.advance_to_history(&mut history);
            }
            return Err(StateNodeError::Halted);
        }
        if let (Some(signer), Some(journal)) = (signer.as_mut(), handoff.as_mut())
            && journal.terminal_prepared()
            && !signer.stopped()?
            && signer.branch()?.state().height() == history.head()?.state().height()
        {
            let ready = journal
                .ready_quorum()
                .ok_or_else(|| {
                    StateNodeError::Rejected("TERMINAL intent lacks READY quorum".into())
                })?
                .to_vec();
            signer.terminal_handoff(journal, &ready)?;
        }
        let recovered = if let Some(signer) = signer.as_mut() {
            if signer.stopped()? {
                Vec::new()
            } else {
                // Selected sealed history retires this period even if an old
                // signature intent was pending at the crash boundary. Only an
                // intent for the still-selected parent may be completed.
                if signer.branch()?.state().height() == history.head()?.state().height()
                    && signer.pending()?
                {
                    let _ = signer.sign_prepared()?;
                }
                signer.advance_to_history(&mut history)?;
                if signer.stopped()? {
                    Vec::new()
                } else {
                    signer.retry_publications()?
                }
            }
        } else {
            Vec::new()
        };
        let mut node = Self {
            history,
            signer,
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            handoff,
            ready: BTreeMap::new(),
            terminal: BTreeMap::new(),
        };
        if let Some(journal) = &node.handoff {
            if let Some(ready) = journal.ready() {
                node.ready.insert(ready.signer(), ready.clone());
            }
            if let Some(terminal) = journal.terminal() {
                node.terminal.insert(terminal.signer(), terminal.clone());
            }
        }
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
    /// Select a new period signer only after sealed history has installed its
    /// authority. The preceding signer must have durably retired.
    pub fn install_selected_signer(
        &mut self,
        signer: StateSigner,
        journal: StateHandoffJournal,
    ) -> Result<()> {
        if let Some(old) = &self.signer
            && !old.stopped()?
        {
            return Err(StateNodeError::Rejected(
                "outgoing signer still active".into(),
            ));
        }
        if signer.branch()?.commitment() != self.history.head()?.commitment() {
            return Err(StateNodeError::Rejected(
                "incoming signer has wrong selected parent".into(),
            ));
        }
        self.signer = Some(signer);
        self.handoff = Some(journal);
        self.ready.clear();
        self.terminal.clear();
        self.proposals.clear();
        self.votes.clear();
        Ok(())
    }
    pub fn install_observer_period(&mut self, journal: StateHandoffJournal) -> Result<()> {
        if let Some(old) = &self.signer
            && !old.stopped()?
        {
            return Err(StateNodeError::Rejected(
                "outgoing signer still active".into(),
            ));
        }
        self.signer = None;
        self.handoff = Some(journal);
        self.ready.clear();
        self.terminal.clear();
        self.proposals.clear();
        self.votes.clear();
        Ok(())
    }
    pub fn signer_key(&self) -> Option<ConsensusKey> {
        self.signer.as_ref().map(StateSigner::signer)
    }
    pub fn signer_parent_height(&self) -> Result<Option<u64>> {
        self.signer
            .as_ref()
            .map(|signer| {
                signer
                    .branch()
                    .map(|branch| branch.state().height())
                    .map_err(StateNodeError::from)
            })
            .transpose()
    }
    pub fn position(&self) -> Result<Option<(u64, u64, StatePhase)>> {
        let Some(signer) = self.signer.as_ref() else {
            return Ok(None);
        };
        if signer.stopped()? {
            return Ok(None);
        }
        Ok(Some((signer.height()?, signer.round()?, signer.phase()?)))
    }
    pub fn has_retained_value(&self) -> Result<bool> {
        match &self.signer {
            Some(s) if !s.stopped()? => Ok(s.retained_record()?.is_some()),
            None => Ok(false),
            Some(_) => Ok(false),
        }
    }
    pub fn maximum_round(&self) -> u64 {
        self.history.maximum_round()
    }
    pub fn is_proposer(&self) -> Result<bool> {
        if self.handoff_agreement().is_some() {
            return Ok(false);
        }
        let Some(s) = &self.signer else {
            return Ok(false);
        };
        if s.stopped()? {
            return Ok(false);
        }
        Ok(s.phase()? == StatePhase::Proposal
            && self.branch()?.proposer(s.round()?, self.maximum_round())? == Some(s.signer()))
    }
    pub fn already_authored(&self) -> Result<bool> {
        let Some(s) = &self.signer else {
            return Ok(false);
        };
        if s.stopped()? {
            return Ok(false);
        }
        let round = s.round()?;
        Ok(self
            .proposals
            .values()
            .any(|p| p.round() == round && p.proposer() == s.signer()))
    }
    pub fn sign_time_report(&self, utc_seconds: u64) -> Result<Option<SignedTimeReport>> {
        if self.handoff_agreement().is_some() {
            return Ok(None);
        }
        let Some(signer) = self.signer.as_ref() else {
            return Ok(None);
        };
        if signer.stopped()? {
            return Ok(None);
        }
        Ok(Some(signer.sign_time_report(utc_seconds)?))
    }
    pub fn finality_bytes(&mut self, height: u64) -> Result<Vec<u8>> {
        Ok(self.history.finality_bytes(height)?)
    }
    pub fn publications(&self) -> Result<Vec<StatePublication>> {
        if let Some(signer) = &self.signer
            && signer.stopped()?
        {
            return Ok(Vec::new());
        }
        // Retry current proposals and this key's current/previous-round votes.
        // A sole advanced node must still let lagging peers finish the quorum
        // that advanced it; one future signer cannot trigger their round jump.
        let active = match &self.signer {
            Some(s) if !s.stopped()? => Some(s),
            _ => None,
        };
        let round = active.map(StateSigner::round).transpose()?;
        let signer = active.map(StateSigner::signer);
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
        let vote = StateVote::decode(bytes, self.state()?.genesis(), self.branch()?.authority())?;
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
        if signer.stopped()? {
            return Ok(());
        }
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
        if let Some(signer) = self.signer.as_mut()
            && !signer.stopped()?
        {
            if result == StateAppendOutcome::ConflictHalt {
                // A verified conflict preempts even an anchored unsigned intent.
                let _ = signer.advance_to_history(&mut self.history);
                return Err(StateNodeError::Halted);
            }
            // A newly selected sealed successor retires this period. Never
            // complete a pending old-period signature after the finality has
            // been durably appended.
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
        Ok(Some(StateVoteSet::new(
            votes,
            self.state()?.genesis(),
            self.branch()?.authority(),
        )?))
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
            self.branch()?.authority(),
        )?))
    }
    /// READY and TERMINAL are collected only for the exact durably staged
    /// agreement. A quorum certificate by itself cannot install its child.
    fn finality_for(
        &mut self,
        proposal: &StateProposal,
        quorum: &StateQuorum,
    ) -> Result<Option<Vec<u8>>> {
        let agreement = self
            .branch()?
            .verify_agreement(proposal, quorum, self.maximum_round())?;
        let journal = self
            .handoff
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("handoff journal unavailable".into()))?;
        journal.stage(&agreement, &self.history)?;
        self.finality_for_staged(&agreement)
    }
    fn finality_for_staged(&self, agreement: &StateAgreement) -> Result<Option<Vec<u8>>> {
        if self.ready.len() < 3 || self.terminal.len() < 3 {
            return Ok(None);
        }
        let seal = StateSeal::new(
            self.ready.values().cloned().collect(),
            self.terminal.values().cloned().collect(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        Ok(Some(
            self.branch()?
                .verify_finality(
                    agreement.proposal(),
                    agreement.quorum(),
                    &seal,
                    self.maximum_round(),
                )?
                .encode()?,
        ))
    }
    pub fn handoff_agreement(&self) -> Option<&StateAgreement> {
        self.handoff
            .as_ref()
            .and_then(StateHandoffJournal::agreement)
    }
    pub fn ready_signatures(&self) -> Vec<SealSignature> {
        self.ready.values().cloned().collect()
    }
    pub fn terminal_signatures(&self) -> Vec<SealSignature> {
        self.terminal.values().cloned().collect()
    }
    pub fn local_terminal_saved(&self) -> bool {
        self.handoff
            .as_ref()
            .is_some_and(StateHandoffJournal::terminal_saved)
    }
    pub fn local_terminal_released(&self) -> bool {
        self.handoff
            .as_ref()
            .and_then(StateHandoffJournal::terminal)
            .is_some()
    }
    pub fn retire_selected_custody(
        &self,
        directory: &Path,
        anchor_directory: &Path,
        owner: &ed25519_dalek::SigningKey,
    ) -> Result<()> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| StateNodeError::Rejected("outgoing signer unavailable".into()))?;
        StatePeriodCustody::retire_for_selected(
            directory,
            anchor_directory,
            &self.history,
            owner,
            signer,
        )?;
        Ok(())
    }
    pub fn accept_agreement(&mut self, bytes: &[u8]) -> Result<()> {
        let agreement = self
            .branch()?
            .decode_agreement(bytes, self.maximum_round())?;
        self.handoff
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("handoff journal unavailable".into()))?
            .stage(&agreement, &self.history)?;
        self.retain(StatePublication::Proposal(agreement.proposal().clone()))?;
        for vote in agreement.quorum().vote_set().votes() {
            self.retain(StatePublication::Vote(vote.clone()))?;
        }
        Ok(())
    }
    pub fn accept_seal_signature(&mut self, bytes: &[u8]) -> Result<()> {
        let signature = SealSignature::decode(bytes)?;
        let agreement = self
            .handoff_agreement()
            .ok_or_else(|| StateNodeError::Rejected("handoff agreement unavailable".into()))?;
        signature.verify(
            signature.role(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        let target = match signature.role() {
            SealRole::Ready => &mut self.ready,
            SealRole::Terminal => &mut self.terminal,
        };
        if target
            .get(&signature.signer())
            .is_some_and(|old| old != &signature)
        {
            return Err(StateNodeError::Rejected(
                "equivocating seal signature".into(),
            ));
        }
        if target.len() >= 4 && !target.contains_key(&signature.signer()) {
            return Err(StateNodeError::Rejected("seal signer limit".into()));
        }
        target.insert(signature.signer(), signature);
        Ok(())
    }
    pub fn sign_local_ready(&mut self, key: &ed25519_dalek::SigningKey) -> Result<SealSignature> {
        let journal = self
            .handoff
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("handoff journal unavailable".into()))?;
        let ready = journal.sign_ready(key)?;
        self.accept_seal_signature(&ready.encode())?;
        Ok(ready)
    }
    pub fn sign_local_terminal(&mut self) -> Result<()> {
        let ready: Vec<_> = self.ready.values().cloned().collect();
        let journal = self
            .handoff
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("handoff journal unavailable".into()))?;
        let signer = self
            .signer
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("outgoing signer unavailable".into()))?;
        signer.terminal_handoff(journal, &ready)?;
        Ok(())
    }
    /// Called only after the runtime has dropped its old transport handle.
    pub fn release_local_terminal(&mut self) -> Result<SealSignature> {
        let journal = self
            .handoff
            .as_mut()
            .ok_or_else(|| StateNodeError::Rejected("handoff journal unavailable".into()))?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| StateNodeError::Rejected("outgoing signer unavailable".into()))?;
        let terminal = journal.release_terminal(signer)?;
        self.accept_seal_signature(&terminal.encode())?;
        Ok(terminal)
    }
    /// Drain bounded immediately actionable evidence. Finality always precedes
    /// new votes; runtime measures elapsed time separately via `timeout`.
    pub fn drive(&mut self) -> Result<bool> {
        if self.state()?.terminated() {
            return Ok(false);
        }
        let before = self.state()?.height();
        let next_height = self.branch()?.next_height()?;
        if let Some(staged) = self
            .handoff_agreement()
            .filter(|agreement| agreement.seal_context().height() == next_height)
            .cloned()
        {
            // A valid competing agreement must still be surfaced as a durable
            // conflict. Repeated QC subsets for the same record need no new
            // ordinary votes or full proposal replay while the seal arrives.
            for proposal in self.proposals.values() {
                if proposal.value().signing_root() == staged.proposal().value().signing_root() {
                    continue;
                }
                let target = ConsensusVoteTarget::Proposal(proposal.value().signing_root());
                if let Some(qc) =
                    self.quorum(proposal.round(), ConsensusVoteRole::Precommit, target)?
                {
                    let competing =
                        self.branch()?
                            .verify_agreement(proposal, &qc, self.maximum_round())?;
                    self.handoff
                        .as_mut()
                        .ok_or_else(|| {
                            StateNodeError::Rejected("handoff journal unavailable".into())
                        })?
                        .stage(&competing, &self.history)?;
                }
            }
            if let Some(proof) = self.finality_for_staged(&staged)? {
                self.accept_finality(&proof)?;
                return Ok(true);
            }
            return Ok(false);
        }
        for _ in 0..16 {
            let mut agreements = Vec::new();
            for proposal in self.proposals.values() {
                let target = ConsensusVoteTarget::Proposal(proposal.value().signing_root());
                if let Some(qc) =
                    self.quorum(proposal.round(), ConsensusVoteRole::Precommit, target)?
                {
                    agreements.push((proposal.clone(), qc));
                }
            }
            let mut finalities = Vec::new();
            for (proposal, qc) in agreements {
                if let Some(bytes) = self.finality_for(&proposal, &qc)? {
                    finalities.push(bytes);
                }
            }
            if !finalities.is_empty() {
                for proof in finalities {
                    self.accept_finality(&proof)?;
                }
                return Ok(true);
            }
            if self.handoff_agreement().is_some() {
                return Ok(false);
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
                        && votes
                            .has_one_third(self.state()?.genesis(), self.branch()?.authority())?
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
        if self.handoff_agreement().is_some() {
            return Ok(false);
        }
        let Some((_, round, phase)) = self.position()? else {
            return Ok(false);
        };
        match phase {
            StatePhase::Proposal => self.apply(StateLockEvent::ProposalTimeout)?,
            StatePhase::Prevote => {
                let Some(votes) = self.vote_set(round, ConsensusVoteRole::Prevote)? else {
                    return Ok(false);
                };
                if !votes.has_supermajority(self.state()?.genesis(), self.branch()?.authority())? {
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
                if !votes.has_supermajority(self.state()?.genesis(), self.branch()?.authority())? {
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
