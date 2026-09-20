use super::{
    Result, StateConsensusError as Error,
    branch::{StateBranch, StateFinality, StateProposal, StateProposalIntent, StateValue},
    codec::{Reader, bytes},
    digest,
    evidence::{STATE_QUORUM_MAX_BYTES, StateQuorum, StateVote, StateVoteSet, VoteBody},
};
use crate::{ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget};
use naome_ledger::profile::Genesis;

/// Distinct live phases. Local timeout availability never changes canonical time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatePhase {
    Proposal,
    Prevote,
    Precommit,
}

/// Replayable exact input to the no-key signing kernel. A storage owner records
/// the event and resulting snapshot before key use, then records completion
/// before publication. Replaying these events reconstructs retained bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateLockEvent {
    /// None selects the mandatory retained valid record; Some authors fresh.
    Author {
        record: Option<Vec<u8>>,
    },
    Prevote {
        proposal: Option<Vec<u8>>,
    },
    Precommit {
        proposal: Option<Vec<u8>>,
        quorum: Vec<u8>,
    },
    ProposalTimeout,
    /// More than two-thirds current prevotes, possibly with different targets.
    PrevoteTimeout {
        votes: Vec<u8>,
    },
    /// More than two-thirds current precommits, possibly with different targets.
    PrecommitTimeout {
        votes: Vec<u8>,
    },
    /// More than one-third at one strictly higher round; emits no vote.
    HigherRound {
        votes: Vec<u8>,
    },
    /// A matching current NIL precommit quorum can preempt any local phase.
    NilPrecommit {
        quorum: Vec<u8>,
    },
}
impl StateLockEvent {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = b"NSCE1".to_vec();
        match self {
            Self::Author { record } => {
                out.push(0);
                put_optional(&mut out, record.as_deref())?;
            }
            Self::Prevote { proposal } => {
                out.push(1);
                put_optional(&mut out, proposal.as_deref())?;
            }
            Self::Precommit { proposal, quorum } => {
                out.push(2);
                put_optional(&mut out, proposal.as_deref())?;
                bytes(&mut out, quorum)?;
            }
            Self::ProposalTimeout => out.push(3),
            Self::PrevoteTimeout { votes } => {
                out.push(4);
                bytes(&mut out, votes)?;
            }
            Self::PrecommitTimeout { votes } => {
                out.push(5);
                bytes(&mut out, votes)?;
            }
            Self::HigherRound { votes } => {
                out.push(6);
                bytes(&mut out, votes)?;
            }
            Self::NilPrecommit { quorum } => {
                out.push(7);
                bytes(&mut out, quorum)?;
            }
        }
        Ok(out)
    }
    pub fn decode(input: &[u8], genesis: &Genesis) -> Result<Self> {
        let maximum = genesis.profile().limits().transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum + STATE_QUORUM_MAX_BYTES + 32)?;
        if r.fixed::<5>()? != *b"NSCE1" {
            return Err(Error::Invalid("state event version"));
        }
        let event = match r.u8()? {
            0 => Self::Author {
                record: read_optional(&mut r, genesis.profile().limits().record_bytes as usize)?,
            },
            1 => Self::Prevote {
                proposal: read_optional(&mut r, maximum)?,
            },
            2 => Self::Precommit {
                proposal: read_optional(&mut r, maximum)?,
                quorum: r.bytes(STATE_QUORUM_MAX_BYTES)?.to_vec(),
            },
            3 => Self::ProposalTimeout,
            4 => Self::PrevoteTimeout {
                votes: r.bytes(STATE_QUORUM_MAX_BYTES)?.to_vec(),
            },
            5 => Self::PrecommitTimeout {
                votes: r.bytes(STATE_QUORUM_MAX_BYTES)?.to_vec(),
            },
            6 => Self::HigherRound {
                votes: r.bytes(STATE_QUORUM_MAX_BYTES)?.to_vec(),
            },
            7 => Self::NilPrecommit {
                quorum: r.bytes(STATE_QUORUM_MAX_BYTES)?.to_vec(),
            },
            _ => return Err(Error::Invalid("state event tag")),
        };
        r.finish()?;
        Ok(event)
    }
    fn check_lengths(&self, genesis: &Genesis) -> Result<()> {
        let proposal_max = genesis.profile().limits().transport_frame_bytes as usize;
        let (payload, payload_max, evidence) = match self {
            Self::Author { record } => (
                record.as_deref(),
                genesis.profile().limits().record_bytes as usize,
                None,
            ),
            Self::Prevote { proposal } => (proposal.as_deref(), proposal_max, None),
            Self::Precommit { proposal, quorum } => {
                (proposal.as_deref(), proposal_max, Some(quorum.as_slice()))
            }
            Self::ProposalTimeout => (None, 0, None),
            Self::PrevoteTimeout { votes }
            | Self::PrecommitTimeout { votes }
            | Self::HigherRound { votes } => (None, 0, Some(votes.as_slice())),
            Self::NilPrecommit { quorum } => (None, 0, Some(quorum.as_slice())),
        };
        if payload.is_some_and(|p| p.len() > payload_max)
            || evidence.is_some_and(|e| e.len() > STATE_QUORUM_MAX_BYTES)
        {
            return Err(Error::Limit("state event input"));
        }
        Ok(())
    }
}
fn put_optional(out: &mut Vec<u8>, value: Option<&[u8]>) -> Result<()> {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            bytes(out, value)?;
        }
    }
    Ok(())
}
fn read_optional(r: &mut Reader<'_>, maximum: usize) -> Result<Option<Vec<u8>>> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.bytes(maximum)?.to_vec())),
        _ => Err(Error::Invalid("optional state input")),
    }
}

/// One unsigned vote effect. Its exact post-state must be anchored before the
/// holder of the registered key signs this transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVoteIntent {
    body: VoteBody,
    signer: ConsensusKey,
    parent: [u8; 32],
}
impl StateVoteIntent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.body.signing_bytes(self.signer)
    }
    pub const fn role(&self) -> ConsensusVoteRole {
        self.body.role
    }
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.body.target
    }
    pub const fn height(&self) -> u64 {
        self.body.height
    }
    pub const fn round(&self) -> u64 {
        self.body.round
    }
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }
    pub fn complete(&self, signature: [u8; 64], branch: &StateBranch) -> Result<StateVote> {
        if self.body.height != branch.next_height()? || self.parent != branch.commitment() {
            return Err(Error::Invalid("vote intent branch height"));
        }
        StateVote::complete(self.body, self.signer, signature, branch.state().genesis())
    }
}

/// Result of one kernel event. A checkpoint changes state without key use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateIntent {
    Proposal(StateProposalIntent),
    Vote(StateVoteIntent),
    Checkpoint,
}
impl StateIntent {
    pub fn signing_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Proposal(p) => Some(p.signing_bytes()),
            Self::Vote(v) => Some(v.signing_bytes()),
            Self::Checkpoint => None,
        }
    }
    pub fn complete(
        &self,
        signature: [u8; 64],
        branch: &StateBranch,
        maximum_round: u64,
    ) -> Result<StatePublication> {
        match self {
            Self::Proposal(p) => Ok(StatePublication::Proposal(p.complete(
                signature,
                branch,
                maximum_round,
            )?)),
            Self::Vote(v) => Ok(StatePublication::Vote(v.complete(signature, branch)?)),
            Self::Checkpoint => Err(Error::Invalid("checkpoint has no signature")),
        }
    }
}
/// Self-verified signed bytes, still awaiting durable completion before release.
// Keep this short-lived, bounded carrier inline: the signer retains at most
// three current-round publications, and node evidence has separate hard caps.
// Boxing both variants solely to equalize their sizes would allocate for every
// completed vote without reducing the separately owned proposal/record bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatePublication {
    Proposal(StateProposal),
    Vote(StateVote),
}
impl StatePublication {
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Proposal(p) => p.encode(),
            Self::Vote(v) => Ok(v.encode()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Locked {
    value: StateValue,
    round: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Valid {
    value: StateValue,
    round: u64,
    quorum: StateQuorum,
    record: Vec<u8>,
}

/// No-key, replayable lock machine. Cloning grants no key or persistence rights;
/// a storage/node owner must maintain the only live signing lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateLockState {
    parent: [u8; 32],
    signer: ConsensusKey,
    height: u64,
    round: u64,
    phase: StatePhase,
    locked: Option<Locked>,
    valid: Option<Valid>,
    authored: Option<StateProposalIntent>,
}
impl StateLockState {
    pub fn new(branch: &StateBranch, signer: ConsensusKey) -> Result<Self> {
        if !branch
            .state()
            .genesis()
            .validators()
            .iter()
            .any(|v| v.consensus_key == *signer.as_bytes())
        {
            return Err(Error::Invalid("inactive state signer"));
        }
        Ok(Self {
            parent: branch.commitment(),
            signer,
            height: branch.next_height()?,
            round: 0,
            phase: StatePhase::Proposal,
            locked: None,
            valid: None,
            authored: None,
        })
    }
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn phase(&self) -> StatePhase {
        self.phase
    }
    pub fn locked_value(&self) -> Option<(StateValue, u64)> {
        self.locked.as_ref().map(|l| (l.value, l.round))
    }
    pub fn valid_value(&self) -> Option<(StateValue, u64)> {
        self.valid.as_ref().map(|v| (v.value, v.round))
    }
    pub fn retained_record(&self) -> Option<&[u8]> {
        self.valid.as_ref().map(|v| v.record.as_slice())
    }
    pub fn retained_quorum(&self) -> Option<&StateQuorum> {
        self.valid.as_ref().map(|v| &v.quorum)
    }
    fn check_branch(&self, branch: &StateBranch) -> Result<()> {
        if branch.state().terminated() {
            return Err(Error::Invalid("state run terminated"));
        }
        if self.parent != branch.commitment() || self.height != branch.next_height()? {
            return Err(Error::Invalid("state signer parent"));
        }
        Ok(())
    }
    fn require_phase(&self, phase: StatePhase) -> Result<()> {
        if self.phase != phase {
            return Err(Error::Invalid("state signing phase"));
        }
        Ok(())
    }

    /// Atomically evaluates an event on temporary state. The caller must persist
    /// event + snapshot + returned transcript BEFORE completing its signature.
    pub fn apply(
        &mut self,
        branch: &StateBranch,
        event: &StateLockEvent,
        maximum_round: u64,
    ) -> Result<StateIntent> {
        self.check_branch(branch)?;
        event.check_lengths(branch.state().genesis())?;
        if self.round > maximum_round {
            return Err(Error::Limit("current round"));
        }
        let mut next = self.clone();
        let intent = next.apply_inner(branch, event, maximum_round)?;
        next.check_invariants()?;
        *self = next;
        Ok(intent)
    }
    fn apply_inner(
        &mut self,
        branch: &StateBranch,
        event: &StateLockEvent,
        maximum_round: u64,
    ) -> Result<StateIntent> {
        let genesis = branch.state().genesis();
        match event {
            StateLockEvent::Author { record } => {
                self.require_phase(StatePhase::Proposal)?;
                let (record, valid) = match (&self.valid, record) {
                    (Some(_), Some(_)) => {
                        return Err(Error::Invalid("retained valid state record required"));
                    }
                    (None, None) => return Err(Error::Invalid("fresh state record required")),
                    (Some(valid), None) => (valid.record.clone(), Some(valid.quorum.clone())),
                    (None, Some(record)) => (record.clone(), None),
                };
                let intent = branch.proposal_intent(
                    record,
                    self.round,
                    self.signer,
                    valid,
                    maximum_round,
                )?;
                if self.authored.as_ref().is_some_and(|old| old != &intent) {
                    return Err(Error::Invalid("conflicting authored state proposal"));
                }
                self.authored = Some(intent.clone());
                Ok(StateIntent::Proposal(intent))
            }
            StateLockEvent::Prevote { proposal } => {
                self.require_phase(StatePhase::Proposal)?;
                let proposal = proposal
                    .as_ref()
                    .map(|bytes| branch.verify_proposal(bytes, maximum_round))
                    .transpose()?;
                let target = if let Some(proposal) = proposal {
                    self.check_proposal(&proposal)?;
                    if let Some(qc) = proposal.valid_quorum() {
                        if let Some(valid) = &self.valid
                            && qc.round() == valid.round
                            && proposal.value() != valid.value
                        {
                            return Err(Error::Invalid("conflicting valid ledger values"));
                        }
                        if self
                            .valid
                            .as_ref()
                            .is_none_or(|valid| qc.round() > valid.round)
                        {
                            self.valid = Some(Valid {
                                value: proposal.value(),
                                round: qc.round(),
                                quorum: qc.clone(),
                                record: proposal.record_bytes().to_vec(),
                            });
                        }
                    }
                    match &self.locked {
                        None => ConsensusVoteTarget::Proposal(proposal.value().signing_root()),
                        Some(lock) if lock.value == proposal.value() => {
                            ConsensusVoteTarget::Proposal(proposal.value().signing_root())
                        }
                        Some(lock)
                            if proposal.valid_quorum().is_some_and(|qc| {
                                lock.round < qc.round() && qc.round() < self.round
                            }) =>
                        {
                            self.locked = None;
                            ConsensusVoteTarget::Proposal(proposal.value().signing_root())
                        }
                        Some(lock) => ConsensusVoteTarget::Proposal(lock.value.signing_root()),
                    }
                } else {
                    self.locked
                        .as_ref()
                        .map_or(ConsensusVoteTarget::Nil, |lock| {
                            ConsensusVoteTarget::Proposal(lock.value.signing_root())
                        })
                };
                self.phase = StatePhase::Prevote;
                Ok(self.vote(genesis, ConsensusVoteRole::Prevote, target))
            }
            StateLockEvent::ProposalTimeout => {
                self.require_phase(StatePhase::Proposal)?;
                let target = self
                    .locked
                    .as_ref()
                    .map_or(ConsensusVoteTarget::Nil, |lock| {
                        ConsensusVoteTarget::Proposal(lock.value.signing_root())
                    });
                self.phase = StatePhase::Prevote;
                Ok(self.vote(genesis, ConsensusVoteRole::Prevote, target))
            }
            StateLockEvent::Precommit { proposal, quorum } => {
                self.require_phase(StatePhase::Prevote)?;
                let qc = StateQuorum::decode(quorum, genesis)?;
                let proposal = proposal
                    .as_ref()
                    .map(|bytes| branch.verify_proposal(bytes, maximum_round))
                    .transpose()?;
                let target = if let Some(proposal) = proposal {
                    self.check_proposal(&proposal)?;
                    let target = ConsensusVoteTarget::Proposal(proposal.value().signing_root());
                    qc.check(
                        genesis,
                        self.height,
                        self.round,
                        ConsensusVoteRole::Prevote,
                        target,
                    )?;
                    self.locked = Some(Locked {
                        value: proposal.value(),
                        round: self.round,
                    });
                    self.valid = Some(Valid {
                        value: proposal.value(),
                        round: self.round,
                        quorum: qc,
                        record: proposal.record_bytes().to_vec(),
                    });
                    target
                } else {
                    qc.check(
                        genesis,
                        self.height,
                        self.round,
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Nil,
                    )?;
                    self.locked = None;
                    ConsensusVoteTarget::Nil
                };
                self.phase = StatePhase::Precommit;
                Ok(self.vote(genesis, ConsensusVoteRole::Precommit, target))
            }
            StateLockEvent::PrevoteTimeout { votes } => {
                self.require_phase(StatePhase::Prevote)?;
                self.progress_votes(votes, genesis, ConsensusVoteRole::Prevote)?;
                self.phase = StatePhase::Precommit;
                Ok(self.vote(
                    genesis,
                    ConsensusVoteRole::Precommit,
                    ConsensusVoteTarget::Nil,
                ))
            }
            StateLockEvent::PrecommitTimeout { votes } => {
                self.require_phase(StatePhase::Precommit)?;
                self.progress_votes(votes, genesis, ConsensusVoteRole::Precommit)?;
                self.next_round(maximum_round)?;
                Ok(StateIntent::Checkpoint)
            }
            StateLockEvent::HigherRound { votes } => {
                let votes = StateVoteSet::decode(votes, genesis)?;
                if votes.height() != self.height || votes.round() <= self.round {
                    return Err(Error::Invalid("higher state round"));
                }
                if votes.round() > maximum_round {
                    return Err(Error::Limit("higher state round"));
                }
                if !votes.has_one_third(genesis)? {
                    return Err(Error::Invalid("higher state round authority"));
                }
                // Derive bounded scheduled state as a reachability check, but do
                // not advance the canonical once-per-height proposer base.
                let _ = branch.proposer(votes.round(), maximum_round)?;
                self.round = votes.round();
                self.phase = StatePhase::Proposal;
                self.authored = None;
                Ok(StateIntent::Checkpoint)
            }
            StateLockEvent::NilPrecommit { quorum } => {
                let qc = StateQuorum::decode(quorum, genesis)?;
                qc.check(
                    genesis,
                    self.height,
                    self.round,
                    ConsensusVoteRole::Precommit,
                    ConsensusVoteTarget::Nil,
                )?;
                self.next_round(maximum_round)?;
                Ok(StateIntent::Checkpoint)
            }
        }
    }
    fn check_proposal(&self, proposal: &StateProposal) -> Result<()> {
        if proposal.parent_commitment() != &self.parent
            || proposal.round() != self.round
            || proposal.value().height() != self.height
        {
            return Err(Error::Invalid("state proposal position"));
        }
        Ok(())
    }
    fn vote(
        &self,
        genesis: &Genesis,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> StateIntent {
        StateIntent::Vote(StateVoteIntent {
            body: VoteBody {
                genesis: genesis.id(),
                profile: genesis.profile().id(),
                height: self.height,
                round: self.round,
                role,
                target,
            },
            signer: self.signer,
            parent: self.parent,
        })
    }
    fn progress_votes(
        &self,
        input: &[u8],
        genesis: &Genesis,
        role: ConsensusVoteRole,
    ) -> Result<()> {
        let votes = StateVoteSet::decode(input, genesis)?;
        if votes.height() != self.height
            || votes.round() != self.round
            || votes.role() != role
            || !votes.has_supermajority(genesis)?
        {
            return Err(Error::Invalid("state phase progress quorum"));
        }
        Ok(())
    }
    fn next_round(&mut self, maximum_round: u64) -> Result<()> {
        let next = self.round.checked_add(1).ok_or(Error::Overflow)?;
        if next > maximum_round {
            return Err(Error::Limit("next state round"));
        }
        self.round = next;
        self.phase = StatePhase::Proposal;
        self.authored = None;
        Ok(())
    }
    fn check_invariants(&self) -> Result<()> {
        if let Some(lock) = &self.locked {
            let valid = self
                .valid
                .as_ref()
                .ok_or(Error::Invalid("lock without valid record"))?;
            if lock.round > self.round || valid.round < lock.round || valid.value != lock.value {
                return Err(Error::Invalid("state lock valid mismatch"));
            }
            if lock.round == self.round && self.phase != StatePhase::Precommit {
                return Err(Error::Invalid("current state lock phase"));
            }
        }
        if let Some(valid) = &self.valid {
            if valid.round > self.round {
                return Err(Error::Invalid("future valid state record"));
            }
            if valid.round == self.round
                && (self.phase != StatePhase::Precommit
                    || self
                        .locked
                        .as_ref()
                        .is_none_or(|lock| lock.round != valid.round || lock.value != valid.value))
            {
                return Err(Error::Invalid("current state valid record without lock"));
            }
        }
        Ok(())
    }
    /// Compact deterministic checkpoint. Full record bytes remain in the exact
    /// preceding durable events; the digest and complete QC bind their recovery.
    /// Raw snapshot bytes alone intentionally have no restoration constructor.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.check_invariants()?;
        let mut out = b"NSCS1".to_vec();
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(self.signer.as_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.round.to_be_bytes());
        out.push(match self.phase {
            StatePhase::Proposal => 0,
            StatePhase::Prevote => 1,
            StatePhase::Precommit => 2,
        });
        match &self.locked {
            None => out.push(0),
            Some(lock) => {
                out.push(1);
                out.extend(lock.value.encode());
                out.extend_from_slice(&lock.round.to_be_bytes());
            }
        }
        match &self.valid {
            None => out.push(0),
            Some(valid) => {
                out.push(1);
                out.extend(valid.value.encode());
                out.extend_from_slice(&valid.round.to_be_bytes());
                bytes(&mut out, &valid.quorum.encode())?;
                out.extend_from_slice(&(valid.record.len() as u64).to_be_bytes());
                out.extend_from_slice(&digest(
                    b"naome:state:retained-record:v1\0",
                    &[&valid.record],
                ));
            }
        }
        match &self.authored {
            None => out.push(0),
            Some(intent) => {
                out.push(1);
                out.extend(intent.value.encode());
                out.extend_from_slice(&intent.round.to_be_bytes());
                out.extend_from_slice(&digest(
                    b"naome:state:authored-intent:v1\0",
                    &[&intent.encode()?],
                ));
            }
        }
        Ok(out)
    }
    /// Reset only for an exact verified direct child. Storage must durably select
    /// that finality before making this height handoff available for new signing.
    pub fn advance_height(&mut self, finality: &StateFinality) -> Result<()> {
        if finality.proposal().parent_commitment() != &self.parent
            || finality.proposal().value().height() != self.height
        {
            return Err(Error::Invalid("state height handoff"));
        }
        *self = Self::new(finality.branch(), self.signer)?;
        Ok(())
    }
}
