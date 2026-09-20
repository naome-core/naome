use super::{
    Result, StateConsensusError as Error,
    codec::{Reader, bytes},
    digest,
    evidence::{STATE_QUORUM_MAX_BYTES, StateQuorum, verify_signer},
};
use crate::{
    ActiveAgreementEntry, AgreementWeight, ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    ProposalSigningRoot, proposer_selection::FixedProposerState,
};
use naome_chain::StateRecordExecution;
use naome_chain::{FinalizedStateRecord, StateRecord};
use naome_ledger::{GenesisId, LedgerState, ProfileId, RecordId, StateCommitment};

const VALUE_MAGIC: &[u8; 5] = b"NSCB1";
const VALUE_BYTES: usize = 5 + 8 * 32 + 8;
const PROPOSAL_MAGIC: &[u8; 5] = b"NSCP1";

/// Evidence-free header binding a complete state record and proposer state.
/// Neither observing nor decoding this header grants application authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateValue {
    genesis: GenesisId,
    profile: ProfileId,
    height: u64,
    parent: RecordId,
    record: RecordId,
    previous: StateCommitment,
    next: StateCommitment,
    fixed_set: [u8; 32],
    next_proposer: [u8; 32],
}
impl StateValue {
    pub const BYTE_LENGTH: usize = VALUE_BYTES;
    pub const fn genesis(&self) -> GenesisId {
        self.genesis
    }
    pub const fn profile(&self) -> ProfileId {
        self.profile
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn parent(&self) -> RecordId {
        self.parent
    }
    pub const fn record_id(&self) -> RecordId {
        self.record
    }
    pub const fn previous_state(&self) -> StateCommitment {
        self.previous
    }
    pub const fn next_state(&self) -> StateCommitment {
        self.next
    }
    pub const fn next_proposer_state(&self) -> &[u8; 32] {
        &self.next_proposer
    }
    pub const fn fixed_set(&self) -> &[u8; 32] {
        &self.fixed_set
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = VALUE_MAGIC.to_vec();
        out.extend_from_slice(self.genesis.as_bytes());
        out.extend_from_slice(self.profile.as_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        for field in [
            self.parent.as_bytes(),
            self.record.as_bytes(),
            self.previous.as_bytes(),
            self.next.as_bytes(),
            &self.fixed_set,
            &self.next_proposer,
        ] {
            out.extend_from_slice(field);
        }
        out
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut r = Reader::new(input, VALUE_BYTES)?;
        if r.fixed::<5>()? != *VALUE_MAGIC {
            return Err(Error::Invalid("ledger value version"));
        }
        let result = Self {
            genesis: GenesisId::from_bytes(r.fixed()?),
            profile: ProfileId::from_bytes(r.fixed()?),
            height: r.u64()?,
            parent: RecordId::from_bytes(r.fixed()?),
            record: RecordId::from_bytes(r.fixed()?),
            previous: StateCommitment::from_bytes(r.fixed()?),
            next: StateCommitment::from_bytes(r.fixed()?),
            fixed_set: r.fixed()?,
            next_proposer: r.fixed()?,
        };
        r.finish()?;
        if result.height == 0 {
            return Err(Error::Invalid("zero state height"));
        }
        Ok(result)
    }
    pub fn signing_root(&self) -> ProposalSigningRoot {
        ProposalSigningRoot::from_bytes(digest(
            b"naome:state:consensus-value:v1\0",
            &[&self.encode()],
        ))
    }
    /// Complete branch commitment after this value, independent of signature set.
    pub fn next_consensus_commitment(&self) -> [u8; 32] {
        branch_commitment(
            self.genesis,
            self.height,
            self.record,
            self.next,
            self.fixed_set,
            self.next_proposer,
        )
    }
}

/// Immutable branch whose state state is advanced only by verified finality.
#[derive(Clone)]
pub struct StateBranch {
    state: LedgerState,
    proposer: FixedProposerState,
}
impl StateBranch {
    pub fn from_genesis(state: LedgerState) -> Result<Self> {
        if state.height() != 0 {
            return Err(Error::Invalid("state branch requires genesis"));
        }
        let entries: Vec<_> = state
            .genesis()
            .validators()
            .iter()
            .map(|v| {
                ActiveAgreementEntry::new(
                    ConsensusKey::from_bytes(v.consensus_key),
                    AgreementWeight::new(1),
                )
            })
            .collect();
        let proposer = FixedProposerState::try_from_preselected(&entries)
            .map_err(|_| Error::Invalid("state fixed set"))?;
        Ok(Self { state, proposer })
    }
    pub fn state(&self) -> &LedgerState {
        &self.state
    }
    pub fn commitment(&self) -> [u8; 32] {
        branch_commitment(
            self.state.genesis().id(),
            self.state.height(),
            self.state.head(),
            self.state.commitment(),
            *self.proposer.fixed_set_id().as_bytes(),
            *self.proposer.id().as_bytes(),
        )
    }
    pub fn next_height(&self) -> Result<u64> {
        self.state.height().checked_add(1).ok_or(Error::Overflow)
    }
    pub fn proposer(&self, round: u64, maximum_round: u64) -> Result<ConsensusKey> {
        Ok(self.round_state(round, maximum_round)?.0)
    }
    fn round_state(
        &self,
        round: u64,
        maximum_round: u64,
    ) -> Result<(ConsensusKey, FixedProposerState)> {
        if round > maximum_round {
            return Err(Error::Limit("round derivation"));
        }
        let (mut key, mut state) = self
            .proposer
            .select_next()
            .map_err(|_| Error::Invalid("proposer selection"))?;
        for _ in 0..round {
            (key, state) = state
                .select_next()
                .map_err(|_| Error::Invalid("proposer selection"))?;
        }
        Ok((key, state))
    }
    fn next_proposer(&self) -> Result<FixedProposerState> {
        self.proposer
            .select_next()
            .map(|(_, state)| state)
            .map_err(|_| Error::Invalid("proposer successor"))
    }
    fn validate_record_bytes(&self, record_bytes: &[u8]) -> Result<(StateValue, LedgerState)> {
        let record = StateRecord::decode(record_bytes, self.state.genesis())?;
        if record.encode()?.as_slice() != record_bytes {
            return Err(Error::Invalid("noncanonical state record"));
        }
        if record.parent() != self.state.head()
            || record.height() != self.next_height()?
            || record.previous_state() != self.state.commitment()
        {
            return Err(Error::Invalid("state record parent"));
        }
        let next = self.state.validate_record(&record)?.into_state();
        if next.commitment() != record.next_state()
            || next.head() != record.id()
            || next.height() != record.height()
        {
            return Err(Error::Invalid("state successor state"));
        }
        let proposer = self.next_proposer()?;
        let value = StateValue {
            genesis: self.state.genesis().id(),
            profile: self.state.genesis().profile().id(),
            height: record.height(),
            parent: record.parent(),
            record: record.id(),
            previous: record.previous_state(),
            next: record.next_state(),
            fixed_set: *proposer.fixed_set_id().as_bytes(),
            next_proposer: *proposer.id().as_bytes(),
        };
        Ok((value, next))
    }
    pub(super) fn value_for_record(&self, record_bytes: &[u8]) -> Result<StateValue> {
        self.validate_record_bytes(record_bytes)
            .map(|(value, _)| value)
    }
    pub(super) fn proposal_intent(
        &self,
        record_bytes: Vec<u8>,
        round: u64,
        signer: ConsensusKey,
        valid: Option<StateQuorum>,
        maximum_round: u64,
    ) -> Result<StateProposalIntent> {
        if self.proposer(round, maximum_round)? != signer {
            return Err(Error::Invalid("not scheduled state proposer"));
        }
        let value = self.value_for_record(&record_bytes)?;
        validate_valid_quorum(&valid, &value, round, self.state.genesis())?;
        Ok(StateProposalIntent {
            value,
            record_bytes,
            round,
            proposer: signer,
            valid,
            parent_commitment: self.commitment(),
        })
    }
    pub fn verify_proposal(&self, input: &[u8], maximum_round: u64) -> Result<StateProposal> {
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum)?;
        if r.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("state proposal version"));
        }
        let value = StateValue::decode(r.take(VALUE_BYTES)?)?;
        if value.genesis != self.state.genesis().id()
            || value.profile != self.state.genesis().profile().id()
            || value.parent != self.state.head()
            || value.height != self.next_height()?
            || value.previous != self.state.commitment()
        {
            return Err(Error::Invalid("state proposal parent"));
        }
        let round = r.u64()?;
        let proposer = ConsensusKey::from_bytes(r.fixed()?);
        let signature = r.fixed()?;
        if self.proposer(round, maximum_round)? != proposer {
            return Err(Error::Invalid("state proposer"));
        }
        verify_signer(
            self.state.genesis(),
            proposer,
            &proposal_signing_bytes(value, round, proposer),
            signature,
        )?;
        let qc_bytes = r.bytes(STATE_QUORUM_MAX_BYTES)?;
        let valid = if qc_bytes.is_empty() {
            None
        } else {
            Some(StateQuorum::decode(qc_bytes, self.state.genesis())?)
        };
        validate_valid_quorum(&valid, &value, round, self.state.genesis())?;
        let record_bytes = r
            .bytes(self.state.genesis().profile().limits().record_bytes as usize)?
            .to_vec();
        r.finish()?;
        let expected = self.value_for_record(&record_bytes)?;
        if value != expected {
            return Err(Error::Invalid("ledger value commitment"));
        }
        Ok(StateProposal {
            intent: StateProposalIntent {
                value,
                record_bytes,
                round,
                proposer,
                valid,
                parent_commitment: self.commitment(),
            },
            signature,
        })
    }
    pub fn verify_finality(
        &self,
        proposal: &StateProposal,
        quorum: &StateQuorum,
        maximum_round: u64,
    ) -> Result<StateFinality> {
        quorum.check(
            self.state.genesis(),
            proposal.value().height(),
            proposal.round(),
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(proposal.value().signing_root()),
        )?;
        // A verified token from another branch cannot bypass exact-parent checking.
        let proposal = self.verify_proposal(&proposal.encode()?, maximum_round)?;
        let (_, state) = self.validate_record_bytes(proposal.record_bytes())?;
        let child = Self {
            state,
            proposer: self.next_proposer()?,
        };
        if child.commitment() != proposal.value().next_consensus_commitment() {
            return Err(Error::Invalid("state branch successor"));
        }
        Ok(StateFinality {
            proposal,
            quorum: quorum.clone(),
            child,
        })
    }
    pub fn decode_finality(&self, input: &[u8], maximum_round: u64) -> Result<StateFinality> {
        // Do not start application replay on an unauthenticated finality claim.
        let _ = StateFinality::authenticate(input, self.state.genesis(), maximum_round)?;
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let record = FinalizedStateRecord::decode(input, maximum, STATE_QUORUM_MAX_BYTES)?;
        let proposal = self.verify_proposal(record.proposal(), maximum_round)?;
        let quorum = StateQuorum::decode(record.quorum(), self.state.genesis())?;
        self.verify_finality(&proposal, &quorum, maximum_round)
    }
}
fn branch_commitment(
    genesis: GenesisId,
    height: u64,
    head: RecordId,
    state: StateCommitment,
    set: [u8; 32],
    proposer: [u8; 32],
) -> [u8; 32] {
    digest(
        b"naome:state:consensus-state:v1\0",
        &[
            genesis.as_bytes(),
            &height.to_be_bytes(),
            head.as_bytes(),
            state.as_bytes(),
            &set,
            &proposer,
        ],
    )
}
fn validate_valid_quorum(
    valid: &Option<StateQuorum>,
    value: &StateValue,
    round: u64,
    genesis: &naome_ledger::profile::Genesis,
) -> Result<()> {
    if let Some(qc) = valid {
        if qc.round() >= round {
            return Err(Error::Invalid("non-earlier valid round"));
        }
        qc.check(
            genesis,
            value.height,
            qc.round(),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(value.signing_root()),
        )?;
    }
    Ok(())
}
fn proposal_signing_bytes(value: StateValue, round: u64, proposer: ConsensusKey) -> Vec<u8> {
    let mut bytes = b"naome:state:proposal:v1\0".to_vec();
    bytes.extend(value.encode());
    bytes.extend_from_slice(&round.to_be_bytes());
    bytes.extend_from_slice(proposer.as_bytes());
    bytes
}

/// Application-verified unsigned proposal. Persist intent before key use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateProposalIntent {
    pub(super) value: StateValue,
    pub(super) record_bytes: Vec<u8>,
    pub(super) round: u64,
    pub(super) proposer: ConsensusKey,
    pub(super) valid: Option<StateQuorum>,
    pub(super) parent_commitment: [u8; 32],
}
impl StateProposalIntent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        proposal_signing_bytes(self.value, self.round, self.proposer)
    }
    pub const fn value(&self) -> StateValue {
        self.value
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn proposer(&self) -> ConsensusKey {
        self.proposer
    }
    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }
    pub fn valid_quorum(&self) -> Option<&StateQuorum> {
        self.valid.as_ref()
    }
    /// Exact recovery bytes including the full immutable record and retained QC.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_proposal(self, [0; 64])
    }
    pub fn complete(
        &self,
        signature: [u8; 64],
        branch: &StateBranch,
        maximum_round: u64,
    ) -> Result<StateProposal> {
        branch.verify_proposal(&encode_proposal(self, signature)?, maximum_round)
    }
}
fn encode_proposal(intent: &StateProposalIntent, signature: [u8; 64]) -> Result<Vec<u8>> {
    let mut out = PROPOSAL_MAGIC.to_vec();
    out.extend(intent.value.encode());
    out.extend_from_slice(&intent.round.to_be_bytes());
    out.extend_from_slice(intent.proposer.as_bytes());
    out.extend_from_slice(&signature);
    bytes(
        &mut out,
        &intent
            .valid
            .as_ref()
            .map_or_else(Vec::new, StateQuorum::encode),
    )?;
    bytes(&mut out, &intent.record_bytes)?;
    Ok(out)
}

/// Complete producer-authenticated proposal, verified against an exact branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateProposal {
    pub(super) intent: StateProposalIntent,
    signature: [u8; 64],
}
impl StateProposal {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_proposal(&self.intent, self.signature)
    }
    pub const fn value(&self) -> StateValue {
        self.intent.value
    }
    pub const fn round(&self) -> u64 {
        self.intent.round
    }
    pub const fn proposer(&self) -> ConsensusKey {
        self.intent.proposer
    }
    pub fn record_bytes(&self) -> &[u8] {
        &self.intent.record_bytes
    }
    pub fn valid_quorum(&self) -> Option<&StateQuorum> {
        self.intent.valid.as_ref()
    }
    pub const fn parent_commitment(&self) -> &[u8; 32] {
        &self.intent.parent_commitment
    }
}

/// Sealed state successor and sufficient finality evidence. Durable selection
/// is storage's responsibility; this token establishes only verified transition.
pub struct StateFinality {
    proposal: StateProposal,
    quorum: StateQuorum,
    child: StateBranch,
}
impl StateFinality {
    /// Bounded evidence authentication before historical or mathematical replay.
    /// The result remains an observed header, not a selected/verified successor:
    /// exact parent, scheduled proposer and application effects need the branch.
    pub fn authenticate(
        input: &[u8],
        genesis: &naome_ledger::profile::Genesis,
        maximum_round: u64,
    ) -> Result<StateValue> {
        let maximum = genesis.profile().limits().transport_frame_bytes as usize;
        let record = FinalizedStateRecord::decode(input, maximum, STATE_QUORUM_MAX_BYTES)?;
        let proposal = record.proposal();
        let finality_quorum = record.quorum();
        let mut p = Reader::new(proposal, maximum)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("state proposal version"));
        }
        let value = StateValue::decode(p.take(VALUE_BYTES)?)?;
        if value.genesis != genesis.id() || value.profile != genesis.profile().id() {
            return Err(Error::Invalid("state evidence context"));
        }
        let entries: Vec<_> = genesis
            .validators()
            .iter()
            .map(|v| {
                ActiveAgreementEntry::new(
                    ConsensusKey::from_bytes(v.consensus_key),
                    AgreementWeight::new(1),
                )
            })
            .collect();
        let fixed = FixedProposerState::try_from_preselected(&entries)
            .map_err(|_| Error::Invalid("state fixed set"))?;
        if value.fixed_set != *fixed.fixed_set_id().as_bytes() {
            return Err(Error::Invalid("state evidence fixed set"));
        }
        let round = p.u64()?;
        if round > maximum_round || round > genesis.profile().limits().consensus_rounds {
            return Err(Error::Limit("state evidence round"));
        }
        let proposer = ConsensusKey::from_bytes(p.fixed()?);
        let signature = p.fixed()?;
        verify_signer(
            genesis,
            proposer,
            &proposal_signing_bytes(value, round, proposer),
            signature,
        )?;
        let valid_bytes = p.bytes(STATE_QUORUM_MAX_BYTES)?;
        let valid = if valid_bytes.is_empty() {
            None
        } else {
            Some(StateQuorum::decode(valid_bytes, genesis)?)
        };
        validate_valid_quorum(&valid, &value, round, genesis)?;
        let record_bytes = p.bytes(genesis.profile().limits().record_bytes as usize)?;
        p.finish()?;
        let quorum = StateQuorum::decode(finality_quorum, genesis)?;
        quorum.check(
            genesis,
            value.height,
            round,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(value.signing_root()),
        )?;
        // Only quorum-authenticated content reaches even the bounded record
        // decoder. This performs no proof checking or historical reconstruction.
        let record = StateRecord::decode(record_bytes, genesis)?;
        if record.encode()?.as_slice() != record_bytes
            || record.id() != value.record
            || record.height() != value.height
            || record.parent() != value.parent
            || record.previous_state() != value.previous
            || record.next_state() != value.next
        {
            return Err(Error::Invalid("state evidence record binding"));
        }
        Ok(value)
    }

    /// Untrusted routing hint only. The receiver must still verify the complete
    /// proof against the selected parent at this height before using any field.
    pub fn claimed_height(input: &[u8], maximum_bytes: usize) -> Result<u64> {
        let record = FinalizedStateRecord::decode(input, maximum_bytes, STATE_QUORUM_MAX_BYTES)?;
        let proposal = record.proposal();
        let mut p = Reader::new(proposal, maximum_bytes)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("state proposal version"));
        }
        Ok(StateValue::decode(p.take(VALUE_BYTES)?)?.height())
    }

    pub fn proposal(&self) -> &StateProposal {
        &self.proposal
    }
    pub fn quorum(&self) -> &StateQuorum {
        &self.quorum
    }
    pub fn branch(&self) -> &StateBranch {
        &self.child
    }
    pub fn into_branch(self) -> StateBranch {
        self.child
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(FinalizedStateRecord::encode_evidence(
            &self.proposal.encode()?,
            &self.quorum.encode(),
        )?)
    }
}
