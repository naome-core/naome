use super::{
    Result, StateConsensusError as Error,
    codec::{Reader, bytes},
    digest,
    evidence::{STATE_QUORUM_MAX_BYTES, StateQuorum, verify_signer},
};
use super::{SealContext, StateSeal};
use crate::{
    ActiveAgreementEntry, AgreementWeight, ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    ProposalSigningRoot, proposer_selection::FixedProposerState,
};
use naome_chain::StateRecordExecution;
use naome_chain::{FinalizedStateRecord, StateRecord};
use naome_ledger::{
    GenesisId, LedgerState, ProfileId, RecordId, StateCommitment, authority::AuthoritySnapshot,
};

const VALUE_MAGIC: &[u8; 5] = b"NSCB5";
const VALUE_BYTES: usize = 5 + 9 * 32 + 8;
const PROPOSAL_MAGIC: &[u8; 5] = b"NSCP5";

/// Evidence-free header binding a complete state record and proposer state.
/// Neither observing nor decoding this header grants application authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateValue {
    genesis: GenesisId,
    profile: ProfileId,
    authority: [u8; 32],
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
        out.extend_from_slice(&self.authority);
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
            authority: r.fixed()?,
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
            b"naome:state:consensus-value:v5\0",
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
        let proposer = stable_proposer(state.authority())?;
        Ok(Self { state, proposer })
    }
    pub fn state(&self) -> &LedgerState {
        &self.state
    }
    pub fn authority(&self) -> &AuthoritySnapshot {
        self.state.authority()
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
        if self.state.terminated() {
            return Err(Error::Invalid("terminated state has no successor"));
        }
        self.state.height().checked_add(1).ok_or(Error::Overflow)
    }
    pub fn proposer(&self, round: u64, maximum_round: u64) -> Result<Option<ConsensusKey>> {
        self.next_height()?;
        let slot = self.round_state(round, maximum_round)?.0;
        Ok(self
            .authority()
            .units()
            .iter()
            .find(|u| u.slot().as_bytes() == slot.as_bytes())
            .and_then(|u| u.keys())
            .map(|keys| ConsensusKey::from_bytes(*keys.consensus())))
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
            authority: self.authority().id(),
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
        if self.proposer(round, maximum_round)? != Some(signer) {
            return Err(Error::Invalid("not scheduled state proposer"));
        }
        let value = self.value_for_record(&record_bytes)?;
        validate_valid_quorum(
            &valid,
            &value,
            round,
            self.state.genesis(),
            self.authority(),
        )?;
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
        if self.proposer(round, maximum_round)? != Some(proposer) {
            return Err(Error::Invalid("state proposer"));
        }
        verify_signer(
            self.state.genesis(),
            self.authority(),
            proposer,
            &proposal_signing_bytes(value, round, proposer),
            signature,
        )?;
        let qc_bytes = r.bytes(STATE_QUORUM_MAX_BYTES)?;
        let valid = if qc_bytes.is_empty() {
            None
        } else {
            Some(StateQuorum::decode(
                qc_bytes,
                self.state.genesis(),
                self.authority(),
            )?)
        };
        validate_valid_quorum(
            &valid,
            &value,
            round,
            self.state.genesis(),
            self.authority(),
        )?;
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
    pub fn verify_agreement(
        &self,
        proposal: &StateProposal,
        quorum: &StateQuorum,
        maximum_round: u64,
    ) -> Result<StateAgreement> {
        quorum.check(
            self.state.genesis(),
            self.authority(),
            proposal.value().height(),
            proposal.round(),
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(proposal.value().signing_root()),
        )?;
        let proposal = self.verify_proposal(&proposal.encode()?, maximum_round)?;
        let (_, state) = self.validate_record_bytes(proposal.record_bytes())?;
        let child = Self {
            state,
            proposer: self.next_proposer()?,
        };
        if child.commitment() != proposal.value().next_consensus_commitment() {
            return Err(Error::Invalid("state branch successor"));
        }
        let context = SealContext::new(proposal.value(), self.authority(), child.authority())?;
        Ok(StateAgreement {
            proposal,
            quorum: quorum.clone(),
            outgoing: self.authority().clone(),
            child,
            context,
        })
    }
    pub fn decode_agreement(&self, input: &[u8], maximum_round: u64) -> Result<StateAgreement> {
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum)?;
        if r.fixed::<5>()? != *b"NSAG5" {
            return Err(Error::Invalid("agreement format"));
        }
        let proposal_bytes = r.bytes(maximum)?;
        let quorum_bytes = r.bytes(STATE_QUORUM_MAX_BYTES)?;
        r.finish()?;
        authenticate_parts(proposal_bytes, quorum_bytes, &self.state, maximum_round)?;
        let proposal = self.verify_proposal(proposal_bytes, maximum_round)?;
        let quorum = StateQuorum::decode(quorum_bytes, self.state.genesis(), self.authority())?;
        self.verify_agreement(&proposal, &quorum, maximum_round)
    }
    pub fn verify_finality(
        &self,
        proposal: &StateProposal,
        quorum: &StateQuorum,
        seal: &StateSeal,
        maximum_round: u64,
    ) -> Result<StateFinality> {
        let agreement = self.verify_agreement(proposal, quorum, maximum_round)?;
        seal.verify(
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        Ok(StateFinality {
            agreement,
            seal: seal.clone(),
        })
    }
    pub fn decode_finality(&self, input: &[u8], maximum_round: u64) -> Result<StateFinality> {
        StateFinality::authenticate(input, &self.state, maximum_round)?;
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let record = FinalizedStateRecord::decode(input, maximum, STATE_QUORUM_MAX_BYTES)?;
        let proposal = self.verify_proposal(record.proposal(), maximum_round)?;
        let quorum = StateQuorum::decode(record.quorum(), self.state.genesis(), self.authority())?;
        let seal = StateSeal::decode(record.seal())?;
        self.verify_finality(&proposal, &quorum, &seal, maximum_round)
    }
}

// Arithmetic identities are stable slots, never the keys currently occupying
// them. A missing slot still consumes its proposer turn and quorum weight.
fn stable_proposer(authority: &AuthoritySnapshot) -> Result<FixedProposerState> {
    let entries: Vec<_> = authority
        .units()
        .iter()
        .map(|unit| {
            ActiveAgreementEntry::new(
                ConsensusKey::from_bytes(*unit.slot().as_bytes()),
                AgreementWeight::new(1),
            )
        })
        .collect();
    FixedProposerState::try_from_preselected(&entries)
        .map_err(|_| Error::Invalid("stable proposer slots"))
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
        b"naome:state:consensus-state:v5\0",
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
    authority: &AuthoritySnapshot,
) -> Result<()> {
    if let Some(qc) = valid {
        if qc.round() >= round {
            return Err(Error::Invalid("non-earlier valid round"));
        }
        qc.check(
            genesis,
            authority,
            value.height,
            qc.round(),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(value.signing_root()),
        )?;
    }
    Ok(())
}
fn proposal_signing_bytes(value: StateValue, round: u64, proposer: ConsensusKey) -> Vec<u8> {
    let mut bytes = b"naome:state:proposal:v5\0".to_vec();
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

/// Agreed record with a provisional child. It cannot yield a signing branch:
/// selected authority activation additionally requires the complete seal.
#[derive(Clone)]
pub struct StateAgreement {
    proposal: StateProposal,
    quorum: StateQuorum,
    outgoing: AuthoritySnapshot,
    child: StateBranch,
    context: SealContext,
}
impl StateAgreement {
    pub fn state(&self) -> &LedgerState {
        self.child.state()
    }
    pub fn incoming(&self) -> &AuthoritySnapshot {
        self.child.authority()
    }
    pub fn outgoing(&self) -> &AuthoritySnapshot {
        &self.outgoing
    }
    pub const fn seal_context(&self) -> SealContext {
        self.context
    }
    pub fn proposal(&self) -> &StateProposal {
        &self.proposal
    }
    pub fn quorum(&self) -> &StateQuorum {
        &self.quorum
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = b"NSAG5".to_vec();
        bytes(&mut out, &self.proposal.encode()?)?;
        bytes(&mut out, &self.quorum.encode())?;
        Ok(out)
    }
}

/// Sealed successor. Storage must durably select it before activating keys.
pub struct StateFinality {
    agreement: StateAgreement,
    seal: StateSeal,
}
impl StateFinality {
    /// Authenticate bounded evidence under the exact selected parent before
    /// application/proof replay. Observed headers never supply an electorate.
    pub fn authenticate(
        input: &[u8],
        parent: &LedgerState,
        maximum_round: u64,
    ) -> Result<StateValue> {
        let maximum = parent.genesis().profile().limits().transport_frame_bytes as usize;
        let envelope = FinalizedStateRecord::decode(input, maximum, STATE_QUORUM_MAX_BYTES)?;
        let (value, record) = authenticate_parts(
            envelope.proposal(),
            envelope.quorum(),
            parent,
            maximum_round,
        )?;
        let incoming =
            parent.prepare_handoff_certified(record.handoff_plan(), record.time_certificate())?;
        let context = SealContext::new(value, parent.authority(), &incoming)?;
        StateSeal::decode(envelope.seal())?.verify(context, parent.authority(), &incoming)?;
        Ok(value)
    }
    /// Untrusted routing hint. It may select a historical lookup only.
    pub fn peek_header(
        input: &[u8],
        genesis: &naome_ledger::profile::Genesis,
    ) -> Result<StateValue> {
        let maximum = genesis.profile().limits().transport_frame_bytes as usize;
        let envelope = FinalizedStateRecord::decode(input, maximum, STATE_QUORUM_MAX_BYTES)?;
        let mut p = Reader::new(envelope.proposal(), maximum)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("state proposal version"));
        }
        let value = StateValue::decode(p.take(VALUE_BYTES)?)?;
        if value.genesis != genesis.id() || value.profile != genesis.profile().id() {
            return Err(Error::Invalid("state evidence context"));
        }
        Ok(value)
    }
    pub fn claimed_height(input: &[u8], maximum_bytes: usize) -> Result<u64> {
        let record = FinalizedStateRecord::decode(input, maximum_bytes, STATE_QUORUM_MAX_BYTES)?;
        let mut p = Reader::new(record.proposal(), maximum_bytes)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("state proposal version"));
        }
        Ok(StateValue::decode(p.take(VALUE_BYTES)?)?.height())
    }
    pub fn proposal(&self) -> &StateProposal {
        self.agreement.proposal()
    }
    pub fn quorum(&self) -> &StateQuorum {
        self.agreement.quorum()
    }
    pub fn seal(&self) -> &StateSeal {
        &self.seal
    }
    pub fn agreement(&self) -> &StateAgreement {
        &self.agreement
    }
    pub fn branch(&self) -> &StateBranch {
        &self.agreement.child
    }
    pub fn into_branch(self) -> StateBranch {
        self.agreement.child
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(FinalizedStateRecord::encode_evidence(
            &self.proposal().encode()?,
            &self.quorum().encode(),
            &self.seal.encode(),
        )?)
    }
}

fn authenticate_parts(
    proposal_bytes: &[u8],
    quorum_bytes: &[u8],
    parent: &LedgerState,
    maximum_round: u64,
) -> Result<(StateValue, StateRecord)> {
    if parent.terminated() {
        return Err(Error::Invalid("terminated parent"));
    }
    let genesis = parent.genesis();
    let authority = parent.authority();
    let maximum = genesis.profile().limits().transport_frame_bytes as usize;
    let mut p = Reader::new(proposal_bytes, maximum)?;
    if p.fixed::<5>()? != *PROPOSAL_MAGIC {
        return Err(Error::Invalid("state proposal version"));
    }
    let value = StateValue::decode(p.take(VALUE_BYTES)?)?;
    if value.genesis != genesis.id()
        || value.profile != genesis.profile().id()
        || value.authority != authority.id()
        || value.height != authority.effective_height()
        || value.height != parent.height().checked_add(1).ok_or(Error::Overflow)?
        || value.parent != parent.head()
        || value.previous != parent.commitment()
        || value.fixed_set != *stable_proposer(authority)?.fixed_set_id().as_bytes()
    {
        return Err(Error::Invalid("state evidence parent or authority"));
    }
    let round = p.u64()?;
    if round > maximum_round || round > genesis.profile().limits().consensus_rounds {
        return Err(Error::Limit("state evidence round"));
    }
    let proposer = ConsensusKey::from_bytes(p.fixed()?);
    let signature = p.fixed()?;
    verify_signer(
        genesis,
        authority,
        proposer,
        &proposal_signing_bytes(value, round, proposer),
        signature,
    )?;
    let valid_bytes = p.bytes(STATE_QUORUM_MAX_BYTES)?;
    let valid = if valid_bytes.is_empty() {
        None
    } else {
        Some(StateQuorum::decode(valid_bytes, genesis, authority)?)
    };
    validate_valid_quorum(&valid, &value, round, genesis, authority)?;
    let record_bytes = p.bytes(genesis.profile().limits().record_bytes as usize)?;
    p.finish()?;
    let quorum = StateQuorum::decode(quorum_bytes, genesis, authority)?;
    quorum.check(
        genesis,
        authority,
        value.height,
        round,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.signing_root()),
    )?;
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
    Ok((value, record))
}
