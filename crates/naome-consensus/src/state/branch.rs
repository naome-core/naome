use super::{
    ResearchConsensusError as Error, Result,
    codec::{Reader, bytes},
    digest,
    evidence::{RESEARCH_QUORUM_MAX_BYTES, ResearchQuorum, verify_signer},
};
use crate::{
    ActiveAgreementEntry, AgreementWeight, ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    ProposalSigningRoot, proposer_selection::FixedProposerStateV0,
};
use naome_ledger::{
    GenesisId, ProfileId, RecordId, ResearchRecord, ResearchState, StateCommitment,
};

const VALUE_MAGIC: &[u8; 5] = b"NSCB1";
const VALUE_BYTES: usize = 5 + 8 * 32 + 8;
const PROPOSAL_MAGIC: &[u8; 5] = b"NSCP1";
const FINALITY_MAGIC: &[u8; 5] = b"NSCF1";

/// Evidence-free header binding a complete research record and proposer state.
/// Neither observing nor decoding this header grants application authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResearchValue {
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
impl ResearchValue {
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
            return Err(Error::Invalid("research value version"));
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
            return Err(Error::Invalid("zero research height"));
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

/// Immutable branch whose research state is advanced only by verified finality.
#[derive(Clone)]
pub struct ResearchBranch {
    state: ResearchState,
    proposer: FixedProposerStateV0,
}
impl ResearchBranch {
    pub fn from_genesis(state: ResearchState) -> Result<Self> {
        if state.height() != 0 {
            return Err(Error::Invalid("research branch requires genesis"));
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
        let proposer = FixedProposerStateV0::try_from_preselected(&entries)
            .map_err(|_| Error::Invalid("research fixed set"))?;
        Ok(Self { state, proposer })
    }
    pub fn state(&self) -> &ResearchState {
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
    ) -> Result<(ConsensusKey, FixedProposerStateV0)> {
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
    fn next_proposer(&self) -> Result<FixedProposerStateV0> {
        self.proposer
            .select_next()
            .map(|(_, state)| state)
            .map_err(|_| Error::Invalid("proposer successor"))
    }
    fn validate_record_bytes(&self, record_bytes: &[u8]) -> Result<(ResearchValue, ResearchState)> {
        let record = ResearchRecord::decode(record_bytes, self.state.genesis())?;
        if record.encode()?.as_slice() != record_bytes {
            return Err(Error::Invalid("noncanonical research record"));
        }
        if record.parent() != self.state.head()
            || record.height() != self.next_height()?
            || record.previous_state() != self.state.commitment()
        {
            return Err(Error::Invalid("research record parent"));
        }
        let next = self.state.validate_record(&record)?.into_state();
        if next.commitment() != record.next_state()
            || next.head() != record.id()
            || next.height() != record.height()
        {
            return Err(Error::Invalid("research successor state"));
        }
        let proposer = self.next_proposer()?;
        let value = ResearchValue {
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
    pub(super) fn value_for_record(&self, record_bytes: &[u8]) -> Result<ResearchValue> {
        self.validate_record_bytes(record_bytes)
            .map(|(value, _)| value)
    }
    pub(super) fn proposal_intent(
        &self,
        record_bytes: Vec<u8>,
        round: u64,
        signer: ConsensusKey,
        valid: Option<ResearchQuorum>,
        maximum_round: u64,
    ) -> Result<ResearchProposalIntent> {
        if self.proposer(round, maximum_round)? != signer {
            return Err(Error::Invalid("not scheduled research proposer"));
        }
        let value = self.value_for_record(&record_bytes)?;
        validate_valid_quorum(&valid, &value, round, self.state.genesis())?;
        Ok(ResearchProposalIntent {
            value,
            record_bytes,
            round,
            proposer: signer,
            valid,
            parent_commitment: self.commitment(),
        })
    }
    pub fn verify_proposal(&self, input: &[u8], maximum_round: u64) -> Result<ResearchProposal> {
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum)?;
        if r.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("research proposal version"));
        }
        let value = ResearchValue::decode(r.take(VALUE_BYTES)?)?;
        if value.genesis != self.state.genesis().id()
            || value.profile != self.state.genesis().profile().id()
            || value.parent != self.state.head()
            || value.height != self.next_height()?
            || value.previous != self.state.commitment()
        {
            return Err(Error::Invalid("research proposal parent"));
        }
        let round = r.u64()?;
        let proposer = ConsensusKey::from_bytes(r.fixed()?);
        let signature = r.fixed()?;
        if self.proposer(round, maximum_round)? != proposer {
            return Err(Error::Invalid("research proposer"));
        }
        verify_signer(
            self.state.genesis(),
            proposer,
            &proposal_signing_bytes(value, round, proposer),
            signature,
        )?;
        let qc_bytes = r.bytes(RESEARCH_QUORUM_MAX_BYTES)?;
        let valid = if qc_bytes.is_empty() {
            None
        } else {
            Some(ResearchQuorum::decode(qc_bytes, self.state.genesis())?)
        };
        validate_valid_quorum(&valid, &value, round, self.state.genesis())?;
        let record_bytes = r
            .bytes(self.state.genesis().profile().limits().record_bytes as usize)?
            .to_vec();
        r.finish()?;
        let expected = self.value_for_record(&record_bytes)?;
        if value != expected {
            return Err(Error::Invalid("research value commitment"));
        }
        Ok(ResearchProposal {
            intent: ResearchProposalIntent {
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
        proposal: &ResearchProposal,
        quorum: &ResearchQuorum,
        maximum_round: u64,
    ) -> Result<ResearchFinality> {
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
            return Err(Error::Invalid("research branch successor"));
        }
        Ok(ResearchFinality {
            proposal,
            quorum: quorum.clone(),
            child,
        })
    }
    pub fn decode_finality(&self, input: &[u8], maximum_round: u64) -> Result<ResearchFinality> {
        // Do not start application replay on an unauthenticated finality claim.
        let _ = ResearchFinality::authenticate(input, self.state.genesis(), maximum_round)?;
        let maximum = self
            .state
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum)?;
        if r.fixed::<5>()? != *FINALITY_MAGIC {
            return Err(Error::Invalid("research finality version"));
        }
        let proposal = self.verify_proposal(r.bytes(maximum)?, maximum_round)?;
        let quorum =
            ResearchQuorum::decode(r.bytes(RESEARCH_QUORUM_MAX_BYTES)?, self.state.genesis())?;
        r.finish()?;
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
    valid: &Option<ResearchQuorum>,
    value: &ResearchValue,
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
fn proposal_signing_bytes(value: ResearchValue, round: u64, proposer: ConsensusKey) -> Vec<u8> {
    let mut bytes = b"naome:state:proposal:v1\0".to_vec();
    bytes.extend(value.encode());
    bytes.extend_from_slice(&round.to_be_bytes());
    bytes.extend_from_slice(proposer.as_bytes());
    bytes
}

/// Application-verified unsigned proposal. Persist intent before key use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchProposalIntent {
    pub(super) value: ResearchValue,
    pub(super) record_bytes: Vec<u8>,
    pub(super) round: u64,
    pub(super) proposer: ConsensusKey,
    pub(super) valid: Option<ResearchQuorum>,
    pub(super) parent_commitment: [u8; 32],
}
impl ResearchProposalIntent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        proposal_signing_bytes(self.value, self.round, self.proposer)
    }
    pub const fn value(&self) -> ResearchValue {
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
    pub fn valid_quorum(&self) -> Option<&ResearchQuorum> {
        self.valid.as_ref()
    }
    /// Exact recovery bytes including the full immutable record and retained QC.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_proposal(self, [0; 64])
    }
    pub fn complete(
        &self,
        signature: [u8; 64],
        branch: &ResearchBranch,
        maximum_round: u64,
    ) -> Result<ResearchProposal> {
        branch.verify_proposal(&encode_proposal(self, signature)?, maximum_round)
    }
}
fn encode_proposal(intent: &ResearchProposalIntent, signature: [u8; 64]) -> Result<Vec<u8>> {
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
            .map_or_else(Vec::new, ResearchQuorum::encode),
    )?;
    bytes(&mut out, &intent.record_bytes)?;
    Ok(out)
}

/// Complete producer-authenticated proposal, verified against an exact branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchProposal {
    pub(super) intent: ResearchProposalIntent,
    signature: [u8; 64],
}
impl ResearchProposal {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_proposal(&self.intent, self.signature)
    }
    pub const fn value(&self) -> ResearchValue {
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
    pub fn valid_quorum(&self) -> Option<&ResearchQuorum> {
        self.intent.valid.as_ref()
    }
    pub const fn parent_commitment(&self) -> &[u8; 32] {
        &self.intent.parent_commitment
    }
}

/// Sealed research successor and sufficient finality evidence. Durable selection
/// is storage's responsibility; this token establishes only verified transition.
pub struct ResearchFinality {
    proposal: ResearchProposal,
    quorum: ResearchQuorum,
    child: ResearchBranch,
}
impl ResearchFinality {
    /// Bounded evidence authentication before historical or mathematical replay.
    /// The result remains an observed header, not a selected/verified successor:
    /// exact parent, scheduled proposer and application effects need the branch.
    pub fn authenticate(
        input: &[u8],
        genesis: &naome_ledger::profile::Genesis,
        maximum_round: u64,
    ) -> Result<ResearchValue> {
        let maximum = genesis.profile().limits().transport_frame_bytes as usize;
        let mut r = Reader::new(input, maximum)?;
        if r.fixed::<5>()? != *FINALITY_MAGIC {
            return Err(Error::Invalid("research finality version"));
        }
        let proposal = r.bytes(maximum)?;
        let finality_quorum = r.bytes(RESEARCH_QUORUM_MAX_BYTES)?;
        r.finish()?;
        let mut p = Reader::new(proposal, maximum)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("research proposal version"));
        }
        let value = ResearchValue::decode(p.take(VALUE_BYTES)?)?;
        if value.genesis != genesis.id() || value.profile != genesis.profile().id() {
            return Err(Error::Invalid("research evidence context"));
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
        let fixed = FixedProposerStateV0::try_from_preselected(&entries)
            .map_err(|_| Error::Invalid("research fixed set"))?;
        if value.fixed_set != *fixed.fixed_set_id().as_bytes() {
            return Err(Error::Invalid("research evidence fixed set"));
        }
        let round = p.u64()?;
        if round > maximum_round || round > genesis.profile().limits().consensus_rounds {
            return Err(Error::Limit("research evidence round"));
        }
        let proposer = ConsensusKey::from_bytes(p.fixed()?);
        let signature = p.fixed()?;
        verify_signer(
            genesis,
            proposer,
            &proposal_signing_bytes(value, round, proposer),
            signature,
        )?;
        let valid_bytes = p.bytes(RESEARCH_QUORUM_MAX_BYTES)?;
        let valid = if valid_bytes.is_empty() {
            None
        } else {
            Some(ResearchQuorum::decode(valid_bytes, genesis)?)
        };
        validate_valid_quorum(&valid, &value, round, genesis)?;
        let record_bytes = p.bytes(genesis.profile().limits().record_bytes as usize)?;
        p.finish()?;
        let quorum = ResearchQuorum::decode(finality_quorum, genesis)?;
        quorum.check(
            genesis,
            value.height,
            round,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(value.signing_root()),
        )?;
        // Only quorum-authenticated content reaches even the bounded record
        // decoder. This performs no proof checking or historical reconstruction.
        let record = ResearchRecord::decode(record_bytes, genesis)?;
        if record.encode()?.as_slice() != record_bytes
            || record.id() != value.record
            || record.height() != value.height
            || record.parent() != value.parent
            || record.previous_state() != value.previous
            || record.next_state() != value.next
        {
            return Err(Error::Invalid("research evidence record binding"));
        }
        Ok(value)
    }

    /// Untrusted routing hint only. The receiver must still verify the complete
    /// proof against the selected parent at this height before using any field.
    pub fn claimed_height(input: &[u8], maximum_bytes: usize) -> Result<u64> {
        let mut r = Reader::new(input, maximum_bytes)?;
        if r.fixed::<5>()? != *FINALITY_MAGIC {
            return Err(Error::Invalid("research finality version"));
        }
        let proposal = r.bytes(maximum_bytes)?;
        let _ = r.bytes(RESEARCH_QUORUM_MAX_BYTES)?;
        r.finish()?;
        let mut p = Reader::new(proposal, maximum_bytes)?;
        if p.fixed::<5>()? != *PROPOSAL_MAGIC {
            return Err(Error::Invalid("research proposal version"));
        }
        Ok(ResearchValue::decode(p.take(VALUE_BYTES)?)?.height())
    }

    pub fn proposal(&self) -> &ResearchProposal {
        &self.proposal
    }
    pub fn quorum(&self) -> &ResearchQuorum {
        &self.quorum
    }
    pub fn branch(&self) -> &ResearchBranch {
        &self.child
    }
    pub fn into_branch(self) -> ResearchBranch {
        self.child
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = FINALITY_MAGIC.to_vec();
        bytes(&mut out, &self.proposal.encode()?)?;
        bytes(&mut out, &self.quorum.encode())?;
        Ok(out)
    }
}
