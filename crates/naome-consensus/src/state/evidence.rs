use super::{Result, StateConsensusError as Error, codec::Reader};
use crate::{ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget, ProposalSigningRoot};
use ed25519_dalek::{Signature, VerifyingKey};
use naome_ledger::{GenesisId, ProfileId, authority::AuthoritySnapshot, profile::Genesis};

const MAGIC: &[u8; 5] = b"NSCV5";
/// Fixed width of one versioned state vote, including key and signature.
pub const STATE_VOTE_BYTES: usize = 5 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 32 + 32 + 64;
/// A state quorum carries at most four complete signed votes.
pub const STATE_QUORUM_MAX_BYTES: usize = 1 + 4 * STATE_VOTE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VoteBody {
    pub(super) genesis: GenesisId,
    pub(super) profile: ProfileId,
    pub(super) authority: [u8; 32],
    pub(super) height: u64,
    pub(super) round: u64,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
}
impl VoteBody {
    fn encode(self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(self.genesis.as_bytes());
        bytes.extend_from_slice(self.profile.as_bytes());
        bytes.extend_from_slice(&self.authority);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.push(match self.role {
            ConsensusVoteRole::Prevote => 1,
            ConsensusVoteRole::Precommit => 2,
        });
        match self.target {
            ConsensusVoteTarget::Nil => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 32]);
            }
            ConsensusVoteTarget::Proposal(root) => {
                bytes.push(1);
                bytes.extend_from_slice(root.as_bytes());
            }
        }
        bytes
    }
    pub(super) fn signing_bytes(self, signer: ConsensusKey) -> Vec<u8> {
        let domain: &[u8] = match self.role {
            ConsensusVoteRole::Prevote => b"naome:state:prevote:v5\0",
            ConsensusVoteRole::Precommit => b"naome:state:precommit:v5\0",
        };
        let mut bytes = domain.to_vec();
        bytes.extend(self.encode());
        bytes.extend_from_slice(signer.as_bytes());
        bytes
    }
    pub(super) fn verify_context(
        self,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<()> {
        if self.genesis != genesis.id()
            || self.profile != genesis.profile().id()
            || authority.genesis() != genesis.id()
            || self.authority != authority.id()
            || self.height != authority.effective_height()
            || self.height == 0
        {
            return Err(Error::Invalid("vote context"));
        }
        Ok(())
    }
}

/// A strictly verified signed vote. An opaque target is not a verified proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVote {
    pub(super) body: VoteBody,
    pub(super) signer: ConsensusKey,
    signature: [u8; 64],
}
impl StateVote {
    pub(super) fn complete(
        body: VoteBody,
        signer: ConsensusKey,
        signature: [u8; 64],
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<Self> {
        body.verify_context(genesis, authority)?;
        verify_signer(
            genesis,
            authority,
            signer,
            &body.signing_bytes(signer),
            signature,
        )?;
        Ok(Self {
            body,
            signer,
            signature,
        })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis, authority: &AuthoritySnapshot) -> Result<Self> {
        let mut reader = Reader::new(bytes, STATE_VOTE_BYTES)?;
        if reader.fixed::<5>()? != *MAGIC {
            return Err(Error::Invalid("vote version"));
        }
        let genesis_id = GenesisId::from_bytes(reader.fixed()?);
        let profile = ProfileId::from_bytes(reader.fixed()?);
        let authority_id = reader.fixed()?;
        let height = reader.u64()?;
        let round = reader.u64()?;
        let role = match reader.u8()? {
            1 => ConsensusVoteRole::Prevote,
            2 => ConsensusVoteRole::Precommit,
            _ => return Err(Error::Invalid("vote role")),
        };
        let tag = reader.u8()?;
        let raw = reader.fixed::<32>()?;
        let target = match tag {
            0 if raw == [0; 32] => ConsensusVoteTarget::Nil,
            1 => ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes(raw)),
            _ => return Err(Error::Invalid("vote target")),
        };
        let signer = ConsensusKey::from_bytes(reader.fixed()?);
        let signature = reader.fixed()?;
        reader.finish()?;
        Self::complete(
            VoteBody {
                genesis: genesis_id,
                profile,
                authority: authority_id,
                height,
                round,
                role,
                target,
            },
            signer,
            signature,
            genesis,
            authority,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body.encode();
        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    pub const fn height(&self) -> u64 {
        self.body.height
    }
    pub const fn round(&self) -> u64 {
        self.body.round
    }
    pub const fn role(&self) -> ConsensusVoteRole {
        self.body.role
    }
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.body.target
    }
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.body.signing_bytes(self.signer)
    }
}

pub(super) fn verify_signer(
    genesis: &Genesis,
    authority: &AuthoritySnapshot,
    signer: ConsensusKey,
    transcript: &[u8],
    signature: [u8; 64],
) -> Result<()> {
    if authority.genesis() != genesis.id()
        || !authority.units().iter().any(|unit| {
            unit.keys()
                .is_some_and(|keys| keys.consensus() == signer.as_bytes())
        })
    {
        return Err(Error::Invalid("inactive consensus signer"));
    }
    let key =
        VerifyingKey::from_bytes(signer.as_bytes()).map_err(|_| Error::Invalid("consensus key"))?;
    key.verify_strict(transcript, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Invalid("consensus signature"))
}
/// Distinct, same-position and same-role votes; their targets may differ.
/// Quorum progress and matching-target finality are deliberately separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVoteSet {
    votes: Vec<StateVote>,
}
impl StateVoteSet {
    pub fn new(
        mut votes: Vec<StateVote>,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<Self> {
        if votes.is_empty() || votes.len() > 4 {
            return Err(Error::Limit("vote set"));
        }
        votes.sort_by_key(StateVote::signer);
        if votes.windows(2).any(|p| p[0].signer == p[1].signer) {
            return Err(Error::Invalid("duplicate consensus signer"));
        }
        let first = votes[0].body;
        for vote in &votes {
            vote.body.verify_context(genesis, authority)?;
            if vote.height() != first.height
                || vote.round() != first.round
                || vote.role() != first.role
            {
                return Err(Error::Invalid("mixed vote positions or roles"));
            }
            verify_signer(
                genesis,
                authority,
                vote.signer,
                &vote.signing_bytes(),
                vote.signature,
            )?;
        }
        Ok(Self { votes })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis, authority: &AuthoritySnapshot) -> Result<Self> {
        let mut reader = Reader::new(bytes, STATE_QUORUM_MAX_BYTES)?;
        let count = reader.u8()?;
        if !(1..=4).contains(&count) {
            return Err(Error::Limit("vote set"));
        }
        let mut votes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let vote = StateVote::decode(reader.take(STATE_VOTE_BYTES)?, genesis, authority)?;
            if votes
                .last()
                .is_some_and(|previous: &StateVote| previous.signer >= vote.signer)
            {
                return Err(Error::Invalid("vote signer order"));
            }
            votes.push(vote);
        }
        reader.finish()?;
        Self::new(votes, genesis, authority)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.votes.len() as u8];
        for vote in &self.votes {
            bytes.extend(vote.encode());
        }
        bytes
    }
    pub fn height(&self) -> u64 {
        self.votes[0].height()
    }
    pub fn round(&self) -> u64 {
        self.votes[0].round()
    }
    pub fn role(&self) -> ConsensusVoteRole {
        self.votes[0].role()
    }
    pub fn votes(&self) -> &[StateVote] {
        &self.votes
    }
    pub fn has_supermajority(
        &self,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<bool> {
        self.check_genesis(genesis, authority)?;
        Ok(self.votes.len() >= 3)
    }
    pub fn has_one_third(&self, genesis: &Genesis, authority: &AuthoritySnapshot) -> Result<bool> {
        self.check_genesis(genesis, authority)?;
        Ok(self.votes.len() >= 2)
    }
    pub(super) fn check_genesis(
        &self,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<()> {
        self.votes[0].body.verify_context(genesis, authority)
    }
}

/// Verified strictly-greater-than-two-thirds evidence for one identical target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateQuorum {
    set: StateVoteSet,
}
impl StateQuorum {
    pub fn from_votes(
        votes: Vec<StateVote>,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<Self> {
        Self::from_set(
            StateVoteSet::new(votes, genesis, authority)?,
            genesis,
            authority,
        )
    }
    fn from_set(
        set: StateVoteSet,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<Self> {
        if !set.has_supermajority(genesis, authority)? {
            return Err(Error::Invalid("insufficient quorum"));
        }
        let target = set.votes[0].target();
        if set.votes.iter().any(|vote| vote.target() != target) {
            return Err(Error::Invalid("mixed quorum targets"));
        }
        Ok(Self { set })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis, authority: &AuthoritySnapshot) -> Result<Self> {
        Self::from_set(
            StateVoteSet::decode(bytes, genesis, authority)?,
            genesis,
            authority,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        self.set.encode()
    }
    pub fn height(&self) -> u64 {
        self.set.height()
    }
    pub fn round(&self) -> u64 {
        self.set.round()
    }
    pub fn role(&self) -> ConsensusVoteRole {
        self.set.role()
    }
    pub fn target(&self) -> ConsensusVoteTarget {
        self.set.votes[0].target()
    }
    pub fn vote_set(&self) -> &StateVoteSet {
        &self.set
    }
    pub(super) fn check(
        &self,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
        height: u64,
        round: u64,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Result<()> {
        self.set.check_genesis(genesis, authority)?;
        if self.height() != height
            || self.round() != round
            || self.role() != role
            || self.target() != target
        {
            return Err(Error::Invalid("quorum context or target"));
        }
        Ok(())
    }
}
