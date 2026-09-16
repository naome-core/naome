use super::{ResearchConsensusError as Error, Result, codec::Reader};
use crate::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget, ProposalSigningRoot,
};
use ed25519_dalek::{Signature, VerifyingKey};
use naome_research::{GenesisId, ProfileId, profile::Genesis};

const MAGIC: &[u8; 5] = b"NRCV1";
/// Fixed width of one versioned research vote, including key and signature.
pub const RESEARCH_VOTE_BYTES: usize = 5 + 32 + 32 + 8 + 8 + 1 + 1 + 32 + 32 + 64;
/// A research quorum carries at most four complete signed votes.
pub const RESEARCH_QUORUM_MAX_BYTES: usize = 1 + 4 * RESEARCH_VOTE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VoteBody {
    pub(super) genesis: GenesisId,
    pub(super) profile: ProfileId,
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
            ConsensusVoteRole::Prevote => b"naome:research:prevote:v1\0",
            ConsensusVoteRole::Precommit => b"naome:research:precommit:v1\0",
        };
        let mut bytes = domain.to_vec();
        bytes.extend(self.encode());
        bytes.extend_from_slice(signer.as_bytes());
        bytes
    }
    pub(super) fn verify_context(self, genesis: &Genesis) -> Result<()> {
        if self.genesis != genesis.id()
            || self.profile != genesis.profile().id()
            || self.height == 0
        {
            return Err(Error::Invalid("vote context"));
        }
        Ok(())
    }
}

/// A strictly verified signed vote. An opaque target is not a verified proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchVote {
    pub(super) body: VoteBody,
    pub(super) signer: ConsensusKey,
    signature: [u8; 64],
}
impl ResearchVote {
    pub(super) fn complete(
        body: VoteBody,
        signer: ConsensusKey,
        signature: [u8; 64],
        genesis: &Genesis,
    ) -> Result<Self> {
        body.verify_context(genesis)?;
        verify_signer(genesis, signer, &body.signing_bytes(signer), signature)?;
        Ok(Self {
            body,
            signer,
            signature,
        })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self> {
        let mut reader = Reader::new(bytes, RESEARCH_VOTE_BYTES)?;
        if reader.fixed::<5>()? != *MAGIC {
            return Err(Error::Invalid("vote version"));
        }
        let genesis_id = GenesisId::from_bytes(reader.fixed()?);
        let profile = ProfileId::from_bytes(reader.fixed()?);
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
                height,
                round,
                role,
                target,
            },
            signer,
            signature,
            genesis,
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
    signer: ConsensusKey,
    transcript: &[u8],
    signature: [u8; 64],
) -> Result<()> {
    if !genesis
        .validators()
        .iter()
        .any(|v| v.consensus_key == *signer.as_bytes())
    {
        return Err(Error::Invalid("inactive consensus signer"));
    }
    let key =
        VerifyingKey::from_bytes(signer.as_bytes()).map_err(|_| Error::Invalid("consensus key"))?;
    key.verify_strict(transcript, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Invalid("consensus signature"))
}
pub(super) fn snapshot(
    genesis: &Genesis,
    height: u64,
    round: u64,
) -> Result<ActiveAgreementSnapshot> {
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
    ActiveAgreementSnapshot::try_from_preselected(
        ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round)),
        &entries,
    )
    .map_err(|_| Error::Invalid("agreement set"))
}

/// Distinct, same-position and same-role votes; their targets may differ.
/// Quorum progress and matching-target finality are deliberately separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchVoteSet {
    votes: Vec<ResearchVote>,
}
impl ResearchVoteSet {
    pub fn new(mut votes: Vec<ResearchVote>, genesis: &Genesis) -> Result<Self> {
        if votes.is_empty() || votes.len() > 4 {
            return Err(Error::Limit("vote set"));
        }
        votes.sort_by_key(ResearchVote::signer);
        if votes.windows(2).any(|p| p[0].signer == p[1].signer) {
            return Err(Error::Invalid("duplicate consensus signer"));
        }
        let first = votes[0].body;
        for vote in &votes {
            vote.body.verify_context(genesis)?;
            if vote.height() != first.height
                || vote.round() != first.round
                || vote.role() != first.role
            {
                return Err(Error::Invalid("mixed vote positions or roles"));
            }
            verify_signer(genesis, vote.signer, &vote.signing_bytes(), vote.signature)?;
        }
        Ok(Self { votes })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self> {
        let mut reader = Reader::new(bytes, RESEARCH_QUORUM_MAX_BYTES)?;
        let count = reader.u8()?;
        if !(1..=4).contains(&count) {
            return Err(Error::Limit("vote set"));
        }
        let mut votes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let vote = ResearchVote::decode(reader.take(RESEARCH_VOTE_BYTES)?, genesis)?;
            if votes
                .last()
                .is_some_and(|previous: &ResearchVote| previous.signer >= vote.signer)
            {
                return Err(Error::Invalid("vote signer order"));
            }
            votes.push(vote);
        }
        reader.finish()?;
        Self::new(votes, genesis)
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
    pub fn votes(&self) -> &[ResearchVote] {
        &self.votes
    }
    pub fn has_supermajority(&self, genesis: &Genesis) -> Result<bool> {
        self.check_genesis(genesis)?;
        let keys: Vec<_> = self.votes.iter().map(ResearchVote::signer).collect();
        snapshot(genesis, self.height(), self.round())?
            .has_strict_supermajority(&keys)
            .map_err(|_| Error::Invalid("quorum signer set"))
    }
    pub fn has_one_third(&self, genesis: &Genesis) -> Result<bool> {
        self.check_genesis(genesis)?;
        let keys: Vec<_> = self.votes.iter().map(ResearchVote::signer).collect();
        snapshot(genesis, self.height(), self.round())?
            .has_strict_one_third(&keys)
            .map_err(|_| Error::Invalid("round signer set"))
    }
    pub(super) fn check_genesis(&self, genesis: &Genesis) -> Result<()> {
        self.votes[0].body.verify_context(genesis)
    }
}

/// Verified strictly-greater-than-two-thirds evidence for one identical target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchQuorum {
    set: ResearchVoteSet,
}
impl ResearchQuorum {
    pub fn from_votes(votes: Vec<ResearchVote>, genesis: &Genesis) -> Result<Self> {
        Self::from_set(ResearchVoteSet::new(votes, genesis)?, genesis)
    }
    fn from_set(set: ResearchVoteSet, genesis: &Genesis) -> Result<Self> {
        if !set.has_supermajority(genesis)? {
            return Err(Error::Invalid("insufficient quorum"));
        }
        let target = set.votes[0].target();
        if set.votes.iter().any(|vote| vote.target() != target) {
            return Err(Error::Invalid("mixed quorum targets"));
        }
        Ok(Self { set })
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self> {
        Self::from_set(ResearchVoteSet::decode(bytes, genesis)?, genesis)
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
    pub fn vote_set(&self) -> &ResearchVoteSet {
        &self.set
    }
    pub(super) fn check(
        &self,
        genesis: &Genesis,
        height: u64,
        round: u64,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Result<()> {
        self.set.check_genesis(genesis)?;
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
