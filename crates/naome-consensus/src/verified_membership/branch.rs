//! Membership-aware artifact consensus with immutable, verified successors.

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactChainBranchSnapshot,
};

use crate::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, proposer_selection::FixedProposerStateV0,
};

use super::*;

#[derive(Debug)]
pub enum MembershipConsensusError {
    Membership(MembershipError),
    Artifact(ArtifactBlockApplyError),
    Genesis,
    Coordinate,
    Value,
    Proposer,
    RoundLimit,
    Evidence,
    Overflow,
}
impl fmt::Display for MembershipConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership consensus rejected: {self:?}")
    }
}
impl Error for MembershipConsensusError {}
impl From<MembershipError> for MembershipConsensusError {
    fn from(error: MembershipError) -> Self {
        Self::Membership(error)
    }
}

/// Complete verified-membership proposal value. Current-height signatures are excluded; operation
/// approval witnesses are execution inputs and are committed in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipValue {
    context: MembershipContext,
    height: u64,
    parent: [u8; 32],
    snapshot: [u8; 32],
    artifact: ArtifactBlock,
    membership_root: [u8; 32],
    proposer_root: [u8; 32],
    operation: Option<ApprovedMembershipRequest>,
}

impl MembershipValue {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/value\0";
    pub const MAX_BYTES: usize = 512 + ApprovedMembershipRequest::MAX_BYTES;
    pub const fn context(&self) -> MembershipContext {
        self.context
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn parent(&self) -> [u8; 32] {
        self.parent
    }
    pub const fn snapshot(&self) -> [u8; 32] {
        self.snapshot
    }
    pub const fn artifact(&self) -> ArtifactBlock {
        self.artifact
    }
    pub const fn operation(&self) -> Option<&ApprovedMembershipRequest> {
        self.operation.as_ref()
    }
    pub fn root(&self) -> [u8; 32] {
        digest(
            b"naome/verified-membership/v0/proposal-root\0",
            &self.to_bytes(),
        )
    }
    pub fn ancestry(&self) -> [u8; 32] {
        digest(b"naome/verified-membership/v0/ancestry\0", &self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.context.0);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.parent);
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(&self.artifact.to_canonical_bytes());
        bytes.extend_from_slice(&self.membership_root);
        bytes.extend_from_slice(&self.proposer_root);
        match &self.operation {
            None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
            Some(operation) => {
                let operation = operation.to_bytes();
                bytes.extend_from_slice(&(operation.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&operation);
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let context = MembershipContext(reader.array()?);
        let height = reader.u64()?;
        if height == 0 {
            return Err(MembershipError::Encoding);
        }
        let parent = reader.array()?;
        let snapshot = reader.array()?;
        let artifact = ArtifactBlock::from_canonical_bytes(reader.take(ARTIFACT_BLOCK_BYTES)?)
            .map_err(|_| MembershipError::Encoding)?;
        let membership_root = reader.array()?;
        let proposer_root = reader.array()?;
        let length = reader.u32()? as usize;
        let operation = if length == 0 {
            None
        } else {
            Some(ApprovedMembershipRequest::from_bytes(reader.take(length)?)?)
        };
        reader.finish()?;
        Ok(Self {
            context,
            height,
            parent,
            snapshot,
            artifact,
            membership_root,
            proposer_root,
            operation,
        })
    }
}

/// Immutable selected-or-candidate branch. Only virtual genesis and completely
/// verified finality construct branch successors; configuration cannot replace
/// the active set or skip history.
#[derive(Clone)]
pub struct MembershipBranch {
    context: MembershipContext,
    height: u64,
    ancestry: [u8; 32],
    artifact: ArtifactChainBranchSnapshot,
    membership: MembershipState,
    priorities: FixedProposerStateV0,
}

impl MembershipBranch {
    /// Creates a caller-trusted genesis; its complete sorted organization list,
    /// artifact-chain identity and epoch rule are committed into the context.
    pub fn genesis(
        artifact: ArtifactChainBranchSnapshot,
        members: Vec<Member>,
    ) -> Result<Self, MembershipConsensusError> {
        if !artifact.is_virtual_genesis() {
            return Err(MembershipConsensusError::Genesis);
        }
        // Structural validation precedes deriving the deployment identity.
        MembershipSnapshot::genesis(MembershipContext([0; 32]), members.clone())?;
        let mut bytes = artifact.chain_id().as_bytes().to_vec();
        bytes.extend_from_slice(&EPOCH_HEIGHTS.to_be_bytes());
        bytes.extend_from_slice(&(members.len() as u16).to_be_bytes());
        for member in &members {
            bytes.extend_from_slice(&member.to_bytes());
        }
        let context = MembershipContext(digest(b"naome/verified-membership/v0/genesis\0", &bytes));
        let snapshot = MembershipSnapshot::genesis(context, members)?;
        let priorities = FixedProposerStateV0::try_from_preselected(&entries(&snapshot))
            .map_err(|_| MembershipConsensusError::Genesis)?;
        Ok(Self {
            context,
            height: 0,
            ancestry: digest(
                b"naome/verified-membership/v0/genesis-ancestry\0",
                &context.0,
            ),
            artifact,
            membership: MembershipState::genesis(snapshot)?,
            priorities,
        })
    }

    pub const fn context(&self) -> MembershipContext {
        self.context
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn ancestry(&self) -> [u8; 32] {
        self.ancestry
    }
    pub const fn artifact(&self) -> &ArtifactChainBranchSnapshot {
        &self.artifact
    }
    pub const fn membership(&self) -> &MembershipState {
        &self.membership
    }
    pub fn next_height(&self) -> Result<u64, MembershipConsensusError> {
        self.height
            .checked_add(1)
            .ok_or(MembershipConsensusError::Overflow)
    }
    pub fn next_snapshot(&self) -> Result<&MembershipSnapshot, MembershipConsensusError> {
        Ok(self.membership.active_at(self.next_height()?))
    }

    fn next_priorities(&self) -> Result<FixedProposerStateV0, MembershipConsensusError> {
        let next = self.next_snapshot()?;
        if next.id() == self.membership.active_at(self.height).id() {
            return Ok(self.priorities.clone());
        }
        let snapshot = ActiveAgreementSnapshot::try_from_preselected(
            ConsensusPosition::new(
                ConsensusHeight::new(self.next_height()?),
                ConsensusRound::new(0),
            ),
            &entries(next),
        )
        .map_err(|_| MembershipConsensusError::Proposer)?;
        self.priorities
            .transition_to_preselected_snapshot(&snapshot)
            .map_err(|_| MembershipConsensusError::Proposer)
    }

    pub fn proposer(
        &self,
        round: u64,
        maximum_round: u64,
    ) -> Result<[u8; 32], MembershipConsensusError> {
        if round > maximum_round {
            return Err(MembershipConsensusError::RoundLimit);
        }
        let mut state = self.next_priorities()?;
        let mut index = 0;
        loop {
            let (key, next) = state
                .select_next()
                .map_err(|_| MembershipConsensusError::Proposer)?;
            if index == round {
                return Ok(*key.as_bytes());
            }
            state = next;
            index += 1;
        }
    }

    /// Derives a candidate value without signing or finalizing it. Artifact
    /// validation is repeated during complete proposal admission.
    pub fn value(
        &self,
        artifact: ArtifactBlock,
        operation: Option<ApprovedMembershipRequest>,
    ) -> Result<MembershipValue, MembershipConsensusError> {
        let height = self.next_height()?;
        let membership = self.membership.transition(height, operation.as_ref())?;
        let (_, priorities) = self
            .next_priorities()?
            .select_next()
            .map_err(|_| MembershipConsensusError::Proposer)?;
        Ok(MembershipValue {
            context: self.context,
            height,
            parent: self.ancestry,
            snapshot: self.next_snapshot()?.id(),
            artifact,
            membership_root: membership.commitment(),
            proposer_root: *priorities.id().as_bytes(),
            operation,
        })
    }

    pub fn prepare_value(
        &self,
        artifact: ArtifactBlock,
        operation: Option<ApprovedMembershipRequest>,
        payload: &[u8],
    ) -> Result<MembershipValue, MembershipConsensusError> {
        if payload.len() > super::MAX_ARTIFACT_BYTES {
            return Err(MembershipError::Limit.into());
        }
        let value = self.value(artifact, operation)?;
        let _ = self
            .artifact
            .validate_child(&artifact, payload.to_vec())
            .map_err(MembershipConsensusError::Artifact)?;
        Ok(value)
    }

    pub fn vote_coordinate(
        &self,
        round: u64,
        role: MembershipVoteRole,
        target: Option<[u8; 32]>,
    ) -> Result<MembershipVoteCoordinate, MembershipConsensusError> {
        Ok(MembershipVoteCoordinate {
            context: self.context.0,
            height: self.next_height()?,
            round,
            parent: self.ancestry,
            snapshot: self.next_snapshot()?.id(),
            role,
            target,
        })
    }

    fn verify_coordinate(
        &self,
        coordinate: MembershipVoteCoordinate,
        maximum_round: u64,
    ) -> Result<(), MembershipConsensusError> {
        if coordinate.round > maximum_round {
            return Err(MembershipConsensusError::RoundLimit);
        }
        if coordinate
            != self.vote_coordinate(coordinate.round, coordinate.role, coordinate.target)?
        {
            return Err(MembershipConsensusError::Coordinate);
        }
        Ok(())
    }

    pub fn verify_vote(
        &self,
        vote: &MembershipVote,
        maximum_round: u64,
    ) -> Result<(), MembershipConsensusError> {
        self.verify_coordinate(vote.coordinate, maximum_round)?;
        vote.verify(self.next_snapshot()?)?;
        Ok(())
    }

    pub fn verify_certificate(
        &self,
        certificate: &MembershipCertificate,
        maximum_round: u64,
    ) -> Result<(), MembershipConsensusError> {
        self.verify_coordinate(certificate.coordinate(), maximum_round)?;
        certificate.verify(self.next_snapshot()?)?;
        Ok(())
    }

    pub fn verify_proposal(
        &self,
        proposal: MembershipProposal,
        payload: Vec<u8>,
        maximum_round: u64,
    ) -> Result<VerifiedMembershipProposal, MembershipConsensusError> {
        if payload.len() > super::MAX_ARTIFACT_BYTES {
            return Err(MembershipError::Limit.into());
        }
        if proposal.proposer != self.proposer(proposal.round, maximum_round)? {
            return Err(MembershipConsensusError::Proposer);
        }
        verify(
            &proposal.proposer,
            &MembershipProposal::signing_bytes(
                &proposal.value,
                proposal.round,
                proposal.valid_round.as_ref(),
            ),
            &proposal.signature,
        )?;
        if let Some(certificate) = &proposal.valid_round {
            self.verify_certificate(certificate, maximum_round)?;
            let coordinate = certificate.coordinate();
            if coordinate.role != MembershipVoteRole::Prevote
                || coordinate.round >= proposal.round
                || coordinate.target != Some(proposal.value.root())
            {
                return Err(MembershipConsensusError::Evidence);
            }
        }
        let expected = self.value(proposal.value.artifact, proposal.value.operation.clone())?;
        if proposal.value != expected {
            return Err(MembershipConsensusError::Value);
        }
        let artifact = self
            .artifact
            .validate_child(&proposal.value.artifact, payload.clone())
            .map_err(MembershipConsensusError::Artifact)?;
        let membership = self
            .membership
            .transition(proposal.value.height, proposal.value.operation.as_ref())?;
        let (_, priorities) = self
            .next_priorities()?
            .select_next()
            .map_err(|_| MembershipConsensusError::Proposer)?;
        let child = Self {
            context: self.context,
            height: proposal.value.height,
            ancestry: proposal.value.ancestry(),
            artifact,
            membership,
            priorities,
        };
        Ok(VerifiedMembershipProposal {
            proposal,
            payload,
            child,
        })
    }

    pub fn verify_finality(
        &self,
        proposal: MembershipProposal,
        payload: Vec<u8>,
        certificate: MembershipCertificate,
        maximum_round: u64,
    ) -> Result<VerifiedMembershipFinality, MembershipConsensusError> {
        self.verify_certificate(&certificate, maximum_round)?;
        let coordinate = certificate.coordinate();
        if coordinate.role != MembershipVoteRole::Precommit
            || coordinate.target != Some(proposal.value.root())
            || coordinate.round != proposal.round
        {
            return Err(MembershipConsensusError::Evidence);
        }
        let proposal = self.verify_proposal(proposal, payload, maximum_round)?;
        Ok(VerifiedMembershipFinality {
            proposal,
            certificate,
        })
    }
}

fn entries(snapshot: &MembershipSnapshot) -> Vec<ActiveAgreementEntry> {
    let mut entries: Vec<_> = snapshot
        .members()
        .iter()
        .map(|member| {
            ActiveAgreementEntry::new(
                ConsensusKey::from_bytes(member.consensus_key),
                AgreementWeight::new(1),
            )
        })
        .collect();
    entries.sort_by_key(|entry| entry.consensus_key());
    entries
}

/// Fully admitted proposal. It does not expose its unfinalized branch successor.
#[derive(Clone)]
pub struct VerifiedMembershipProposal {
    proposal: MembershipProposal,
    payload: Vec<u8>,
    child: MembershipBranch,
}
impl VerifiedMembershipProposal {
    pub const fn proposal(&self) -> &MembershipProposal {
        &self.proposal
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A complete finalized direct-child transition; storage must anchor it before
/// publishing its successor as selected or allowing another signature.
pub struct VerifiedMembershipFinality {
    proposal: VerifiedMembershipProposal,
    certificate: MembershipCertificate,
}
impl VerifiedMembershipFinality {
    pub const fn proposal(&self) -> &MembershipProposal {
        &self.proposal.proposal
    }
    pub fn payload(&self) -> &[u8] {
        &self.proposal.payload
    }
    pub const fn certificate(&self) -> &MembershipCertificate {
        &self.certificate
    }
    pub fn into_branch(self) -> MembershipBranch {
        self.proposal.child
    }
}
