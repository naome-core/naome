//! Organization membership for the separately framed verified-membership consensus profile.
//!
//! Public keys prove possession, not that organizations are independent. Current
//! operators attest admission explicitly using keys separate from consensus keys.

mod branch;
mod codec;
mod evidence;
mod machine;
mod state;

pub use branch::{
    MembershipBranch, MembershipConsensusError, MembershipValue, VerifiedMembershipFinality,
    VerifiedMembershipProposal,
};
pub use evidence::{
    MembershipCertificate, MembershipProposal, MembershipVote, MembershipVoteCoordinate,
    MembershipVoteRole,
};
pub use machine::{
    MembershipFinalityProof, MembershipMachine, MembershipMachineEvent,
    MembershipMachineTransition, MembershipPhase, MembershipPublication, MembershipSigningIntent,
};
pub use state::{ApprovedMembershipRequest, MembershipState};

use std::{collections::BTreeSet, error::Error, fmt};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use codec::Reader;

/// Minimum independently admitted organizations in this profile.
pub const MIN_MEMBERS: usize = 4;
/// Maximum active organizations, each with exactly one vote.
pub const MAX_MEMBERS: usize = 256;
/// The existing consensus epoch width, in finalized heights.
pub const EPOCH_HEIGHTS: u64 = 8192;
/// Exact existing canonical artifact admission bound.
pub const MAX_ARTIFACT_BYTES: usize = naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;

/// A rejected membership input; errors deliberately omit supplied key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipError {
    Encoding,
    Limit,
    InvalidKey,
    InvalidSignature,
    Duplicate,
    Context,
    StaleRequest,
    UnknownMember,
    MinimumMembers,
    Quorum,
    PendingTransition,
    Overflow,
    WrongAction,
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership input rejected: {self:?}")
    }
}
impl Error for MembershipError {}

/// Explicit deployment identity, derived from the complete verified-membership genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipContext(pub [u8; 32]);

/// One admitted organization and its three distinct Ed25519 identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    pub organization: [u8; 32],
    pub consensus_key: [u8; 32],
    pub approval_key: [u8; 32],
    pub network_key: [u8; 32],
}

impl Member {
    pub const BYTE_LENGTH: usize = 128;

    pub fn validate(&self) -> Result<(), MembershipError> {
        let keys = [self.consensus_key, self.approval_key, self.network_key];
        for key in keys {
            let key = VerifyingKey::from_bytes(&key).map_err(|_| MembershipError::InvalidKey)?;
            if key.is_weak() {
                return Err(MembershipError::InvalidKey);
            }
        }
        if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
            return Err(MembershipError::Duplicate);
        }
        if self.organization == [0; 32] {
            return Err(MembershipError::Encoding);
        }
        Ok(())
    }

    pub fn to_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        let mut bytes = [0; Self::BYTE_LENGTH];
        bytes[..32].copy_from_slice(&self.organization);
        bytes[32..64].copy_from_slice(&self.consensus_key);
        bytes[64..96].copy_from_slice(&self.approval_key);
        bytes[96..].copy_from_slice(&self.network_key);
        bytes
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, MembershipError> {
        let member = Self {
            organization: reader.array()?,
            consensus_key: reader.array()?,
            approval_key: reader.array()?,
            network_key: reader.array()?,
        };
        member.validate()?;
        Ok(member)
    }
}

/// Strictly ordered, immutable equal-vote authorization snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSnapshot {
    context: MembershipContext,
    generation: u64,
    members: Vec<Member>,
    id: [u8; 32],
}

impl MembershipSnapshot {
    /// Constructs a genesis snapshot from an operator-selected organization list.
    /// This checks structure; independence remains an external genesis decision.
    pub fn genesis(
        context: MembershipContext,
        members: Vec<Member>,
    ) -> Result<Self, MembershipError> {
        Self::new(context, 0, members)
    }

    fn new(
        context: MembershipContext,
        generation: u64,
        members: Vec<Member>,
    ) -> Result<Self, MembershipError> {
        if members.len() < MIN_MEMBERS {
            return Err(MembershipError::MinimumMembers);
        }
        if members.len() > MAX_MEMBERS {
            return Err(MembershipError::Limit);
        }
        let mut previous = None;
        let mut keys = BTreeSet::new();
        for member in &members {
            member.validate()?;
            if previous.is_some_and(|id| id >= member.organization) {
                return Err(MembershipError::Duplicate);
            }
            previous = Some(member.organization);
            for key in [
                member.consensus_key,
                member.approval_key,
                member.network_key,
            ] {
                if !keys.insert(key) {
                    return Err(MembershipError::Duplicate);
                }
            }
        }
        let mut bytes = context.0.to_vec();
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&(members.len() as u16).to_be_bytes());
        for member in &members {
            bytes.extend_from_slice(&member.to_bytes());
        }
        let id = digest(b"naome/verified-membership/v0/snapshot\0", &bytes);
        Ok(Self {
            context,
            generation,
            members,
            id,
        })
    }

    pub const fn context(&self) -> MembershipContext {
        self.context
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn members(&self) -> &[Member] {
        &self.members
    }
    pub fn quorum(&self) -> usize {
        self.members.len() * 2 / 3 + 1
    }
    pub fn member(&self, organization: &[u8; 32]) -> Option<&Member> {
        self.members
            .binary_search_by_key(organization, |member| member.organization)
            .ok()
            .map(|index| &self.members[index])
    }
}

/// Explicit membership action; a forced removal needs no departed-key witness.
// Keep the bounded, fixed-size key witnesses inline in this public value type.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipAction {
    Join {
        member: Member,
        possession: [[u8; 64]; 3],
    },
    Exit {
        organization: [u8; 32],
        authorization: [u8; 64],
    },
    Remove {
        organization: [u8; 32],
    },
}

/// A request is bound to one deployment and exact active membership generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipRequest {
    context: MembershipContext,
    generation: u64,
    snapshot: [u8; 32],
    action: MembershipAction,
}

impl MembershipRequest {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/request\0";
    pub const MAX_BYTES: usize = 512;

    pub fn join(
        snapshot: &MembershipSnapshot,
        member: Member,
        keys: [&SigningKey; 3],
    ) -> Result<Self, MembershipError> {
        member.validate()?;
        if keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect::<Vec<_>>()
            != [
                member.consensus_key,
                member.approval_key,
                member.network_key,
            ]
        {
            return Err(MembershipError::InvalidKey);
        }
        let mut request = Self::new(
            snapshot,
            MembershipAction::Join {
                member,
                possession: [[0; 64]; 3],
            },
        );
        let transcript = request.authorization_transcript();
        request.action = MembershipAction::Join {
            member,
            possession: keys.map(|key| key.sign(&transcript).to_bytes()),
        };
        request.validate(snapshot)?;
        Ok(request)
    }

    pub fn exit(
        snapshot: &MembershipSnapshot,
        organization: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, MembershipError> {
        let member = snapshot
            .member(&organization)
            .ok_or(MembershipError::UnknownMember)?;
        if key.verifying_key().to_bytes() != member.approval_key {
            return Err(MembershipError::InvalidKey);
        }
        let mut request = Self::new(
            snapshot,
            MembershipAction::Exit {
                organization,
                authorization: [0; 64],
            },
        );
        let authorization = key.sign(&request.authorization_transcript()).to_bytes();
        request.action = MembershipAction::Exit {
            organization,
            authorization,
        };
        request.validate(snapshot)?;
        Ok(request)
    }

    pub fn remove(
        snapshot: &MembershipSnapshot,
        organization: [u8; 32],
    ) -> Result<Self, MembershipError> {
        let request = Self::new(snapshot, MembershipAction::Remove { organization });
        request.validate(snapshot)?;
        Ok(request)
    }

    fn new(snapshot: &MembershipSnapshot, action: MembershipAction) -> Self {
        Self {
            context: snapshot.context,
            generation: snapshot.generation,
            snapshot: snapshot.id,
            action,
        }
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.context.0);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.snapshot);
        match &self.action {
            MembershipAction::Join { member, .. } => {
                bytes.push(0);
                bytes.extend_from_slice(&member.to_bytes());
            }
            MembershipAction::Exit { organization, .. } => {
                bytes.push(1);
                bytes.extend_from_slice(organization);
            }
            MembershipAction::Remove { organization } => {
                bytes.push(2);
                bytes.extend_from_slice(organization);
            }
        }
        bytes
    }

    fn authorization_transcript(&self) -> Vec<u8> {
        transcript(
            b"naome/verified-membership/v0/request-possession\0",
            &self.unsigned_bytes(),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        match &self.action {
            MembershipAction::Join { possession, .. } => {
                for signature in possession {
                    bytes.extend_from_slice(signature);
                }
            }
            MembershipAction::Exit { authorization, .. } => bytes.extend_from_slice(authorization),
            MembershipAction::Remove { .. } => {}
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let context = MembershipContext(reader.array()?);
        let generation = reader.u64()?;
        let snapshot = reader.array()?;
        let action = match reader.byte()? {
            0 => MembershipAction::Join {
                member: Member::read(&mut reader)?,
                possession: [reader.array()?, reader.array()?, reader.array()?],
            },
            1 => MembershipAction::Exit {
                organization: reader.array()?,
                authorization: reader.array()?,
            },
            2 => MembershipAction::Remove {
                organization: reader.array()?,
            },
            _ => return Err(MembershipError::Encoding),
        };
        reader.finish()?;
        Ok(Self {
            context,
            generation,
            snapshot,
            action,
        })
    }

    pub fn id(&self) -> [u8; 32] {
        digest(
            b"naome/verified-membership/v0/request-id\0",
            &self.to_bytes(),
        )
    }
    pub const fn action(&self) -> &MembershipAction {
        &self.action
    }

    pub fn validate(&self, snapshot: &MembershipSnapshot) -> Result<(), MembershipError> {
        if self.context != snapshot.context {
            return Err(MembershipError::Context);
        }
        if self.generation != snapshot.generation || self.snapshot != snapshot.id {
            return Err(MembershipError::StaleRequest);
        }
        let authorization = self.authorization_transcript();
        match &self.action {
            MembershipAction::Join { member, possession } => {
                member.validate()?;
                for (key, signature) in [
                    member.consensus_key,
                    member.approval_key,
                    member.network_key,
                ]
                .iter()
                .zip(possession)
                {
                    verify(key, &authorization, signature)?;
                }
            }
            MembershipAction::Exit {
                organization,
                authorization: signature,
            } => {
                let member = snapshot
                    .member(organization)
                    .ok_or(MembershipError::UnknownMember)?;
                verify(&member.approval_key, &authorization, signature)?;
            }
            MembershipAction::Remove { organization } => {
                snapshot
                    .member(organization)
                    .ok_or(MembershipError::UnknownMember)?;
            }
        }
        self.successor(snapshot).map(|_| ())
    }

    fn successor(
        &self,
        snapshot: &MembershipSnapshot,
    ) -> Result<MembershipSnapshot, MembershipError> {
        let mut members = snapshot.members.clone();
        match &self.action {
            MembershipAction::Join { member, .. } => {
                members.push(*member);
                members.sort_by_key(|member| member.organization);
            }
            MembershipAction::Exit { organization, .. }
            | MembershipAction::Remove { organization } => {
                if snapshot.member(organization).is_none() {
                    return Err(MembershipError::UnknownMember);
                }
                members.retain(|member| &member.organization != organization);
            }
        }
        MembershipSnapshot::new(
            snapshot.context,
            snapshot
                .generation
                .checked_add(1)
                .ok_or(MembershipError::Overflow)?,
            members,
        )
    }
}

/// Explicit operator approval. Constructing it never changes membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipApproval {
    pub organization: [u8; 32],
    pub request: [u8; 32],
    pub signature: [u8; 64],
}

impl MembershipApproval {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/approval\0";
    pub const MAX_BYTES: usize = 192;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.organization);
        bytes.extend_from_slice(&self.request);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let approval = Self {
            organization: reader.array()?,
            request: reader.array()?,
            signature: reader.array()?,
        };
        reader.finish()?;
        Ok(approval)
    }

    pub fn sign(
        request: &MembershipRequest,
        snapshot: &MembershipSnapshot,
        organization: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, MembershipError> {
        request.validate(snapshot)?;
        let member = snapshot
            .member(&organization)
            .ok_or(MembershipError::UnknownMember)?;
        if key.verifying_key().to_bytes() != member.approval_key {
            return Err(MembershipError::InvalidKey);
        }
        let request = request.id();
        let signature = key
            .sign(&transcript(
                b"naome/verified-membership/v0/operator-approval\0",
                &request,
            ))
            .to_bytes();
        Ok(Self {
            organization,
            request,
            signature,
        })
    }

    pub fn verify(
        &self,
        request: &MembershipRequest,
        snapshot: &MembershipSnapshot,
    ) -> Result<(), MembershipError> {
        request.validate(snapshot)?;
        if self.request != request.id() {
            return Err(MembershipError::StaleRequest);
        }
        let member = snapshot
            .member(&self.organization)
            .ok_or(MembershipError::UnknownMember)?;
        verify(
            &member.approval_key,
            &transcript(
                b"naome/verified-membership/v0/operator-approval\0",
                &self.request,
            ),
            &self.signature,
        )
    }
}

pub(super) fn transcript(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len() + bytes.len());
    result.extend_from_slice(domain);
    result.extend_from_slice(bytes);
    result
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

pub(super) fn verify(
    key: &[u8; 32],
    bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), MembershipError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| MembershipError::InvalidKey)?;
    if key.is_weak() {
        return Err(MembershipError::InvalidKey);
    }
    key.verify_strict(bytes, &Signature::from_bytes(signature))
        .map_err(|_| MembershipError::InvalidSignature)
}

#[cfg(test)]
mod tests;
