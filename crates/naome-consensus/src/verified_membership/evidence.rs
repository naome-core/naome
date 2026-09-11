//! Parent- and snapshot-bound verified-membership evidence; no V0 message is accepted here.

use super::*;

/// Roles deliberately have separate signing transcripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MembershipVoteRole {
    Prevote,
    Precommit,
}

/// Descriptive signed coordinates, authenticated against a branch on admission.
/// Parent and snapshot are never part of the durable anti-equivocation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MembershipVoteCoordinate {
    pub context: [u8; 32],
    pub height: u64,
    pub round: u64,
    pub parent: [u8; 32],
    pub snapshot: [u8; 32],
    pub role: MembershipVoteRole,
    pub target: Option<[u8; 32]>,
}

impl MembershipVoteCoordinate {
    fn bytes(self) -> Vec<u8> {
        let mut bytes = self.context.to_vec();
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.extend_from_slice(&self.parent);
        bytes.extend_from_slice(&self.snapshot);
        bytes.push(match self.role {
            MembershipVoteRole::Prevote => 0,
            MembershipVoteRole::Precommit => 1,
        });
        match self.target {
            None => bytes.push(0),
            Some(root) => {
                bytes.push(1);
                bytes.extend_from_slice(&root);
            }
        }
        bytes
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, MembershipError> {
        let context = reader.array()?;
        let height = reader.u64()?;
        let round = reader.u64()?;
        let parent = reader.array()?;
        let snapshot = reader.array()?;
        let role = match reader.byte()? {
            0 => MembershipVoteRole::Prevote,
            1 => MembershipVoteRole::Precommit,
            _ => return Err(MembershipError::Encoding),
        };
        let target = match reader.byte()? {
            0 => None,
            1 => Some(reader.array()?),
            _ => return Err(MembershipError::Encoding),
        };
        if height == 0 {
            return Err(MembershipError::Encoding);
        }
        Ok(Self {
            context,
            height,
            round,
            parent,
            snapshot,
            role,
            target,
        })
    }

    pub fn signing_bytes(self) -> Vec<u8> {
        let domain: &[u8] = match self.role {
            MembershipVoteRole::Prevote => b"naome/verified-membership/v0/prevote\0",
            MembershipVoteRole::Precommit => b"naome/verified-membership/v0/precommit\0",
        };
        transcript(domain, &self.bytes())
    }
}

/// Untrusted decoded signed vote. Only branch verification grants admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipVote {
    pub coordinate: MembershipVoteCoordinate,
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

impl MembershipVote {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/vote\0";
    pub const MAX_BYTES: usize = 320;

    /// Low-level completion for a durably prepared signing intent.
    pub fn sign(coordinate: MembershipVoteCoordinate, key: &SigningKey) -> Self {
        Self {
            coordinate,
            signer: key.verifying_key().to_bytes(),
            signature: key.sign(&coordinate.signing_bytes()).to_bytes(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.coordinate.bytes());
        bytes.extend_from_slice(&self.signer);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let vote = Self {
            coordinate: MembershipVoteCoordinate::read(&mut reader)?,
            signer: reader.array()?,
            signature: reader.array()?,
        };
        reader.finish()?;
        Ok(vote)
    }

    pub fn verify(&self, snapshot: &MembershipSnapshot) -> Result<(), MembershipError> {
        if self.coordinate.context != snapshot.context.0 || self.coordinate.snapshot != snapshot.id
        {
            return Err(MembershipError::Context);
        }
        if !snapshot
            .members
            .iter()
            .any(|member| member.consensus_key == self.signer)
        {
            return Err(MembershipError::UnknownMember);
        }
        verify(
            &self.signer,
            &self.coordinate.signing_bytes(),
            &self.signature,
        )
    }
}

/// Canonical shared-coordinate certificate with strictly ordered signer keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipCertificate {
    coordinate: MembershipVoteCoordinate,
    signatures: Vec<([u8; 32], [u8; 64])>,
}

impl MembershipCertificate {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/certificate\0";
    pub const MAX_BYTES: usize = 256 + MAX_MEMBERS * 96;

    pub fn from_votes(
        votes: &[MembershipVote],
        snapshot: &MembershipSnapshot,
    ) -> Result<Self, MembershipError> {
        if votes.len() > MAX_MEMBERS {
            return Err(MembershipError::Limit);
        }
        let first = votes.first().ok_or(MembershipError::Quorum)?;
        let mut signatures = Vec::with_capacity(votes.len());
        for vote in votes {
            if vote.coordinate != first.coordinate {
                return Err(MembershipError::Context);
            }
            signatures.push((vote.signer, vote.signature));
        }
        signatures.sort_by_key(|entry| entry.0);
        let result = Self {
            coordinate: first.coordinate,
            signatures,
        };
        result.verify(snapshot)?;
        Ok(result)
    }

    pub const fn coordinate(&self) -> MembershipVoteCoordinate {
        self.coordinate
    }
    pub fn participant_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn verify(&self, snapshot: &MembershipSnapshot) -> Result<(), MembershipError> {
        if self.signatures.len() > MAX_MEMBERS {
            return Err(MembershipError::Limit);
        }
        if self.signatures.len() < 3 || self.signatures.len() < snapshot.quorum() {
            return Err(MembershipError::Quorum);
        }
        let mut previous = None;
        for (signer, signature) in &self.signatures {
            if previous.is_some_and(|key| key >= *signer) {
                return Err(MembershipError::Duplicate);
            }
            previous = Some(*signer);
            MembershipVote {
                coordinate: self.coordinate,
                signer: *signer,
                signature: *signature,
            }
            .verify(snapshot)?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.coordinate.bytes());
        bytes.extend_from_slice(&(self.signatures.len() as u16).to_be_bytes());
        for (key, signature) in &self.signatures {
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let coordinate = MembershipVoteCoordinate::read(&mut reader)?;
        let count = reader.u16()? as usize;
        if !(3..=MAX_MEMBERS).contains(&count) {
            return Err(MembershipError::Limit);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push((reader.array()?, reader.array()?));
        }
        reader.finish()?;
        Ok(Self {
            coordinate,
            signatures,
        })
    }
}

/// Untrusted proposal control. Complete artifact validation precedes voting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProposal {
    pub value: MembershipValue,
    pub round: u64,
    pub proposer: [u8; 32],
    pub signature: [u8; 64],
    pub valid_round: Option<MembershipCertificate>,
}

impl MembershipProposal {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/proposal\0";
    pub const MAX_BYTES: usize =
        256 + MembershipValue::MAX_BYTES + MembershipCertificate::MAX_BYTES;

    pub fn signing_bytes(
        value: &MembershipValue,
        round: u64,
        valid_round: Option<&MembershipCertificate>,
    ) -> Vec<u8> {
        let mut bytes = value.context().0.to_vec();
        bytes.extend_from_slice(&value.height().to_be_bytes());
        bytes.extend_from_slice(&round.to_be_bytes());
        bytes.extend_from_slice(&value.parent());
        bytes.extend_from_slice(&value.snapshot());
        bytes.extend_from_slice(&value.root());
        match valid_round {
            None => bytes.push(0),
            Some(certificate) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest(
                    b"naome/verified-membership/v0/valid-round\0",
                    &certificate.to_bytes(),
                ));
            }
        }
        transcript(b"naome/verified-membership/v0/producer\0", &bytes)
    }

    /// Low-level completion; callers must durably prepare the exact intent first.
    pub fn sign(
        value: MembershipValue,
        round: u64,
        valid_round: Option<MembershipCertificate>,
        key: &SigningKey,
    ) -> Self {
        let signature = key
            .sign(&Self::signing_bytes(&value, round, valid_round.as_ref()))
            .to_bytes();
        Self {
            value,
            round,
            proposer: key.verifying_key().to_bytes(),
            signature,
            valid_round,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let value = self.value.to_bytes();
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&value);
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.extend_from_slice(&self.proposer);
        bytes.extend_from_slice(&self.signature);
        match &self.valid_round {
            None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
            Some(certificate) => {
                let certificate = certificate.to_bytes();
                bytes.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&certificate);
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let length = reader.u32()? as usize;
        let value = MembershipValue::from_bytes(reader.take(length)?)?;
        let round = reader.u64()?;
        let proposer = reader.array()?;
        let signature = reader.array()?;
        let length = reader.u32()? as usize;
        let valid_round = if length == 0 {
            None
        } else {
            Some(MembershipCertificate::from_bytes(reader.take(length)?)?)
        };
        reader.finish()?;
        Ok(Self {
            value,
            round,
            proposer,
            signature,
            valid_round,
        })
    }
}
