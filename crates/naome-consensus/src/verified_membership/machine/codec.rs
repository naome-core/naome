//! Exact event and publication records shared by durable replay and transport.

use super::*;

const MAGIC: &[u8] = b"naome/verified-membership/v0/event\0";

fn put(bytes: &mut Vec<u8>, part: &[u8]) {
    bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
    bytes.extend_from_slice(part);
}
fn part<'a>(reader: &mut Reader<'a>, maximum: usize) -> Result<&'a [u8], MembershipError> {
    let length = reader.u32()? as usize;
    if length > maximum {
        return Err(MembershipError::Limit);
    }
    reader.take(length)
}

impl MembershipMachineEvent {
    pub const MAX_BYTES: usize = 512 + MembershipFinalityProof::MAX_BYTES;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        match self {
            Self::Proposal { proposal, payload } => {
                bytes.push(0);
                put(&mut bytes, &proposal.to_bytes());
                put(&mut bytes, payload);
            }
            Self::Vote(vote) => {
                bytes.push(1);
                put(&mut bytes, &vote.to_bytes());
            }
            Self::Certificate(certificate) => {
                bytes.push(2);
                put(&mut bytes, &certificate.to_bytes());
            }
            Self::Finality(proof) => {
                bytes.push(3);
                put(&mut bytes, &proof.to_bytes());
            }
            Self::Timeout {
                height,
                round,
                phase,
            } => {
                bytes.push(4);
                bytes.extend_from_slice(&height.to_be_bytes());
                bytes.extend_from_slice(&round.to_be_bytes());
                bytes.push(match phase {
                    MembershipPhase::Proposal => 0,
                    MembershipPhase::Prevote => 1,
                    MembershipPhase::Precommit => 2,
                });
            }
            Self::Author {
                artifact,
                payload,
                operation,
            } => {
                bytes.push(5);
                bytes.extend_from_slice(&artifact.to_canonical_bytes());
                put(&mut bytes, payload);
                put(
                    &mut bytes,
                    &operation
                        .as_ref()
                        .map_or_else(Vec::new, ApprovedMembershipRequest::to_bytes),
                );
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(MembershipError::Encoding);
        }
        let event = match reader.byte()? {
            0 => Self::Proposal {
                proposal: MembershipProposal::from_bytes(part(
                    &mut reader,
                    MembershipProposal::MAX_BYTES,
                )?)?,
                payload: part(&mut reader, MAX_ARTIFACT_BYTES)?.to_vec(),
            },
            1 => Self::Vote(MembershipVote::from_bytes(part(
                &mut reader,
                MembershipVote::MAX_BYTES,
            )?)?),
            2 => Self::Certificate(MembershipCertificate::from_bytes(part(
                &mut reader,
                MembershipCertificate::MAX_BYTES,
            )?)?),
            3 => Self::Finality(MembershipFinalityProof::from_bytes(part(
                &mut reader,
                MembershipFinalityProof::MAX_BYTES,
            )?)?),
            4 => Self::Timeout {
                height: reader.u64()?,
                round: reader.u64()?,
                phase: match reader.byte()? {
                    0 => MembershipPhase::Proposal,
                    1 => MembershipPhase::Prevote,
                    2 => MembershipPhase::Precommit,
                    _ => return Err(MembershipError::Encoding),
                },
            },
            5 => {
                let artifact = ArtifactBlock::from_canonical_bytes(
                    reader.take(naome_chain::ARTIFACT_BLOCK_BYTES)?,
                )
                .map_err(|_| MembershipError::Encoding)?;
                let payload = part(&mut reader, MAX_ARTIFACT_BYTES)?.to_vec();
                let operation = part(&mut reader, ApprovedMembershipRequest::MAX_BYTES)?;
                Self::Author {
                    artifact,
                    payload,
                    operation: if operation.is_empty() {
                        None
                    } else {
                        Some(ApprovedMembershipRequest::from_bytes(operation)?)
                    },
                }
            }
            _ => return Err(MembershipError::Encoding),
        };
        reader.finish()?;
        Ok(event)
    }
}

impl MembershipPublication {
    pub fn to_event(&self) -> MembershipMachineEvent {
        match self {
            Self::Proposal { proposal, payload } => MembershipMachineEvent::Proposal {
                proposal: proposal.clone(),
                payload: payload.clone(),
            },
            Self::Vote(vote) => MembershipMachineEvent::Vote(vote.clone()),
            Self::Certificate(certificate) => {
                MembershipMachineEvent::Certificate(certificate.clone())
            }
            Self::Finality(proof) => MembershipMachineEvent::Finality(proof.clone()),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_event().to_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        Ok(match MembershipMachineEvent::from_bytes(bytes)? {
            MembershipMachineEvent::Proposal { proposal, payload } => {
                Self::Proposal { proposal, payload }
            }
            MembershipMachineEvent::Vote(vote) => Self::Vote(vote),
            MembershipMachineEvent::Certificate(certificate) => Self::Certificate(certificate),
            MembershipMachineEvent::Finality(proof) => Self::Finality(proof),
            _ => return Err(MembershipError::WrongAction),
        })
    }
    pub fn id(&self) -> [u8; 32] {
        digest(
            b"naome/verified-membership/v0/publication\0",
            &self.to_bytes(),
        )
    }
    pub fn height(&self) -> u64 {
        match self {
            Self::Proposal { proposal, .. } => proposal.value.height(),
            Self::Vote(vote) => vote.coordinate.height,
            Self::Certificate(certificate) => certificate.coordinate().height,
            Self::Finality(proof) => proof.proposal.value.height(),
        }
    }
}
