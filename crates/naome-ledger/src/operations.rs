//! Canonical user actions and author authentication for original proof packages.

use crate::{
    AccountId, CommitmentId, GenesisId, PackageHash, ProfileId, QuestionId, ResearchError,
    SolutionRoundId,
    authentication::SignedOperation,
    codec::{Reader, Writer},
    identity::hash,
    library::ProofPackage,
    profile::Genesis,
    question::CompiledQuestion,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const ORIGINAL_MAGIC: &[u8; 4] = b"NSOR";
const ORIGINAL_DOMAIN: &[u8] = b"naome:state:original-authorization:v1\0";
const ORIGINAL_OVERHEAD: usize = 4 + 2 + 32 + 32 + 32 + 4 + 64;
const PURPOSE_MAX_BYTES: usize = 16 * 1024;

/// A package signed by its single author under the exact approved solution round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOriginal {
    genesis: GenesisId,
    profile: ProfileId,
    round: SolutionRoundId,
    package: ProofPackage,
    signature: [u8; 64],
}

impl SignedOriginal {
    /// Signs unchanged package bytes before commitment publication.
    pub fn sign(
        genesis: &Genesis,
        round: SolutionRoundId,
        package: ProofPackage,
        key: &SigningKey,
    ) -> Result<Self, ResearchError> {
        let author = AccountId::for_key(key.verifying_key().as_bytes());
        if package.author() != author
            || genesis.account_key(author) != Some(key.verifying_key().as_bytes())
        {
            return Err(ResearchError::Invalid("original package signer"));
        }
        let mut original = Self {
            genesis: genesis.id(),
            profile: genesis.profile().id(),
            round,
            package,
            signature: [0; 64],
        };
        original.signature = key.sign(&original.signing_bytes()?).to_bytes();
        Ok(original)
    }
    /// Validates the original signature and context, before mathematical checking.
    pub fn verify(
        &self,
        genesis: &Genesis,
        round: SolutionRoundId,
        author: AccountId,
    ) -> Result<(), ResearchError> {
        if self.genesis != genesis.id()
            || self.profile != genesis.profile().id()
            || self.round != round
            || self.package.author() != author
        {
            return Err(ResearchError::Invalid("original context"));
        }
        let key = genesis
            .account_key(author)
            .ok_or(ResearchError::Invalid("original author account"))?;
        VerifyingKey::from_bytes(key)
            .map_err(|_| ResearchError::Invalid("original author key"))?
            .verify_strict(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ResearchError::Invalid("original author signature"))
    }
    pub fn package(&self) -> &ProofPackage {
        &self.package
    }
    pub const fn round(&self) -> SolutionRoundId {
        self.round
    }
    pub fn original_hash(&self) -> PackageHash {
        self.package.original_hash()
    }
    pub fn encode(&self) -> Result<Vec<u8>, ResearchError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, ResearchError> {
        let maximum = genesis.profile().limits().package_bytes as usize;
        let mut reader = Reader::new(bytes, maximum + ORIGINAL_OVERHEAD)?;
        if reader.fixed::<4>()? != *ORIGINAL_MAGIC || reader.u16()? != 1 {
            return Err(ResearchError::Invalid("original format"));
        }
        let original = Self {
            genesis: GenesisId::from_bytes(reader.fixed()?),
            profile: ProfileId::from_bytes(reader.fixed()?),
            round: SolutionRoundId::from_bytes(reader.fixed()?),
            package: ProofPackage::decode(reader.bytes(maximum)?, genesis.profile())?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        Ok(original)
    }
    fn unsigned_bytes(&self) -> Result<Vec<u8>, ResearchError> {
        let mut writer = Writer::new();
        writer.fixed(ORIGINAL_MAGIC);
        writer.u16(1);
        writer.fixed(self.genesis.as_bytes());
        writer.fixed(self.profile.as_bytes());
        writer.fixed(self.round.as_bytes());
        writer.bytes(&self.package.encode()?)?;
        Ok(writer.finish())
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, ResearchError> {
        let mut bytes = ORIGINAL_DOMAIN.to_vec();
        bytes.extend(self.unsigned_bytes()?);
        Ok(bytes)
    }
}

impl CommitmentId {
    /// Conceals the complete original package, binding all approval/author roles.
    pub fn for_original(
        genesis: &Genesis,
        round: SolutionRoundId,
        author: AccountId,
        original: PackageHash,
        secret: &[u8; 32],
    ) -> Self {
        Self::from_bytes(hash(
            b"naome:state:commitment:v1\0",
            &[
                genesis.id().as_bytes(),
                genesis.profile().id().as_bytes(),
                round.as_bytes(),
                author.as_bytes(),
                original.as_bytes(),
                secret,
            ],
        ))
    }
}

/// Strict domain payload inside a signed account operation.
#[derive(Clone, PartialEq, Eq)]
pub enum OperationBody {
    Submit {
        purpose: String,
        question: CompiledQuestion,
    },
    Vote {
        question: QuestionId,
        attempt: u64,
        yes: bool,
    },
    Commit {
        round: SolutionRoundId,
        commitment: CommitmentId,
    },
    Reveal {
        round: SolutionRoundId,
        secret: [u8; 32],
        original: SignedOriginal,
    },
}

impl std::fmt::Debug for OperationBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submit { question, .. } => f
                .debug_tuple("Submit")
                .field(&question.resolution_id())
                .finish(),
            Self::Vote {
                question,
                attempt,
                yes,
            } => f
                .debug_tuple("Vote")
                .field(question)
                .field(attempt)
                .field(yes)
                .finish(),
            Self::Commit { round, commitment } => f
                .debug_tuple("Commit")
                .field(round)
                .field(commitment)
                .finish(),
            Self::Reveal { round, .. } => f
                .debug_tuple("Reveal")
                .field(round)
                .field(&"[original and secret redacted]")
                .finish(),
        }
    }
}

impl OperationBody {
    pub fn sign(
        &self,
        genesis: &Genesis,
        nonce: u64,
        key: &SigningKey,
    ) -> Result<SignedOperation, ResearchError> {
        SignedOperation::sign(genesis, nonce, self.encode()?, key)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ResearchError> {
        let mut writer = Writer::new();
        writer.u8(1);
        match self {
            Self::Submit { purpose, question } => {
                if purpose.is_empty() || purpose.len() > PURPOSE_MAX_BYTES {
                    return Err(ResearchError::Limit("question purpose"));
                }
                writer.u8(1);
                writer.string(purpose)?;
                writer.bytes(&question.to_canonical_bytes()?)?;
            }
            Self::Vote {
                question,
                attempt,
                yes,
            } => {
                writer.u8(2);
                writer.fixed(question.as_bytes());
                writer.u64(*attempt);
                writer.u8(u8::from(*yes));
            }
            Self::Commit { round, commitment } => {
                writer.u8(3);
                writer.fixed(round.as_bytes());
                writer.fixed(commitment.as_bytes());
            }
            Self::Reveal {
                round,
                secret,
                original,
            } => {
                writer.u8(4);
                writer.fixed(round.as_bytes());
                writer.fixed(secret);
                writer.bytes(&original.encode()?)?;
            }
        }
        Ok(writer.finish())
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, ResearchError> {
        let mut reader = Reader::new(bytes, genesis.profile().limits().record_bytes as usize)?;
        if reader.u8()? != 1 {
            return Err(ResearchError::Invalid("user body version"));
        }
        let body = match reader.u8()? {
            1 => {
                let purpose = reader.string(PURPOSE_MAX_BYTES)?.to_owned();
                if purpose.is_empty() {
                    return Err(ResearchError::Invalid("empty question purpose"));
                }
                let question = CompiledQuestion::from_canonical_bytes(
                    reader.bytes(genesis.profile().limits().question_source_bytes as usize + 5)?,
                    genesis.profile(),
                )?;
                Self::Submit { purpose, question }
            }
            2 => {
                let question = QuestionId::from_bytes(reader.fixed()?);
                let attempt = reader.u64()?;
                if attempt == 0 {
                    return Err(ResearchError::Invalid("zero voting attempt"));
                }
                let yes = match reader.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ResearchError::Invalid("ballot choice")),
                };
                Self::Vote {
                    question,
                    attempt,
                    yes,
                }
            }
            3 => Self::Commit {
                round: SolutionRoundId::from_bytes(reader.fixed()?),
                commitment: CommitmentId::from_bytes(reader.fixed()?),
            },
            4 => Self::Reveal {
                round: SolutionRoundId::from_bytes(reader.fixed()?),
                secret: reader.fixed()?,
                original: SignedOriginal::decode(
                    reader.bytes(
                        genesis.profile().limits().package_bytes as usize + ORIGINAL_OVERHEAD,
                    )?,
                    genesis,
                )?,
            },
            _ => return Err(ResearchError::Invalid("user operation tag")),
        };
        reader.finish()?;
        Ok(body)
    }
}
