//! Canonical user actions and author authentication for original proof packages.

use crate::{
    AccountId, CommitmentId, GenesisId, LedgerError, PackageHash, ProfileId, QuestionId,
    SolutionRoundId,
    authentication::{SignedOperation, author_key},
    codec::{Reader, Writer},
    identity::hash,
    library::ProofPackage,
    profile::Genesis,
    question::CompiledQuestion,
};
use ed25519_dalek::{Signature, Signer, SigningKey};

const ORIGINAL_MAGIC: &[u8; 4] = b"NSOR";
const ORIGINAL_VERSION: u16 = 2;
const ORIGINAL_DOMAIN: &[u8] = b"naome:state:original-authorization:v2\0";
const ORIGINAL_OVERHEAD: usize = 4 + 2 + 32 + 32 + 32 + 32 + 4 + 64;
const PURPOSE_MAX_BYTES: usize = 16 * 1024;

/// A package signed by its single author under the exact approved solution round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOriginal {
    genesis: GenesisId,
    profile: ProfileId,
    round: SolutionRoundId,
    public_key: [u8; 32],
    package: ProofPackage,
    signature: [u8; 64],
}

impl SignedOriginal {
    /// Signs unchanged package bytes before commitment publication. Registration
    /// and publication authority are checked separately by canonical ledger state.
    pub fn sign(
        genesis: &Genesis,
        round: SolutionRoundId,
        package: ProofPackage,
        key: &SigningKey,
    ) -> Result<Self, LedgerError> {
        let author = AccountId::for_key(key.verifying_key().as_bytes());
        if package.author() != author {
            return Err(LedgerError::Invalid("original package signer"));
        }
        let mut original = Self {
            genesis: genesis.id(),
            profile: genesis.profile().id(),
            round,
            public_key: key.verifying_key().to_bytes(),
            package,
            signature: [0; 64],
        };
        original.signature = key.sign(&original.signing_bytes()?).to_bytes();
        Ok(original)
    }
    /// Validates the signature, key-derived author and context, before canonical
    /// registration checks and mathematical checking grant publication authority.
    pub fn verify_signature(
        &self,
        genesis: &Genesis,
        round: SolutionRoundId,
        author: AccountId,
    ) -> Result<(), LedgerError> {
        if self.genesis != genesis.id()
            || self.profile != genesis.profile().id()
            || self.round != round
            || self.package.author() != author
        {
            return Err(LedgerError::Invalid("original context"));
        }
        author_key(&self.public_key, author)?
            .verify_strict(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| LedgerError::Invalid("original author signature"))
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
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, LedgerError> {
        let maximum = genesis.profile().limits().package_bytes as usize;
        let mut reader = Reader::new(bytes, maximum + ORIGINAL_OVERHEAD)?;
        if reader.fixed::<4>()? != *ORIGINAL_MAGIC || reader.u16()? != ORIGINAL_VERSION {
            return Err(LedgerError::Invalid("original format"));
        }
        let original = Self {
            genesis: GenesisId::from_bytes(reader.fixed()?),
            profile: ProfileId::from_bytes(reader.fixed()?),
            round: SolutionRoundId::from_bytes(reader.fixed()?),
            public_key: reader.fixed()?,
            package: ProofPackage::decode(reader.bytes(maximum)?, genesis.profile())?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        author_key(&original.public_key, original.package.author())?;
        Ok(original)
    }
    fn unsigned_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut writer = Writer::new();
        writer.fixed(ORIGINAL_MAGIC);
        writer.u16(ORIGINAL_VERSION);
        writer.fixed(self.genesis.as_bytes());
        writer.fixed(self.profile.as_bytes());
        writer.fixed(self.round.as_bytes());
        writer.fixed(&self.public_key);
        writer.bytes(&self.package.encode()?)?;
        Ok(writer.finish())
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, LedgerError> {
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
    /// Registers the account identified by the authenticated envelope's key.
    Register,
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
            Self::Register => f.write_str("Register"),
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
    ) -> Result<SignedOperation, LedgerError> {
        SignedOperation::sign(genesis, nonce, self.encode()?, key)
    }
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let mut writer = Writer::new();
        writer.u8(2);
        match self {
            Self::Register => writer.u8(5),
            Self::Submit { purpose, question } => {
                if purpose.is_empty() || purpose.len() > PURPOSE_MAX_BYTES {
                    return Err(LedgerError::Limit("question purpose"));
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
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(bytes, genesis.profile().limits().record_bytes as usize)?;
        if reader.u8()? != 2 {
            return Err(LedgerError::Invalid("user body version"));
        }
        let body = match reader.u8()? {
            5 => Self::Register,
            1 => {
                let purpose = reader.string(PURPOSE_MAX_BYTES)?.to_owned();
                if purpose.is_empty() {
                    return Err(LedgerError::Invalid("empty question purpose"));
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
                    return Err(LedgerError::Invalid("zero voting attempt"));
                }
                let yes = match reader.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(LedgerError::Invalid("ballot choice")),
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
            _ => return Err(LedgerError::Invalid("user operation tag")),
        };
        reader.finish()?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
