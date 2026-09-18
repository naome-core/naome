//! Account authorization. A verified signature does not apply a state transition.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{
    AccountId, GenesisId, OperationId, ResearchError,
    codec::{Reader, Writer},
    identity::hash,
    profile::Genesis,
};

const MAGIC: &[u8; 4] = b"NSUA";
const VERSION: u16 = 1;
const SIGNING_DOMAIN: &[u8] = b"naome:state:user-action:v1\0";
/// Maximum signed operation bytes, including framing and signature.
pub const SIGNED_OPERATION_MAX_BYTES: usize = 1_048_576;
const OVERHEAD: usize = 4 + 2 + 32 + 32 + 8 + 4 + 64;

/// Exact authenticated action bytes, before state-dependent nonce admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOperation {
    genesis: GenesisId,
    author: AccountId,
    nonce: u64,
    payload: Vec<u8>,
    signature: [u8; 64],
}

#[cfg(test)]
mod tests;

impl SignedOperation {
    /// Signs one bounded action using a registered account. A first nonce is one.
    pub fn sign(
        genesis: &Genesis,
        nonce: u64,
        payload: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, ResearchError> {
        let author = AccountId::for_key(key.verifying_key().as_bytes());
        if genesis.account_key(author) != Some(key.verifying_key().as_bytes()) {
            return Err(ResearchError::Invalid("unregistered action signer"));
        }
        let mut operation = Self {
            genesis: genesis.id(),
            author,
            nonce,
            payload,
            signature: [0; 64],
        };
        operation.validate_shape()?;
        operation.signature = key.sign(&operation.signing_bytes()).to_bytes();
        Ok(operation)
    }

    /// Verifies exact genesis and role-specific authorization, not state validity.
    pub fn verify(&self, genesis: &Genesis) -> Result<(), ResearchError> {
        self.validate_shape()?;
        if self.genesis != genesis.id() {
            return Err(ResearchError::Invalid("action genesis"));
        }
        let public = genesis
            .account_key(self.author)
            .ok_or(ResearchError::Invalid("unregistered action author"))?;
        let key =
            VerifyingKey::from_bytes(public).map_err(|_| ResearchError::Invalid("account key"))?;
        key.verify_strict(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ResearchError::Invalid("action signature"))
    }

    /// Returns the action identity, independent of its signature representation.
    pub fn id(&self) -> OperationId {
        OperationId::from_bytes(hash(
            b"naome:state:operation:v1\0",
            &[&self.unsigned_bytes()],
        ))
    }
    /// Returns the authorized account.
    pub const fn author(&self) -> AccountId {
        self.author
    }
    /// Returns the exact nonce; the state machine checks the next expected value.
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Returns the bound test-run identity.
    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis
    }
    /// Returns the exact operation body for strict domain decoding.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Returns exact signature bytes.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Encodes exactly one canonical signed operation.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.unsigned_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes bounded bytes. Call `verify` before trusting their authorization.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResearchError> {
        let mut reader = Reader::new(bytes, SIGNED_OPERATION_MAX_BYTES)?;
        if reader.fixed::<4>()? != *MAGIC || reader.u16()? != VERSION {
            return Err(ResearchError::Invalid("action format"));
        }
        let operation = Self {
            genesis: GenesisId::from_bytes(reader.fixed()?),
            author: AccountId::from_bytes(reader.fixed()?),
            nonce: reader.u64()?,
            payload: reader
                .bytes(SIGNED_OPERATION_MAX_BYTES - OVERHEAD)?
                .to_vec(),
            signature: reader.fixed()?,
        };
        reader.finish()?;
        operation.validate_shape()?;
        Ok(operation)
    }

    fn validate_shape(&self) -> Result<(), ResearchError> {
        if self.nonce == 0 {
            return Err(ResearchError::Invalid("zero action nonce"));
        }
        if self.payload.is_empty() {
            return Err(ResearchError::Invalid("empty action payload"));
        }
        if self.payload.len() > SIGNED_OPERATION_MAX_BYTES - OVERHEAD {
            return Err(ResearchError::Limit("action payload"));
        }
        Ok(())
    }
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.fixed(MAGIC);
        writer.u16(VERSION);
        writer.fixed(self.genesis.as_bytes());
        writer.fixed(self.author.as_bytes());
        writer.u64(self.nonce);
        writer
            .bytes(&self.payload)
            .expect("private action shape bounds payload");
        writer.finish()
    }
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend(self.unsigned_bytes());
        bytes
    }
}
