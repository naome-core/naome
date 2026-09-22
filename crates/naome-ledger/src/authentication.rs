//! Stateless account signatures. Canonical ledger state separately enforces
//! registration, operation authority, and nonce admission.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{
    AccountId, GenesisId, LedgerError, OperationId,
    codec::{Reader, Writer},
    identity::hash,
    profile::Genesis,
};

const MAGIC: &[u8; 4] = b"NSUA";
const VERSION: u16 = 4;
const SIGNING_DOMAIN: &[u8] = b"naome:state:user-action:v4\0";
/// Maximum signed operation bytes, including framing and signature.
pub const SIGNED_OPERATION_MAX_BYTES: usize = 1_048_576;
const OVERHEAD: usize = 4 + 2 + 32 + 32 + 32 + 8 + 4 + 64;

/// Exact authenticated action bytes, before state-dependent nonce admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOperation {
    genesis: GenesisId,
    author: AccountId,
    public_key: [u8; 32],
    nonce: u64,
    payload: Vec<u8>,
    signature: [u8; 64],
}

#[cfg(test)]
mod tests;

impl SignedOperation {
    /// Signs one bounded action without claiming registration or admission.
    /// The canonical ledger checks registration and the exact next nonce.
    pub fn sign(
        genesis: &Genesis,
        nonce: u64,
        payload: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, LedgerError> {
        let author = AccountId::for_key(key.verifying_key().as_bytes());
        let mut operation = Self {
            genesis: genesis.id(),
            author,
            public_key: key.verifying_key().to_bytes(),
            nonce,
            payload,
            signature: [0; 64],
        };
        operation.validate_shape()?;
        operation.signature = key.sign(&operation.signing_bytes()).to_bytes();
        Ok(operation)
    }

    /// Verifies genesis, key-derived identity, and the exact role-specific
    /// signature. Registration and operation authority require canonical state.
    pub fn verify_signature(&self, genesis: &Genesis) -> Result<(), LedgerError> {
        self.validate_shape()?;
        if self.genesis != genesis.id() {
            return Err(LedgerError::Invalid("action genesis"));
        }
        let key = author_key(&self.public_key, self.author)?;
        key.verify_strict(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| LedgerError::Invalid("action signature"))
    }

    /// Returns the action identity, independent of its signature representation.
    pub fn id(&self) -> OperationId {
        OperationId::from_bytes(hash(
            b"naome:state:operation:v4\0",
            &[&self.unsigned_bytes()],
        ))
    }
    /// Returns the authorized account.
    pub const fn author(&self) -> AccountId {
        self.author
    }
    /// Returns the signature's public key; its address must equal `author()`.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
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

    /// Decodes bounded bytes. `verify_signature` checks key possession;
    /// canonical ledger admission separately checks registration and authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(bytes, SIGNED_OPERATION_MAX_BYTES)?;
        if reader.fixed::<4>()? != *MAGIC || reader.u16()? != VERSION {
            return Err(LedgerError::Invalid("action format"));
        }
        let operation = Self {
            genesis: GenesisId::from_bytes(reader.fixed()?),
            author: AccountId::from_bytes(reader.fixed()?),
            public_key: reader.fixed()?,
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

    fn validate_shape(&self) -> Result<(), LedgerError> {
        author_key(&self.public_key, self.author)?;
        if self.nonce == 0 {
            return Err(LedgerError::Invalid("zero action nonce"));
        }
        if self.payload.is_empty() {
            return Err(LedgerError::Invalid("empty action payload"));
        }
        if self.payload.len() > SIGNED_OPERATION_MAX_BYTES - OVERHEAD {
            return Err(LedgerError::Limit("action payload"));
        }
        Ok(())
    }
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.fixed(MAGIC);
        writer.u16(VERSION);
        writer.fixed(self.genesis.as_bytes());
        writer.fixed(self.author.as_bytes());
        writer.fixed(&self.public_key);
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

pub(crate) fn author_key(
    public_key: &[u8; 32],
    author: AccountId,
) -> Result<VerifyingKey, LedgerError> {
    if AccountId::for_key(public_key) != author {
        return Err(LedgerError::Invalid("account key address"));
    }
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| LedgerError::Invalid("account key"))?;
    if key.is_weak() {
        return Err(LedgerError::Invalid("weak account key"));
    }
    Ok(key)
}
