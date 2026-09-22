//! Claim-bound candidate key possession. An intent confers no validator authority.

use crate::{
    AccountId, LedgerError, ResolutionId,
    codec::{Reader, Writer},
    profile::Genesis,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::net::{IpAddr, SocketAddr};

const INTENT_MAGIC: &[u8; 4] = b"NSJI";
const INTENT_VERSION: u16 = 1;
const CONSENSUS_DOMAIN: &[u8] = b"naome:state:join-consensus-possession:v3\0";
const TRANSPORT_DOMAIN: &[u8] = b"naome:state:join-transport-possession:v3\0";
const ENDPOINT_MAX_BYTES: usize = 128;

/// A claim holder's proposed validator keys and endpoint, without installation.
/// The containing account action supplies the author's signature and nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinIntent {
    family: ResolutionId,
    completion_ordinal: u64,
    consensus_key: [u8; 32],
    transport_key: [u8; 32],
    endpoint: String,
    consensus_signature: [u8; 64],
    transport_signature: [u8; 64],
}

impl JoinIntent {
    /// Creates two distinct role proofs over the exact account, claim, and run.
    /// State admission separately checks claim ownership and live-key uniqueness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: &Genesis,
        author: AccountId,
        nonce: u64,
        family: ResolutionId,
        completion_ordinal: u64,
        consensus_signing: &SigningKey,
        transport_signing: &SigningKey,
        endpoint: String,
    ) -> Result<Self, LedgerError> {
        let mut intent = Self {
            family,
            completion_ordinal,
            consensus_key: consensus_signing.verifying_key().to_bytes(),
            transport_key: transport_signing.verifying_key().to_bytes(),
            endpoint,
            consensus_signature: [0; 64],
            transport_signature: [0; 64],
        };
        intent.validate_shape()?;
        intent.validate_context(genesis, author, nonce)?;
        let binding = intent.binding(genesis, author, nonce)?;
        intent.consensus_signature = consensus_signing
            .sign(&role_message(CONSENSUS_DOMAIN, &binding))
            .to_bytes();
        intent.transport_signature = transport_signing
            .sign(&role_message(TRANSPORT_DOMAIN, &binding))
            .to_bytes();
        Ok(intent)
    }

    /// Verifies both candidate key proofs. This does not verify the account
    /// envelope or grant membership; the ledger must check those separately.
    pub fn verify(
        &self,
        genesis: &Genesis,
        author: AccountId,
        nonce: u64,
    ) -> Result<(), LedgerError> {
        self.validate_shape()?;
        self.validate_context(genesis, author, nonce)?;
        let binding = self.binding(genesis, author, nonce)?;
        candidate_key(&self.consensus_key)?
            .verify_strict(
                &role_message(CONSENSUS_DOMAIN, &binding),
                &Signature::from_bytes(&self.consensus_signature),
            )
            .map_err(|_| LedgerError::Invalid("join consensus key possession"))?;
        candidate_key(&self.transport_key)?
            .verify_strict(
                &role_message(TRANSPORT_DOMAIN, &binding),
                &Signature::from_bytes(&self.transport_signature),
            )
            .map_err(|_| LedgerError::Invalid("join transport key possession"))
    }

    pub const fn family(&self) -> ResolutionId {
        self.family
    }
    pub const fn completion_ordinal(&self) -> u64 {
        self.completion_ordinal
    }
    pub const fn consensus_key(&self) -> &[u8; 32] {
        &self.consensus_key
    }
    pub const fn transport_key(&self) -> &[u8; 32] {
        &self.transport_key
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(super) fn encode_into(&self, writer: &mut Writer) -> Result<(), LedgerError> {
        self.validate_shape()?;
        writer.fixed(self.family.as_bytes());
        writer.u64(self.completion_ordinal);
        writer.fixed(&self.consensus_key);
        writer.fixed(&self.transport_key);
        writer.string(&self.endpoint)?;
        writer.fixed(&self.consensus_signature);
        writer.fixed(&self.transport_signature);
        Ok(())
    }

    pub(super) fn decode_from(reader: &mut Reader<'_>) -> Result<Self, LedgerError> {
        let intent = Self {
            family: ResolutionId::from_bytes(reader.fixed()?),
            completion_ordinal: reader.u64()?,
            consensus_key: reader.fixed()?,
            transport_key: reader.fixed()?,
            endpoint: reader.string(ENDPOINT_MAX_BYTES)?.to_owned(),
            consensus_signature: reader.fixed()?,
            transport_signature: reader.fixed()?,
        };
        intent.validate_shape()?;
        Ok(intent)
    }

    fn validate_shape(&self) -> Result<(), LedgerError> {
        if self.completion_ordinal == 0 {
            return Err(LedgerError::Invalid("zero join completion ordinal"));
        }
        candidate_key(&self.consensus_key)?;
        candidate_key(&self.transport_key)?;
        if self.consensus_key == self.transport_key {
            return Err(LedgerError::Invalid("join key roles overlap"));
        }
        if self.endpoint.len() > ENDPOINT_MAX_BYTES {
            return Err(LedgerError::Limit("join endpoint bytes"));
        }
        let endpoint: SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| LedgerError::Invalid("join endpoint"))?;
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || matches!(endpoint, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || matches!(endpoint.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            || endpoint.to_string() != self.endpoint
        {
            return Err(LedgerError::Invalid("canonical join endpoint"));
        }
        Ok(())
    }

    fn validate_context(
        &self,
        genesis: &Genesis,
        author: AccountId,
        nonce: u64,
    ) -> Result<(), LedgerError> {
        if nonce == 0 {
            return Err(LedgerError::Invalid("zero join nonce"));
        }
        for candidate in [&self.consensus_key, &self.transport_key] {
            if AccountId::for_key(candidate) == author
                || genesis
                    .accounts()
                    .iter()
                    .any(|account| account.key() == candidate)
                || genesis.validators().iter().any(|validator| {
                    &validator.consensus_key == candidate || &validator.transport_key == candidate
                })
            {
                return Err(LedgerError::Invalid("join key already has another role"));
            }
        }
        if genesis
            .validators()
            .iter()
            .any(|validator| validator.endpoint == self.endpoint)
        {
            return Err(LedgerError::Invalid("join endpoint already assigned"));
        }
        Ok(())
    }

    fn binding(
        &self,
        genesis: &Genesis,
        author: AccountId,
        nonce: u64,
    ) -> Result<Vec<u8>, LedgerError> {
        let mut writer = Writer::new();
        writer.fixed(INTENT_MAGIC);
        writer.u16(INTENT_VERSION);
        writer.fixed(genesis.id().as_bytes());
        writer.fixed(author.as_bytes());
        writer.u64(nonce);
        writer.fixed(self.family.as_bytes());
        writer.u64(self.completion_ordinal);
        writer.fixed(&self.consensus_key);
        writer.fixed(&self.transport_key);
        writer.string(&self.endpoint)?;
        Ok(writer.finish())
    }
}

fn candidate_key(bytes: &[u8; 32]) -> Result<VerifyingKey, LedgerError> {
    let key = VerifyingKey::from_bytes(bytes)
        .map_err(|_| LedgerError::Invalid("join candidate Ed25519 key"))?;
    if key.is_weak() {
        return Err(LedgerError::Invalid("weak join candidate key"));
    }
    Ok(key)
}

fn role_message(domain: &[u8], binding: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + binding.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(binding);
    message
}

#[cfg(test)]
mod tests;
