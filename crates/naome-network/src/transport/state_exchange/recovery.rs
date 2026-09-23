//! Owner-authenticated history access for a node whose selected parent is stale.
//!
//! A recovery proof never grants period authority. It only permits bounded
//! history and handoff exchange after a recipient-issued challenge is consumed.

use super::{StateContext, StateNetworkBuildError, state_peer_id};
use crate::PeerId;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use naome_ledger::{AccountId, state::LedgerState};

const OWNER_DOMAIN: &[u8] = b"naome:state:recovery-owner:v5\0";
const TRANSPORT_DOMAIN: &[u8] = b"naome:state:recovery-transport:v5\0";
pub const RECOVERY_HELLO_BYTES: usize = 32 + 32 + 32 + 64 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryHello {
    owner: AccountId,
    transport_key: [u8; 32],
    challenge: [u8; 32],
    owner_signature: [u8; 64],
    transport_signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Length,
    Context,
    Challenge,
    Owner,
    Identity,
    Signature,
}
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid recovery proof: {self:?}")
    }
}
impl std::error::Error for RecoveryError {}

impl RecoveryHello {
    pub fn sign(
        context: StateContext,
        recipient: PeerId,
        challenge: [u8; 32],
        owner: &SigningKey,
        transport: &SigningKey,
    ) -> Self {
        let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
        let mut hello = Self {
            owner: owner_id,
            transport_key: transport.verifying_key().to_bytes(),
            challenge,
            owner_signature: [0; 64],
            transport_signature: [0; 64],
        };
        hello.owner_signature = owner
            .sign(&hello.message(OWNER_DOMAIN, context, recipient))
            .to_bytes();
        hello.transport_signature = transport
            .sign(&hello.message(TRANSPORT_DOMAIN, context, recipient))
            .to_bytes();
        hello
    }
    pub const fn owner(&self) -> AccountId {
        self.owner
    }
    pub const fn transport_key(&self) -> &[u8; 32] {
        &self.transport_key
    }
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    pub fn encode(&self) -> [u8; RECOVERY_HELLO_BYTES] {
        let mut out = [0; RECOVERY_HELLO_BYTES];
        out[..32].copy_from_slice(self.owner.as_bytes());
        out[32..64].copy_from_slice(&self.transport_key);
        out[64..96].copy_from_slice(&self.challenge);
        out[96..160].copy_from_slice(&self.owner_signature);
        out[160..224].copy_from_slice(&self.transport_signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() != RECOVERY_HELLO_BYTES {
            return Err(RecoveryError::Length);
        }
        Ok(Self {
            owner: AccountId::from_bytes(bytes[..32].try_into().expect("checked")),
            transport_key: bytes[32..64].try_into().expect("checked"),
            challenge: bytes[64..96].try_into().expect("checked"),
            owner_signature: bytes[96..160].try_into().expect("checked"),
            transport_signature: bytes[160..224].try_into().expect("checked"),
        })
    }
    pub fn verify(
        &self,
        selected: &LedgerState,
        context: StateContext,
        recipient: PeerId,
        remote: PeerId,
        challenge: [u8; 32],
    ) -> Result<AccountId, RecoveryError> {
        if context.genesis() != selected.genesis().id().as_bytes()
            || context.profile() != selected.genesis().profile().id().as_bytes()
        {
            return Err(RecoveryError::Context);
        }
        if self.challenge != challenge {
            return Err(RecoveryError::Challenge);
        }
        if state_peer_id(self.transport_key).map_err(|_| RecoveryError::Identity)? != remote {
            return Err(RecoveryError::Identity);
        }
        let owner_key = selected
            .account_key(self.owner)
            .ok_or(RecoveryError::Owner)?;
        if selected.used_period_keys().contains(&self.transport_key)
            || selected
                .accounts()
                .values()
                .any(|key| key == &self.transport_key)
        {
            return Err(RecoveryError::Identity);
        }
        for (key, signature, domain) in [
            (owner_key, &self.owner_signature, OWNER_DOMAIN),
            (
                &self.transport_key,
                &self.transport_signature,
                TRANSPORT_DOMAIN,
            ),
        ] {
            VerifyingKey::from_bytes(key)
                .map_err(|_| RecoveryError::Signature)?
                .verify_strict(
                    &self.message(domain, context, recipient),
                    &Signature::from_bytes(signature),
                )
                .map_err(|_| RecoveryError::Signature)?;
        }
        Ok(self.owner)
    }
    fn message(&self, domain: &[u8], context: StateContext, recipient: PeerId) -> Vec<u8> {
        let peer = recipient.to_bytes();
        let mut result = Vec::with_capacity(domain.len() + 32 * 4 + peer.len() + 1);
        result.extend_from_slice(domain);
        result.extend_from_slice(context.genesis());
        result.extend_from_slice(context.profile());
        result.extend_from_slice(self.owner.as_bytes());
        result.extend_from_slice(&self.transport_key);
        result.extend_from_slice(&self.challenge);
        result.push(peer.len() as u8);
        result.extend_from_slice(&peer);
        result
    }
}

impl From<StateNetworkBuildError> for RecoveryError {
    fn from(_: StateNetworkBuildError) -> Self {
        Self::Identity
    }
}
