//! Pseudonymous wallet identities and challenge-bound proofs of key control.
//!
//! An ownership proof establishes control of a key, never a coin balance,
//! payment, unique operator, or right to issue currency. Verifiers must supply
//! their expected address and a fresh challenge that they do not reuse.
//!
//! ```
//! use naome_wallet::{OwnershipChallenge, WalletKey};
//!
//! let key = WalletKey::generate()?;
//! let expected_address = key.address();
//! let challenge = OwnershipChallenge::new("research.example/key-control".into())?;
//! let proof = key.prove(challenge.clone())?;
//! proof.verify(expected_address, &challenge)?;
//! # Ok::<(), String>(())
//! ```
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fmt, str::FromStr};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"naome:wallet-key-ownership:v1\0";
const AUDIENCE_MAX_BYTES: usize = 256;

/// A private wallet key with an address and challenge-bound signing capability.
///
/// Keys are independent of node identities and storage. Private material is
/// zeroized on drop and is never included in proofs or serialized implicitly.
/// Applications own custody, access control, and durable storage.
pub struct WalletKey {
    key: SigningKey,
    address: Address,
}

impl WalletKey {
    fn from_signing_key(key: SigningKey) -> Result<Self, String> {
        let address = Address::from_key(key.verifying_key())?;
        Ok(Self { key, address })
    }

    /// Generates a key using operating-system randomness.
    pub fn generate() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).map_err(|_| "wallet randomness unavailable")?;
        Self::from_signing_key(SigningKey::from_bytes(&seed))
    }

    /// Imports a 32-byte Ed25519 seed followed by its matching public key.
    pub fn from_keypair_bytes(bytes: &[u8; 64]) -> Result<Self, String> {
        let key = SigningKey::from_keypair_bytes(bytes)
            .map_err(|_| "wallet private and public keys do not match")?;
        Self::from_signing_key(key)
    }

    /// Exports the seed and public key for explicit private custody or backup.
    ///
    /// The returned buffer is zeroized on drop. Callers must protect any copies
    /// or persistent records they make from it.
    pub fn to_keypair_bytes(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.key.to_keypair_bytes())
    }

    /// Returns the public receiving address for this key.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Signs a validated ownership challenge in the wallet key-control domain.
    pub fn prove(&self, challenge: OwnershipChallenge) -> Result<OwnershipProof, String> {
        OwnershipProof::sign(&self.key, challenge)
    }
}

/// An Ed25519 public key encoded as a canonical `nao` Bech32m address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 32]);

impl Address {
    fn from_key(key: VerifyingKey) -> Result<Self, String> {
        if key.is_weak() {
            return Err("weak wallet public key".into());
        }
        Ok(Self(key.to_bytes()))
    }

    fn key(&self) -> Result<VerifyingKey, String> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| "invalid wallet public key".into())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = bech32::encode::<Bech32m>(Hrp::parse("nao").expect("fixed HRP"), &self.0)
            .expect("fixed-size wallet address");
        f.write_str(&encoded)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() > 90 {
            return Err("wallet address length".into());
        }
        let decoded = CheckedHrpstring::new::<Bech32m>(text)
            .map_err(|_| "invalid wallet address checksum or encoding")?;
        if decoded.hrp() != Hrp::parse("nao").expect("fixed HRP") {
            return Err("wallet address prefix".into());
        }
        let bytes: [u8; 32] = decoded
            .byte_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "wallet address public-key length")?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid wallet public key")?;
        let address = Self::from_key(key)?;
        if address.to_string() != text {
            return Err("wallet address must use canonical lower-case Bech32m".into());
        }
        Ok(address)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// A verifier-issued, single-use challenge for a particular audience.
///
/// The audience identifies the verifier and purpose. It is included in the
/// signed bytes, but does not independently authenticate the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipChallenge {
    pub version: u8,
    pub audience: String,
    pub nonce: String,
}

impl OwnershipChallenge {
    /// Creates a challenge from operating-system randomness, without a wallet.
    pub fn new(audience: String) -> Result<Self, String> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| "wallet challenge randomness unavailable")?;
        let challenge = Self {
            version: 1,
            audience,
            nonce: hex::encode(nonce),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    fn validate(&self) -> Result<[u8; 32], String> {
        if self.version != 1 {
            return Err("unsupported wallet challenge version".into());
        }
        if self.audience.is_empty() || self.audience.len() > AUDIENCE_MAX_BYTES {
            return Err("wallet challenge audience must be 1..=256 UTF-8 bytes".into());
        }
        if self.nonce.len() != 64 {
            return Err("wallet challenge nonce must be 32 bytes of lower-case hex".into());
        }
        let nonce = hex::decode(&self.nonce).map_err(|error| error.to_string())?;
        if hex::encode(&nonce) != self.nonce {
            return Err("wallet challenge nonce must use lower-case hex".into());
        }
        nonce
            .try_into()
            .map_err(|_| "wallet challenge nonce length".into())
    }

    fn message(&self, address: Address) -> Result<Vec<u8>, String> {
        let nonce = self.validate()?;
        let mut message = Vec::with_capacity(DOMAIN.len() + 2 + self.audience.len() + 64);
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&(self.audience.len() as u16).to_be_bytes());
        message.extend_from_slice(self.audience.as_bytes());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&address.0);
        Ok(message)
    }
}

/// A domain-separated signature proving control of one wallet key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipProof {
    pub version: u8,
    pub address: Address,
    pub challenge: OwnershipChallenge,
    pub signature: String,
}

impl OwnershipProof {
    fn sign(key: &SigningKey, challenge: OwnershipChallenge) -> Result<Self, String> {
        let address = Address::from_key(key.verifying_key())?;
        let signature = key.sign(&challenge.message(address)?);
        Ok(Self {
            version: 1,
            address,
            challenge,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    /// Checks key control against the verifier's address and original challenge.
    ///
    /// This does not consume the challenge. The verifier owns single-use
    /// tracking and must not take the expected challenge from the proof itself.
    pub fn verify(
        &self,
        expected_address: Address,
        expected_challenge: &OwnershipChallenge,
    ) -> Result<(), String> {
        if self.version != 1 {
            return Err("unsupported wallet ownership proof version".into());
        }
        if self.address != expected_address || self.challenge != *expected_challenge {
            return Err("wallet ownership proof address or challenge mismatch".into());
        }
        if self.signature.len() != 128 {
            return Err("wallet ownership signature length".into());
        }
        let bytes = hex::decode(&self.signature).map_err(|error| error.to_string())?;
        if hex::encode(&bytes) != self.signature {
            return Err("wallet ownership signature must use lower-case hex".into());
        }
        let signature = Signature::from_slice(&bytes).map_err(|_| "invalid wallet signature")?;
        self.address
            .key()?
            .verify_strict(&expected_challenge.message(expected_address)?, &signature)
            .map_err(|_| "invalid wallet ownership signature".into())
    }
}

#[cfg(test)]
mod tests;
