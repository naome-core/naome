//! Domain-separated signatures for the explicitly non-production test ledger.
use super::{Address, Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"naome:test-ledger-signature:v1\0";

/// A signature over one canonical test-ledger transaction digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TestLedgerSignature(String);

fn message(digest: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, digest].concat()
}

pub(super) fn sign(key: &SigningKey, digest: &[u8; 32]) -> TestLedgerSignature {
    TestLedgerSignature(hex::encode(key.sign(&message(digest)).to_bytes()))
}

impl TestLedgerSignature {
    /// Verifies the exact digest against the expected signing wallet address.
    pub fn verify(&self, address: Address, digest: &[u8; 32]) -> Result<(), String> {
        if self.0.len() != 128 {
            return Err("test-ledger signature length".into());
        }
        let bytes = hex::decode(&self.0).map_err(|error| error.to_string())?;
        if hex::encode(&bytes) != self.0 {
            return Err("test-ledger signature must use lower-case hex".into());
        }
        let signature =
            Signature::from_slice(&bytes).map_err(|_| "invalid test-ledger signature")?;
        address
            .key()?
            .verify_strict(&message(digest), &signature)
            .map_err(|_| "invalid test-ledger signature".into())
    }
}
