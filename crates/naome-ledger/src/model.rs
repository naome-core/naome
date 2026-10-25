//! Canonical transaction identities and integer-only coin values.
use crate::{Error, MAX_ITEMS};
use naome_wallet::{Address, LedgerSignature, WalletKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

/// An exact number of indivisible coin units. Zero is a valid balance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(u64);
impl Amount {
    pub const fn from_units(units: u64) -> Self {
        Self(units)
    }
    pub const fn units(self) -> u64 {
        self.0
    }
    pub fn checked_add(self, other: Self) -> Result<Self, Error> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(Error::AmountOverflow)
    }
    pub fn checked_sub(self, other: Self) -> Result<Self, Error> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(Error::AmountOverflow)
    }
}
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for Amount {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        if text.is_empty()
            || !text.bytes().all(|b| b.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return Err(Error::Invalid("amount must be canonical whole coin units"));
        }
        text.parse().map(Self).map_err(|_| Error::AmountOverflow)
    }
}

macro_rules! digest_id {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);
        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let bytes = hex::decode(&text).map_err(de::Error::custom)?;
                if text.len() != 64 || hex::encode(&bytes) != text {
                    return Err(de::Error::custom(
                        "digest must be 32 bytes of lower-case hex",
                    ));
                }
                Ok(Self(
                    bytes
                        .try_into()
                        .map_err(|_| de::Error::custom("digest length"))?,
                ))
            }
        }
    };
}
digest_id!(
    NetworkId,
    "The identity of the network's canonical genesis, including its initial allocation."
);
digest_id!(
    TransactionId,
    "The hash of canonical unsigned transaction bytes, including the signing address."
);

/// One immutable output reference; an accepted payment consumes it once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutPoint {
    pub transaction: TransactionId,
    pub index: u32,
}
/// A nonzero allocation to a wallet address. Positivity is checked on admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub address: Address,
    pub amount: Amount,
}

/// The canonical genesis adopted by a network, including any initial allocations.
///
/// Applications must obtain this contract from the selected network, not from
/// an untrusted peer. Changing an allocation changes the network identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub outputs: Vec<Output>,
}
impl Genesis {
    pub fn network(&self) -> Result<NetworkId, Error> {
        self.validate()?;
        let mut bytes = b"naome:ledger-genesis:v1\0".to_vec();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chain_id);
        encode_outputs(&mut bytes, &self.outputs);
        Ok(NetworkId(Sha256::digest(bytes).into()))
    }
    pub(crate) fn validate(&self) -> Result<Amount, Error> {
        if self.version != 1 {
            return Err(Error::Invalid("unsupported genesis version"));
        }
        if self.outputs.is_empty() {
            Ok(Amount::default())
        } else {
            output_sum(&self.outputs)
        }
    }
}

/// The complete operation authorized by a transaction's signing wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Payment {
        owner: Address,
        authorization: u64,
        inputs: Vec<OutPoint>,
        outputs: Vec<Output>,
    },
    /// Only the owner grants access; a delegate may revoke its own access.
    Access {
        owner: Address,
        delegate: Address,
        sequence: u64,
        enabled: bool,
    },
}

/// An untrusted signed operation, checked against both its network and state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction {
    pub version: u8,
    pub network: NetworkId,
    pub signer: Address,
    pub operation: Operation,
    pub signature: LedgerSignature,
}
impl SignedTransaction {
    pub fn sign(network: NetworkId, operation: Operation, key: &WalletKey) -> Result<Self, Error> {
        let signer = key.address();
        let digest = signing_digest(1, network, signer, &operation)?;
        Ok(Self {
            version: 1,
            network,
            signer,
            operation,
            signature: key.sign_ledger(&digest),
        })
    }
    pub fn id(&self) -> Result<TransactionId, Error> {
        signing_digest(self.version, self.network, self.signer, &self.operation).map(TransactionId)
    }
    pub fn verify_signature(&self) -> Result<TransactionId, Error> {
        let id = self.id()?;
        self.signature
            .verify(self.signer, id.as_bytes())
            .map_err(|_| Error::InvalidSignature)?;
        Ok(id)
    }
}

pub(crate) fn output_sum(outputs: &[Output]) -> Result<Amount, Error> {
    if outputs.is_empty() || outputs.len() > MAX_ITEMS {
        return Err(Error::Capacity);
    }
    outputs.iter().try_fold(Amount::default(), |sum, output| {
        if output.amount.units() == 0 {
            return Err(Error::Invalid("zero-valued coin output"));
        }
        sum.checked_add(output.amount)
    })
}
fn encode_outputs(bytes: &mut Vec<u8>, outputs: &[Output]) {
    bytes.extend_from_slice(&(outputs.len() as u16).to_be_bytes());
    for output in outputs {
        bytes.extend_from_slice(output.address.as_bytes());
        bytes.extend_from_slice(&output.amount.units().to_be_bytes());
    }
}
fn signing_digest(
    version: u8,
    network: NetworkId,
    signer: Address,
    operation: &Operation,
) -> Result<[u8; 32], Error> {
    if version != 1 {
        return Err(Error::Invalid("unsupported transaction version"));
    }
    let mut bytes = b"naome:ledger-transaction:v1\0".to_vec();
    bytes.push(version);
    bytes.extend_from_slice(network.as_bytes());
    bytes.extend_from_slice(signer.as_bytes());
    match operation {
        Operation::Payment {
            owner,
            authorization,
            inputs,
            outputs,
        } => {
            if inputs.is_empty() || inputs.len() > MAX_ITEMS {
                return Err(Error::Capacity);
            }
            output_sum(outputs)?;
            bytes.push(0);
            bytes.extend_from_slice(owner.as_bytes());
            bytes.extend_from_slice(&authorization.to_be_bytes());
            bytes.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
            for input in inputs {
                bytes.extend_from_slice(input.transaction.as_bytes());
                bytes.extend_from_slice(&input.index.to_be_bytes());
            }
            encode_outputs(&mut bytes, outputs);
        }
        Operation::Access {
            owner,
            delegate,
            sequence,
            enabled,
        } => {
            if owner == delegate || *sequence == 0 {
                return Err(Error::Invalid("invalid node spending authorization"));
            }
            bytes.push(1);
            bytes.extend_from_slice(owner.as_bytes());
            bytes.extend_from_slice(delegate.as_bytes());
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.push(u8::from(*enabled));
        }
    }
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests;
