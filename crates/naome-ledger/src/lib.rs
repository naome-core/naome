//! A local, explicitly non-production test-coin ledger.
//!
//! Every coin originates in an explicit test genesis. There is no later minting,
//! mining reward, network consensus, or claim of monetary value. A state checks
//! a caller-selected transaction order; it cannot choose a shared network order.
//! Wallet signatures authorize payments and individual node spending keys.
mod model;
mod state;
#[cfg(unix)]
mod store;

pub use model::{
    Amount, NetworkId, Operation, OutPoint, Output, SignedTransaction, TestGenesis, TransactionId,
};
pub use state::State;
#[cfg(unix)]
pub use store::Ledger;

/// Maximum inputs, outputs, or initial allocations in one bounded operation.
pub const MAX_ITEMS: usize = 128;
/// Maximum encoded JSON bytes of one genesis or signed transaction.
pub const MAX_RECORD_BYTES: usize = 65_536;

/// A rejected transaction or an unavailable local ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    WrongNetwork,
    InvalidSignature,
    DuplicateInput,
    MissingInput,
    Unauthorized,
    InvalidSequence,
    ValueMismatch,
    AmountOverflow,
    Capacity,
    Busy,
    RecoveryRequired,
    Storage(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::WrongNetwork => f.write_str("test-ledger network mismatch"),
            Self::InvalidSignature => f.write_str("invalid test-ledger signature"),
            Self::DuplicateInput => f.write_str("duplicate transaction input"),
            Self::MissingInput => f.write_str("input is missing or already spent"),
            Self::Unauthorized => f.write_str("wallet has not authorized this spending key"),
            Self::InvalidSequence => f.write_str("stale wallet authorization sequence"),
            Self::ValueMismatch => f.write_str("input and output values must match exactly"),
            Self::AmountOverflow => f.write_str("test-coin amount overflow or insufficient funds"),
            Self::Capacity => f.write_str("test-ledger operation capacity"),
            Self::Busy => f.write_str("test ledger is already in use"),
            Self::RecoveryRequired => {
                f.write_str("test-ledger commit unconfirmed; reopen before use")
            }
            Self::Storage(message) => write!(f, "test-ledger storage: {message}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
#[cfg(unix)]
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[cfg(test)]
mod test_support;
