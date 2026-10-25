//! Immutable checker-validated proof sets, independent of ledger selection.
//!
//! Peers exchange hints and derived questions before full certificates. Each
//! receiver requires fresh formal approval and positive local interest, then
//! checks the complete necessary proof closure before atomic publication.
//! Union convergence requires every relevant question to be selected, compatible
//! honest peers to reconnect, and data to fit the explicit local resource limits.

mod autonomous;
#[cfg(unix)]
mod checkpoint;
mod corpus;
mod discovery;
mod error;
pub use error::Error;
mod graph;
mod index_storage;
mod intake;
#[cfg(unix)]
mod jobs;
pub mod mocks;
pub mod network;
mod object;
#[cfg(unix)]
pub mod proof_work;
mod publication;
pub mod question;
mod quota;
pub mod relay;
pub mod resources;
#[cfg(unix)]
pub mod runtime;
mod storage;
mod store;
#[cfg(unix)]
mod wallet;
#[cfg(unix)]
pub use wallet::{NodeWallet, WalletConnection, WalletFunds, WalletFundsScope, WalletStatus};
mod wire;

pub use corpus::ROOT_FORMAT as CORPUS_ROOT_FORMAT;
pub use graph::{Graph, Ingest};
pub use object::{CHECKER_ID, CODEC_ID, Envelope, GRAPH_POLICY_ID, compatibility, hex, unhex};
