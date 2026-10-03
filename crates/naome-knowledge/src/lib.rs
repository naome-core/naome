//! Immutable checker-validated proof sets, independent of ledger selection.
//!
//! Peers exchange hints and content; only local checking admits an object.
//! Availability and eventual union convergence require compatible honest peers
//! to reconnect and retain the data within the explicit local resource limits.

mod graph;
pub mod network;
mod object;
mod store;
mod wire;

pub use graph::{
    Graph, Ingest, MAX_ACCEPTED_BYTES, MAX_CONTEXT_BYTES, MAX_OBJECTS, MAX_PENDING, PENDING_TTL,
};
pub use object::{
    CHECKER_ID, CODEC_ID, Envelope, GRAPH_POLICY_ID, MAX_DEPENDENCIES, MAX_DEPTH, MAX_PROOF_BYTES,
    compatibility, hex, unhex,
};
