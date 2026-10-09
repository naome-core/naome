//! Immutable checker-validated proof sets, independent of ledger selection.
//!
//! Peers exchange hints and derived questions before full certificates. Each
//! receiver requires fresh formal approval and positive local interest, then
//! checks the complete necessary proof closure before atomic publication.
//! Union convergence requires every relevant question to be selected, compatible
//! honest peers to reconnect, and data to fit the explicit local resource limits.

mod autonomous;
#[cfg(unix)]
mod corpus;
mod discovery;
#[cfg(unix)]
mod generation;
mod graph;
mod intake;
#[cfg(unix)]
mod jobs;
pub mod mocks;
pub mod network;
mod object;
pub mod question;
pub mod relay;
#[cfg(unix)]
pub mod runtime;
mod store;
mod wire;

pub use graph::{
    Graph, Ingest, MAX_ACCEPTED_BYTES, MAX_CONTEXT_BYTES, MAX_OBJECTS, MAX_PENDING, PENDING_TTL,
};
pub use object::{
    CHECKER_ID, CODEC_ID, Envelope, GRAPH_POLICY_ID, MAX_DEPENDENCIES, MAX_DEPTH, MAX_PROOF_BYTES,
    compatibility, hex, unhex,
};

#[cfg(unix)]
pub use corpus::ProofCorpus;
#[cfg(unix)]
pub use corpus::semantic::{
    EncoderIdentity, SEMANTIC_REPRESENTATION_VERSION, SemanticEncoder, SemanticHit, SemanticIndex,
    SemanticPage,
};
