//! Economy-free replication of immutable, checker-validated mathematical artifacts.
//!
//! Peers exchange hints and derived questions before full certificates. Each
//! receiver requires fresh formal approval and positive local selection, then
//! checks the complete necessary artifact closure before atomic publication.
//! Union convergence requires every relevant question to be selected, compatible
//! honest peers to reconnect, and data to fit the explicit local resource limits.

mod autonomous;
#[cfg(unix)]
mod checkpoint;
mod corpus;
mod discovery;
mod error;
mod outcome;
pub use learning::evidence::{EvidenceLimit, Failure as EvidenceFailure};
/// All node and checker outcomes for offline machine consumers.
#[cfg(feature = "developer-tools")]
pub fn outcome_codes() -> impl Iterator<Item = (&'static str, &'static str, u32)> {
    outcome::OUTCOME_CODES
        .iter()
        .chain(naome_checker::question::PREFILTER_CODES.iter())
        .chain(naome_checker::question::PREFILTER_RULE_CODES.iter())
        .chain(naome_checker::diagnostics::DIAGNOSTIC_FAILURE_CODES.iter())
        .chain(naome_checker::diagnostics::FORMULA_FAILURE_CODES.iter())
        .chain(naome_checker::diagnostics::EXPANSION_FAILURE_CODES.iter())
        .copied()
}
pub use outcome::{
    DurabilityCode, IngestStatus, InputFault, InputLimit, LearningGraphFailure, PauseReason,
    ResearchFailure, RuntimeFailure, StartupFailure,
};
mod frontier;
pub use error::{CertificateFormatError, DurabilityFailure, Error};
mod graph;
mod index_storage;
mod intake;
#[cfg(unix)]
mod jobs;
mod learning;
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
mod sampling;
mod storage;
mod store;
mod structure;
/// Checked proof curricula and model-bound development feedback.
pub mod training;
mod wire;

pub use corpus::ROOT_FORMAT as CORPUS_ROOT_FORMAT;
pub use graph::{Graph, Ingest};
pub use object::{CHECKER_ID, CODEC_ID, Envelope, GRAPH_POLICY_ID, compatibility, hex, unhex};

#[cfg(test)]
mod test_inputs;
