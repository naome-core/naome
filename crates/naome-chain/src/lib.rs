//! Canonical complete state records and exact-parent replay for NAOME.
//!
//! [`StateRecord`] binds authenticated operations, certified time, deterministic
//! effects, and the complete ledger commitment. [`FinalizedStateRecord`] owns
//! the wire envelope binding that proposal to consensus evidence. Consensus
//! authenticates and verifies the envelope; storage owns durable selection.
//! Decoding or provisional execution alone never grants finality.
//!
pub mod state;
pub use state::{FinalizedStateRecord, StateRecord, StateRecordExecution, StateTransition};
