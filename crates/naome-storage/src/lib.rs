//! Observed SQLite transaction outcomes, independent of domain state and policy.
//!
//! Stores classify their own errors and stop serving cached state after an
//! uncertain outcome. No caller may infer a successful rollback from `Drop`.

#[cfg(unix)]
mod transaction;
#[cfg(unix)]
pub use transaction::{CommitError, write};
