//! Executes the canonical finalized state through anchored history and signing.
//!
//! The node coordinates authenticated operations, certified time, proposals,
//! votes, finality, and restart recovery. Deterministic state rules belong to
//! the ledger; this crate does not create a second selected history.

pub mod state;
