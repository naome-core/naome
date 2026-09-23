//! Live scheduling, delivery, and catch-up for the canonical finalized state.
//!
//! Consensus verification, durable signing, and finality remain in their owning
//! crates. The caller drives this authority-period runtime and its network loop.

pub mod state;
