//! Bounded transport-neutral artifact, block, and chain-head wire contracts.
//!
//! These contracts preserve exact wire bytes and immutable request addresses.
//! Decoding or observing availability grants no peer, mathematical-validity,
//! selected-chain, consensus, finality, or economic authority.
//! Transport runtime and storage coordination belong to their owning crates.

pub mod artifact_exchange;
pub mod block_exchange;
pub mod chain_head_announcement;
pub mod chain_head_exchange;
