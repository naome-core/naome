//! Core integration contracts for the NAOME protocol.
//!
//! The root crate combines otherwise independent protocol value types only at
//! narrow caller-authority boundaries. Its artifact-inclusion priority value
//! orders caller-supplied artifact identities and numeric bids without proving
//! candidate or bid validity. Its citation-reward projection accepts
//! caller-supplied reward atoms and numeric epochs; it does not establish that
//! a reward was earned, matured canonically, or belongs to any account, and it
//! neither consumes reward value nor returns, records, or persists an origin
//! batch. Its checked-proof citation projection validates only that a caller-
//! asserted target slice is bounded, distinct, and direct before coupling those
//! exact identities to numeric citation-pool division. The selected-proof path
//! additionally requires the source identity to name one locally admitted proof
//! in the supplied artifact chain. That success establishes only local strict
//! admission and selected membership; neither path mutates state or establishes
//! consensus canonicality or finality, target eligibility, attribution, reward,
//! burn, or economic or consensus-state authority. Its validator-fee projections
//! accept either caller-supplied aggregate pool atoms or caller-supplied fee
//! partitions, an immutable active snapshot, and either one active key or a
//! bounded signer-key list. The partition path aggregates once before allocation,
//! but establishes no partition completeness or grouping, certificate,
//! entitlement, burn, settlement, or state authority.

pub mod artifact_inclusion_priority;
pub mod citation_pool_split;
pub mod citation_reward_weight;
pub mod validator_bond;
pub mod validator_fee_share;

// Compatibility paths for the transport-neutral protocol contracts.
pub use naome_protocol::{
    artifact_exchange, block_exchange, chain_head_announcement, chain_head_exchange,
};
