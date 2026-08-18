//! Core integration contracts for the NAOME protocol.
//!
//! The root crate combines otherwise independent protocol value types only at
//! narrow caller-authority boundaries. Its citation-reward projection accepts
//! caller-supplied reward atoms and numeric epochs; it does not establish that
//! a reward was earned, matured canonically, or belongs to any account, and it
//! neither consumes reward value nor returns, records, or persists an origin
//! batch. Its validator-fee projections accept caller-supplied aggregate pool
//! atoms, an immutable active snapshot, and either one active key or a bounded
//! signer-key list; they establish no pool provenance, certificate,
//! entitlement, burn, settlement, or state authority.

pub mod artifact_exchange;
pub mod block_exchange;
pub mod chain_head_announcement;
pub mod chain_head_exchange;
pub mod citation_reward_weight;
pub mod validator_bond;
pub mod validator_fee_share;
