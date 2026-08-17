//! Stateless citation-reward maturity and live Knowledge Weight projection.
//!
//! This module combines caller-supplied [`NaoAtoms`] and projected
//! [`ConsensusEpoch`] values with the economy kernel's immutable origin-batch
//! decay. It establishes no reward earning, eligibility, canonical maturation,
//! finality, ancestry, beneficiary, ownership, balance, settlement,
//! first-maturation consumption, persistence, delegation, proposer weight,
//! agreement weight, or consensus state. Repeated evaluation neither consumes
//! reward value nor returns, records, or persists an origin batch.

use naome_consensus::ConsensusEpoch;
use naome_economy::{KnowledgeWeight, KnowledgeWeightBatch, NaoAtoms};

const CITATION_REWARD_MATURITY_DELAY_EPOCHS: u64 = 2;

/// Returns the live Knowledge Weight projected from one citation reward.
///
/// `earned_epoch` and `evaluated_epoch` are caller-supplied numeric epochs. An
/// evaluation before earning or during the two-epoch maturation delay returns
/// zero. At elapsed epoch two, one reward atom contributes one live Knowledge
/// Weight unit. Later evaluations use the immutable origin batch at age
/// `evaluated_epoch - earned_epoch - 2`, including terminal zero from age 730.
///
/// The function returns only the current weight, not a refreshable origin
/// batch. It neither consumes reward value nor records or persists a batch and
/// proves none of the protocol authority excluded by this module.
pub const fn live_citation_reward_weight(
    reward_atoms: NaoAtoms,
    earned_epoch: ConsensusEpoch,
    evaluated_epoch: ConsensusEpoch,
) -> KnowledgeWeight {
    let earned_epoch = earned_epoch.value();
    let evaluated_epoch = evaluated_epoch.value();

    if evaluated_epoch < earned_epoch {
        return KnowledgeWeight::ZERO;
    }

    let elapsed_epochs = evaluated_epoch - earned_epoch;
    if elapsed_epochs < CITATION_REWARD_MATURITY_DELAY_EPOCHS {
        return KnowledgeWeight::ZERO;
    }

    let age_epochs = elapsed_epochs - CITATION_REWARD_MATURITY_DELAY_EPOCHS;
    KnowledgeWeightBatch::from_matured_citation_atoms(reward_atoms.atoms())
        .live_weight_at_age(age_epochs)
}

#[cfg(test)]
mod tests;
