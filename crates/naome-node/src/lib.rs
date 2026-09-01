//! Explicit lifecycle integration for a NAOME node.
//!
//! The fixed-validator V0 boundary composes exact caller configuration,
//! anchored finality, and one anchored per-key vote-safety journal. It owns
//! strict provisioning, restart ordering, and consuming sealed or
//! candidate-backed finality-to-signer coupling plus bounded current-round
//! vote execution and quorum-driven round progression while deliberately
//! leaving daemon, networking, timeout, key-loading, event selection, and
//! branch-selection policy to later components.

mod fixed_validator_startup;

pub use fixed_validator_startup::{
    FixedValidatorNodeDirectoriesV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalitySelectionV0,
    FixedValidatorNodeFinalityStoppedV0, FixedValidatorNodeProvisionV0, FixedValidatorNodeReadyV0,
    FixedValidatorNodeRoundAdvanceErrorV0, FixedValidatorNodeRoundAdvanceOutcomeV0,
    FixedValidatorNodeRoundAdvanceRejectionV0, FixedValidatorNodeSignerStopV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeStartupErrorV0,
    FixedValidatorNodeStartupV0, FixedValidatorNodeVoteExecutionErrorV0,
    FixedValidatorNodeVoteExecutionOutcomeV0, FixedValidatorNodeVoteRejectionV0,
    FixedValidatorNodeVotingSessionV0, FixedValidatorSignerCatchUpHeightLimitV0,
};
