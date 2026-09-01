//! Explicit lifecycle integration for a NAOME node.
//!
//! The fixed-validator V0 boundary composes exact caller configuration,
//! anchored finality, and one anchored per-key vote-safety journal. It owns
//! strict provisioning, restart ordering, and consuming sealed or
//! candidate-backed finality-to-signer coupling while deliberately leaving
//! daemon, networking, timeout, key-loading, and branch-selection policy to
//! later components.

mod fixed_validator_startup;

pub use fixed_validator_startup::{
    FixedValidatorNodeDirectoriesV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalitySelectionV0,
    FixedValidatorNodeFinalityStoppedV0, FixedValidatorNodeProvisionV0, FixedValidatorNodeReadyV0,
    FixedValidatorNodeSignerStopV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeStartupErrorV0, FixedValidatorNodeStartupV0,
    FixedValidatorNodeVotingSessionV0, FixedValidatorSignerCatchUpHeightLimitV0,
};
