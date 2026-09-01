//! Explicit lifecycle integration for a NAOME node.
//!
//! The initial fixed-validator V0 boundary composes exact caller configuration,
//! anchored finality, and one anchored per-key vote-safety journal. It owns
//! strict provisioning and restart ordering while deliberately leaving daemon,
//! networking, timeout, key-loading, and branch-selection policy to later
//! components.

mod fixed_validator_startup;

pub use fixed_validator_startup::{
    FixedValidatorNodeDirectoriesV0, FixedValidatorNodeFinalityStoppedV0,
    FixedValidatorNodeProvisionV0, FixedValidatorNodeReadyV0, FixedValidatorNodeSignerStopV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeStartupErrorV0,
    FixedValidatorNodeStartupV0, FixedValidatorSignerCatchUpHeightLimitV0,
};
