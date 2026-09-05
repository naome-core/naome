//! Bounded, caller-configured fixed-validator V0 event-loop integration.
//!
//! The runtime composes the existing sole-scope driver and authenticated direct
//! delivery. Consensus verification, signing, and finality remain in the driver.
//! Its explicit local timing and routing policy does not establish production
//! timing, general gossip, durable delivery, or distributed liveness.

mod owner;
mod publication;
mod routing;
mod timer;
mod types;

pub use owner::FixedValidatorRuntimeV0;
pub use owner::artifact_exchange::{
    FixedValidatorRuntimeAcquisitionRefusalV0, FixedValidatorRuntimeAcquisitionStartErrorV0,
    FixedValidatorRuntimeAncestryFillAdvanceErrorV0,
    FixedValidatorRuntimePayloadFillAdvanceErrorV0,
};
pub use publication::{
    FixedValidatorRuntimeDeliveryStateV0, FixedValidatorRuntimePeerDeliveryV0,
    FixedValidatorRuntimePublicationMessageV0, FixedValidatorRuntimePublicationV0,
};
pub use routing::{
    FixedValidatorRuntimeAdmissionReportV0, FixedValidatorRuntimeAdmissionResultV0,
    FixedValidatorRuntimeInputSourceV0, FixedValidatorRuntimeRouteV0,
    FixedValidatorRuntimeRoutingErrorV0,
};

pub use timer::{
    FixedValidatorPhaseDurationV0, FixedValidatorRuntimeTimeoutsV0, FixedValidatorRuntimeTimerV0,
    FixedValidatorRuntimeTimingErrorV0,
};
pub use types::{
    FixedValidatorRuntimeCreateErrorV0, FixedValidatorRuntimeCreateFailureV0,
    FixedValidatorRuntimeEventV0, FixedValidatorRuntimeFailureV0, FixedValidatorRuntimePartsV0,
    FixedValidatorRuntimeProofRefusalV0, FixedValidatorRuntimeQueueErrorV0,
    FixedValidatorRuntimeQueueFailureV0, FixedValidatorRuntimeTransportPollV0,
};
