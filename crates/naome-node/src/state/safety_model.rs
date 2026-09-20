//! Bounded independent decision-event exploration and canonical journal replay.
//! Four unit-weight validators, each Byzantine placement, three rounds and two
//! valid full-state values. This finite check does not prove public-network safety.
mod model;
#[cfg(unix)]
mod replay;
