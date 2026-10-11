//! Host-shared interest inference. Native checking and admission remain node-owned.
mod client;
mod contract;
pub(crate) mod host;
mod ipc;
mod proxy;

pub(crate) use client::Live;
pub(crate) use proxy::{Session, score, verify_record_decision};

pub(crate) use contract::Owner;

pub(crate) const MOCK_PROVIDER: &str = "naome-deterministic-mocks-v1";
pub(crate) const QWEN_PROVIDER: &str = "naome-qwen3-4b-owner-interest-v1";

pub(crate) fn internal(args: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    client::internal(args).or_else(|| host::internal(args))
}
