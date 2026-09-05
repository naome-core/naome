//! Untrusted peer-record admission, persistence, and bootstrap routing.

pub(crate) mod address_store;
pub(crate) mod bootstrap;
pub(crate) mod learned_pull;
pub(crate) mod local_issuer;
pub(crate) mod record_exchange;
pub(crate) mod responder;
pub(crate) mod snapshot_io;
