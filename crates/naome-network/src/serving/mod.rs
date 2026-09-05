//! Caller-routed store and journal serving.

use crate::*;

pub(crate) mod journal_service;
pub(crate) mod payload_archive_transport;

mod selected_responses;
