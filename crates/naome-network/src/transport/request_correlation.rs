//! Immutable request identity comparison; owns no permit or cancellation policy.

use libp2p::{PeerId, request_response::OutboundRequestId};
use std::sync::Arc;

#[derive(PartialEq, Eq)]
pub(crate) struct RequestCorrelation<'request, R> {
    request_id: OutboundRequestId,
    peer_id: PeerId,
    request: &'request R,
}

impl<'request, R: PartialEq> RequestCorrelation<'request, R> {
    pub(crate) const fn new(
        request_id: OutboundRequestId,
        peer_id: PeerId,
        request: &'request R,
    ) -> Self {
        Self {
            request_id,
            peer_id,
            request,
        }
    }

    pub(crate) fn matches<O>(self, other: Self, owner: &Arc<O>, other_owner: &Arc<O>) -> bool {
        self == other && Arc::ptr_eq(owner, other_owner)
    }
}
