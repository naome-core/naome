//! Strict, bounded state transport envelopes. Payloads remain untrusted.
//!
//! A decoded proposal or finalized-history item still needs its complete domain,
//! signature, mathematical, state-transition, and finality verification.

use naome_proof::ProofId;
use std::{error::Error, fmt, sync::Arc};

pub const STATE_MAX_FRAME_BYTES: usize = 1024 * 1024 + 64 * 1024;
pub const STATE_FRAME_HEADER_BYTES: usize = 72;
pub const STATE_MAX_HISTORY_RECORDS: usize = 16;
pub const STATE_MAX_CONTROL_BYTES: usize = 4096;
pub const STATE_RECOVERY_HELLO_BYTES: usize = 224;
pub const STATE_MAX_PROOF_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateContext {
    genesis: [u8; 32],
    profile: [u8; 32],
}
impl StateContext {
    pub const fn new(genesis: [u8; 32], profile: [u8; 32]) -> Self {
        Self { genesis, profile }
    }
    pub const fn genesis(&self) -> &[u8; 32] {
        &self.genesis
    }
    pub const fn profile(&self) -> &[u8; 32] {
        &self.profile
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateRequestBody {
    Handshake,
    TimeReport(Arc<[u8]>),
    UserAction(Arc<[u8]>),
    Proposal(Arc<[u8]>),
    Vote(Arc<[u8]>),
    Finalized(Arc<[u8]>),
    History {
        from: u64,
        max_records: u16,
    },
    Proof {
        proof_id: ProofId,
    },
    /// Parent-bound fresh keys from a current unit; payload authority is checked by the node.
    Offer(Arc<[u8]>),
    /// Claim-holder preparation for one selected successor.
    CandidateOffer(Arc<[u8]>),
    /// Outgoing agreement evidence for the exact successor under preparation.
    Agreement(Arc<[u8]>),
    /// Incoming preparation certificate or signature.
    ReadySignature(Arc<[u8]>),
    /// Saved outgoing terminal signature or certificate.
    TerminalSignature(Arc<[u8]>),
    /// Requests an unpredictable, recipient-issued nonce for recovery admission.
    RecoveryChallenge,
    /// Owner and fresh-transport possession proofs bound to the issued nonce.
    RecoveryHello(Arc<[u8]>),
    /// Fetches unsealed agreement evidence; the recipient must verify it against its parent.
    PendingAgreement {
        height: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateHistoryItem {
    pub height: u64,
    pub evidence: Arc<[u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRejection {
    Invalid,
    Unauthorized,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateResponseBody {
    Ready,
    Accepted,
    Busy,
    Rejected(StateRejection),
    History(Vec<StateHistoryItem>),
    Proof {
        proof_id: ProofId,
        certificate: Arc<[u8]>,
    },
    Unavailable,
    RecoveryNonce([u8; 32]),
    Agreement(Option<Arc<[u8]>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRequest {
    context: StateContext,
    body: StateRequestBody,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateResponse {
    context: StateContext,
    request_digest: [u8; 32],
    body: StateResponseBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateWireError {
    Length,
    Limit,
    Version,
    Direction,
    Context,
    Tag,
    Range,
    Order,
    ResponseKind,
}
impl fmt::Display for StateWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid research exchange: {self:?}")
    }
}
impl Error for StateWireError {}

fn frame_limit(length: usize, maximum: usize) -> Result<(), StateWireError> {
    if !(STATE_FRAME_HEADER_BYTES..=STATE_MAX_FRAME_BYTES).contains(&maximum) || length > maximum {
        return Err(StateWireError::Limit);
    }
    Ok(())
}
fn payload(bytes: &[u8], maximum: usize) -> Result<usize, StateWireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(StateWireError::Limit)
    } else {
        Ok(bytes.len())
    }
}
fn request_shape(body: &StateRequestBody) -> Result<(u8, usize), StateWireError> {
    Ok(match body {
        StateRequestBody::Handshake => (0, 0),
        StateRequestBody::TimeReport(bytes) => (1, payload(bytes, STATE_MAX_CONTROL_BYTES)?),
        StateRequestBody::UserAction(bytes) => (2, payload(bytes, STATE_MAX_FRAME_BYTES)?),
        StateRequestBody::Proposal(bytes) => (3, payload(bytes, STATE_MAX_FRAME_BYTES)?),
        StateRequestBody::Vote(bytes) => (4, payload(bytes, STATE_MAX_CONTROL_BYTES)?),
        StateRequestBody::Finalized(bytes) => (5, payload(bytes, STATE_MAX_FRAME_BYTES)?),
        StateRequestBody::History { from, max_records } => {
            if *from == 0
                || *max_records == 0
                || usize::from(*max_records) > STATE_MAX_HISTORY_RECORDS
                || from.checked_add(u64::from(*max_records) - 1).is_none()
            {
                return Err(StateWireError::Range);
            }
            (6, 10)
        }
        StateRequestBody::Proof { .. } => (7, 32),
        StateRequestBody::Offer(bytes) => (8, payload(bytes, STATE_MAX_CONTROL_BYTES)?),
        StateRequestBody::CandidateOffer(bytes) => (9, payload(bytes, STATE_MAX_CONTROL_BYTES)?),
        StateRequestBody::Agreement(bytes) => (10, payload(bytes, STATE_MAX_FRAME_BYTES)?),
        StateRequestBody::ReadySignature(bytes) => (11, payload(bytes, STATE_MAX_CONTROL_BYTES)?),
        StateRequestBody::TerminalSignature(bytes) => {
            (12, payload(bytes, STATE_MAX_CONTROL_BYTES)?)
        }
        StateRequestBody::RecoveryChallenge => (13, 0),
        StateRequestBody::RecoveryHello(bytes) => {
            if bytes.len() != STATE_RECOVERY_HELLO_BYTES {
                return Err(StateWireError::Length);
            }
            (14, bytes.len())
        }
        StateRequestBody::PendingAgreement { height } => {
            if *height == 0 {
                return Err(StateWireError::Range);
            }
            (15, 8)
        }
    })
}
fn response_shape(body: &StateResponseBody) -> Result<(u8, usize), StateWireError> {
    Ok(match body {
        StateResponseBody::Ready => (0, 0),
        StateResponseBody::Accepted => (1, 0),
        StateResponseBody::Busy => (2, 0),
        StateResponseBody::Rejected(_) => (3, 1),
        StateResponseBody::History(items) => {
            if items.len() > STATE_MAX_HISTORY_RECORDS {
                return Err(StateWireError::Limit);
            }
            let mut length = 2usize;
            let mut previous = None;
            for item in items {
                if item.height == 0
                    || previous
                        .is_some_and(|height: u64| height.checked_add(1) != Some(item.height))
                {
                    return Err(StateWireError::Order);
                }
                previous = Some(item.height);
                length = length
                    .checked_add(12 + payload(&item.evidence, STATE_MAX_FRAME_BYTES)?)
                    .ok_or(StateWireError::Limit)?;
            }
            (4, length)
        }
        StateResponseBody::Proof { certificate, .. } => {
            (5, 32 + payload(certificate, STATE_MAX_PROOF_BYTES)?)
        }
        StateResponseBody::Unavailable => (6, 0),
        StateResponseBody::RecoveryNonce(_) => (7, 32),
        StateResponseBody::Agreement(bytes) => (
            8,
            1 + bytes
                .as_ref()
                .map_or(Ok(0), |bytes| payload(bytes, STATE_MAX_FRAME_BYTES))?,
        ),
    })
}

fn header(context: StateContext, response: bool, tag: u8, body_length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATE_FRAME_HEADER_BYTES + body_length);
    out.extend_from_slice(&3u16.to_be_bytes());
    out.push(u8::from(response));
    out.extend_from_slice(&context.genesis);
    out.extend_from_slice(&context.profile);
    out.push(tag);
    out.extend_from_slice(&(body_length as u32).to_be_bytes());
    out
}

/// Validates fixed fields and the total declared length before a body allocation.
pub fn state_frame_length(
    header: &[u8],
    response: bool,
    expected: StateContext,
    maximum: usize,
) -> Result<usize, StateWireError> {
    if header.len() != STATE_FRAME_HEADER_BYTES {
        return Err(StateWireError::Length);
    }
    if header[..2] != 3u16.to_be_bytes() {
        return Err(StateWireError::Version);
    }
    if header[2] != u8::from(response) {
        return Err(StateWireError::Direction);
    }
    if header[3..35] != expected.genesis || header[35..67] != expected.profile {
        return Err(StateWireError::Context);
    }
    let tag = header[67];
    if tag > if response { 8 } else { 15 } {
        return Err(StateWireError::Tag);
    }
    let body = u32::from_be_bytes(header[68..72].try_into().expect("fixed length")) as usize;
    let total = STATE_FRAME_HEADER_BYTES
        .checked_add(body)
        .ok_or(StateWireError::Limit)?;
    frame_limit(total, maximum)?;
    let length = if response {
        body.checked_sub(32).ok_or(StateWireError::Length)?
    } else {
        body
    };
    let valid = if response {
        match tag {
            0..=2 | 6 => length == 0,
            3 => length == 1,
            4 => length >= 2,
            5 => (33..=32 + STATE_MAX_PROOF_BYTES).contains(&length),
            7 => length == 32,
            8 => length >= 1,
            _ => false,
        }
    } else {
        match tag {
            0 => length == 0,
            1 | 4 => (1..=STATE_MAX_CONTROL_BYTES).contains(&length),
            2 | 3 | 5 => length > 0,
            6 => length == 10,
            7 => length == 32,
            8 | 9 | 11 | 12 => (1..=STATE_MAX_CONTROL_BYTES).contains(&length),
            10 => length > 0,
            13 => length == 0,
            14 => length == STATE_RECOVERY_HELLO_BYTES,
            15 => length == 8,
            _ => false,
        }
    };
    if !valid {
        return Err(StateWireError::Length);
    }
    Ok(total)
}

impl StateRequest {
    pub fn new(
        context: StateContext,
        body: StateRequestBody,
        maximum: usize,
    ) -> Result<Self, StateWireError> {
        let (_, length) = request_shape(&body)?;
        frame_limit(STATE_FRAME_HEADER_BYTES + length, maximum)?;
        Ok(Self { context, body })
    }
    pub const fn context(&self) -> StateContext {
        self.context
    }
    pub fn body(&self) -> &StateRequestBody {
        &self.body
    }
    pub fn wire_len(&self) -> usize {
        STATE_FRAME_HEADER_BYTES + request_shape(&self.body).expect("validated request").1
    }
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let (tag, length) = request_shape(&self.body).expect("validated request");
        let mut out = header(self.context, false, tag, length);
        match &self.body {
            StateRequestBody::Handshake | StateRequestBody::RecoveryChallenge => {}
            StateRequestBody::TimeReport(b)
            | StateRequestBody::UserAction(b)
            | StateRequestBody::Proposal(b)
            | StateRequestBody::Vote(b)
            | StateRequestBody::Finalized(b)
            | StateRequestBody::Offer(b)
            | StateRequestBody::CandidateOffer(b)
            | StateRequestBody::Agreement(b)
            | StateRequestBody::ReadySignature(b)
            | StateRequestBody::TerminalSignature(b)
            | StateRequestBody::RecoveryHello(b) => out.extend_from_slice(b),
            StateRequestBody::History { from, max_records } => {
                out.extend_from_slice(&from.to_be_bytes());
                out.extend_from_slice(&max_records.to_be_bytes());
            }
            StateRequestBody::Proof { proof_id } => out.extend_from_slice(proof_id.as_bytes()),
            StateRequestBody::PendingAgreement { height } => {
                out.extend_from_slice(&height.to_be_bytes())
            }
        }
        out
    }
    pub fn from_wire_bytes(
        bytes: &[u8],
        expected: StateContext,
        maximum: usize,
    ) -> Result<Self, StateWireError> {
        let prefix = bytes
            .get(..STATE_FRAME_HEADER_BYTES)
            .ok_or(StateWireError::Length)?;
        if state_frame_length(prefix, false, expected, maximum)? != bytes.len() {
            return Err(StateWireError::Length);
        }
        let b = &bytes[STATE_FRAME_HEADER_BYTES..];
        let body = match prefix[67] {
            0 => StateRequestBody::Handshake,
            1 => StateRequestBody::TimeReport(b.into()),
            2 => StateRequestBody::UserAction(b.into()),
            3 => StateRequestBody::Proposal(b.into()),
            4 => StateRequestBody::Vote(b.into()),
            5 => StateRequestBody::Finalized(b.into()),
            6 => StateRequestBody::History {
                from: u64::from_be_bytes(b[..8].try_into().expect("checked range width")),
                max_records: u16::from_be_bytes(b[8..].try_into().expect("checked count width")),
            },
            7 => StateRequestBody::Proof {
                proof_id: ProofId::from_bytes(b.try_into().expect("checked proof ID width")),
            },
            8 => StateRequestBody::Offer(b.into()),
            9 => StateRequestBody::CandidateOffer(b.into()),
            10 => StateRequestBody::Agreement(b.into()),
            11 => StateRequestBody::ReadySignature(b.into()),
            12 => StateRequestBody::TerminalSignature(b.into()),
            13 => StateRequestBody::RecoveryChallenge,
            14 => StateRequestBody::RecoveryHello(b.into()),
            15 => StateRequestBody::PendingAgreement {
                height: u64::from_be_bytes(b.try_into().expect("checked height width")),
            },
            _ => return Err(StateWireError::Tag),
        };
        Self::new(expected, body, maximum)
    }
}

impl StateResponse {
    pub fn new(
        context: StateContext,
        request_digest: [u8; 32],
        body: StateResponseBody,
        maximum: usize,
    ) -> Result<Self, StateWireError> {
        let (_, length) = response_shape(&body)?;
        frame_limit(STATE_FRAME_HEADER_BYTES + 32 + length, maximum)?;
        Ok(Self {
            context,
            request_digest,
            body,
        })
    }
    pub const fn context(&self) -> StateContext {
        self.context
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub fn body(&self) -> &StateResponseBody {
        &self.body
    }
    pub fn wire_len(&self) -> usize {
        STATE_FRAME_HEADER_BYTES + 32 + response_shape(&self.body).expect("validated response").1
    }
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let (tag, length) = response_shape(&self.body).expect("validated response");
        let mut out = header(self.context, true, tag, 32 + length);
        out.extend_from_slice(&self.request_digest);
        match &self.body {
            StateResponseBody::Rejected(reason) => out.push(match reason {
                StateRejection::Invalid => 0,
                StateRejection::Unauthorized => 1,
                StateRejection::Unsupported => 2,
            }),
            StateResponseBody::History(items) => {
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
                for item in items {
                    out.extend_from_slice(&item.height.to_be_bytes());
                    out.extend_from_slice(&(item.evidence.len() as u32).to_be_bytes());
                    out.extend_from_slice(&item.evidence);
                }
            }
            StateResponseBody::Proof {
                proof_id,
                certificate,
            } => {
                out.extend_from_slice(proof_id.as_bytes());
                out.extend_from_slice(certificate);
            }
            StateResponseBody::RecoveryNonce(nonce) => out.extend_from_slice(nonce),
            StateResponseBody::Agreement(bytes) => {
                out.push(u8::from(bytes.is_some()));
                if let Some(bytes) = bytes {
                    out.extend_from_slice(bytes);
                }
            }
            _ => {}
        }
        out
    }
    pub fn from_wire_bytes(
        bytes: &[u8],
        expected: StateContext,
        maximum: usize,
    ) -> Result<Self, StateWireError> {
        let prefix = bytes
            .get(..STATE_FRAME_HEADER_BYTES)
            .ok_or(StateWireError::Length)?;
        if state_frame_length(prefix, true, expected, maximum)? != bytes.len() {
            return Err(StateWireError::Length);
        }
        let mut r = Cursor(&bytes[STATE_FRAME_HEADER_BYTES..]);
        let request_digest = r.take(32)?.try_into().expect("digest width");
        let body = match prefix[67] {
            0 => StateResponseBody::Ready,
            1 => StateResponseBody::Accepted,
            2 => StateResponseBody::Busy,
            3 => StateResponseBody::Rejected(match r.take(1)?[0] {
                0 => StateRejection::Invalid,
                1 => StateRejection::Unauthorized,
                2 => StateRejection::Unsupported,
                _ => return Err(StateWireError::Tag),
            }),
            4 => {
                let count =
                    u16::from_be_bytes(r.take(2)?.try_into().expect("count width")) as usize;
                if count > STATE_MAX_HISTORY_RECORDS {
                    return Err(StateWireError::Limit);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let height = u64::from_be_bytes(r.take(8)?.try_into().expect("height width"));
                    let length =
                        u32::from_be_bytes(r.take(4)?.try_into().expect("length width")) as usize;
                    items.push(StateHistoryItem {
                        height,
                        evidence: r.take(length)?.into(),
                    });
                }
                StateResponseBody::History(items)
            }
            5 => {
                let proof_id = ProofId::from_bytes(r.take(32)?.try_into().expect("proof ID width"));
                let certificate = r.take(r.0.len())?.into();
                StateResponseBody::Proof {
                    proof_id,
                    certificate,
                }
            }
            6 => StateResponseBody::Unavailable,
            7 => StateResponseBody::RecoveryNonce(r.take(32)?.try_into().expect("nonce width")),
            8 => StateResponseBody::Agreement(match r.take(1)?[0] {
                0 => None,
                1 => Some(r.take(r.0.len())?.into()),
                _ => return Err(StateWireError::Tag),
            }),
            _ => return Err(StateWireError::Tag),
        };
        if !r.0.is_empty() {
            return Err(StateWireError::Length);
        }
        Self::new(expected, request_digest, body, maximum)
    }
    /// Correlates response kind and addressed data; it does not verify payloads.
    /// Transport separately compares `request_digest` with the exact request bytes.
    pub fn matches_request(&self, request: &StateRequest) -> bool {
        if self.context != request.context {
            return false;
        }
        match (&request.body, &self.body) {
            (_, StateResponseBody::Busy | StateResponseBody::Rejected(_)) => true,
            (StateRequestBody::Handshake, StateResponseBody::Ready) => true,
            (StateRequestBody::RecoveryChallenge, StateResponseBody::RecoveryNonce(_)) => true,
            (StateRequestBody::PendingAgreement { .. }, StateResponseBody::Agreement(_)) => true,
            (
                StateRequestBody::TimeReport(_)
                | StateRequestBody::UserAction(_)
                | StateRequestBody::Proposal(_)
                | StateRequestBody::Vote(_)
                | StateRequestBody::Finalized(_)
                | StateRequestBody::Offer(_)
                | StateRequestBody::CandidateOffer(_)
                | StateRequestBody::Agreement(_)
                | StateRequestBody::ReadySignature(_)
                | StateRequestBody::TerminalSignature(_)
                | StateRequestBody::RecoveryHello(_),
                StateResponseBody::Accepted,
            ) => true,
            (
                StateRequestBody::History { from, max_records },
                StateResponseBody::History(items),
            ) => {
                items.len() <= usize::from(*max_records)
                    && items.first().is_none_or(|item| item.height == *from)
            }
            (
                StateRequestBody::Proof {
                    proof_id: requested,
                },
                StateResponseBody::Proof { proof_id, .. },
            ) => requested == proof_id,
            (
                StateRequestBody::History { .. } | StateRequestBody::Proof { .. },
                StateResponseBody::Unavailable,
            ) => true,
            _ => false,
        }
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], StateWireError> {
        let value = self.0.get(..length).ok_or(StateWireError::Length)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
