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
    History { from: u64, max_records: u16 },
    Proof { proof_id: ProofId },
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
    })
}

fn header(context: StateContext, response: bool, tag: u8, body_length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATE_FRAME_HEADER_BYTES + body_length);
    out.extend_from_slice(&2u16.to_be_bytes());
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
    if header[..2] != 2u16.to_be_bytes() {
        return Err(StateWireError::Version);
    }
    if header[2] != u8::from(response) {
        return Err(StateWireError::Direction);
    }
    if header[3..35] != expected.genesis || header[35..67] != expected.profile {
        return Err(StateWireError::Context);
    }
    let tag = header[67];
    if tag > if response { 6 } else { 7 } {
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
            _ => false,
        }
    } else {
        match tag {
            0 => length == 0,
            1 | 4 => (1..=STATE_MAX_CONTROL_BYTES).contains(&length),
            2 | 3 | 5 => length > 0,
            6 => length == 10,
            7 => length == 32,
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
            StateRequestBody::Handshake => {}
            StateRequestBody::TimeReport(b)
            | StateRequestBody::UserAction(b)
            | StateRequestBody::Proposal(b)
            | StateRequestBody::Vote(b)
            | StateRequestBody::Finalized(b) => out.extend_from_slice(b),
            StateRequestBody::History { from, max_records } => {
                out.extend_from_slice(&from.to_be_bytes());
                out.extend_from_slice(&max_records.to_be_bytes());
            }
            StateRequestBody::Proof { proof_id } => out.extend_from_slice(proof_id.as_bytes()),
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
            (
                StateRequestBody::TimeReport(_)
                | StateRequestBody::UserAction(_)
                | StateRequestBody::Proposal(_)
                | StateRequestBody::Vote(_)
                | StateRequestBody::Finalized(_),
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
