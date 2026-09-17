//! Strict, bounded research transport envelopes. Payloads remain untrusted.
//!
//! A decoded proposal or finalized-history item still needs its complete domain,
//! signature, mathematical, state-transition, and finality verification.

use naome_proof::ProofId;
use std::{error::Error, fmt, sync::Arc};

pub const RESEARCH_MAX_FRAME_BYTES: usize = 1024 * 1024 + 64 * 1024;
pub const RESEARCH_FRAME_HEADER_BYTES: usize = 72;
pub const RESEARCH_MAX_HISTORY_RECORDS: usize = 16;
pub const RESEARCH_MAX_CONTROL_BYTES: usize = 4096;
pub const RESEARCH_MAX_PROOF_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResearchContext {
    genesis: [u8; 32],
    profile: [u8; 32],
}
impl ResearchContext {
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
pub enum ResearchRequestBody {
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
pub struct ResearchHistoryItem {
    pub height: u64,
    pub evidence: Arc<[u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchRejection {
    Invalid,
    Unauthorized,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResearchResponseBody {
    Ready,
    Accepted,
    Busy,
    Rejected(ResearchRejection),
    History(Vec<ResearchHistoryItem>),
    Proof {
        proof_id: ProofId,
        certificate: Arc<[u8]>,
    },
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchRequest {
    context: ResearchContext,
    body: ResearchRequestBody,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchResponse {
    context: ResearchContext,
    request_digest: [u8; 32],
    body: ResearchResponseBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchWireError {
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
impl fmt::Display for ResearchWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid research exchange: {self:?}")
    }
}
impl Error for ResearchWireError {}

fn frame_limit(length: usize, maximum: usize) -> Result<(), ResearchWireError> {
    if !(RESEARCH_FRAME_HEADER_BYTES..=RESEARCH_MAX_FRAME_BYTES).contains(&maximum)
        || length > maximum
    {
        return Err(ResearchWireError::Limit);
    }
    Ok(())
}
fn payload(bytes: &[u8], maximum: usize) -> Result<usize, ResearchWireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(ResearchWireError::Limit)
    } else {
        Ok(bytes.len())
    }
}
fn request_shape(body: &ResearchRequestBody) -> Result<(u8, usize), ResearchWireError> {
    Ok(match body {
        ResearchRequestBody::Handshake => (0, 0),
        ResearchRequestBody::TimeReport(bytes) => (1, payload(bytes, RESEARCH_MAX_CONTROL_BYTES)?),
        ResearchRequestBody::UserAction(bytes) => (2, payload(bytes, RESEARCH_MAX_FRAME_BYTES)?),
        ResearchRequestBody::Proposal(bytes) => (3, payload(bytes, RESEARCH_MAX_FRAME_BYTES)?),
        ResearchRequestBody::Vote(bytes) => (4, payload(bytes, RESEARCH_MAX_CONTROL_BYTES)?),
        ResearchRequestBody::Finalized(bytes) => (5, payload(bytes, RESEARCH_MAX_FRAME_BYTES)?),
        ResearchRequestBody::History { from, max_records } => {
            if *from == 0
                || *max_records == 0
                || usize::from(*max_records) > RESEARCH_MAX_HISTORY_RECORDS
                || from.checked_add(u64::from(*max_records) - 1).is_none()
            {
                return Err(ResearchWireError::Range);
            }
            (6, 10)
        }
        ResearchRequestBody::Proof { .. } => (7, 32),
    })
}
fn response_shape(body: &ResearchResponseBody) -> Result<(u8, usize), ResearchWireError> {
    Ok(match body {
        ResearchResponseBody::Ready => (0, 0),
        ResearchResponseBody::Accepted => (1, 0),
        ResearchResponseBody::Busy => (2, 0),
        ResearchResponseBody::Rejected(_) => (3, 1),
        ResearchResponseBody::History(items) => {
            if items.len() > RESEARCH_MAX_HISTORY_RECORDS {
                return Err(ResearchWireError::Limit);
            }
            let mut length = 2usize;
            let mut previous = None;
            for item in items {
                if item.height == 0
                    || previous
                        .is_some_and(|height: u64| height.checked_add(1) != Some(item.height))
                {
                    return Err(ResearchWireError::Order);
                }
                previous = Some(item.height);
                length = length
                    .checked_add(12 + payload(&item.evidence, RESEARCH_MAX_FRAME_BYTES)?)
                    .ok_or(ResearchWireError::Limit)?;
            }
            (4, length)
        }
        ResearchResponseBody::Proof { certificate, .. } => {
            (5, 32 + payload(certificate, RESEARCH_MAX_PROOF_BYTES)?)
        }
        ResearchResponseBody::Unavailable => (6, 0),
    })
}

fn header(context: ResearchContext, response: bool, tag: u8, body_length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESEARCH_FRAME_HEADER_BYTES + body_length);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(u8::from(response));
    out.extend_from_slice(&context.genesis);
    out.extend_from_slice(&context.profile);
    out.push(tag);
    out.extend_from_slice(&(body_length as u32).to_be_bytes());
    out
}

/// Validates fixed fields and the total declared length before a body allocation.
pub fn research_frame_length(
    header: &[u8],
    response: bool,
    expected: ResearchContext,
    maximum: usize,
) -> Result<usize, ResearchWireError> {
    if header.len() != RESEARCH_FRAME_HEADER_BYTES {
        return Err(ResearchWireError::Length);
    }
    if header[..2] != 1u16.to_be_bytes() {
        return Err(ResearchWireError::Version);
    }
    if header[2] != u8::from(response) {
        return Err(ResearchWireError::Direction);
    }
    if header[3..35] != expected.genesis || header[35..67] != expected.profile {
        return Err(ResearchWireError::Context);
    }
    let tag = header[67];
    if tag > if response { 6 } else { 7 } {
        return Err(ResearchWireError::Tag);
    }
    let body = u32::from_be_bytes(header[68..72].try_into().expect("fixed length")) as usize;
    let total = RESEARCH_FRAME_HEADER_BYTES
        .checked_add(body)
        .ok_or(ResearchWireError::Limit)?;
    frame_limit(total, maximum)?;
    let length = if response {
        body.checked_sub(32).ok_or(ResearchWireError::Length)?
    } else {
        body
    };
    let valid = if response {
        match tag {
            0..=2 | 6 => length == 0,
            3 => length == 1,
            4 => length >= 2,
            5 => (33..=32 + RESEARCH_MAX_PROOF_BYTES).contains(&length),
            _ => false,
        }
    } else {
        match tag {
            0 => length == 0,
            1 | 4 => (1..=RESEARCH_MAX_CONTROL_BYTES).contains(&length),
            2 | 3 | 5 => length > 0,
            6 => length == 10,
            7 => length == 32,
            _ => false,
        }
    };
    if !valid {
        return Err(ResearchWireError::Length);
    }
    Ok(total)
}

impl ResearchRequest {
    pub fn new(
        context: ResearchContext,
        body: ResearchRequestBody,
        maximum: usize,
    ) -> Result<Self, ResearchWireError> {
        let (_, length) = request_shape(&body)?;
        frame_limit(RESEARCH_FRAME_HEADER_BYTES + length, maximum)?;
        Ok(Self { context, body })
    }
    pub const fn context(&self) -> ResearchContext {
        self.context
    }
    pub fn body(&self) -> &ResearchRequestBody {
        &self.body
    }
    pub fn wire_len(&self) -> usize {
        RESEARCH_FRAME_HEADER_BYTES + request_shape(&self.body).expect("validated request").1
    }
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let (tag, length) = request_shape(&self.body).expect("validated request");
        let mut out = header(self.context, false, tag, length);
        match &self.body {
            ResearchRequestBody::Handshake => {}
            ResearchRequestBody::TimeReport(b)
            | ResearchRequestBody::UserAction(b)
            | ResearchRequestBody::Proposal(b)
            | ResearchRequestBody::Vote(b)
            | ResearchRequestBody::Finalized(b) => out.extend_from_slice(b),
            ResearchRequestBody::History { from, max_records } => {
                out.extend_from_slice(&from.to_be_bytes());
                out.extend_from_slice(&max_records.to_be_bytes());
            }
            ResearchRequestBody::Proof { proof_id } => out.extend_from_slice(proof_id.as_bytes()),
        }
        out
    }
    pub fn from_wire_bytes(
        bytes: &[u8],
        expected: ResearchContext,
        maximum: usize,
    ) -> Result<Self, ResearchWireError> {
        let prefix = bytes
            .get(..RESEARCH_FRAME_HEADER_BYTES)
            .ok_or(ResearchWireError::Length)?;
        if research_frame_length(prefix, false, expected, maximum)? != bytes.len() {
            return Err(ResearchWireError::Length);
        }
        let b = &bytes[RESEARCH_FRAME_HEADER_BYTES..];
        let body = match prefix[67] {
            0 => ResearchRequestBody::Handshake,
            1 => ResearchRequestBody::TimeReport(b.into()),
            2 => ResearchRequestBody::UserAction(b.into()),
            3 => ResearchRequestBody::Proposal(b.into()),
            4 => ResearchRequestBody::Vote(b.into()),
            5 => ResearchRequestBody::Finalized(b.into()),
            6 => ResearchRequestBody::History {
                from: u64::from_be_bytes(b[..8].try_into().expect("checked range width")),
                max_records: u16::from_be_bytes(b[8..].try_into().expect("checked count width")),
            },
            7 => ResearchRequestBody::Proof {
                proof_id: ProofId::from_bytes(b.try_into().expect("checked proof ID width")),
            },
            _ => return Err(ResearchWireError::Tag),
        };
        Self::new(expected, body, maximum)
    }
}

impl ResearchResponse {
    pub fn new(
        context: ResearchContext,
        request_digest: [u8; 32],
        body: ResearchResponseBody,
        maximum: usize,
    ) -> Result<Self, ResearchWireError> {
        let (_, length) = response_shape(&body)?;
        frame_limit(RESEARCH_FRAME_HEADER_BYTES + 32 + length, maximum)?;
        Ok(Self {
            context,
            request_digest,
            body,
        })
    }
    pub const fn context(&self) -> ResearchContext {
        self.context
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub fn body(&self) -> &ResearchResponseBody {
        &self.body
    }
    pub fn wire_len(&self) -> usize {
        RESEARCH_FRAME_HEADER_BYTES + 32 + response_shape(&self.body).expect("validated response").1
    }
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let (tag, length) = response_shape(&self.body).expect("validated response");
        let mut out = header(self.context, true, tag, 32 + length);
        out.extend_from_slice(&self.request_digest);
        match &self.body {
            ResearchResponseBody::Rejected(reason) => out.push(match reason {
                ResearchRejection::Invalid => 0,
                ResearchRejection::Unauthorized => 1,
                ResearchRejection::Unsupported => 2,
            }),
            ResearchResponseBody::History(items) => {
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
                for item in items {
                    out.extend_from_slice(&item.height.to_be_bytes());
                    out.extend_from_slice(&(item.evidence.len() as u32).to_be_bytes());
                    out.extend_from_slice(&item.evidence);
                }
            }
            ResearchResponseBody::Proof {
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
        expected: ResearchContext,
        maximum: usize,
    ) -> Result<Self, ResearchWireError> {
        let prefix = bytes
            .get(..RESEARCH_FRAME_HEADER_BYTES)
            .ok_or(ResearchWireError::Length)?;
        if research_frame_length(prefix, true, expected, maximum)? != bytes.len() {
            return Err(ResearchWireError::Length);
        }
        let mut r = Cursor(&bytes[RESEARCH_FRAME_HEADER_BYTES..]);
        let request_digest = r.take(32)?.try_into().expect("digest width");
        let body = match prefix[67] {
            0 => ResearchResponseBody::Ready,
            1 => ResearchResponseBody::Accepted,
            2 => ResearchResponseBody::Busy,
            3 => ResearchResponseBody::Rejected(match r.take(1)?[0] {
                0 => ResearchRejection::Invalid,
                1 => ResearchRejection::Unauthorized,
                2 => ResearchRejection::Unsupported,
                _ => return Err(ResearchWireError::Tag),
            }),
            4 => {
                let count =
                    u16::from_be_bytes(r.take(2)?.try_into().expect("count width")) as usize;
                if count > RESEARCH_MAX_HISTORY_RECORDS {
                    return Err(ResearchWireError::Limit);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let height = u64::from_be_bytes(r.take(8)?.try_into().expect("height width"));
                    let length =
                        u32::from_be_bytes(r.take(4)?.try_into().expect("length width")) as usize;
                    items.push(ResearchHistoryItem {
                        height,
                        evidence: r.take(length)?.into(),
                    });
                }
                ResearchResponseBody::History(items)
            }
            5 => {
                let proof_id = ProofId::from_bytes(r.take(32)?.try_into().expect("proof ID width"));
                let certificate = r.take(r.0.len())?.into();
                ResearchResponseBody::Proof {
                    proof_id,
                    certificate,
                }
            }
            6 => ResearchResponseBody::Unavailable,
            _ => return Err(ResearchWireError::Tag),
        };
        if !r.0.is_empty() {
            return Err(ResearchWireError::Length);
        }
        Self::new(expected, request_digest, body, maximum)
    }
    /// Correlates response kind and addressed data; it does not verify payloads.
    /// Transport separately compares `request_digest` with the exact request bytes.
    pub fn matches_request(&self, request: &ResearchRequest) -> bool {
        if self.context != request.context {
            return false;
        }
        match (&request.body, &self.body) {
            (_, ResearchResponseBody::Busy | ResearchResponseBody::Rejected(_)) => true,
            (ResearchRequestBody::Handshake, ResearchResponseBody::Ready) => true,
            (
                ResearchRequestBody::TimeReport(_)
                | ResearchRequestBody::UserAction(_)
                | ResearchRequestBody::Proposal(_)
                | ResearchRequestBody::Vote(_)
                | ResearchRequestBody::Finalized(_),
                ResearchResponseBody::Accepted,
            ) => true,
            (
                ResearchRequestBody::History { from, max_records },
                ResearchResponseBody::History(items),
            ) => {
                items.len() <= usize::from(*max_records)
                    && items.first().is_none_or(|item| item.height == *from)
            }
            (
                ResearchRequestBody::Proof {
                    proof_id: requested,
                },
                ResearchResponseBody::Proof { proof_id, .. },
            ) => requested == proof_id,
            (
                ResearchRequestBody::History { .. } | ResearchRequestBody::Proof { .. },
                ResearchResponseBody::Unavailable,
            ) => true,
            _ => false,
        }
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ResearchWireError> {
        let value = self.0.get(..length).ok_or(ResearchWireError::Length)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
