use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;

use libp2p::PeerId;

use crate::address_store::{
    MAX_RECORDS_PER_BOOTSTRAP, MAX_SIGNED_PEER_RECORD_BYTES, SignedPeerRecord,
    SignedPeerRecordError, compare_peer_id_bytes,
};

/// Maximum signed peer records carried by one pull response.
///
/// One authenticated pull response can therefore contribute at most the
/// complete per-provenance capacity accepted by the peer-address store.
pub const MAX_PEER_RECORDS_PER_BATCH: usize = MAX_RECORDS_PER_BOOTSTRAP;
/// Exact maximum byte length of one encoded peer-record batch.
pub const PEER_RECORD_BATCH_MAX_BYTES: usize =
    1 + MAX_PEER_RECORDS_PER_BATCH * (2 + MAX_SIGNED_PEER_RECORD_BYTES);
/// Exact byte length of one pull request.
pub const PEER_RECORD_PULL_REQUEST_BYTES: usize = 0;

/// A request for one bounded batch of signed peer records.
///
/// The request is intentionally empty. [`crate::PeerRecordBootstrapClient`]
/// and [`crate::LearnedPeerRecordPullClient`] bind the immediate responder
/// through its Noise-authenticated peer identity rather than through untrusted
/// request bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct PeerRecordPullRequest;

impl PeerRecordPullRequest {
    /// Encodes the exact empty request.
    pub const fn to_wire_bytes(self) -> [u8; PEER_RECORD_PULL_REQUEST_BYTES] {
        []
    }

    /// Decodes one complete request message.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PeerRecordExchangeWireError> {
        if bytes.is_empty() {
            Ok(Self)
        } else {
            Err(PeerRecordExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: PEER_RECORD_PULL_REQUEST_BYTES,
            })
        }
    }
}

/// One canonical bounded batch of verified standard signed peer records.
///
/// Records are stored in strictly increasing raw `PeerId` order. The type is
/// deliberately not cloneable because one value may own the complete bounded
/// response payload.
#[must_use]
pub struct PeerRecordBatch {
    records: Vec<SignedPeerRecord>,
}

impl PeerRecordBatch {
    /// Constructs one canonical batch from already verified records.
    ///
    /// At most 33 input items are consumed: the first item beyond the fixed
    /// maximum terminates construction without exhausting an unbounded source.
    pub fn new(
        records: impl IntoIterator<Item = SignedPeerRecord>,
    ) -> Result<Self, PeerRecordExchangeWireError> {
        let records = records.into_iter();
        let initial_capacity = records.size_hint().0.min(MAX_PEER_RECORDS_PER_BATCH);
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(initial_capacity)
            .map_err(PeerRecordExchangeWireError::Allocation)?;
        for record in records {
            if canonical.len() == MAX_PEER_RECORDS_PER_BATCH {
                return Err(PeerRecordExchangeWireError::RecordCount {
                    actual: MAX_PEER_RECORDS_PER_BATCH + 1,
                    maximum: MAX_PEER_RECORDS_PER_BATCH,
                });
            }
            if canonical.len() == canonical.capacity() {
                canonical
                    .try_reserve(1)
                    .map_err(PeerRecordExchangeWireError::Allocation)?;
            }
            canonical.push(record);
        }
        canonical.sort_unstable_by(|left, right| {
            compare_peer_id_bytes(left.peer_id_ref(), right.peer_id_ref())
        });
        require_unique_subjects(&canonical)?;
        Ok(Self { records: canonical })
    }

    /// Decodes one complete canonical response message.
    ///
    /// Length and count bounds are checked before allocating each variable
    /// field. Valid but non-normalized signed-envelope protobufs are rejected;
    /// the wire representation must contain the exact normalized bytes.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PeerRecordExchangeWireError> {
        if bytes.len() > PEER_RECORD_BATCH_MAX_BYTES {
            return Err(PeerRecordExchangeWireError::ResponseTooLong {
                actual: bytes.len(),
                maximum: PEER_RECORD_BATCH_MAX_BYTES,
            });
        }
        let Some((&count, _)) = bytes.split_first() else {
            return Err(PeerRecordExchangeWireError::MissingRecordCount);
        };
        let count = usize::from(count);
        if count > MAX_PEER_RECORDS_PER_BATCH {
            return Err(PeerRecordExchangeWireError::RecordCount {
                actual: count,
                maximum: MAX_PEER_RECORDS_PER_BATCH,
            });
        }

        let mut records = Vec::<SignedPeerRecord>::new();
        records
            .try_reserve_exact(count)
            .map_err(PeerRecordExchangeWireError::Allocation)?;
        let mut position = 1_usize;
        for index in 0..count {
            let remaining = bytes.len() - position;
            if remaining < 2 {
                return Err(PeerRecordExchangeWireError::TruncatedRecordLength {
                    index,
                    actual: remaining,
                });
            }
            let length = usize::from(u16::from_be_bytes([bytes[position], bytes[position + 1]]));
            position += 2;
            if length == 0 {
                return Err(PeerRecordExchangeWireError::EmptyRecord { index });
            }
            if length > MAX_SIGNED_PEER_RECORD_BYTES {
                return Err(PeerRecordExchangeWireError::RecordTooLong {
                    index,
                    actual: length,
                    maximum: MAX_SIGNED_PEER_RECORD_BYTES,
                });
            }
            let remaining = bytes.len() - position;
            if remaining < length {
                return Err(PeerRecordExchangeWireError::TruncatedRecord {
                    index,
                    expected: length,
                    actual: remaining,
                });
            }
            let end = position + length;
            let encoded = &bytes[position..end];
            let record = SignedPeerRecord::from_envelope_slice(encoded).map_err(|source| {
                PeerRecordExchangeWireError::InvalidRecord {
                    index,
                    source: Box::new(source),
                }
            })?;
            if record.envelope_bytes() != encoded {
                return Err(PeerRecordExchangeWireError::NonCanonicalRecord { index });
            }
            if let Some(previous) = records.last() {
                match compare_peer_id_bytes(previous.peer_id_ref(), record.peer_id_ref()) {
                    std::cmp::Ordering::Equal => {
                        return Err(PeerRecordExchangeWireError::DuplicateSubject {
                            index,
                            peer_id: Box::new(record.peer_id()),
                        });
                    }
                    std::cmp::Ordering::Greater => {
                        return Err(PeerRecordExchangeWireError::NonCanonicalSubjectOrder {
                            index,
                        });
                    }
                    std::cmp::Ordering::Less => {}
                }
            }
            records.push(record);
            position = end;
        }
        if position != bytes.len() {
            return Err(PeerRecordExchangeWireError::TrailingBytes {
                actual: bytes.len() - position,
            });
        }
        Ok(Self { records })
    }

    /// Encodes this batch into its exact canonical response bytes.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, PeerRecordExchangeWireError> {
        let encoded_length = self.records.iter().try_fold(1_usize, |length, record| {
            length.checked_add(2 + record.envelope_bytes().len()).ok_or(
                PeerRecordExchangeWireError::ResponseTooLong {
                    actual: usize::MAX,
                    maximum: PEER_RECORD_BATCH_MAX_BYTES,
                },
            )
        })?;
        debug_assert!(encoded_length <= PEER_RECORD_BATCH_MAX_BYTES);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_length)
            .map_err(PeerRecordExchangeWireError::Allocation)?;
        bytes.push(
            u8::try_from(self.records.len()).expect("the fixed batch count fits in one byte"),
        );
        for record in &self.records {
            let envelope = record.envelope_bytes();
            bytes.extend_from_slice(
                &u16::try_from(envelope.len())
                    .expect("the signed-record envelope cap fits u16")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(envelope);
        }
        debug_assert_eq!(bytes.len(), encoded_length);
        Ok(bytes)
    }

    /// Returns the verified records in canonical subject order.
    pub fn records(&self) -> &[SignedPeerRecord] {
        &self.records
    }

    /// Consumes this batch and returns its verified records in canonical order.
    pub(crate) fn into_records(self) -> Vec<SignedPeerRecord> {
        self.records
    }

    /// Returns the number of records in this batch.
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether this batch contains no record.
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl fmt::Debug for PeerRecordBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRecordBatch")
            .field("record_count", &self.records.len())
            .finish()
    }
}

fn require_unique_subjects(
    records: &[SignedPeerRecord],
) -> Result<(), PeerRecordExchangeWireError> {
    for (index, pair) in records.windows(2).enumerate() {
        if pair[0].peer_id() == pair[1].peer_id() {
            return Err(PeerRecordExchangeWireError::DuplicateSubject {
                index: index + 1,
                peer_id: Box::new(pair[1].peer_id()),
            });
        }
    }
    Ok(())
}

/// A fail-closed peer-record pull or batch message error.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordExchangeWireError {
    /// A pull request was not exactly empty.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A complete response exceeded the fixed batch-byte cap.
    ResponseTooLong { actual: usize, maximum: usize },
    /// A response omitted its one-byte record count.
    MissingRecordCount,
    /// A response or constructor supplied too many records.
    RecordCount { actual: usize, maximum: usize },
    /// One record's two-byte length was incomplete.
    TruncatedRecordLength { index: usize, actual: usize },
    /// One record declared an empty signed envelope.
    EmptyRecord { index: usize },
    /// One record declared more than the fixed envelope cap.
    RecordTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    /// One declared envelope body was incomplete.
    TruncatedRecord {
        index: usize,
        expected: usize,
        actual: usize,
    },
    /// One envelope was not a valid standard signed peer record.
    InvalidRecord {
        index: usize,
        source: Box<SignedPeerRecordError>,
    },
    /// One valid envelope was not in its normalized protobuf encoding.
    NonCanonicalRecord { index: usize },
    /// One subject appeared more than once.
    DuplicateSubject { index: usize, peer_id: Box<PeerId> },
    /// Subjects were not in strictly increasing raw identity order.
    NonCanonicalSubjectOrder { index: usize },
    /// Bytes remained after the declared records.
    TrailingBytes { actual: usize },
    /// Reserving one bounded message buffer failed.
    Allocation(TryReserveError),
}

impl fmt::Display for PeerRecordExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "peer-record pull request has {actual} bytes; expected {expected}"
            ),
            Self::ResponseTooLong { actual, maximum } => write!(
                formatter,
                "peer-record batch has {actual} bytes; maximum is {maximum}"
            ),
            Self::MissingRecordCount => {
                formatter.write_str("peer-record batch is missing its record count")
            }
            Self::RecordCount { actual, maximum } => write!(
                formatter,
                "peer-record batch has {actual} records; maximum is {maximum}"
            ),
            Self::TruncatedRecordLength { index, actual } => write!(
                formatter,
                "peer-record batch record {index} has only {actual} of 2 length bytes"
            ),
            Self::EmptyRecord { index } => {
                write!(formatter, "peer-record batch record {index} is empty")
            }
            Self::RecordTooLong {
                index,
                actual,
                maximum,
            } => write!(
                formatter,
                "peer-record batch record {index} has {actual} bytes; maximum is {maximum}"
            ),
            Self::TruncatedRecord {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "peer-record batch record {index} has {actual} of {expected} declared bytes"
            ),
            Self::InvalidRecord { index, source } => {
                write!(
                    formatter,
                    "peer-record batch record {index} is invalid: {source}"
                )
            }
            Self::NonCanonicalRecord { index } => write!(
                formatter,
                "peer-record batch record {index} is not normalized"
            ),
            Self::DuplicateSubject { index, peer_id } => write!(
                formatter,
                "peer-record batch subject {peer_id} is duplicated at record {index}"
            ),
            Self::NonCanonicalSubjectOrder { index } => write!(
                formatter,
                "peer-record batch record {index} is not in increasing subject order"
            ),
            Self::TrailingBytes { actual } => {
                write!(formatter, "peer-record batch has {actual} trailing bytes")
            }
            Self::Allocation(source) => {
                write!(
                    formatter,
                    "cannot reserve peer-record batch buffer: {source}"
                )
            }
        }
    }
}

impl Error for PeerRecordExchangeWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRecord { source, .. } => Some(source.as_ref()),
            Self::Allocation(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
