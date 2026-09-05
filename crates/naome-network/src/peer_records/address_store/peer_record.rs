use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;

use libp2p::core::peer_record::{FromEnvelopeError, PeerRecord};
use libp2p::core::signed_envelope::{DecodingError as EnvelopeDecodingError, SignedEnvelope};
use libp2p::{
    Multiaddr, PeerId,
    identity::{Keypair, SigningError},
};

use super::{MAX_PEER_ID_BYTES, encode_peer_id, endpoint_group};

const STANDARD_PEER_RECORD_DOMAIN: &str = "libp2p-peer-record";
const STANDARD_PEER_RECORD_PAYLOAD_TYPE: &[u8] = &[0x03, 0x01];

/// Maximum number of signed addresses in one peer record.
pub const MAX_ADDRESSES_PER_PEER_RECORD: usize = 4;
/// Maximum encoded bytes in one signed peer-record envelope.
pub const MAX_SIGNED_PEER_RECORD_BYTES: usize = 4_096;
/// Maximum binary bytes in one stored multi-address.
pub const MAX_PEER_ADDRESS_BYTES: usize = 256;

/// One verified standard interoperable libp2p signed peer record.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct SignedPeerRecord {
    pub(super) peer_id: PeerId,
    pub(super) sequence: u64,
    pub(super) addresses: Vec<Multiaddr>,
    pub(super) envelope_bytes: Vec<u8>,
}

impl SignedPeerRecord {
    /// Verifies and normalizes one bounded standard signed peer-record envelope.
    pub fn from_envelope_bytes(bytes: Vec<u8>) -> Result<Self, SignedPeerRecordError> {
        Self::from_envelope_slice(&bytes)
    }

    pub(crate) fn from_envelope_slice(bytes: &[u8]) -> Result<Self, SignedPeerRecordError> {
        if bytes.is_empty() {
            return Err(SignedPeerRecordError::Empty);
        }
        if bytes.len() > MAX_SIGNED_PEER_RECORD_BYTES {
            return Err(SignedPeerRecordError::InputTooLong {
                actual: bytes.len(),
                maximum: MAX_SIGNED_PEER_RECORD_BYTES,
            });
        }

        let envelope = SignedEnvelope::from_protobuf_encoding(bytes)
            .map_err(|source| SignedPeerRecordError::Envelope(Box::new(source)))?;
        Self::from_signed_envelope(envelope)
    }

    fn from_signed_envelope(envelope: SignedEnvelope) -> Result<Self, SignedPeerRecordError> {
        let peer_record = PeerRecord::from_signed_envelope_interop(envelope)
            .map_err(|source| SignedPeerRecordError::PeerRecord(Box::new(source)))?;
        let peer_id_length = peer_record.peer_id().as_ref().encoded_len();
        if peer_id_length > MAX_PEER_ID_BYTES {
            return Err(SignedPeerRecordError::PeerIdTooLong {
                actual: peer_id_length,
                maximum: MAX_PEER_ID_BYTES,
            });
        }
        let peer_id = peer_record.peer_id();
        let sequence = peer_record.seq();
        let addresses = peer_record.addresses().to_vec();
        let envelope_bytes = peer_record.into_signed_envelope().into_protobuf_encoding();
        if envelope_bytes.len() > MAX_SIGNED_PEER_RECORD_BYTES {
            return Err(SignedPeerRecordError::NormalizedTooLong {
                actual: envelope_bytes.len(),
                maximum: MAX_SIGNED_PEER_RECORD_BYTES,
            });
        }

        validate_peer_record_addresses(&addresses)?;

        Ok(Self {
            peer_id,
            sequence,
            addresses,
            envelope_bytes,
        })
    }

    pub(crate) fn sign_with_sequence(
        identity: &Keypair,
        sequence: u64,
        addresses: Vec<Multiaddr>,
    ) -> Result<Self, SignedPeerRecordConstructionError> {
        let peer_id = identity.public().to_peer_id();
        let peer_id_length = peer_id.as_ref().encoded_len();
        if peer_id_length > MAX_PEER_ID_BYTES {
            return Err(SignedPeerRecordConstructionError::InvalidRecord(
                SignedPeerRecordError::PeerIdTooLong {
                    actual: peer_id_length,
                    maximum: MAX_PEER_ID_BYTES,
                },
            ));
        }
        validate_peer_record_addresses(&addresses)
            .map_err(SignedPeerRecordConstructionError::InvalidRecord)?;

        let payload = encode_peer_record_payload(peer_id, sequence, &addresses)?;
        let envelope_bytes = SignedEnvelope::new(
            identity,
            String::from(STANDARD_PEER_RECORD_DOMAIN),
            STANDARD_PEER_RECORD_PAYLOAD_TYPE.to_vec(),
            payload,
        )
        .map_err(SignedPeerRecordConstructionError::Signing)?
        .into_protobuf_encoding();
        if envelope_bytes.len() > MAX_SIGNED_PEER_RECORD_BYTES {
            return Err(SignedPeerRecordConstructionError::InvalidRecord(
                SignedPeerRecordError::NormalizedTooLong {
                    actual: envelope_bytes.len(),
                    maximum: MAX_SIGNED_PEER_RECORD_BYTES,
                },
            ));
        }
        Ok(Self {
            peer_id,
            sequence,
            addresses,
            envelope_bytes,
        })
    }

    /// Returns the identity that signed this address claim.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub(crate) const fn peer_id_ref(&self) -> &PeerId {
        &self.peer_id
    }

    /// Returns the signer-controlled monotonic sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact signed addresses.
    pub fn addresses(&self) -> &[Multiaddr] {
        &self.addresses
    }

    /// Returns the normalized standard signed-envelope bytes.
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }
}

impl fmt::Debug for SignedPeerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPeerRecord")
            .field("peer_id", &self.peer_id)
            .field("sequence", &self.sequence)
            .field("address_count", &self.addresses.len())
            .field("envelope_bytes", &self.envelope_bytes.len())
            .finish()
    }
}

/// Error decoding or validating a signed peer record.
#[derive(Debug)]
pub enum SignedPeerRecordError {
    /// The envelope was empty.
    Empty,
    /// The input exceeded the envelope cap before decoding.
    InputTooLong { actual: usize, maximum: usize },
    /// The signed-envelope protobuf was invalid.
    Envelope(Box<EnvelopeDecodingError>),
    /// The standard peer-record payload or signature was invalid.
    PeerRecord(Box<FromEnvelopeError>),
    /// Normalized envelope bytes exceeded the envelope cap.
    NormalizedTooLong { actual: usize, maximum: usize },
    /// The signing identity exceeded the persisted identity cap.
    PeerIdTooLong { actual: usize, maximum: usize },
    /// The record had zero or too many addresses.
    AddressCount { actual: usize, maximum: usize },
    /// One address exceeded its byte cap.
    AddressTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    /// One address was not an exact globally routable IP/TCP endpoint.
    UnsupportedAddress {
        index: usize,
        address: Box<Multiaddr>,
    },
    /// One signed address appeared more than once.
    DuplicateAddress { index: usize },
}

impl fmt::Display for SignedPeerRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("signed peer record is empty"),
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "signed peer record has {actual} bytes; maximum is {maximum}"
            ),
            Self::Envelope(source) => write!(formatter, "invalid signed envelope: {source}"),
            Self::PeerRecord(source) => write!(formatter, "invalid standard peer record: {source}"),
            Self::NormalizedTooLong { actual, maximum } => write!(
                formatter,
                "normalized signed peer record has {actual} bytes; maximum is {maximum}"
            ),
            Self::PeerIdTooLong { actual, maximum } => write!(
                formatter,
                "signed peer identity has {actual} bytes; maximum is {maximum}"
            ),
            Self::AddressCount { actual, maximum } => write!(
                formatter,
                "signed peer record has {actual} addresses; expected 1..={maximum}"
            ),
            Self::AddressTooLong {
                index,
                actual,
                maximum,
            } => write!(
                formatter,
                "signed peer record address {index} has {actual} bytes; maximum is {maximum}"
            ),
            Self::UnsupportedAddress { index, address } => write!(
                formatter,
                "signed peer record address {index} ({address}) is not an exact globally routable IP/TCP endpoint"
            ),
            Self::DuplicateAddress { index } => {
                write!(
                    formatter,
                    "signed peer record address {index} is duplicated"
                )
            }
        }
    }
}

impl Error for SignedPeerRecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Envelope(source) => Some(source.as_ref()),
            Self::PeerRecord(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

pub(crate) enum SignedPeerRecordConstructionError {
    InvalidRecord(SignedPeerRecordError),
    Signing(SigningError),
    Allocation(TryReserveError),
}

fn validate_peer_record_addresses(addresses: &[Multiaddr]) -> Result<(), SignedPeerRecordError> {
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES_PER_PEER_RECORD {
        return Err(SignedPeerRecordError::AddressCount {
            actual: addresses.len(),
            maximum: MAX_ADDRESSES_PER_PEER_RECORD,
        });
    }

    for (index, address) in addresses.iter().enumerate() {
        if address.len() > MAX_PEER_ADDRESS_BYTES {
            return Err(SignedPeerRecordError::AddressTooLong {
                index,
                actual: address.len(),
                maximum: MAX_PEER_ADDRESS_BYTES,
            });
        }
        endpoint_group(address, true).map_err(|_| SignedPeerRecordError::UnsupportedAddress {
            index,
            address: Box::new(address.clone()),
        })?;
        if addresses[..index].contains(address) {
            return Err(SignedPeerRecordError::DuplicateAddress { index });
        }
    }
    Ok(())
}

fn encode_peer_record_payload(
    peer_id: PeerId,
    sequence: u64,
    addresses: &[Multiaddr],
) -> Result<Vec<u8>, SignedPeerRecordConstructionError> {
    let (peer_id_bytes, peer_id_length) = encode_peer_id(peer_id);
    let peer_id_field = 1 + varint_length(peer_id_length as u64) + peer_id_length;
    let sequence_field = usize::from(sequence != 0) * (1 + varint_length(sequence));
    let address_fields = addresses.iter().map(|address| {
        let inner = 1 + varint_length(address.len() as u64) + address.len();
        1 + varint_length(inner as u64) + inner
    });
    let capacity = address_fields.fold(peer_id_field + sequence_field, usize::saturating_add);

    let mut payload = Vec::new();
    payload
        .try_reserve_exact(capacity)
        .map_err(SignedPeerRecordConstructionError::Allocation)?;
    push_bytes_field(&mut payload, 0x0a, &peer_id_bytes[..peer_id_length]);
    if sequence != 0 {
        payload.push(0x10);
        push_varint(&mut payload, sequence);
    }
    for address in addresses {
        let inner_length = 1 + varint_length(address.len() as u64) + address.len();
        payload.push(0x1a);
        push_varint(&mut payload, inner_length as u64);
        push_bytes_field(&mut payload, 0x0a, address.as_ref());
    }
    debug_assert_eq!(payload.len(), capacity);
    Ok(payload)
}

fn push_bytes_field(bytes: &mut Vec<u8>, tag: u8, value: &[u8]) {
    bytes.push(tag);
    push_varint(bytes, value.len() as u64);
    bytes.extend_from_slice(value);
}

fn push_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

const fn varint_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}
