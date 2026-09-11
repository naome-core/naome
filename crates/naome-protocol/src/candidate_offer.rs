//! A publisher's replaceable untrusted candidate offer, never selected history.
use naome_chain::{ArtifactBlockId, ArtifactChainId};
use std::{error::Error, fmt};

/// Maximum candidates in one publisher's current offer.
pub const CANDIDATE_OFFER_MAX_IDS: usize = 32;
/// Maximum complete wire bytes: chain, count, and strictly increasing IDs.
pub const CANDIDATE_OFFER_MAX_BYTES: usize = 33 + 32 * CANDIDATE_OFFER_MAX_IDS;

/// One canonical offer. An empty offer withdraws only this publisher's hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateOffer {
    chain: ArtifactChainId,
    candidates: Vec<ArtifactBlockId>,
}
impl CandidateOffer {
    /// Requires at most 32 unique IDs already in canonical ascending order.
    pub fn new(
        chain: ArtifactChainId,
        candidates: Vec<ArtifactBlockId>,
    ) -> Result<Self, CandidateOfferError> {
        if candidates.len() > CANDIDATE_OFFER_MAX_IDS {
            return Err(CandidateOfferError::Count);
        }
        if candidates
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(CandidateOfferError::Order);
        }
        Ok(Self { chain, candidates })
    }
    /// Returns the untrusted chain context.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.chain
    }
    /// Returns the complete bounded candidate set.
    pub fn candidates(&self) -> &[ArtifactBlockId] {
        &self.candidates
    }
    /// Encodes `chain[32]`, `count[1]`, and count canonical `IDs[32]`.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33 + self.candidates.len() * 32);
        bytes.extend_from_slice(self.chain.as_bytes());
        bytes.push(self.candidates.len() as u8);
        for id in &self.candidates {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes
    }
    /// Rejects oversized counts, truncation, trailing bytes and noncanonical order.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CandidateOfferError> {
        let count = usize::from(*bytes.get(32).ok_or(CandidateOfferError::Length)?);
        if count > CANDIDATE_OFFER_MAX_IDS {
            return Err(CandidateOfferError::Count);
        }
        if bytes.len() != 33 + 32 * count {
            return Err(CandidateOfferError::Length);
        }
        let chain =
            ArtifactChainId::from_bytes(bytes[..32].try_into().expect("checked chain prefix"));
        Self::new(
            chain,
            bytes[33..]
                .chunks_exact(32)
                .map(|id| ArtifactBlockId::from_bytes(id.try_into().expect("exact ID chunk")))
                .collect(),
        )
    }
}
/// Structural refusal; successful decoding grants no validity or availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateOfferError {
    Length,
    Count,
    Order,
}
impl fmt::Display for CandidateOfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid candidate offer: {self:?}")
    }
}
impl Error for CandidateOfferError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_offer_boundaries_and_every_truncation() {
        let chain = ArtifactChainId::from_bytes([7; 32]);
        for count in [0, 1, 32] {
            let ids = (0..count)
                .map(|i| ArtifactBlockId::from_bytes([i as u8; 32]))
                .collect();
            let offer = CandidateOffer::new(chain, ids).unwrap();
            let bytes = offer.to_wire_bytes();
            assert_eq!(CandidateOffer::from_wire_bytes(&bytes).unwrap(), offer);
            for cut in 0..bytes.len() {
                assert!(CandidateOffer::from_wire_bytes(&bytes[..cut]).is_err());
            }
            let mut extra = bytes;
            extra.push(0);
            assert!(CandidateOffer::from_wire_bytes(&extra).is_err());
        }
        let id = ArtifactBlockId::from_bytes([1; 32]);
        assert_eq!(
            CandidateOffer::new(chain, vec![id; 33]),
            Err(CandidateOfferError::Count)
        );
        assert_eq!(
            CandidateOffer::new(chain, vec![id; 2]),
            Err(CandidateOfferError::Order)
        );
        assert_eq!(
            CandidateOffer::new(chain, vec![ArtifactBlockId::from_bytes([2; 32]), id]),
            Err(CandidateOfferError::Order)
        );
        let mut header = [0; 33];
        header[32] = 255;
        assert_eq!(
            CandidateOffer::from_wire_bytes(&header),
            Err(CandidateOfferError::Count)
        );
    }
}
