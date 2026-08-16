//! Position-scoped weighted agreement arithmetic for NAOME consensus.
//!
//! This crate accepts an already selected active validator set, freezes its
//! exact position and weights, and evaluates the strict greater-than-two-thirds
//! threshold without renormalizing offline weight. It does not select
//! validators, encode or verify signatures, define consensus messages, or run
//! a Byzantine-fault-tolerant state machine.

use std::error::Error;
use std::fmt;

/// Exact width of one opaque consensus-key address.
pub const CONSENSUS_KEY_BYTES: usize = 32;

/// Maximum number of active validator entries in one agreement snapshot.
pub const MAX_ACTIVE_VALIDATORS: usize = 256;

/// In-memory consensus height used to distinguish agreement positions.
///
/// This reference representation does not define canonical wire bytes or the
/// relationship between genesis and the first non-genesis height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusHeight(u64);

impl ConsensusHeight {
    /// Constructs an in-memory consensus height.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the in-memory height value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// In-memory Tendermint round used to distinguish agreement positions.
///
/// This reference representation does not define canonical wire bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusRound(u64);

impl ConsensusRound {
    /// Constructs an in-memory consensus round.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the in-memory round value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// One exact height-and-round agreement position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusPosition {
    height: ConsensusHeight,
    round: ConsensusRound,
}

impl ConsensusPosition {
    /// Constructs one exact agreement position.
    pub const fn new(height: ConsensusHeight, round: ConsensusRound) -> Self {
        Self { height, round }
    }

    /// Returns this position's height.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns this position's round.
    pub const fn round(self) -> ConsensusRound {
        self.round
    }
}

/// An opaque 32-byte consensus-key address.
///
/// Constructing this address does not prove possession, key validity, active-
/// set membership, or signature validity. Network peer identities belong to a
/// separate authority domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusKey([u8; CONSENSUS_KEY_BYTES]);

impl ConsensusKey {
    /// Constructs an observed consensus-key address from raw bytes.
    pub const fn from_bytes(bytes: [u8; CONSENSUS_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw consensus-key address bytes.
    pub const fn as_bytes(&self) -> &[u8; CONSENSUS_KEY_BYTES] {
        &self.0
    }
}

/// Exact agreement-weight units in the reference kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct AgreementWeight(u128);

impl AgreementWeight {
    /// Zero agreement weight.
    pub const ZERO: Self = Self(0);

    /// Constructs an exact agreement weight.
    pub const fn new(units: u128) -> Self {
        Self(units)
    }

    /// Returns the exact agreement-weight units.
    pub const fn units(self) -> u128 {
        self.0
    }

    /// Returns whether this weight is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// One already selected active consensus key and its exact agreement weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ActiveAgreementEntry {
    consensus_key: ConsensusKey,
    agreement_weight: AgreementWeight,
}

impl ActiveAgreementEntry {
    /// Constructs one preselected active-set entry.
    pub const fn new(consensus_key: ConsensusKey, agreement_weight: AgreementWeight) -> Self {
        Self {
            consensus_key,
            agreement_weight,
        }
    }

    /// Returns the active consensus-key address.
    pub const fn consensus_key(self) -> ConsensusKey {
        self.consensus_key
    }

    /// Returns the active agreement weight.
    pub const fn agreement_weight(self) -> AgreementWeight {
        self.agreement_weight
    }
}

/// One immutable, position-scoped active agreement-weight snapshot.
///
/// Entries are stored in ascending consensus-key order only to make lookup and
/// error precedence deterministic. This order grants no ranking, selection, or
/// proposer authority.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ActiveAgreementSnapshot {
    position: ConsensusPosition,
    entries: Box<[ActiveAgreementEntry]>,
    total_weight: AgreementWeight,
}

impl ActiveAgreementSnapshot {
    /// Freezes one already selected active set at one exact position.
    ///
    /// An empty set is valid and represents a zero-authority halt state. The
    /// constructor performs no validator selection, ranking, or weight
    /// renormalization. Validation rejects too many entries first, then the
    /// lowest duplicate key, then the lowest zero-weight key, and finally total
    /// weight overflow.
    pub fn try_from_preselected(
        position: ConsensusPosition,
        entries: &[ActiveAgreementEntry],
    ) -> Result<Self, ActiveAgreementSnapshotError> {
        if entries.len() > MAX_ACTIVE_VALIDATORS {
            return Err(ActiveAgreementSnapshotError::TooManyValidators {
                actual: entries.len(),
                maximum: MAX_ACTIVE_VALIDATORS,
            });
        }

        let mut entries = entries.to_vec();
        entries.sort_unstable_by_key(|entry| entry.consensus_key);

        for pair in entries.windows(2) {
            if pair[0].consensus_key == pair[1].consensus_key {
                return Err(ActiveAgreementSnapshotError::DuplicateConsensusKey {
                    consensus_key: pair[0].consensus_key,
                });
            }
        }

        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.agreement_weight.is_zero())
        {
            return Err(ActiveAgreementSnapshotError::ZeroAgreementWeight {
                consensus_key: entry.consensus_key,
            });
        }

        let total_weight = entries.iter().try_fold(0_u128, |total, entry| {
            total.checked_add(entry.agreement_weight.units())
        });
        let Some(total_weight) = total_weight else {
            return Err(ActiveAgreementSnapshotError::TotalWeightOverflow);
        };

        Ok(Self {
            position,
            entries: entries.into_boxed_slice(),
            total_weight: AgreementWeight::new(total_weight),
        })
    }

    /// Returns the exact position bound to this snapshot.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the active entries in ascending consensus-key order.
    pub fn entries(&self) -> &[ActiveAgreementEntry] {
        &self.entries
    }

    /// Returns the number of active entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether this snapshot contains no active entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the immutable total active agreement weight.
    pub const fn total_weight(&self) -> AgreementWeight {
        self.total_weight
    }

    /// Returns the exact weight signed by one complete signer-key list.
    ///
    /// Duplicate or unknown keys invalidate the complete list. Active keys that
    /// are absent from the list remain in [`Self::total_weight`]. Validation
    /// rejects too many signer entries first, then the lowest duplicate key,
    /// then the lowest unknown key.
    pub fn signed_weight(
        &self,
        signer_keys: &[ConsensusKey],
    ) -> Result<AgreementWeight, AgreementSignerError> {
        if signer_keys.len() > MAX_ACTIVE_VALIDATORS {
            return Err(AgreementSignerError::TooManySigners {
                actual: signer_keys.len(),
                maximum: MAX_ACTIVE_VALIDATORS,
            });
        }

        let mut signer_keys = signer_keys.to_vec();
        signer_keys.sort_unstable();

        for pair in signer_keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(AgreementSignerError::DuplicateSigner {
                    consensus_key: pair[0],
                });
            }
        }

        let mut signed_weight = 0_u128;
        for consensus_key in signer_keys {
            let entry_index = self
                .entries
                .binary_search_by_key(&consensus_key, |entry| entry.consensus_key)
                .map_err(|_| AgreementSignerError::UnknownSigner { consensus_key })?;
            signed_weight = signed_weight
                .checked_add(self.entries[entry_index].agreement_weight.units())
                .expect("distinct known signer weights cannot exceed validated total weight");
        }

        Ok(AgreementWeight::new(signed_weight))
    }

    /// Returns whether one complete signer-key list has strict supermajority.
    pub fn has_strict_supermajority(
        &self,
        signer_keys: &[ConsensusKey],
    ) -> Result<bool, AgreementSignerError> {
        let signed_weight = self.signed_weight(signer_keys)?;
        Ok(has_strict_supermajority(
            signed_weight.units(),
            self.total_weight.units(),
        ))
    }
}

fn has_strict_supermajority(signed_weight: u128, total_weight: u128) -> bool {
    if total_weight == 0 {
        return false;
    }

    let floor_two_thirds = (total_weight / 3) * 2 + ((total_weight % 3) * 2) / 3;
    signed_weight > floor_two_thirds
}

/// A failure to construct one immutable active agreement snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActiveAgreementSnapshotError {
    /// The caller supplied more entries than the active-set bound.
    TooManyValidators { actual: usize, maximum: usize },
    /// One consensus key occurs more than once.
    DuplicateConsensusKey { consensus_key: ConsensusKey },
    /// An active entry contributes no weight.
    ZeroAgreementWeight { consensus_key: ConsensusKey },
    /// Exact active-weight summation exceeds the reference representation.
    TotalWeightOverflow,
}

impl fmt::Display for ActiveAgreementSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyValidators { actual, maximum } => write!(
                formatter,
                "active agreement snapshot has {actual} entries; the limit is {maximum}"
            ),
            Self::DuplicateConsensusKey { consensus_key } => write!(
                formatter,
                "active agreement snapshot repeats consensus key {consensus_key:?}"
            ),
            Self::ZeroAgreementWeight { consensus_key } => write!(
                formatter,
                "active agreement snapshot assigns zero weight to consensus key {consensus_key:?}"
            ),
            Self::TotalWeightOverflow => {
                formatter.write_str("active agreement snapshot total weight exceeds u128")
            }
        }
    }
}

impl Error for ActiveAgreementSnapshotError {}

/// A malformed or unauthorized signer-key list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgreementSignerError {
    /// The caller supplied more signer entries than the active-set bound.
    TooManySigners { actual: usize, maximum: usize },
    /// One signer key occurs more than once.
    DuplicateSigner { consensus_key: ConsensusKey },
    /// A signer key does not belong to the immutable active snapshot.
    UnknownSigner { consensus_key: ConsensusKey },
}

impl fmt::Display for AgreementSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManySigners { actual, maximum } => write!(
                formatter,
                "agreement signer list has {actual} entries; the limit is {maximum}"
            ),
            Self::DuplicateSigner { consensus_key } => {
                write!(
                    formatter,
                    "agreement signer list repeats key {consensus_key:?}"
                )
            }
            Self::UnknownSigner { consensus_key } => {
                write!(
                    formatter,
                    "agreement signer key is not active: {consensus_key:?}"
                )
            }
        }
    }
}

impl Error for AgreementSignerError {}

#[cfg(test)]
mod tests;
