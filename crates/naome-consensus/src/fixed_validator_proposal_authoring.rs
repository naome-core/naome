//! Branch-bound fixed-validator proposal-authoring intents.

use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlock;

use super::fixed_validator_lock_state::FixedValidatorProposalStateSnapshotV0;
use super::producer_authorization::{
    complete_producer_authorization, producer_authorization_signing_transcript,
};
use super::{
    CONSENSUS_KEY_BYTES, ConsensusContextV0, ConsensusKey, ConsensusPosition, ConsensusSignature,
    ConsensusValueError, ConsensusValueV0, FixedAgreementSetId,
    FixedConsensusProposalValueVerifyErrorV0, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateV0, FixedValidatorVoteIntentError, ProducerAuthorizationVerifyError,
    ProposalSigningRoot, QuorumCertificateVerifyError, VerifiedFixedConsensusProposalV0,
    VerifiedProducerAuthorizationV0,
};

const PROPOSAL_INTENT_HEADER: &[u8] = b"naome:fixed-validator-proposal-intent:v0\0";
const INTENT_SUFFIX_BYTES: usize = ConsensusValueV0::BYTE_LENGTH + CONSENSUS_KEY_BYTES;

/// Exact caller-selected availability input for one proposal-authoring event.
#[derive(Debug)]
#[must_use]
pub enum FixedValidatorProposalSourceV0 {
    /// Author one new branch-derived value when no valid value is retained.
    Fresh {
        artifact_block: ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    },
    /// Re-propose the exact retained valid value and certificate.
    RetainedValid { canonical_artifact_bytes: Vec<u8> },
}

/// One complete current-state and producer-authorization intent.
///
/// The private construction path binds the exact branch-derived state snapshot,
/// scheduled proposer, value, and retained valid-round proof before any key use.
/// It creates no signature and grants no persistence or publication authority.
#[derive(Clone, Debug)]
#[must_use]
pub struct FixedValidatorProposalIntentV0 {
    observed: ObservedFixedValidatorProposalIntentV0,
}

/// One strictly replayed proposal intent from an externally anchored journal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ObservedFixedValidatorProposalIntentV0 {
    snapshot: FixedValidatorProposalStateSnapshotV0,
    value: ConsensusValueV0,
    proposer: ConsensusKey,
    canonical_bytes: Vec<u8>,
}

/// One strictly self-verified proposal control assembled from a sealed intent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct CompletedFixedValidatorProposalV0 {
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    proposer: ConsensusKey,
    canonical_proposal_control_bytes: Vec<u8>,
}

impl FixedValidatorLockStateV0 {
    /// Validates and seals exactly the proposal permitted by current state.
    ///
    /// A retained valid value is mandatory when present. Otherwise one explicit
    /// caller-selected artifact block is required. Scheduled-proposer authority
    /// and Proposal phase are checked before artifact work; complete immutable
    /// child validation finishes before an intent can be returned.
    pub fn prepare_proposal_intent(
        &self,
        round: &FixedConsensusRoundV0<'_>,
        source: FixedValidatorProposalSourceV0,
        signer: ConsensusKey,
    ) -> Result<FixedValidatorProposalIntentV0, FixedValidatorProposalIntentErrorV0> {
        if self.position() != round.position() {
            return Err(FixedValidatorProposalIntentErrorV0::PositionMismatch {
                state: self.position(),
                round: round.position(),
            });
        }
        if self.phase() != FixedValidatorLockPhaseV0::Proposal {
            return Err(FixedValidatorProposalIntentErrorV0::WrongPhase {
                actual: self.phase(),
            });
        }
        if round.proposer() != signer {
            return Err(FixedValidatorProposalIntentErrorV0::NotScheduledProposer {
                scheduled: round.proposer(),
                signer,
            });
        }

        let (value, canonical_artifact_bytes) = match (self.valid_value(), source) {
            (
                None,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes,
                },
            ) => (
                round.value_for_artifact_block(artifact_block),
                canonical_artifact_bytes,
            ),
            (None, FixedValidatorProposalSourceV0::RetainedValid { .. }) => {
                return Err(FixedValidatorProposalIntentErrorV0::FreshValueRequired);
            }
            (Some(_), FixedValidatorProposalSourceV0::Fresh { .. }) => {
                return Err(FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired);
            }
            (
                Some(valid),
                FixedValidatorProposalSourceV0::RetainedValid {
                    canonical_artifact_bytes,
                },
            ) => {
                let certificate_position =
                    ConsensusPosition::new(round.position().height(), valid.round());
                let verifies = round
                    .verify_retained_prevote_certificate(
                        valid.canonical_prevote_certificate(),
                        certificate_position,
                        super::ConsensusVoteTarget::Proposal(valid.value().proposal_signing_root()),
                        valid.prevote_certificate_id(),
                    )
                    .map_err(FixedValidatorProposalIntentErrorV0::RetainedCertificate)?;
                if !verifies {
                    return Err(FixedValidatorProposalIntentErrorV0::RetainedCertificateMismatch);
                }
                (valid.value(), canonical_artifact_bytes)
            }
        };

        round
            .validate_authored_proposal_value(value, canonical_artifact_bytes)
            .map_err(FixedValidatorProposalIntentErrorV0::Value)?;
        let snapshot = FixedValidatorProposalStateSnapshotV0::from_lock_state(self)
            .map_err(FixedValidatorProposalIntentErrorV0::State)?;
        FixedValidatorProposalIntentV0::new(snapshot, value, signer)
    }
}

impl FixedValidatorProposalIntentV0 {
    fn new(
        snapshot: FixedValidatorProposalStateSnapshotV0,
        value: ConsensusValueV0,
        proposer: ConsensusKey,
    ) -> Result<Self, FixedValidatorProposalIntentErrorV0> {
        validate_snapshot_value(&snapshot, value)?;
        let length =
            PROPOSAL_INTENT_HEADER.len() + snapshot.canonical_bytes().len() + INTENT_SUFFIX_BYTES;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(length)
            .map_err(|_| FixedValidatorProposalIntentErrorV0::Allocation { bytes: length })?;
        canonical_bytes.extend_from_slice(PROPOSAL_INTENT_HEADER);
        canonical_bytes.extend_from_slice(snapshot.canonical_bytes());
        canonical_bytes.extend_from_slice(&value.to_canonical_bytes());
        canonical_bytes.extend_from_slice(proposer.as_bytes());
        debug_assert_eq!(canonical_bytes.len(), length);
        Ok(Self {
            observed: ObservedFixedValidatorProposalIntentV0 {
                snapshot,
                value,
                proposer,
                canonical_bytes,
            },
        })
    }

    /// Returns the sole canonical complete-state and pre-signing intent bytes.
    pub fn canonical_intent_bytes(&self) -> &[u8] {
        self.observed.canonical_intent_bytes()
    }

    /// Returns the exact producer-authorization transcript for the live intent.
    pub fn signing_transcript(&self) -> Vec<u8> {
        self.observed.signing_transcript()
    }

    /// Strictly self-verifies and completes the live intent with one signature.
    pub fn complete_with_signature(
        &self,
        signature: ConsensusSignature,
    ) -> Result<CompletedFixedValidatorProposalV0, FixedValidatorProposalIntentErrorV0> {
        self.observed.complete_with_signature(signature)
    }
}

impl ObservedFixedValidatorProposalIntentV0 {
    /// Exact minimum intent width with an empty Proposal state.
    pub const MIN_BYTE_LENGTH: usize = PROPOSAL_INTENT_HEADER.len()
        + FixedValidatorProposalStateSnapshotV0::MIN_BYTE_LENGTH
        + INTENT_SUFFIX_BYTES;
    /// Exact maximum intent width with bounded lock and valid proof state.
    pub const MAX_BYTE_LENGTH: usize = PROPOSAL_INTENT_HEADER.len()
        + FixedValidatorProposalStateSnapshotV0::MAX_BYTE_LENGTH
        + INTENT_SUFFIX_BYTES;

    /// Strictly decodes a journal-retained proposal intent.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_fixed_set_id: FixedAgreementSetId,
        expected_proposer: ConsensusKey,
    ) -> Result<Self, FixedValidatorProposalIntentErrorV0> {
        if !(Self::MIN_BYTE_LENGTH..=Self::MAX_BYTE_LENGTH).contains(&bytes.len()) {
            return Err(FixedValidatorProposalIntentErrorV0::InvalidLength {
                actual: bytes.len(),
                minimum: Self::MIN_BYTE_LENGTH,
                maximum: Self::MAX_BYTE_LENGTH,
            });
        }
        if &bytes[..PROPOSAL_INTENT_HEADER.len()] != PROPOSAL_INTENT_HEADER {
            return Err(FixedValidatorProposalIntentErrorV0::HeaderMismatch);
        }
        let snapshot_end = bytes.len() - INTENT_SUFFIX_BYTES;
        let snapshot = FixedValidatorProposalStateSnapshotV0::decode_and_verify(
            &bytes[PROPOSAL_INTENT_HEADER.len()..snapshot_end],
            expected_context,
            expected_fixed_set_id,
        )
        .map_err(FixedValidatorProposalIntentErrorV0::State)?;
        if snapshot.phase() != FixedValidatorLockPhaseV0::Proposal {
            return Err(FixedValidatorProposalIntentErrorV0::WrongPhase {
                actual: snapshot.phase(),
            });
        }
        let value = ConsensusValueV0::from_canonical_bytes(
            &bytes[snapshot_end..snapshot_end + ConsensusValueV0::BYTE_LENGTH],
        )
        .map_err(FixedValidatorProposalIntentErrorV0::ConsensusValue)?;
        let proposer = ConsensusKey::from_bytes(
            bytes[snapshot_end + ConsensusValueV0::BYTE_LENGTH..]
                .try_into()
                .expect("the fixed proposal-intent signer suffix is 32 bytes"),
        );
        if proposer != expected_proposer {
            return Err(FixedValidatorProposalIntentErrorV0::ProposerMismatch {
                expected: expected_proposer,
                actual: proposer,
            });
        }
        validate_snapshot_value(&snapshot, value)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| FixedValidatorProposalIntentErrorV0::Allocation { bytes: bytes.len() })?;
        canonical_bytes.extend_from_slice(bytes);
        Ok(Self {
            snapshot,
            value,
            proposer,
            canonical_bytes,
        })
    }

    /// Returns the exact proposal position.
    pub const fn position(&self) -> ConsensusPosition {
        self.snapshot.position()
    }

    /// Returns the exact evidence-free value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the evidence-free proposal signing root.
    pub fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.value.proposal_signing_root()
    }

    /// Returns the sole canonical complete-state and pre-signing intent bytes.
    pub fn canonical_intent_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn signing_transcript(&self) -> Vec<u8> {
        producer_authorization_signing_transcript(
            self.snapshot.context(),
            self.position(),
            self.proposal_signing_root(),
            self.proposer,
        )
    }

    fn complete_with_signature(
        &self,
        signature: ConsensusSignature,
    ) -> Result<CompletedFixedValidatorProposalV0, FixedValidatorProposalIntentErrorV0> {
        let authorization = complete_producer_authorization(
            self.snapshot.context(),
            self.position(),
            self.proposal_signing_root(),
            self.proposer,
            signature,
        )
        .map_err(FixedValidatorProposalIntentErrorV0::ProducerAuthorization)?;
        let valid = self.snapshot.valid_value();
        let proof_len = valid.map_or(0, |value| value.canonical_prevote_certificate().len());
        let length = ConsensusValueV0::BYTE_LENGTH
            + VerifiedProducerAuthorizationV0::BYTE_LENGTH
            + 1
            + proof_len;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| FixedValidatorProposalIntentErrorV0::Allocation { bytes: length })?;
        bytes.extend_from_slice(&self.value.to_canonical_bytes());
        bytes.extend_from_slice(&authorization);
        match valid {
            None => bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG),
            Some(valid) => {
                bytes.push(VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG);
                bytes.extend_from_slice(valid.canonical_prevote_certificate());
            }
        }
        Ok(CompletedFixedValidatorProposalV0 {
            position: self.position(),
            proposal_signing_root: self.proposal_signing_root(),
            proposer: self.proposer,
            canonical_proposal_control_bytes: bytes,
        })
    }

    /// Verifies complete bytes as exactly this intent plus one valid signature.
    pub fn verify_completed_proposal_control(
        &self,
        bytes: &[u8],
    ) -> Result<CompletedFixedValidatorProposalV0, FixedValidatorProposalIntentErrorV0> {
        let minimum =
            ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH + 1;
        if bytes.len() < minimum {
            return Err(
                FixedValidatorProposalIntentErrorV0::InvalidCompletionLength {
                    actual: bytes.len(),
                    minimum,
                },
            );
        }
        let signature_offset = ConsensusValueV0::BYTE_LENGTH
            + VerifiedProducerAuthorizationV0::BYTE_LENGTH
            - super::CONSENSUS_SIGNATURE_BYTES;
        let signature = ConsensusSignature::from_bytes(
            bytes[signature_offset..signature_offset + super::CONSENSUS_SIGNATURE_BYTES]
                .try_into()
                .expect("the guarded producer-signature slice has exact width"),
        );
        let completed = self.complete_with_signature(signature)?;
        if completed.canonical_proposal_control_bytes() != bytes {
            return Err(FixedValidatorProposalIntentErrorV0::CompletionMismatch);
        }
        Ok(completed)
    }

    /// Verifies the exact fixed-width producer authorization completing this intent.
    pub fn verify_completed_producer_authorization(
        &self,
        bytes: &[u8],
    ) -> Result<CompletedFixedValidatorProposalV0, FixedValidatorProposalIntentErrorV0> {
        if bytes.len() != VerifiedProducerAuthorizationV0::BYTE_LENGTH {
            return Err(
                FixedValidatorProposalIntentErrorV0::InvalidProducerAuthorizationLength {
                    actual: bytes.len(),
                    expected: VerifiedProducerAuthorizationV0::BYTE_LENGTH,
                },
            );
        }
        let signature_offset =
            VerifiedProducerAuthorizationV0::BYTE_LENGTH - super::CONSENSUS_SIGNATURE_BYTES;
        let signature = ConsensusSignature::from_bytes(
            bytes[signature_offset..]
                .try_into()
                .expect("the fixed producer-authorization suffix is one signature"),
        );
        let completed = self.complete_with_signature(signature)?;
        let authorization_start = ConsensusValueV0::BYTE_LENGTH;
        let authorization_end = authorization_start + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
        if &completed.canonical_proposal_control_bytes()[authorization_start..authorization_end]
            != bytes
        {
            return Err(FixedValidatorProposalIntentErrorV0::CompletionMismatch);
        }
        Ok(completed)
    }

    /// Strictly restores the complete Proposal-phase state against one exact round.
    pub fn restore_lock_state_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorProposalIntentErrorV0> {
        if round.proposer() != self.proposer {
            return Err(FixedValidatorProposalIntentErrorV0::NotScheduledProposer {
                scheduled: round.proposer(),
                signer: self.proposer,
            });
        }
        self.snapshot
            .restore_for_round(round)
            .map_err(FixedValidatorProposalIntentErrorV0::State)
    }
}

impl CompletedFixedValidatorProposalV0 {
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    pub const fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }

    pub const fn proposer(&self) -> ConsensusKey {
        self.proposer
    }

    pub fn canonical_proposal_control_bytes(&self) -> &[u8] {
        &self.canonical_proposal_control_bytes
    }

    pub fn into_canonical_proposal_control_bytes(self) -> Vec<u8> {
        self.canonical_proposal_control_bytes
    }
}

fn validate_snapshot_value(
    snapshot: &FixedValidatorProposalStateSnapshotV0,
    value: ConsensusValueV0,
) -> Result<(), FixedValidatorProposalIntentErrorV0> {
    if value.context() != snapshot.context() || value.height() != snapshot.position().height() {
        return Err(FixedValidatorProposalIntentErrorV0::ValueHeaderMismatch);
    }
    match snapshot.valid_value() {
        None => Ok(()),
        Some(valid) if valid.value() == value => Ok(()),
        Some(_) => Err(FixedValidatorProposalIntentErrorV0::RetainedValidValueMismatch),
    }
}

/// Proposal construction, validation, or structural replay failed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorProposalIntentErrorV0 {
    InvalidLength {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    HeaderMismatch,
    PositionMismatch {
        state: ConsensusPosition,
        round: ConsensusPosition,
    },
    WrongPhase {
        actual: FixedValidatorLockPhaseV0,
    },
    NotScheduledProposer {
        scheduled: ConsensusKey,
        signer: ConsensusKey,
    },
    ProposerMismatch {
        expected: ConsensusKey,
        actual: ConsensusKey,
    },
    FreshValueRequired,
    RetainedValidValueRequired,
    RetainedValidValueMismatch,
    ValueHeaderMismatch,
    ConsensusValue(ConsensusValueError),
    Value(FixedConsensusProposalValueVerifyErrorV0),
    RetainedCertificate(QuorumCertificateVerifyError),
    RetainedCertificateMismatch,
    State(FixedValidatorVoteIntentError),
    ProducerAuthorization(ProducerAuthorizationVerifyError),
    InvalidCompletionLength {
        actual: usize,
        minimum: usize,
    },
    InvalidProducerAuthorizationLength {
        actual: usize,
        expected: usize,
    },
    CompletionMismatch,
    Allocation {
        bytes: usize,
    },
}

impl fmt::Display for FixedValidatorProposalIntentErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "proposal intent length {actual} is outside {minimum}..={maximum}"
            ),
            Self::HeaderMismatch => formatter.write_str("proposal intent header is invalid"),
            Self::PositionMismatch { state, round } => write!(
                formatter,
                "proposal state position {state:?} differs from round {round:?}"
            ),
            Self::WrongPhase { actual } => write!(
                formatter,
                "proposal authoring requires Proposal phase, not {actual:?}"
            ),
            Self::NotScheduledProposer { scheduled, signer } => write!(
                formatter,
                "local signer {signer:?} is not scheduled proposer {scheduled:?}"
            ),
            Self::ProposerMismatch { expected, actual } => write!(
                formatter,
                "proposal intent proposer {actual:?} differs from expected {expected:?}"
            ),
            Self::FreshValueRequired => formatter.write_str(
                "no retained valid value exists, so a fresh artifact candidate is required",
            ),
            Self::RetainedValidValueRequired => {
                formatter.write_str("a retained valid value exists and must be re-proposed exactly")
            }
            Self::RetainedValidValueMismatch => {
                formatter.write_str("proposal value differs from the retained valid value")
            }
            Self::ValueHeaderMismatch => formatter.write_str(
                "proposal value context or height differs from the complete state snapshot",
            ),
            Self::ConsensusValue(source) => source.fmt(formatter),
            Self::Value(source) => source.fmt(formatter),
            Self::RetainedCertificate(source) => source.fmt(formatter),
            Self::RetainedCertificateMismatch => formatter
                .write_str("retained certificate no longer matches its value, round, and identity"),
            Self::State(source) => source.fmt(formatter),
            Self::ProducerAuthorization(source) => source.fmt(formatter),
            Self::InvalidCompletionLength { actual, minimum } => write!(
                formatter,
                "completed proposal length {actual} is shorter than {minimum}"
            ),
            Self::InvalidProducerAuthorizationLength { actual, expected } => write!(
                formatter,
                "completed producer authorization has {actual} bytes, expected {expected}"
            ),
            Self::CompletionMismatch => {
                formatter.write_str("completed proposal does not exactly match its prepared intent")
            }
            Self::Allocation { bytes } => write!(
                formatter,
                "proposal intent could not allocate {bytes} bytes"
            ),
        }
    }
}

impl Error for FixedValidatorProposalIntentErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConsensusValue(source) => Some(source),
            Self::Value(source) => Some(source),
            Self::RetainedCertificate(source) => Some(source),
            Self::State(source) => Some(source),
            Self::ProducerAuthorization(source) => Some(source),
            _ => None,
        }
    }
}
