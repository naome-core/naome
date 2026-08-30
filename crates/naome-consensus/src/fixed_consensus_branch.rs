//! Typed fixed-validator branch and sequential proposer-round authority.

use std::error::Error;
use std::fmt;

use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainBranchSnapshot, ArtifactChainId, ArtifactSetRoot,
};

use super::consensus_value::{
    VerifiedConsensusEnvelopeV0, derive_fixed_validator_artifact_state_commitment,
};
use super::proposer_selection::FixedProposerStateV0;
use super::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, ActiveAgreementSnapshotError,
    ConsensusAncestryId, ConsensusContextV0, ConsensusEnvelopeId, ConsensusEnvelopeVerifyError,
    ConsensusHeight, ConsensusKey, ConsensusPosition, ConsensusRound, ConsensusValueV0,
    FixedAgreementSetId, ProposerPriorityStateId, ProposerSelectionError,
    VerifiedPrecommitCertificateV0, VerifiedProducerAuthorizationV0,
};

/// One immutable in-memory fixed-validator consensus branch.
///
/// The only public root constructor accepts an exact virtual-genesis artifact
/// snapshot and initializes canonical zero proposer priorities. Later branch
/// states are published only by a successfully verified direct-child
/// transition. This state is intentionally branchable and establishes no
/// canonical selection, durable finality, persistence, restart recovery,
/// networking, peer trust, or validator-set transition authority.
#[derive(Clone)]
#[must_use]
pub struct FixedConsensusBranchV0 {
    context: ConsensusContextV0,
    verified_height: Option<ConsensusHeight>,
    ancestry_id: ConsensusAncestryId,
    artifact_snapshot: ArtifactChainBranchSnapshot,
    proposer_base: FixedProposerStateV0,
}

/// Complete semantic coordinate of one fixed-validator consensus branch.
///
/// The coordinate binds every parent component needed to reject a verified
/// transition prepared from another branch. It is descriptive identity only:
/// callers cannot construct it from raw fields, and possessing one does not
/// establish selection, finality, persistence, or signing authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct FixedConsensusBranchCoordinateV0 {
    context: ConsensusContextV0,
    verified_height: Option<ConsensusHeight>,
    ancestry_id: ConsensusAncestryId,
    artifact_head_block_id: ArtifactBlockId,
    artifact_set_root: ArtifactSetRoot,
    fixed_agreement_set_id: FixedAgreementSetId,
    proposer_priority_state_id: ProposerPriorityStateId,
}

impl FixedConsensusBranchCoordinateV0 {
    /// Returns the exact consensus context.
    pub const fn context(self) -> ConsensusContextV0 {
        self.context
    }

    /// Returns the last verified height, or `None` at virtual genesis.
    pub const fn verified_height(self) -> Option<ConsensusHeight> {
        self.verified_height
    }

    /// Returns the exact consensus ancestry identity.
    pub const fn ancestry_id(self) -> ConsensusAncestryId {
        self.ancestry_id
    }

    /// Returns the artifact block at this branch's exact head.
    pub const fn artifact_head_block_id(self) -> ArtifactBlockId {
        self.artifact_head_block_id
    }

    /// Returns the authenticated artifact-set root at this branch's exact head.
    pub const fn artifact_set_root(self) -> ArtifactSetRoot {
        self.artifact_set_root
    }

    /// Returns the immutable fixed validator-set identity.
    pub const fn fixed_agreement_set_id(self) -> FixedAgreementSetId {
        self.fixed_agreement_set_id
    }

    /// Returns the proposer-priority base identity for the next height.
    pub const fn proposer_priority_state_id(self) -> ProposerPriorityStateId {
        self.proposer_priority_state_id
    }
}

impl FixedConsensusBranchV0 {
    /// Constructs one caller-selected fixed set at an exact artifact virtual genesis.
    ///
    /// The context and fixed entries remain explicit caller authority. This
    /// constructor proves only their structural consistency and does not prove
    /// that either was globally selected or durably configured.
    pub fn try_from_virtual_genesis(
        context: ConsensusContextV0,
        fixed_entries: &[ActiveAgreementEntry],
        artifact_genesis: ArtifactChainBranchSnapshot,
    ) -> Result<Self, FixedConsensusGenesisError> {
        if artifact_genesis.chain_id() != context.chain_id() {
            return Err(FixedConsensusGenesisError::ArtifactChainMismatch {
                expected: context.chain_id(),
                actual: artifact_genesis.chain_id(),
            });
        }
        if !artifact_genesis.is_virtual_genesis() {
            return Err(FixedConsensusGenesisError::ArtifactSnapshotNotVirtualGenesis);
        }

        let proposer_base = FixedProposerStateV0::try_from_preselected(fixed_entries)
            .map_err(FixedConsensusGenesisError::AgreementSnapshot)?;
        Ok(Self {
            context,
            verified_height: None,
            ancestry_id: ConsensusAncestryId::virtual_genesis(context),
            artifact_snapshot: artifact_genesis,
            proposer_base,
        })
    }

    /// Returns the exact caller-selected consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.context
    }

    /// Returns the last verified height, or `None` at virtual genesis.
    pub const fn verified_height(&self) -> Option<ConsensusHeight> {
        self.verified_height
    }

    /// Returns the exact ancestry required by the next direct child.
    pub const fn ancestry_id(&self) -> ConsensusAncestryId {
        self.ancestry_id
    }

    /// Returns the immutable artifact state required by the next direct child.
    pub const fn artifact_snapshot(&self) -> &ArtifactChainBranchSnapshot {
        &self.artifact_snapshot
    }

    /// Returns the identity of the immutable fixed validator key-and-weight set.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.proposer_base.fixed_set_id()
    }

    /// Returns the next height's exact proposer-priority base identity.
    pub const fn proposer_priority_state_id(&self) -> ProposerPriorityStateId {
        self.proposer_base.id()
    }

    /// Returns this branch's complete semantic parent coordinate.
    pub fn coordinate(&self) -> FixedConsensusBranchCoordinateV0 {
        FixedConsensusBranchCoordinateV0 {
            context: self.context,
            verified_height: self.verified_height,
            ancestry_id: self.ancestry_id,
            artifact_head_block_id: self.artifact_snapshot.head_block_id(),
            artifact_set_root: self.artifact_snapshot.artifact_set_root(),
            fixed_agreement_set_id: self.proposer_base.fixed_set_id(),
            proposer_priority_state_id: self.proposer_base.id(),
        }
    }

    /// Returns the exact next positive child height.
    pub fn next_height(&self) -> Result<ConsensusHeight, ProposerSelectionError> {
        match self.verified_height {
            None => Ok(ConsensusHeight::new(1)),
            Some(height) => height
                .value()
                .checked_add(1)
                .map(ConsensusHeight::new)
                .ok_or(ProposerSelectionError::HeightExhausted),
        }
    }

    /// Derives round zero for the exact next height without changing this branch.
    ///
    /// The first smooth weighted-round-robin step determines both round zero's
    /// proposer and the base carried to the following height. Later rounds
    /// advance only a round-local copy of that result.
    pub fn begin_round_zero(&self) -> Result<FixedConsensusRoundV0<'_>, ProposerSelectionError> {
        let height = self.next_height()?;
        let position = ConsensusPosition::new(height, ConsensusRound::new(0));
        let (proposer, height_successor_base) = self.proposer_base.select_next()?;
        let snapshot = height_successor_base.positioned_snapshot(position);
        Ok(FixedConsensusRoundV0 {
            branch: self,
            position,
            snapshot,
            proposer,
            round_state: height_successor_base.clone(),
            height_successor_base,
        })
    }
}

/// One exact sequential round cursor derived from a fixed consensus branch.
///
/// Callers cannot choose its height, round, snapshot, proposer, or priority
/// state. Advancing applies exactly one additional round-local proposer step;
/// there is no random-access round constructor or attacker-sized loop.
#[must_use]
pub struct FixedConsensusRoundV0<'branch> {
    branch: &'branch FixedConsensusBranchV0,
    position: ConsensusPosition,
    snapshot: ActiveAgreementSnapshot,
    proposer: ConsensusKey,
    round_state: FixedProposerStateV0,
    height_successor_base: FixedProposerStateV0,
}

impl<'branch> FixedConsensusRoundV0<'branch> {
    /// Returns the exact derived height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact derived proposer.
    pub const fn proposer(&self) -> ConsensusKey {
        self.proposer
    }

    /// Returns the proposer-priority base carried to the next height on success.
    ///
    /// This identity is anchored to the first proposer step for this height and
    /// is therefore unchanged by later round-local advancement.
    pub const fn post_height_proposer_priority_state_id(&self) -> ProposerPriorityStateId {
        self.height_successor_base.id()
    }

    /// Constructs the sole evidence-free value for one candidate artifact block.
    ///
    /// This binds the exact branch context, direct child height, parent ancestry,
    /// fixed agreement set, and once-per-height proposer successor. It does not
    /// validate the artifact block or select the resulting value.
    pub fn value_for_artifact_block(&self, artifact_block: ArtifactBlock) -> ConsensusValueV0 {
        let commitment = derive_fixed_validator_artifact_state_commitment(
            self.branch.context,
            self.position.height(),
            self.branch.ancestry_id,
            artifact_block,
            self.height_successor_base.fixed_set_id(),
            self.height_successor_base.id(),
        );
        ConsensusValueV0::try_new(
            self.branch.context,
            self.position.height(),
            self.branch.ancestry_id,
            artifact_block,
            commitment,
        )
        .expect("a branch-derived round always has a positive child height")
    }

    /// Advances this cursor by exactly one round-local proposer step.
    pub fn advance_round(mut self) -> Result<Self, ProposerSelectionError> {
        let next_round = self
            .position
            .round()
            .value()
            .checked_add(1)
            .map(ConsensusRound::new)
            .ok_or(ProposerSelectionError::RoundExhausted)?;
        let (proposer, round_state) = self.round_state.select_next()?;
        self.position = ConsensusPosition::new(self.position.height(), next_round);
        self.snapshot = round_state.positioned_snapshot(self.position);
        self.proposer = proposer;
        self.round_state = round_state;
        Ok(self)
    }

    /// Strictly verifies one complete envelope as this branch's exact child.
    ///
    /// Context, height, ancestry, proposer, active snapshot, the complete
    /// fixed-validator artifact-only V0 branch-state projection, and artifact
    /// parent are derived from this cursor and cannot be independently supplied.
    /// Success remains an immutable, branch-relative in-memory result rather
    /// than installed finality.
    pub fn decode_and_verify<'round>(
        &'round self,
        bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<VerifiedFixedConsensusTransitionV0<'round, 'branch>, ConsensusEnvelopeVerifyError>
    where
        'branch: 'round,
    {
        let value = VerifiedConsensusEnvelopeV0::decode_value(bytes)?;
        let expected_commitment = derive_fixed_validator_artifact_state_commitment(
            self.branch.context,
            self.position.height(),
            self.branch.ancestry_id,
            value.artifact_block(),
            self.height_successor_base.fixed_set_id(),
            self.height_successor_base.id(),
        );
        let expected_prior_ancestry = self.branch.verified_height.map(|_| self.branch.ancestry_id);
        let envelope = VerifiedConsensusEnvelopeV0::decode_and_verify(
            bytes,
            self.branch.context,
            self.proposer,
            &self.snapshot,
            expected_prior_ancestry,
            expected_commitment,
            &self.branch.artifact_snapshot,
            canonical_artifact_bytes,
        )?;
        Ok(VerifiedFixedConsensusTransitionV0 {
            round: self,
            envelope,
        })
    }
}

/// One complete envelope verified against a typed fixed consensus branch.
///
/// The result borrows the exact round cursor that supplied its proposer and
/// active snapshot. Consuming it publishes a separate immutable child branch;
/// the parent and cursor remain unchanged and reusable for sibling candidates.
#[must_use]
pub struct VerifiedFixedConsensusTransitionV0<'round, 'branch> {
    round: &'round FixedConsensusRoundV0<'branch>,
    envelope: VerifiedConsensusEnvelopeV0<'round>,
}

/// One owned, sealed transition produced by complete typed branch verification.
///
/// This transferable result retains the exact canonical envelope and artifact
/// payload together with its semantic parent coordinate and immutable child.
/// Its fields are private and it has no raw constructor, so downstream storage
/// can require this proof object without accepting caller-assembled authority.
#[must_use]
pub struct OwnedVerifiedFixedConsensusTransitionV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    value: ConsensusValueV0,
    envelope_id: ConsensusEnvelopeId,
    canonical_envelope_bytes: Vec<u8>,
    canonical_artifact_bytes: Vec<u8>,
    child_branch: FixedConsensusBranchV0,
}

impl OwnedVerifiedFixedConsensusTransitionV0 {
    /// Returns the exact semantic branch coordinate used during verification.
    pub const fn parent_coordinate(&self) -> FixedConsensusBranchCoordinateV0 {
        self.parent_coordinate
    }

    /// Returns the exact authenticated height and round of this transition.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the verified evidence-free value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the evidence-variant identity of the complete envelope.
    pub const fn envelope_id(&self) -> ConsensusEnvelopeId {
        self.envelope_id
    }

    /// Returns the exact canonical envelope bytes that were verified.
    pub fn canonical_envelope_bytes(&self) -> &[u8] {
        &self.canonical_envelope_bytes
    }

    /// Returns the exact canonical artifact payload verified with the envelope.
    pub fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes
    }

    /// Consumes this proof and publishes its immutable child branch.
    pub fn into_branch(self) -> FixedConsensusBranchV0 {
        self.child_branch
    }
}

impl VerifiedFixedConsensusTransitionV0<'_, '_> {
    /// Smallest canonical envelope width, containing one precommit signer.
    pub const MIN_BYTE_LENGTH: usize = VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH;

    /// Largest canonical envelope width, containing 256 precommit signers.
    pub const MAX_BYTE_LENGTH: usize = VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH;

    /// Returns the exact verified evidence-free value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.envelope.value()
    }

    /// Returns the round-specific complete-envelope identity.
    pub const fn envelope_id(&self) -> ConsensusEnvelopeId {
        self.envelope.id()
    }

    /// Returns the verified producer authorization.
    pub const fn producer_authorization(&self) -> &VerifiedProducerAuthorizationV0<'_> {
        self.envelope.producer_authorization()
    }

    /// Returns the verified non-nil precommit certificate.
    pub const fn precommit_certificate(&self) -> &VerifiedPrecommitCertificateV0<'_> {
        self.envelope.precommit_certificate()
    }

    /// Returns the immutable artifact successor before consuming this result.
    pub const fn artifact_successor(&self) -> &ArtifactChainBranchSnapshot {
        self.envelope.artifact_successor()
    }

    /// Re-encodes the complete verified envelope byte-identically.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.envelope.to_canonical_bytes()
    }

    /// Consumes this borrowed proof into a transferable sealed transition.
    ///
    /// The owned result preserves the exact parent coordinate and both byte
    /// inputs admitted by the same verification operation. It remains only a
    /// branch-relative proof and does not itself install durable finality.
    pub fn into_owned(self) -> OwnedVerifiedFixedConsensusTransitionV0 {
        let parent_coordinate = self.round.branch.coordinate();
        let position = self.round.position;
        let (
            value,
            envelope_id,
            canonical_envelope_bytes,
            canonical_artifact_bytes,
            artifact_snapshot,
        ) = self.envelope.into_owned_components();
        let child_branch = FixedConsensusBranchV0 {
            context: self.round.branch.context,
            verified_height: Some(value.height()),
            ancestry_id: value.ancestry_id(),
            artifact_snapshot,
            proposer_base: self.round.height_successor_base.clone(),
        };
        OwnedVerifiedFixedConsensusTransitionV0 {
            parent_coordinate,
            position,
            value,
            envelope_id,
            canonical_envelope_bytes,
            canonical_artifact_bytes,
            child_branch,
        }
    }

    /// Consumes this verified transition and publishes its immutable child branch.
    ///
    /// The next height carries the proposer base derived by exactly the round-
    /// zero step, regardless of the later round whose evidence authenticated the
    /// unchanged value.
    pub fn into_branch(self) -> FixedConsensusBranchV0 {
        self.into_owned().into_branch()
    }
}

/// A failure to construct one fixed consensus branch at virtual genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedConsensusGenesisError {
    /// The artifact snapshot belongs to another chain.
    ArtifactChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// The matching-chain artifact snapshot is not its exact empty virtual genesis.
    ArtifactSnapshotNotVirtualGenesis,
    /// The caller-selected fixed validator entries are invalid.
    AgreementSnapshot(ActiveAgreementSnapshotError),
}

impl fmt::Display for FixedConsensusGenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactChainMismatch { expected, actual } => write!(
                formatter,
                "consensus genesis artifact chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactSnapshotNotVirtualGenesis => formatter.write_str(
                "consensus genesis requires the exact empty artifact virtual-genesis snapshot",
            ),
            Self::AgreementSnapshot(error) => error.fmt(formatter),
        }
    }
}

impl Error for FixedConsensusGenesisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AgreementSnapshot(error) => Some(error),
            Self::ArtifactChainMismatch { .. } | Self::ArtifactSnapshotNotVirtualGenesis => None,
        }
    }
}

#[cfg(test)]
#[path = "fixed_consensus_branch/tests.rs"]
mod tests;
