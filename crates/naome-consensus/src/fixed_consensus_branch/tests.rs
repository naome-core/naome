use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag,
    ArtifactSetRoot,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use sha2::{Digest, Sha256};

use super::*;
use crate::{AgreementWeight, ConsensusGenesisId, ConsensusProtocolVersion};

fn key(byte: u8) -> ConsensusKey {
    ConsensusKey::from_bytes([byte; 32])
}

fn entry(byte: u8, weight: u128) -> ActiveAgreementEntry {
    ActiveAgreementEntry::new(key(byte), AgreementWeight::new(weight))
}

fn context(chain_id: ArtifactChainId) -> ConsensusContextV0 {
    ConsensusContextV0::new(
        chain_id,
        ConsensusGenesisId::from_bytes([0x71; 32]),
        ConsensusProtocolVersion::new(3),
    )
}

fn payload() -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn artifact_id_for(bytes: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap()
        .artifact_id()
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid lowercase hexadecimal test vector"),
        };
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    bytes
}

#[test]
fn genesis_binds_context_set_zero_priorities_and_virtual_artifact_state() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = context(definition.id());
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &[entry(2, 3), entry(1, 1)],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();

    assert_eq!(branch.context(), context);
    assert_eq!(branch.verified_height(), None);
    assert_eq!(branch.next_height().unwrap(), ConsensusHeight::new(1));
    assert_eq!(
        branch.ancestry_id(),
        ConsensusAncestryId::virtual_genesis(context)
    );
    assert!(branch.artifact_snapshot().is_virtual_genesis());

    let canonical =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 3)]).unwrap();
    assert_eq!(branch.fixed_agreement_set_id(), canonical.fixed_set_id());
    assert_eq!(branch.proposer_priority_state_id(), canonical.id());
}

#[test]
fn genesis_rejects_another_chain_before_snapshot_shape() {
    let expected = ArtifactChainDefinition::new([0x31; 32]);
    let actual = ArtifactChainDefinition::new([0x32; 32]);
    let error = FixedConsensusBranchV0::try_from_virtual_genesis(
        context(expected.id()),
        &[entry(1, 1)],
        ArtifactChainState::new(actual).branch_snapshot(),
    )
    .err()
    .unwrap();

    assert_eq!(
        error,
        FixedConsensusGenesisError::ArtifactChainMismatch {
            expected: expected.id(),
            actual: actual.id(),
        }
    );
}

#[test]
fn genesis_rejects_a_matching_chain_non_genesis_snapshot() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = context(definition.id());
    let payload = payload();
    let state = ArtifactChainState::new(definition);
    let block = state.prepare_block(artifact_id_for(&payload)).unwrap();
    let non_genesis = state
        .branch_snapshot()
        .validate_child(&block, payload)
        .unwrap();

    assert!(matches!(
        FixedConsensusBranchV0::try_from_virtual_genesis(context, &[entry(1, 1)], non_genesis,),
        Err(FixedConsensusGenesisError::ArtifactSnapshotNotVirtualGenesis)
    ));
}

#[test]
fn round_cursor_advances_sequentially_without_changing_the_height_base() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context(definition.id()),
        &[entry(1, 1), entry(2, 3)],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();

    let round_zero = branch.begin_round_zero().unwrap();
    let height_successor = round_zero.post_height_proposer_priority_state_id();
    assert_eq!(
        round_zero.position(),
        ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(0))
    );
    assert_eq!(round_zero.snapshot.position(), round_zero.position());
    assert_eq!(round_zero.proposer(), key(2));
    assert_eq!(
        round_zero.branch.proposer_priority_state_id(),
        branch.proposer_priority_state_id()
    );

    let round_one = round_zero.advance_round().unwrap();
    assert_eq!(round_one.position().round(), ConsensusRound::new(1));
    assert_eq!(round_one.proposer(), key(1));
    assert_eq!(
        round_one.post_height_proposer_priority_state_id(),
        height_successor
    );

    let round_two = round_one.advance_round().unwrap();
    assert_eq!(round_two.position().round(), ConsensusRound::new(2));
    assert_eq!(round_two.proposer(), key(2));
    assert_eq!(
        round_two.post_height_proposer_priority_state_id(),
        height_successor
    );
    assert_eq!(branch.verified_height(), None);
}

#[test]
fn empty_fixed_set_is_a_representable_halt_state() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context(definition.id()),
        &[],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();

    assert_eq!(
        branch.begin_round_zero().err(),
        Some(ProposerSelectionError::NoActiveValidators)
    );
}

#[test]
fn height_and_round_overflow_halt_without_wrapping() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let mut branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context(definition.id()),
        &[entry(1, 1)],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();
    branch.verified_height = Some(ConsensusHeight::new(u64::MAX));
    assert_eq!(
        branch.next_height(),
        Err(ProposerSelectionError::HeightExhausted)
    );

    branch.verified_height = None;
    let mut round = branch.begin_round_zero().unwrap();
    round.position = ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(u64::MAX));
    assert_eq!(
        round.advance_round().err(),
        Some(ProposerSelectionError::RoundExhausted)
    );
}

#[test]
fn complete_branch_state_commitment_layout_and_digest_are_exact() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = context(definition.id());
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &[entry(1, 1), entry(2, 3)],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x44; 32]),
        ArtifactSetRoot::from_bytes([0x55; 32]),
        ArtifactSetRoot::from_bytes([0x66; 32]),
        ArtifactId::from_bytes([0x77; 32]),
    );
    let value = round.value_for_artifact_block(block);
    let domain = b"naome:consensus-state-commitment:fixed-validator-artifact:v0\0";

    let mut preimage = Vec::new();
    preimage.extend_from_slice(context.chain_id().as_bytes());
    preimage.extend_from_slice(context.genesis_id().as_bytes());
    preimage.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    preimage.extend_from_slice(&round.position().height().value().to_be_bytes());
    preimage.extend_from_slice(branch.ancestry_id().as_bytes());
    preimage.extend_from_slice(&block.to_canonical_bytes());
    preimage.extend_from_slice(branch.fixed_agreement_set_id().as_bytes());
    preimage.extend_from_slice(round.post_height_proposer_priority_state_id().as_bytes());
    assert_eq!(domain.len(), 61);
    assert_eq!(preimage.len(), 300);

    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&preimage);
    let independent: [u8; 32] = hasher.finalize().into();
    assert_eq!(
        value.post_consensus_state_commitment().as_bytes(),
        &independent
    );
    assert_eq!(
        independent,
        hex_array::<32>("9ba91bcbf71c87f199f95cd833d70b3e3c10c22a25eac65ee93e0fd6cb74e728")
    );
}

#[test]
fn complete_branch_state_commitment_binds_every_top_level_component() {
    let context = ConsensusContextV0::new(
        ArtifactChainId::from_bytes([0x11; 32]),
        ConsensusGenesisId::from_bytes([0x22; 32]),
        ConsensusProtocolVersion::new(3),
    );
    let height = ConsensusHeight::new(9);
    let ancestry = ConsensusAncestryId::from_bytes([0x33; 32]);
    let block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x44; 32]),
        ArtifactSetRoot::from_bytes([0x55; 32]),
        ArtifactSetRoot::from_bytes([0x66; 32]),
        ArtifactId::from_bytes([0x77; 32]),
    );
    let proposer_state =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 3)]).unwrap();
    let base = derive_fixed_validator_artifact_state_commitment(
        context,
        height,
        ancestry,
        block,
        proposer_state.fixed_set_id(),
        proposer_state.id(),
    );

    let changed_contexts = [
        ConsensusContextV0::new(
            ArtifactChainId::from_bytes([0x12; 32]),
            context.genesis_id(),
            context.protocol_version(),
        ),
        ConsensusContextV0::new(
            context.chain_id(),
            ConsensusGenesisId::from_bytes([0x23; 32]),
            context.protocol_version(),
        ),
        ConsensusContextV0::new(
            context.chain_id(),
            context.genesis_id(),
            ConsensusProtocolVersion::new(4),
        ),
    ];
    for changed in changed_contexts {
        assert_ne!(
            derive_fixed_validator_artifact_state_commitment(
                changed,
                height,
                ancestry,
                block,
                proposer_state.fixed_set_id(),
                proposer_state.id(),
            ),
            base
        );
    }

    assert_ne!(
        derive_fixed_validator_artifact_state_commitment(
            context,
            ConsensusHeight::new(10),
            ancestry,
            block,
            proposer_state.fixed_set_id(),
            proposer_state.id(),
        ),
        base
    );
    assert_ne!(
        derive_fixed_validator_artifact_state_commitment(
            context,
            height,
            ConsensusAncestryId::from_bytes([0x34; 32]),
            block,
            proposer_state.fixed_set_id(),
            proposer_state.id(),
        ),
        base
    );

    let changed_blocks = [
        ArtifactBlock::new(
            ArtifactBlockId::from_bytes([0x45; 32]),
            block.previous_artifact_set_root(),
            block.resulting_artifact_set_root(),
            block.artifact_id(),
        ),
        ArtifactBlock::new(
            block.parent_block_id(),
            ArtifactSetRoot::from_bytes([0x56; 32]),
            block.resulting_artifact_set_root(),
            block.artifact_id(),
        ),
        ArtifactBlock::new(
            block.parent_block_id(),
            block.previous_artifact_set_root(),
            ArtifactSetRoot::from_bytes([0x67; 32]),
            block.artifact_id(),
        ),
        ArtifactBlock::new(
            block.parent_block_id(),
            block.previous_artifact_set_root(),
            block.resulting_artifact_set_root(),
            ArtifactId::from_bytes([0x78; 32]),
        ),
    ];
    for changed in changed_blocks {
        assert_ne!(
            derive_fixed_validator_artifact_state_commitment(
                context,
                height,
                ancestry,
                changed,
                proposer_state.fixed_set_id(),
                proposer_state.id(),
            ),
            base
        );
    }

    let changed_set =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 4)]).unwrap();
    assert_ne!(
        derive_fixed_validator_artifact_state_commitment(
            context,
            height,
            ancestry,
            block,
            changed_set.fixed_set_id(),
            changed_set.id(),
        ),
        base
    );
    let (_, changed_priorities) = proposer_state.select_next().unwrap();
    assert_ne!(
        derive_fixed_validator_artifact_state_commitment(
            context,
            height,
            ancestry,
            block,
            proposer_state.fixed_set_id(),
            changed_priorities.id(),
        ),
        base
    );
}
