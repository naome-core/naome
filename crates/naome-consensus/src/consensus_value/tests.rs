use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{
    ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag, ArtifactSetRoot,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
use crate::{
    ActiveAgreementEntry, AgreementWeight, CONSENSUS_KEY_BYTES, ConsensusRound,
    FixedConsensusBranchV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateV0,
};

const AUTHORIZATION_BODY_BYTES: usize = 116;
const AUTHORIZATION_PROPOSER_OFFSET: usize = AUTHORIZATION_BODY_BYTES;
const AUTHORIZATION_SIGNATURE_OFFSET: usize = AUTHORIZATION_PROPOSER_OFFSET + CONSENSUS_KEY_BYTES;
const VOTE_BODY_BYTES: usize = 118;
const CERTIFICATE_COUNT_OFFSET: usize = VOTE_BODY_BYTES;
const CERTIFICATE_ENTRIES_OFFSET: usize = CERTIFICATE_COUNT_OFFSET + 2;

fn context(chain_id: ArtifactChainId, genesis: u8, version: u32) -> ConsensusContextV0 {
    ConsensusContextV0::new(
        chain_id,
        ConsensusGenesisId::from_bytes([genesis; ConsensusGenesisId::BYTE_LENGTH]),
        ConsensusProtocolVersion::new(version),
    )
}

fn position(height: u64, round: u64) -> ConsensusPosition {
    ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round))
}

fn signing_key(index: u16) -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    seed[2] = 0xa5;
    SigningKey::from_bytes(&seed)
}

fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

fn snapshot(
    position: ConsensusPosition,
    weighted_keys: &[(&SigningKey, u128)],
) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        position,
        &weighted_keys
            .iter()
            .map(|(key, weight)| {
                ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(*weight))
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    proposer: &SigningKey,
) -> [u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH] {
    let mut body = [0_u8; AUTHORIZATION_BODY_BYTES];
    body[..32].copy_from_slice(context.chain_id().as_bytes());
    body[32..64].copy_from_slice(context.genesis_id().as_bytes());
    body[64..68].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[68..76].copy_from_slice(&position.height().value().to_be_bytes());
    body[76..84].copy_from_slice(&position.round().value().to_be_bytes());
    body[84..].copy_from_slice(root.as_bytes());

    let proposer_key = consensus_key(proposer);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"naome:consensus-producer-authorization:v0\0");
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(proposer_key.as_bytes());
    let signature = proposer.sign(&transcript).to_bytes();

    let mut bytes = [0_u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body);
    bytes[AUTHORIZATION_PROPOSER_OFFSET..AUTHORIZATION_SIGNATURE_OFFSET]
        .copy_from_slice(proposer_key.as_bytes());
    bytes[AUTHORIZATION_SIGNATURE_OFFSET..].copy_from_slice(&signature);
    bytes
}

fn certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    signers: &[&SigningKey],
) -> Vec<u8> {
    quorum_certificate_bytes(
        context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        signers,
    )
}

fn quorum_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signers: &[&SigningKey],
) -> Vec<u8> {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => {
            body[85] = 0;
        }
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }

    let mut signers = signers.to_vec();
    signers.sort_unstable_by_key(|signer| consensus_key(signer));
    let mut bytes = Vec::with_capacity(CERTIFICATE_ENTRIES_OFFSET + signers.len() * 96);
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&u16::try_from(signers.len()).unwrap().to_be_bytes());
    for signer in signers {
        let key = consensus_key(signer);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(match role {
            ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0".as_slice(),
            ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0".as_slice(),
        });
        transcript.extend_from_slice(&body);
        transcript.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    }
    bytes
}

fn proposal_control_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
    valid_round_certificate: Option<&[u8]>,
) -> Vec<u8> {
    let authorization = authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        proposer,
    );
    let mut bytes = Vec::with_capacity(
        ConsensusValueV0::BYTE_LENGTH
            + authorization.len()
            + 1
            + valid_round_certificate.map_or(0, <[u8]>::len),
    );
    bytes.extend_from_slice(&value.to_canonical_bytes());
    bytes.extend_from_slice(&authorization);
    match valid_round_certificate {
        Some(certificate) => {
            bytes.push(1);
            bytes.extend_from_slice(certificate);
        }
        None => bytes.push(0),
    }
    bytes
}

fn envelope_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
    certificate_signers: &[&SigningKey],
) -> Vec<u8> {
    envelope_bytes_with_roots(
        value,
        position,
        proposer,
        certificate_signers,
        value.proposal_signing_root(),
        value.proposal_signing_root(),
    )
}

fn envelope_bytes_with_roots(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
    certificate_signers: &[&SigningKey],
    authorization_root: ProposalSigningRoot,
    certificate_root: ProposalSigningRoot,
) -> Vec<u8> {
    let authorization =
        authorization_bytes(value.context(), position, authorization_root, proposer);
    let certificate = certificate_bytes(
        value.context(),
        position,
        certificate_root,
        certificate_signers,
    );
    let mut bytes =
        Vec::with_capacity(ConsensusValueV0::BYTE_LENGTH + authorization.len() + certificate.len());
    bytes.extend_from_slice(&value.to_canonical_bytes());
    bytes.extend_from_slice(&authorization);
    bytes.extend_from_slice(&certificate);
    bytes
}

fn proof_payload(axiom: ZfcAxiom) -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn artifact_id_for(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

struct Fixture {
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposer: SigningKey,
    snapshot: ActiveAgreementSnapshot,
    value: ConsensusValueV0,
    parent: ArtifactChainBranchSnapshot,
    payload: Vec<u8>,
    expected_state: ConsensusStateCommitment,
    bytes: Vec<u8>,
}

fn fixture(round: u64) -> Fixture {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = context(definition.id(), 0x42, 7);
    let position = position(1, round);
    let proposer = signing_key(1);
    let snapshot = snapshot(position, &[(&proposer, 1)]);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let state = ArtifactChainState::new(definition);
    let block = state.prepare_block(artifact_id_for(&payload)).unwrap();
    let parent = state.branch_snapshot();
    let expected_state = ConsensusStateCommitment::from_bytes([0x53; 32]);
    let value = ConsensusValueV0::try_new(
        context,
        position.height(),
        ConsensusAncestryId::virtual_genesis(context),
        block,
        expected_state,
    )
    .unwrap();
    let bytes = envelope_bytes(value, position, &proposer, &[&proposer]);
    Fixture {
        context,
        position,
        proposer,
        snapshot,
        value,
        parent,
        payload,
        expected_state,
        bytes,
    }
}

fn verify_fixture<'snapshot>(
    fixture: &'snapshot Fixture,
    bytes: &[u8],
    payload: Vec<u8>,
) -> Result<VerifiedConsensusEnvelopeV0<'snapshot>, ConsensusEnvelopeVerifyError> {
    VerifiedConsensusEnvelopeV0::decode_and_verify(
        bytes,
        fixture.context,
        consensus_key(&fixture.proposer),
        &fixture.snapshot,
        None,
        fixture.expected_state,
        &fixture.parent,
        payload,
    )
}

fn verify_proposal_fixture<'snapshot>(
    fixture: &'snapshot Fixture,
    bytes: &[u8],
    payload: Vec<u8>,
) -> Result<VerifiedConsensusProposalV0<'snapshot>, ConsensusProposalVerifyError> {
    VerifiedConsensusProposalV0::decode_and_verify(
        bytes,
        fixture.context,
        consensus_key(&fixture.proposer),
        &fixture.snapshot,
        None,
        fixture.expected_state,
        &fixture.parent,
        payload,
        |proof_position| snapshot(proof_position, &[(&fixture.proposer, 1)]),
    )
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

fn golden_value() -> ConsensusValueV0 {
    ConsensusValueV0::try_new(
        context(ArtifactChainId::from_bytes([0x11; 32]), 0x22, 0x0102_0304),
        ConsensusHeight::new(0x0102_0304_0506_0708),
        ConsensusAncestryId::from_bytes([0x33; 32]),
        ArtifactBlock::new(
            ArtifactBlockId::from_bytes([0x44; 32]),
            ArtifactSetRoot::from_bytes([0x55; 32]),
            ArtifactSetRoot::from_bytes([0x66; 32]),
            ArtifactId::from_bytes([0x77; 32]),
        ),
        ConsensusStateCommitment::from_bytes([0x88; 32]),
    )
    .unwrap()
}

#[test]
fn fixed_value_layout_and_domain_hashes_have_independent_goldens() {
    let value = golden_value();
    let bytes = value.to_canonical_bytes();
    assert_eq!(ConsensusValueV0::BYTE_LENGTH, 268);
    assert_eq!(&bytes[0..32], &[0x11; 32]);
    assert_eq!(&bytes[32..64], &[0x22; 32]);
    assert_eq!(&bytes[64..68], &0x0102_0304_u32.to_be_bytes());
    assert_eq!(&bytes[68..76], &0x0102_0304_0506_0708_u64.to_be_bytes());
    assert_eq!(&bytes[76..108], &[0x33; 32]);
    assert_eq!(&bytes[108..140], &[0x44; 32]);
    assert_eq!(&bytes[140..172], &[0x55; 32]);
    assert_eq!(&bytes[172..204], &[0x66; 32]);
    assert_eq!(&bytes[204..236], &[0x77; 32]);
    assert_eq!(&bytes[236..268], &[0x88; 32]);
    assert_eq!(ConsensusValueV0::from_canonical_bytes(&bytes), Ok(value));
    assert_eq!(
        value.proposal_signing_root().as_bytes(),
        &hex_array::<32>("78e4be2276389085c7e3541d37b93626d077dfc5e737886078c7d0702489120b")
    );
    assert_eq!(
        value.ancestry_id().as_bytes(),
        &hex_array::<32>("d051b3d3da623c952df59d4ad81c35c8968a4dfb8da5a4343fb4a9d8f76ddded")
    );
    assert_eq!(
        ConsensusAncestryId::virtual_genesis(value.context()).as_bytes(),
        &hex_array::<32>("2f17b4dc216011b82cf5cb518767af514520a291709a8b48daf80367d76ccbe5")
    );
    let signer = signing_key(1);
    let envelope = envelope_bytes(
        value,
        position(value.height().value(), 0x1112_1314_1516_1718),
        &signer,
        &[&signer],
    );
    assert_eq!(envelope.len(), VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH);
    assert_eq!(
        domain_hash(CONSENSUS_ENVELOPE_DOMAIN, &envelope),
        hex_array::<32>("9841e8ac33a8bf53044731ea519eceacc0e60e66d0ff9a562e1236502c8e6982")
    );
}

#[test]
fn value_rejects_every_other_length_and_reserved_height() {
    let mut bytes = golden_value().to_canonical_bytes().to_vec();
    for length in 0..ConsensusValueV0::BYTE_LENGTH {
        assert_eq!(
            ConsensusValueV0::from_canonical_bytes(&bytes[..length]),
            Err(ConsensusValueError::InvalidLength {
                actual: length,
                expected: ConsensusValueV0::BYTE_LENGTH,
            })
        );
    }
    bytes.push(0);
    assert_eq!(
        ConsensusValueV0::from_canonical_bytes(&bytes),
        Err(ConsensusValueError::InvalidLength {
            actual: ConsensusValueV0::BYTE_LENGTH + 1,
            expected: ConsensusValueV0::BYTE_LENGTH,
        })
    );
    assert_eq!(
        ConsensusValueV0::try_new(
            golden_value().context(),
            ConsensusHeight::new(0),
            golden_value().parent_ancestry_id(),
            golden_value().artifact_block(),
            golden_value().post_consensus_state_commitment(),
        ),
        Err(ConsensusValueError::ReservedGenesisHeight)
    );
}

#[test]
fn minimum_envelope_verifies_reencodes_and_advances_only_its_snapshot() {
    let fixture = fixture(9);
    let predecessor_head = fixture.parent.head_block_id();
    let predecessor_root = fixture.parent.artifact_set_root();
    let verified = verify_fixture(&fixture, &fixture.bytes, fixture.payload.clone()).unwrap();

    assert_eq!(VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH, 696);
    assert_eq!(VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH, 25_176);
    assert_eq!(
        fixture.bytes.len(),
        VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH
    );
    assert_eq!(verified.value(), fixture.value);
    assert_eq!(
        verified.producer_authorization().position(),
        fixture.position
    );
    assert_eq!(verified.to_canonical_bytes(), fixture.bytes);
    assert_eq!(
        verified.id().as_bytes(),
        &domain_hash(b"naome:consensus-envelope:v0\0", &fixture.bytes)
    );
    assert_eq!(
        verified.id().as_bytes(),
        &hex_array::<32>("7a2e661ea2badef8f9c9424370edd4369f84de6ee2a83bc12f1adb2d998a77e7")
    );
    assert_eq!(
        verified.artifact_successor().head_block_id(),
        fixture.value.artifact_block().id()
    );
    assert_eq!(
        verified.artifact_successor().artifact_set_root(),
        fixture.value.artifact_block().resulting_artifact_set_root()
    );
    assert_eq!(fixture.parent.head_block_id(), predecessor_head);
    assert_eq!(fixture.parent.artifact_set_root(), predecessor_root);
}

#[test]
fn every_minimum_envelope_byte_is_bound_or_strictly_checked() {
    let fixture = fixture(3);
    assert_eq!(fixture.bytes.len(), 696);
    for index in 0..fixture.bytes.len() {
        let mut mutated = fixture.bytes.clone();
        mutated[index] ^= 1;
        assert!(
            verify_fixture(&fixture, &mutated, fixture.payload.clone()).is_err(),
            "mutated envelope byte {index} was accepted"
        );
    }
    assert_ne!(
        fixture.parent.head_block_id(),
        fixture.value.artifact_block().id()
    );
}

#[test]
fn envelope_bounds_precede_child_decoding() {
    let fixture = fixture(4);
    for length in 0..VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH {
        assert!(matches!(
            verify_fixture(&fixture, &fixture.bytes[..length], fixture.payload.clone()),
            Err(ConsensusEnvelopeVerifyError::InvalidLength { actual, minimum })
                if actual == length && minimum == VerifiedConsensusEnvelopeV0::MIN_BYTE_LENGTH
        ));
    }

    let mut trailing = fixture.bytes.clone();
    trailing.push(0);
    assert!(matches!(
        verify_fixture(&fixture, &trailing, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificate(
            PrecommitCertificateVerifyError::LengthMismatch { .. }
        ))
    ));

    let oversized = vec![0_u8; VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        verify_fixture(&fixture, &oversized, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::InputTooLong { actual, maximum })
            if actual == VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH + 1
                && maximum == VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH
    ));
}

#[test]
fn caller_context_parent_and_state_checks_precede_evidence() {
    let fixture = fixture(5);
    let other_context = context(ArtifactChainId::from_bytes([0xee; 32]), 0x42, 7);
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            other_context,
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ChainIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            context(fixture.context.chain_id(), 0x43, 7),
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::GenesisIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            context(fixture.context.chain_id(), 0x42, 8),
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ProtocolVersionMismatch { .. })
    ));
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            Some(ConsensusAncestryId::from_bytes([0xaa; 32])),
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::UnexpectedPriorAncestryAtFirstHeight { actual })
            if actual == ConsensusAncestryId::from_bytes([0xaa; 32])
    ));
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            None,
            ConsensusStateCommitment::from_bytes([0xbb; 32]),
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::PostConsensusStateCommitmentMismatch {
            expected,
            actual,
        })
            if expected == ConsensusStateCommitment::from_bytes([0xbb; 32])
                && actual == fixture.expected_state
    ));

    let wrong_parent_value = ConsensusValueV0::try_new(
        fixture.context,
        fixture.position.height(),
        ConsensusAncestryId::from_bytes([0xa5; 32]),
        fixture.value.artifact_block(),
        fixture.expected_state,
    )
    .unwrap();
    let wrong_parent_bytes = envelope_bytes(
        wrong_parent_value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
    );
    assert!(matches!(
        verify_fixture(&fixture, &wrong_parent_bytes, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ParentAncestryMismatch { .. })
    ));
}

#[test]
fn later_height_requires_the_exact_caller_expected_parent() {
    let base = fixture(6);
    let parent = ConsensusAncestryId::from_bytes([0x91; 32]);
    let value = ConsensusValueV0::try_new(
        base.context,
        ConsensusHeight::new(2),
        parent,
        base.value.artifact_block(),
        base.expected_state,
    )
    .unwrap();
    let position = position(2, 6);
    let snapshot = snapshot(position, &[(&base.proposer, 1)]);
    let bytes = envelope_bytes(value, position, &base.proposer, &[&base.proposer]);

    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &bytes,
            base.context,
            consensus_key(&base.proposer),
            &snapshot,
            None,
            base.expected_state,
            &base.parent,
            base.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::MissingPriorAncestry { height })
            if height == ConsensusHeight::new(2)
    ));
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &bytes,
            base.context,
            consensus_key(&base.proposer),
            &snapshot,
            Some(ConsensusAncestryId::from_bytes([0x92; 32])),
            base.expected_state,
            &base.parent,
            base.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ParentAncestryMismatch { .. })
    ));
    let verified = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &bytes,
        base.context,
        consensus_key(&base.proposer),
        &snapshot,
        Some(parent),
        base.expected_state,
        &base.parent,
        base.payload,
    )
    .unwrap();
    assert_eq!(verified.value().parent_ancestry_id(), parent);
}

#[test]
fn producer_and_precommit_roots_join_only_to_the_derived_value_root() {
    let fixture = fixture(7);
    let wrong = ProposalSigningRoot::from_bytes([0xcc; 32]);

    let wrong_authorization = envelope_bytes_with_roots(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
        wrong,
        fixture.value.proposal_signing_root(),
    );
    assert!(matches!(
        verify_fixture(&fixture, &wrong_authorization, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ProducerAuthorizationRootMismatch { .. })
    ));

    let wrong_certificate = envelope_bytes_with_roots(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
        fixture.value.proposal_signing_root(),
        wrong,
    );
    assert!(matches!(
        verify_fixture(&fixture, &wrong_certificate, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificateRootMismatch { .. })
    ));

    let both_wrong = envelope_bytes_with_roots(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
        wrong,
        wrong,
    );
    assert!(matches!(
        verify_fixture(&fixture, &both_wrong, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ProducerAuthorizationRootMismatch { .. })
    ));
}

#[test]
fn envelope_rejects_mixed_positions_snapshots_and_proposer_authority() {
    let fixture = fixture(11);
    let later_position = position(
        fixture.position.height().value(),
        fixture.position.round().value() + 1,
    );
    let later_snapshot = snapshot(later_position, &[(&fixture.proposer, 1)]);

    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&fixture.proposer),
            &later_snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ProducerAuthorization(
            ProducerAuthorizationVerifyError::SnapshotPositionMismatch { .. }
        ))
    ));

    let authorization = authorization_bytes(
        fixture.context,
        fixture.position,
        fixture.value.proposal_signing_root(),
        &fixture.proposer,
    );
    let later_certificate = certificate_bytes(
        fixture.context,
        later_position,
        fixture.value.proposal_signing_root(),
        &[&fixture.proposer],
    );
    let mut mixed = Vec::new();
    mixed.extend_from_slice(&fixture.value.to_canonical_bytes());
    mixed.extend_from_slice(&authorization);
    mixed.extend_from_slice(&later_certificate);
    assert!(matches!(
        verify_fixture(&fixture, &mixed, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificate(
            PrecommitCertificateVerifyError::SnapshotPositionMismatch { .. }
        ))
    ));

    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&signing_key(2)),
            &fixture.snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ProducerAuthorization(
            ProducerAuthorizationVerifyError::UnexpectedProposer { .. }
        ))
    ));

    let wrong_height_snapshot = snapshot(position(2, 11), &[(&fixture.proposer, 1)]);
    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&fixture.proposer),
            &wrong_height_snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::SnapshotHeightMismatch { .. })
    ));
}

#[test]
fn artifact_parent_chain_is_explicit_authority_and_remains_immutable() {
    let fixture = fixture(12);
    let other_state = ArtifactChainState::new(ArtifactChainDefinition::new([0xf1; 32]));
    let other_parent = other_state.branch_snapshot();
    let expected_head = other_parent.head_block_id();
    let expected_root = other_parent.artifact_set_root();

    assert!(matches!(
        VerifiedConsensusEnvelopeV0::decode_and_verify(
            &fixture.bytes,
            fixture.context,
            consensus_key(&fixture.proposer),
            &fixture.snapshot,
            None,
            fixture.expected_state,
            &other_parent,
            fixture.payload.clone(),
        ),
        Err(ConsensusEnvelopeVerifyError::ArtifactChainMismatch { .. })
    ));
    assert_eq!(other_parent.head_block_id(), expected_head);
    assert_eq!(other_parent.artifact_set_root(), expected_root);
}

#[test]
fn authenticated_invalid_artifact_and_payload_fail_without_changing_predecessor() {
    let fixture = fixture(8);
    let predecessor_head = fixture.parent.head_block_id();
    let predecessor_root = fixture.parent.artifact_set_root();

    let mut wrong_payload = fixture.payload.clone();
    wrong_payload[0] ^= 1;
    assert!(matches!(
        verify_fixture(&fixture, &fixture.bytes, wrong_payload),
        Err(ConsensusEnvelopeVerifyError::ArtifactValidation(_))
    ));

    let invalid_block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xdd; 32]),
        fixture.value.artifact_block().previous_artifact_set_root(),
        fixture.value.artifact_block().resulting_artifact_set_root(),
        fixture.value.artifact_block().artifact_id(),
    );
    let invalid_value = ConsensusValueV0::try_new(
        fixture.context,
        fixture.position.height(),
        fixture.value.parent_ancestry_id(),
        invalid_block,
        fixture.expected_state,
    )
    .unwrap();
    let invalid_envelope = envelope_bytes(
        invalid_value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
    );
    assert!(matches!(
        verify_fixture(&fixture, &invalid_envelope, fixture.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ArtifactValidation(
            ArtifactBlockApplyError::ParentBlockIdMismatch { .. }
        ))
    ));
    assert_eq!(fixture.parent.head_block_id(), predecessor_head);
    assert_eq!(fixture.parent.artifact_set_root(), predecessor_root);
}

#[test]
fn round_and_evidence_variants_preserve_value_identities_but_change_envelopes() {
    let definition = ArtifactChainDefinition::new([0x61; 32]);
    let context = context(definition.id(), 0x62, 3);
    let payload = proof_payload(ZfcAxiom::Union);
    let state = ArtifactChainState::new(definition);
    let block = state.prepare_block(artifact_id_for(&payload)).unwrap();
    let parent = state.branch_snapshot();
    let expected_state = ConsensusStateCommitment::from_bytes([0x63; 32]);
    let value = ConsensusValueV0::try_new(
        context,
        ConsensusHeight::new(1),
        ConsensusAncestryId::virtual_genesis(context),
        block,
        expected_state,
    )
    .unwrap();
    let keys = [
        signing_key(10),
        signing_key(11),
        signing_key(12),
        signing_key(13),
    ];
    let first_position = position(1, 1);
    let second_position = position(1, 2);
    let first_snapshot = snapshot(
        first_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let second_snapshot = snapshot(
        second_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let first_bytes = envelope_bytes(
        value,
        first_position,
        &keys[0],
        &[&keys[0], &keys[1], &keys[2]],
    );
    let variant_bytes = envelope_bytes(
        value,
        first_position,
        &keys[0],
        &[&keys[0], &keys[1], &keys[3]],
    );
    let later_round_bytes = envelope_bytes(
        value,
        second_position,
        &keys[0],
        &[&keys[0], &keys[1], &keys[2]],
    );
    let producer_variant_bytes = envelope_bytes(
        value,
        first_position,
        &keys[1],
        &[&keys[0], &keys[1], &keys[2]],
    );

    let first = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &first_bytes,
        context,
        consensus_key(&keys[0]),
        &first_snapshot,
        None,
        expected_state,
        &parent,
        payload.clone(),
    )
    .unwrap();
    let variant = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &variant_bytes,
        context,
        consensus_key(&keys[0]),
        &first_snapshot,
        None,
        expected_state,
        &parent,
        payload.clone(),
    )
    .unwrap();
    let later_round = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &later_round_bytes,
        context,
        consensus_key(&keys[0]),
        &second_snapshot,
        None,
        expected_state,
        &parent,
        payload,
    )
    .unwrap();
    let producer_variant = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &producer_variant_bytes,
        context,
        consensus_key(&keys[1]),
        &first_snapshot,
        None,
        expected_state,
        &parent,
        proof_payload(ZfcAxiom::Union),
    )
    .unwrap();

    for verified in [&first, &variant, &later_round, &producer_variant] {
        assert_eq!(
            verified.value().proposal_signing_root(),
            value.proposal_signing_root()
        );
        assert_eq!(verified.value().ancestry_id(), value.ancestry_id());
        assert_eq!(
            verified.artifact_successor().head_block_id(),
            value.artifact_block().id()
        );
    }
    assert_ne!(first.id(), variant.id());
    assert_ne!(first.id(), later_round.id());
    assert_ne!(first.id(), producer_variant.id());
    assert_ne!(
        first.precommit_certificate().id(),
        variant.precommit_certificate().id()
    );
    assert_eq!(
        first.precommit_certificate().id(),
        producer_variant.precommit_certificate().id()
    );
}

#[test]
fn exact_maximum_signer_envelope_verifies_without_exceeding_the_bound() {
    let fixture = fixture(u64::MAX);
    let keys = (0_u16..256).map(signing_key).collect::<Vec<_>>();
    let weighted = keys.iter().map(|key| (key, 1)).collect::<Vec<_>>();
    let snapshot = snapshot(fixture.position, &weighted);
    let signers = keys.iter().collect::<Vec<_>>();
    let bytes = envelope_bytes(fixture.value, fixture.position, &keys[0], &signers);
    assert_eq!(bytes.len(), VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH);

    let verified = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &bytes,
        fixture.context,
        consensus_key(&keys[0]),
        &snapshot,
        None,
        fixture.expected_state,
        &fixture.parent,
        fixture.payload.clone(),
    )
    .unwrap();
    assert_eq!(verified.precommit_certificate().signer_count(), 256);
    assert_eq!(verified.to_canonical_bytes(), bytes);
}

#[test]
fn zero_state_commitment_and_owned_output_are_exact() {
    let fixture = fixture(10);
    let value = ConsensusValueV0::try_new(
        fixture.context,
        fixture.position.height(),
        fixture.value.parent_ancestry_id(),
        fixture.value.artifact_block(),
        ConsensusStateCommitment::from_bytes([0; 32]),
    )
    .unwrap();
    let mut bytes = envelope_bytes(
        value,
        fixture.position,
        &fixture.proposer,
        &[&fixture.proposer],
    );
    let verified = VerifiedConsensusEnvelopeV0::decode_and_verify(
        &bytes,
        fixture.context,
        consensus_key(&fixture.proposer),
        &fixture.snapshot,
        None,
        ConsensusStateCommitment::from_bytes([0; 32]),
        &fixture.parent,
        fixture.payload.clone(),
    )
    .unwrap();
    let accepted = verified.to_canonical_bytes();
    bytes.fill(0xff);
    assert_eq!(verified.to_canonical_bytes(), accepted);
    assert_eq!(
        verified
            .value()
            .post_consensus_state_commitment()
            .as_bytes(),
        &[0; 32]
    );
}

#[test]
fn typed_branch_derives_all_authority_and_publishes_one_direct_child() {
    let definition = ArtifactChainDefinition::new([0x91; 32]);
    let context = context(definition.id(), 0x42, 7);
    let proposer = signing_key(41);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&proposer),
        AgreementWeight::new(1),
    )];
    let payload = proof_payload(ZfcAxiom::Pairing);
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let parent_head = artifact_state.head_block_id();
    let parent_root = artifact_state.artifact_dag().artifact_set_root();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let parent_coordinate = branch.coordinate();
    let round = branch.begin_round_zero().unwrap();
    let next_priority_state = round.post_height_proposer_priority_state_id();
    let value = round.value_for_artifact_block(block);
    let bytes = envelope_bytes(value, round.position(), &proposer, &[&proposer]);

    let verified = round.decode_and_verify(&bytes, payload.clone()).unwrap();
    assert_eq!(verified.value(), value);
    assert_eq!(
        verified.producer_authorization().proposer(),
        round.proposer()
    );
    assert_eq!(verified.precommit_certificate().signer_count(), 1);
    assert_eq!(verified.artifact_successor().head_block_id(), block.id());

    let envelope_id = verified.envelope_id();
    let verified_position = round.position();
    let owned = verified.into_owned();
    assert_eq!(owned.parent_coordinate(), parent_coordinate);
    assert_eq!(owned.position(), verified_position);
    assert_eq!(owned.value(), value);
    assert_eq!(owned.envelope_id(), envelope_id);
    assert_eq!(owned.canonical_envelope_bytes(), bytes);
    assert_eq!(owned.canonical_artifact_bytes(), payload);

    let child = owned.into_branch();
    assert_eq!(child.context(), context);
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), value.ancestry_id());
    assert_eq!(child.artifact_snapshot().head_block_id(), block.id());
    assert_eq!(child.proposer_priority_state_id(), next_priority_state);
    assert_eq!(branch.verified_height(), None);
    assert_eq!(branch.artifact_snapshot().head_block_id(), parent_head);
    assert_eq!(branch.artifact_snapshot().artifact_set_root(), parent_root);
}

#[test]
fn typed_branch_rejects_an_active_unscheduled_proposer_and_remains_retryable() {
    let definition = ArtifactChainDefinition::new([0x96; 32]);
    let context = context(definition.id(), 0x47, 7);
    let mut keys = [signing_key(91), signing_key(92)];
    keys.sort_unstable_by_key(consensus_key);
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&keys[0]), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&keys[1]), AgreementWeight::new(1)),
    ];
    let payload = proof_payload(ZfcAxiom::Infinity);
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    assert_eq!(round.proposer(), consensus_key(&keys[0]));
    let value = round.value_for_artifact_block(block);
    let signer_refs = [&keys[0], &keys[1]];

    let wrong_bytes = envelope_bytes(value, round.position(), &keys[1], &signer_refs);
    assert!(matches!(
        round.decode_and_verify(&wrong_bytes, payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ProducerAuthorization(
            ProducerAuthorizationVerifyError::UnexpectedProposer { expected, actual }
        )) if expected == consensus_key(&keys[0]) && actual == consensus_key(&keys[1])
    ));
    assert_eq!(branch.verified_height(), None);
    assert!(branch.artifact_snapshot().is_virtual_genesis());

    let valid_bytes = envelope_bytes(value, round.position(), &keys[0], &signer_refs);
    let child = round
        .decode_and_verify(&valid_bytes, payload)
        .unwrap()
        .into_branch();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), value.ancestry_id());
    assert_eq!(child.artifact_snapshot().head_block_id(), block.id());
}

#[test]
fn later_round_evidence_keeps_one_value_and_one_next_height_base() {
    let definition = ArtifactChainDefinition::new([0x92; 32]);
    let context = context(definition.id(), 0x43, 7);
    let mut keys = [signing_key(51), signing_key(52)];
    keys.sort_unstable_by_key(consensus_key);
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&keys[0]), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&keys[1]), AgreementWeight::new(3)),
    ];
    let payload = proof_payload(ZfcAxiom::Union);
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    assert_eq!(round_zero.proposer(), consensus_key(&keys[1]));
    assert_eq!(round_one.proposer(), consensus_key(&keys[0]));
    assert_eq!(
        round_zero.post_height_proposer_priority_state_id(),
        round_one.post_height_proposer_priority_state_id()
    );
    let value = round_zero.value_for_artifact_block(block);
    assert_eq!(round_one.value_for_artifact_block(block), value);

    let round_zero_bytes = envelope_bytes(value, round_zero.position(), &keys[1], &[&keys[1]]);
    let round_one_bytes = envelope_bytes(value, round_one.position(), &keys[0], &[&keys[1]]);
    let round_zero_verified = round_zero
        .decode_and_verify(&round_zero_bytes, payload.clone())
        .unwrap();
    let round_one_verified = round_one
        .decode_and_verify(&round_one_bytes, payload)
        .unwrap();
    assert_ne!(
        round_zero_verified.envelope_id(),
        round_one_verified.envelope_id()
    );

    let round_zero_child = round_zero_verified.into_branch();
    let round_one_child = round_one_verified.into_branch();
    assert_eq!(
        round_zero_child.ancestry_id(),
        round_one_child.ancestry_id()
    );
    assert_eq!(
        round_zero_child.artifact_snapshot().head_block_id(),
        round_one_child.artifact_snapshot().head_block_id()
    );
    assert_eq!(
        round_zero_child.proposer_priority_state_id(),
        round_one_child.proposer_priority_state_id()
    );
}

#[test]
fn typed_branch_rejects_a_changed_commitment_before_invalidated_evidence() {
    let definition = ArtifactChainDefinition::new([0x93; 32]);
    let context = context(definition.id(), 0x44, 7);
    let proposer = signing_key(61);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&proposer),
        AgreementWeight::new(1),
    )];
    let payload = proof_payload(ZfcAxiom::PowerSet);
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let parent_head = artifact_state.head_block_id();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let value = round.value_for_artifact_block(block);
    let expected = value.post_consensus_state_commitment();
    let mut bytes = envelope_bytes(value, round.position(), &proposer, &[&proposer]);
    bytes[POST_CONSENSUS_STATE_OFFSET] ^= 0x80;
    let actual = ConsensusStateCommitment::from_bytes(
        bytes[POST_CONSENSUS_STATE_OFFSET..CONSENSUS_VALUE_BYTES]
            .try_into()
            .unwrap(),
    );

    assert!(matches!(
        round.decode_and_verify(&bytes, payload),
        Err(ConsensusEnvelopeVerifyError::PostConsensusStateCommitmentMismatch {
            expected: error_expected,
            actual: error_actual,
        }) if error_expected == expected && error_actual == actual
    ));
    assert_eq!(branch.verified_height(), None);
    assert_eq!(branch.artifact_snapshot().head_block_id(), parent_head);
}

#[test]
fn typed_sibling_branches_cannot_mix_consensus_and_artifact_parents() {
    let definition = ArtifactChainDefinition::new([0x94; 32]);
    let context = context(definition.id(), 0x45, 7);
    let proposer = signing_key(71);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&proposer),
        AgreementWeight::new(1),
    )];
    let pairing = proof_payload(ZfcAxiom::Pairing);
    let union = proof_payload(ZfcAxiom::Union);
    let infinity = proof_payload(ZfcAxiom::Infinity);
    let mut selected_a = ArtifactChainState::new(definition);
    let pairing_block = selected_a.prepare_block(artifact_id_for(&pairing)).unwrap();
    let union_block = selected_a.prepare_block(artifact_id_for(&union)).unwrap();
    let genesis = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        selected_a.branch_snapshot(),
    )
    .unwrap();
    let first_round = genesis.begin_round_zero().unwrap();

    let pairing_value = first_round.value_for_artifact_block(pairing_block);
    let pairing_bytes = envelope_bytes(
        pairing_value,
        first_round.position(),
        &proposer,
        &[&proposer],
    );
    let pairing_branch = first_round
        .decode_and_verify(&pairing_bytes, pairing.clone())
        .unwrap()
        .into_branch();
    let union_value = first_round.value_for_artifact_block(union_block);
    let union_bytes = envelope_bytes(union_value, first_round.position(), &proposer, &[&proposer]);
    let union_branch = first_round
        .decode_and_verify(&union_bytes, union)
        .unwrap()
        .into_branch();

    selected_a.apply_block(&pairing_block, pairing).unwrap();
    let infinity_block = selected_a
        .prepare_block(artifact_id_for(&infinity))
        .unwrap();
    let pairing_round = pairing_branch.begin_round_zero().unwrap();
    let union_round = union_branch.begin_round_zero().unwrap();
    let pairing_child_value = pairing_round.value_for_artifact_block(infinity_block);
    let pairing_child_bytes = envelope_bytes(
        pairing_child_value,
        pairing_round.position(),
        &proposer,
        &[&proposer],
    );

    assert!(matches!(
        union_round.decode_and_verify(&pairing_child_bytes, infinity.clone()),
        Err(ConsensusEnvelopeVerifyError::ParentAncestryMismatch {
            expected,
            actual,
        }) if expected == union_branch.ancestry_id() && actual == pairing_branch.ancestry_id()
    ));

    let mixed_value = union_round.value_for_artifact_block(infinity_block);
    let mixed_bytes = envelope_bytes(mixed_value, union_round.position(), &proposer, &[&proposer]);
    assert!(matches!(
        union_round.decode_and_verify(&mixed_bytes, infinity),
        Err(ConsensusEnvelopeVerifyError::ArtifactValidation(
            ArtifactBlockApplyError::ParentBlockIdMismatch { .. }
        ))
    ));
    assert_eq!(
        union_branch.verified_height(),
        Some(ConsensusHeight::new(1))
    );
    assert_eq!(
        union_branch.artifact_snapshot().head_block_id(),
        union_block.id()
    );
}

#[test]
fn typed_branch_advances_only_exact_direct_heights() {
    let definition = ArtifactChainDefinition::new([0x95; 32]);
    let context = context(definition.id(), 0x46, 7);
    let proposer = signing_key(81);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&proposer),
        AgreementWeight::new(1),
    )];
    let pairing = proof_payload(ZfcAxiom::Pairing);
    let union = proof_payload(ZfcAxiom::Union);
    let mut selected = ArtifactChainState::new(definition);
    let first_block = selected.prepare_block(artifact_id_for(&pairing)).unwrap();
    let genesis = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        selected.branch_snapshot(),
    )
    .unwrap();
    let first_round = genesis.begin_round_zero().unwrap();
    let first_value = first_round.value_for_artifact_block(first_block);
    let first_bytes = envelope_bytes(first_value, first_round.position(), &proposer, &[&proposer]);
    let first_child = first_round
        .decode_and_verify(&first_bytes, pairing.clone())
        .unwrap()
        .into_branch();

    selected.apply_block(&first_block, pairing).unwrap();
    let second_block = selected.prepare_block(artifact_id_for(&union)).unwrap();
    let second_round = first_child.begin_round_zero().unwrap();
    assert_eq!(second_round.position().height(), ConsensusHeight::new(2));
    let second_value = second_round.value_for_artifact_block(second_block);
    assert_eq!(second_value.parent_ancestry_id(), first_child.ancestry_id());
    let second_bytes = envelope_bytes(
        second_value,
        second_round.position(),
        &proposer,
        &[&proposer],
    );
    let second_child = second_round
        .decode_and_verify(&second_bytes, union)
        .unwrap()
        .into_branch();
    assert_eq!(
        second_child.verified_height(),
        Some(ConsensusHeight::new(2))
    );
    assert_eq!(second_child.ancestry_id(), second_value.ancestry_id());
    assert_eq!(
        second_child.artifact_snapshot().head_block_id(),
        second_block.id()
    );

    let stale_round = first_child.begin_round_zero().unwrap();
    assert!(matches!(
        stale_round.decode_and_verify(&first_bytes, proof_payload(ZfcAxiom::Pairing)),
        Err(ConsensusEnvelopeVerifyError::SnapshotHeightMismatch {
            value,
            snapshot,
        }) if value == ConsensusHeight::new(1) && snapshot.height() == ConsensusHeight::new(2)
    ));
}

#[test]
fn proposal_control_tag_zero_and_proof_derived_tag_one_are_exact() {
    let fixture = fixture(3);
    let without_proof =
        proposal_control_bytes(fixture.value, fixture.position, &fixture.proposer, None);
    assert_eq!(
        without_proof.len(),
        VerifiedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH
    );
    assert_eq!(without_proof.len(), 481);
    assert_eq!(without_proof[VALID_ROUND_PROOF_TAG_OFFSET], 0);
    let admitted =
        verify_proposal_fixture(&fixture, &without_proof, fixture.payload.clone()).unwrap();
    assert_eq!(admitted.value(), fixture.value);
    assert_eq!(admitted.valid_round(), None);
    assert_eq!(admitted.valid_round_certificate_id(), None);
    assert_eq!(admitted.valid_round_certificate_bytes(), None);
    assert_eq!(admitted.canonical_proposal_control_bytes(), without_proof);

    let valid_round = ConsensusRound::new(0);
    let certificate = quorum_certificate_bytes(
        fixture.context,
        position(fixture.position.height().value(), valid_round.value()),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let with_proof = proposal_control_bytes(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        Some(&certificate),
    );
    assert_eq!(with_proof[VALID_ROUND_PROOF_TAG_OFFSET], 1);
    assert_eq!(
        with_proof.len(),
        PROPOSAL_CONTROL_PREFIX_BYTES + VerifiedQuorumCertificateV0::MIN_BYTE_LENGTH
    );
    assert_eq!(with_proof.len(), 697);
    let admitted = verify_proposal_fixture(&fixture, &with_proof, fixture.payload.clone()).unwrap();
    let expected_id: [u8; QuorumCertificateId::BYTE_LENGTH] = Sha256::digest(&certificate).into();
    assert_eq!(admitted.valid_round(), Some(valid_round));
    assert_eq!(
        admitted.valid_round_certificate_id().unwrap().as_bytes(),
        &expected_id
    );
    assert_eq!(
        admitted.valid_round_certificate_bytes(),
        Some(certificate.as_slice())
    );
    assert_eq!(admitted.canonical_proposal_control_bytes(), with_proof);
    assert_eq!(admitted.canonical_artifact_bytes(), fixture.payload);
}

#[test]
fn exact_maximum_signer_proposal_control_verifies_at_the_frozen_bound() {
    let fixture = fixture(u64::MAX);
    let keys = (0_u16..256).map(signing_key).collect::<Vec<_>>();
    let weighted = keys.iter().map(|key| (key, 1)).collect::<Vec<_>>();
    let current_snapshot = snapshot(fixture.position, &weighted);
    let proof_position = position(1, u64::MAX - 1);
    let signers = keys.iter().collect::<Vec<_>>();
    let certificate = quorum_certificate_bytes(
        fixture.context,
        proof_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &signers,
    );
    assert_eq!(
        certificate.len(),
        VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH
    );
    let control = proposal_control_bytes(
        fixture.value,
        fixture.position,
        &keys[0],
        Some(&certificate),
    );
    assert_eq!(control.len(), 25_177);
    assert_eq!(control.len(), VerifiedConsensusProposalV0::MAX_BYTE_LENGTH);

    let admitted = VerifiedConsensusProposalV0::decode_and_verify(
        &control,
        fixture.context,
        consensus_key(&keys[0]),
        &current_snapshot,
        None,
        fixture.expected_state,
        &fixture.parent,
        fixture.payload,
        |position| snapshot(position, &weighted),
    )
    .unwrap();
    assert_eq!(admitted.valid_round(), Some(proof_position.round()));
    assert_eq!(
        admitted.valid_round_certificate_bytes(),
        Some(certificate.as_slice())
    );
}

#[test]
fn proposal_control_tags_and_remainder_framing_are_strict() {
    let fixture = fixture(3);
    let control = proposal_control_bytes(fixture.value, fixture.position, &fixture.proposer, None);
    for length in 0..VerifiedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH {
        assert!(matches!(
            verify_proposal_fixture(&fixture, &control[..length], fixture.payload.clone()),
            Err(ConsensusProposalVerifyError::InvalidLength { actual, minimum })
                if actual == length
                    && minimum == VerifiedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH
        ));
    }

    let mut unknown = control.clone();
    unknown[VALID_ROUND_PROOF_TAG_OFFSET] = 2;
    assert_eq!(
        verify_proposal_fixture(&fixture, &unknown, fixture.payload.clone()).err(),
        Some(ConsensusProposalVerifyError::UnknownValidRoundProofTag { actual: 2 })
    );

    let mut trailing_without_proof = control.clone();
    trailing_without_proof.push(0);
    assert!(matches!(
        verify_proposal_fixture(
            &fixture,
            &trailing_without_proof,
            fixture.payload.clone(),
        ),
        Err(ConsensusProposalVerifyError::TrailingBytesWithoutValidRoundProof {
            actual,
            expected,
        }) if actual == control.len() + 1 && expected == control.len()
    ));

    let mut missing_certificate = control;
    missing_certificate[VALID_ROUND_PROOF_TAG_OFFSET] = 1;
    assert!(matches!(
        verify_proposal_fixture(&fixture, &missing_certificate, fixture.payload.clone()),
        Err(ConsensusProposalVerifyError::ValidRoundCertificate(
            QuorumCertificateVerifyError::InvalidLength { actual: 0, .. }
        ))
    ));

    let certificate = quorum_certificate_bytes(
        fixture.context,
        position(1, 1),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let mut trailing_certificate = proposal_control_bytes(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        Some(&certificate),
    );
    trailing_certificate.push(0);
    assert!(matches!(
        verify_proposal_fixture(&fixture, &trailing_certificate, fixture.payload.clone(),),
        Err(ConsensusProposalVerifyError::ValidRoundCertificate(
            QuorumCertificateVerifyError::LengthMismatch { .. }
        ))
    ));

    let oversized = vec![0_u8; VerifiedConsensusProposalV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        verify_proposal_fixture(&fixture, &oversized, fixture.payload.clone()),
        Err(ConsensusProposalVerifyError::InputTooLong { actual, maximum })
            if actual == VerifiedConsensusProposalV0::MAX_BYTE_LENGTH + 1
                && maximum == VerifiedConsensusProposalV0::MAX_BYTE_LENGTH
    ));
}

#[test]
fn proposal_admission_rejects_nonprior_and_other_height_valid_rounds() {
    let fixture = fixture(3);
    for proof_round in [3, 4] {
        let certificate = quorum_certificate_bytes(
            fixture.context,
            position(1, proof_round),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
            &[&fixture.proposer],
        );
        let control = proposal_control_bytes(
            fixture.value,
            fixture.position,
            &fixture.proposer,
            Some(&certificate),
        );
        assert!(matches!(
            verify_proposal_fixture(&fixture, &control, fixture.payload.clone()),
            Err(ConsensusProposalVerifyError::ValidRoundNotEarlier {
                valid_round,
                current_round,
            }) if valid_round == ConsensusRound::new(proof_round)
                && current_round == fixture.position.round()
        ));
    }

    let other_height = quorum_certificate_bytes(
        fixture.context,
        position(2, 1),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let control = proposal_control_bytes(
        fixture.value,
        fixture.position,
        &fixture.proposer,
        Some(&other_height),
    );
    assert!(matches!(
        verify_proposal_fixture(&fixture, &control, fixture.payload.clone()),
        Err(ConsensusProposalVerifyError::ValidRoundHeightMismatch {
            proposal,
            certificate,
        }) if proposal == fixture.position && certificate == position(2, 1)
    ));
}

#[test]
fn valid_round_proof_requires_exact_context_prevote_and_proposal_root() {
    let fixture = fixture(3);
    let proof_position = position(1, 1);
    let other_context = context(ArtifactChainId::from_bytes([0xee; 32]), 0x42, 7);
    let cases = [
        (
            quorum_certificate_bytes(
                other_context,
                proof_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
                &[&fixture.proposer],
            ),
            0,
        ),
        (
            quorum_certificate_bytes(
                fixture.context,
                proof_position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
                &[&fixture.proposer],
            ),
            1,
        ),
        (
            quorum_certificate_bytes(
                fixture.context,
                proof_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                &[&fixture.proposer],
            ),
            2,
        ),
        (
            quorum_certificate_bytes(
                fixture.context,
                proof_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0xcc; 32])),
                &[&fixture.proposer],
            ),
            3,
        ),
    ];

    for (certificate, case) in cases {
        let control = proposal_control_bytes(
            fixture.value,
            fixture.position,
            &fixture.proposer,
            Some(&certificate),
        );
        let error = verify_proposal_fixture(&fixture, &control, fixture.payload.clone())
            .err()
            .unwrap();
        match case {
            0 => assert!(matches!(
                error,
                ConsensusProposalVerifyError::ValidRoundCertificate(
                    QuorumCertificateVerifyError::ChainIdMismatch { .. }
                )
            )),
            1 => assert_eq!(
                error,
                ConsensusProposalVerifyError::ValidRoundWrongVoteRole {
                    actual: ConsensusVoteRole::Precommit,
                }
            ),
            2 => assert_eq!(error, ConsensusProposalVerifyError::ValidRoundNilTarget),
            3 => assert!(matches!(
                error,
                ConsensusProposalVerifyError::ValidRoundRootMismatch { .. }
            )),
            _ => unreachable!(),
        }
    }
}

#[test]
fn typed_proposal_rejects_prior_round_proof_from_another_fixed_set() {
    let fixture = fixture(2);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&fixture.proposer),
        AgreementWeight::new(1),
    )];
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        fixture.parent.clone(),
    )
    .unwrap();
    let round = branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap()
        .advance_round()
        .unwrap();
    let value = round.value_for_artifact_block(fixture.value.artifact_block());
    let attacker = signing_key(909);
    let certificate = quorum_certificate_bytes(
        fixture.context,
        position(round.position().height().value(), 1),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &[&attacker],
    );
    let control = proposal_control_bytes(
        value,
        round.position(),
        &fixture.proposer,
        Some(&certificate),
    );

    assert!(matches!(
        round.decode_and_verify_proposal_control(&control, fixture.payload),
        Err(ConsensusProposalVerifyError::ValidRoundCertificate(
            QuorumCertificateVerifyError::UnknownSigner { signer }
        )) if signer == consensus_key(&attacker)
    ));
}

#[test]
fn invalid_artifact_precedes_optional_valid_round_certificate_work() {
    let fixture = fixture(3);
    let mut control =
        proposal_control_bytes(fixture.value, fixture.position, &fixture.proposer, None);
    control[VALID_ROUND_PROOF_TAG_OFFSET] = 1;
    control.extend_from_slice(&[0xff; 7]);
    let mut invalid_payload = fixture.payload.clone();
    invalid_payload[0] ^= 1;

    assert!(matches!(
        verify_proposal_fixture(&fixture, &control, invalid_payload),
        Err(ConsensusProposalVerifyError::ArtifactValidation(_))
    ));
}

#[test]
fn valid_round_evidence_variants_preserve_value_and_round_but_not_proof_identity() {
    let fixture = fixture(4);
    let keys = [
        signing_key(20),
        signing_key(21),
        signing_key(22),
        signing_key(23),
    ];
    let current_snapshot = snapshot(
        fixture.position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let value = fixture.value;
    let first_certificate = quorum_certificate_bytes(
        fixture.context,
        position(1, 2),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &[&keys[0], &keys[1], &keys[2]],
    );
    let second_certificate = quorum_certificate_bytes(
        fixture.context,
        position(1, 2),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &[&keys[0], &keys[1], &keys[3]],
    );

    let verify = |certificate: &[u8]| {
        let control = proposal_control_bytes(value, fixture.position, &keys[0], Some(certificate));
        VerifiedConsensusProposalV0::decode_and_verify(
            &control,
            fixture.context,
            consensus_key(&keys[0]),
            &current_snapshot,
            None,
            fixture.expected_state,
            &fixture.parent,
            fixture.payload.clone(),
            |proof_position| {
                snapshot(
                    proof_position,
                    &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
                )
            },
        )
        .unwrap()
    };
    let first = verify(&first_certificate);
    let second = verify(&second_certificate);
    assert_eq!(first.value(), second.value());
    assert_eq!(first.valid_round(), second.valid_round());
    assert_ne!(
        first.valid_round_certificate_id(),
        second.valid_round_certificate_id()
    );
    assert_ne!(
        first.valid_round_certificate_bytes(),
        second.valid_round_certificate_bytes()
    );
}

#[test]
fn typed_two_stage_admission_seals_to_the_legacy_envelope_byte_identically() {
    let definition = ArtifactChainDefinition::new([0x99; 32]);
    let context = context(definition.id(), 0x42, 7);
    let proposer = signing_key(101);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&proposer),
        AgreementWeight::new(1),
    )];
    let payload = proof_payload(ZfcAxiom::Pairing);
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let round = branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap()
        .advance_round()
        .unwrap();
    let value = round.value_for_artifact_block(block);
    let envelope = envelope_bytes(value, round.position(), &proposer, &[&proposer]);
    let valid_round_certificate = quorum_certificate_bytes(
        context,
        position(1, 1),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &[&proposer],
    );
    let control = proposal_control_bytes(
        value,
        round.position(),
        &proposer,
        Some(&valid_round_certificate),
    );

    let legacy = round.decode_and_verify(&envelope, payload.clone()).unwrap();
    let staged = round
        .decode_and_verify_proposal_control(&control, payload)
        .unwrap();
    assert_eq!(staged.position(), round.position());
    assert_eq!(staged.value(), value);
    assert_eq!(
        staged.proposal_signing_root(),
        value.proposal_signing_root()
    );
    assert_eq!(staged.valid_round(), Some(ConsensusRound::new(1)));
    let sealed = staged
        .seal_with_precommit_certificate(&envelope[PRECOMMIT_CERTIFICATE_OFFSET..])
        .unwrap();

    assert_eq!(sealed.to_canonical_bytes(), envelope);
    assert_eq!(sealed.to_canonical_bytes(), legacy.to_canonical_bytes());
    assert_eq!(sealed.envelope_id(), legacy.envelope_id());
    assert_eq!(sealed.value(), legacy.value());
    assert_eq!(
        sealed.artifact_successor().head_block_id(),
        legacy.artifact_successor().head_block_id()
    );
}

#[test]
fn admitted_proposal_drives_public_prevote_and_precommit_lock_paths() {
    let fixture = fixture(0);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&fixture.proposer),
        AgreementWeight::new(1),
    )];
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        fixture.parent.clone(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let value = round.value_for_artifact_block(fixture.value.artifact_block());
    let control = proposal_control_bytes(value, round.position(), &fixture.proposer, None);
    let proposal = round
        .decode_and_verify_proposal_control(&control, fixture.payload)
        .unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();

    let prevote = state.decide_prevote_for_proposal(&proposal).unwrap();
    assert_eq!(prevote.position(), round.position());
    assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
    assert_eq!(
        prevote.target(),
        ConsensusVoteTarget::Proposal(value.proposal_signing_root())
    );

    let certificate = quorum_certificate_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let precommit = state
        .decide_precommit_for_proposal_quorum(&round, &proposal, &certificate)
        .unwrap();
    assert_eq!(precommit.position(), round.position());
    assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
    assert_eq!(precommit.target(), prevote.target());
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Precommit);
    let locked = state.locked_value().unwrap();
    assert_eq!(locked.value(), value);
    assert_eq!(locked.round(), ConsensusRound::new(0));
    let valid = state.valid_value().unwrap();
    assert_eq!(valid.value(), value);
    assert_eq!(valid.round(), ConsensusRound::new(0));
    assert_eq!(valid.canonical_prevote_certificate(), certificate);
}

#[test]
fn sealing_requires_a_matching_current_round_nonnil_precommit() {
    let fixture = fixture(3);
    let control = proposal_control_bytes(fixture.value, fixture.position, &fixture.proposer, None);
    let wrong_root = certificate_bytes(
        fixture.context,
        fixture.position,
        ProposalSigningRoot::from_bytes([0xdd; 32]),
        &[&fixture.proposer],
    );
    let proposal = verify_proposal_fixture(&fixture, &control, fixture.payload.clone()).unwrap();
    assert!(matches!(
        proposal.seal_with_precommit_certificate(&wrong_root, &fixture.snapshot),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificateRootMismatch { .. })
    ));

    let prior_round = certificate_bytes(
        fixture.context,
        position(1, 2),
        fixture.value.proposal_signing_root(),
        &[&fixture.proposer],
    );
    let proposal = verify_proposal_fixture(&fixture, &control, fixture.payload.clone()).unwrap();
    assert!(matches!(
        proposal.seal_with_precommit_certificate(&prior_round, &fixture.snapshot),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificate(
            PrecommitCertificateVerifyError::SnapshotPositionMismatch { .. }
        ))
    ));

    let prevote = quorum_certificate_bytes(
        fixture.context,
        fixture.position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let proposal = verify_proposal_fixture(&fixture, &control, fixture.payload.clone()).unwrap();
    assert!(matches!(
        proposal.seal_with_precommit_certificate(&prevote, &fixture.snapshot),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificate(
            PrecommitCertificateVerifyError::WrongVoteRole {
                actual: ConsensusVoteRole::Prevote,
            }
        ))
    ));
}

#[test]
fn legacy_envelope_preserves_certificate_before_artifact_error_precedence() {
    let fixture = fixture(3);
    let mut invalid_certificate = fixture.bytes.clone();
    *invalid_certificate.last_mut().unwrap() ^= 1;
    let mut invalid_payload = fixture.payload.clone();
    invalid_payload[0] ^= 1;
    assert!(matches!(
        verify_fixture(&fixture, &invalid_certificate, invalid_payload),
        Err(ConsensusEnvelopeVerifyError::PrecommitCertificate(
            PrecommitCertificateVerifyError::InvalidSignature { .. }
        ))
    ));
}
