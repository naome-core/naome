use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::*;
use crate::{ActiveAgreementEntry, AgreementWeight};

fn context(chain: u8, genesis: u8, version: u32) -> ConsensusContextV0 {
    ConsensusContextV0::new(
        ArtifactChainId::from_bytes([chain; ArtifactChainId::BYTE_LENGTH]),
        ConsensusGenesisId::from_bytes([genesis; ConsensusGenesisId::BYTE_LENGTH]),
        ConsensusProtocolVersion::new(version),
    )
}

fn position(height: u64, round: u64) -> ConsensusPosition {
    ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round))
}

fn root(byte: u8) -> ProposalSigningRoot {
    ProposalSigningRoot::from_bytes([byte; ProposalSigningRoot::BYTE_LENGTH])
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

fn snapshot(
    position: ConsensusPosition,
    entries: &[(&SigningKey, u128)],
) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        position,
        &entries
            .iter()
            .map(|(key, weight)| {
                ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(*weight))
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn snapshot_with_raw_key(
    position: ConsensusPosition,
    key: ConsensusKey,
) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        position,
        &[ActiveAgreementEntry::new(key, AgreementWeight::new(1))],
    )
    .unwrap()
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    proposer: &SigningKey,
) -> [u8; PRODUCER_AUTHORIZATION_BYTES] {
    let body = AuthorizationBody {
        context,
        position,
        proposal_signing_root,
    };
    let proposer_key = consensus_key(proposer);
    let signature = proposer.sign(&signing_transcript(body, proposer_key));
    let mut bytes = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body.to_canonical_bytes());
    bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(proposer_key.as_bytes());
    bytes[SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
    bytes
}

fn bytes_with_raw_key(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    proposer: ConsensusKey,
) -> [u8; PRODUCER_AUTHORIZATION_BYTES] {
    let body = AuthorizationBody {
        context,
        position,
        proposal_signing_root,
    };
    let mut bytes = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body.to_canonical_bytes());
    bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(proposer.as_bytes());
    bytes
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
fn independent_fixed_vector_verifies_and_reencodes_byte_identically() {
    // Independently generated with Python cryptography's RFC 8032 Ed25519
    // implementation rather than this crate's encoder or signing helpers.
    let expected_context = context(0x11, 0x22, 0x0102_0304);
    let expected_position = position(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    let expected_root = root(0x33);
    let proposer = ConsensusKey::from_bytes(hex_array(
        "1a63f83a2fc1ce57fc957b8fe9ceca746b3a6272a239addd7d6681ac2290d6de",
    ));
    let signature = hex_array(
        "33ef1bd2a07fa63f754e2890a8a57dfdfd406c451a30ec9e221ddd3b9507e0ce\
         67100910e2e86ac3ab9bc68db392e29b4533ec96590adb38f5c9affae687cb0d",
    );
    let mut vector = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
    vector[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET].fill(0x11);
    vector[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET].fill(0x22);
    vector[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    vector[HEIGHT_OFFSET..ROUND_OFFSET].copy_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    vector[ROUND_OFFSET..PROPOSAL_ROOT_OFFSET]
        .copy_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
    vector[PROPOSAL_ROOT_OFFSET..AUTHORIZATION_BODY_BYTES].fill(0x33);
    vector[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(proposer.as_bytes());
    vector[SIGNATURE_OFFSET..].copy_from_slice(&signature);
    let snapshot = snapshot_with_raw_key(expected_position, proposer);

    let verified = VerifiedProducerAuthorizationV0::decode_and_verify(
        &vector,
        expected_context,
        proposer,
        &snapshot,
    )
    .unwrap();

    assert_eq!(VerifiedProducerAuthorizationV0::BYTE_LENGTH, 212);
    assert_eq!(AUTHORIZATION_BODY_BYTES, 116);
    assert_eq!(verified.context(), expected_context);
    assert_eq!(verified.position(), expected_position);
    assert_eq!(verified.proposal_signing_root(), expected_root);
    assert_eq!(verified.proposer(), proposer);
    assert_eq!(verified.signature().as_bytes(), &signature);
    assert_eq!(verified.to_canonical_bytes(), vector);
}

#[test]
fn every_truncated_and_trailing_representation_is_rejected() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let valid = authorization_bytes(expected_context, expected_position, root(7), &proposer);
    let snapshot = snapshot(expected_position, &[(&proposer, 1)]);

    for length in 0..PRODUCER_AUTHORIZATION_BYTES {
        assert_eq!(
            VerifiedProducerAuthorizationV0::decode_and_verify(
                &valid[..length],
                expected_context,
                proposer_key,
                &snapshot,
            ),
            Err(ProducerAuthorizationVerifyError::InvalidLength {
                actual: length,
                expected: PRODUCER_AUTHORIZATION_BYTES,
            })
        );
    }

    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &trailing,
            expected_context,
            proposer_key,
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InvalidLength {
            actual: PRODUCER_AUTHORIZATION_BYTES + 1,
            expected: PRODUCER_AUTHORIZATION_BYTES,
        })
    );
}

#[test]
fn zero_height_is_reserved_while_round_zero_and_zero_root_are_canonical() {
    let expected_context = context(1, 2, 3);
    let proposer = signing_key(4);
    let proposer_key = consensus_key(&proposer);
    let expected_position = position(1, 0);
    let snapshot = snapshot(expected_position, &[(&proposer, 9)]);
    let valid = authorization_bytes(
        expected_context,
        expected_position,
        ProposalSigningRoot::from_bytes([0; ProposalSigningRoot::BYTE_LENGTH]),
        &proposer,
    );
    assert!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            expected_context,
            proposer_key,
            &snapshot,
        )
        .is_ok()
    );

    let mut zero_height = valid;
    zero_height[HEIGHT_OFFSET..ROUND_OFFSET].fill(0);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &zero_height,
            context(9, 9, 9),
            ConsensusKey::from_bytes([9; 32]),
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::ReservedGenesisHeight)
    );
}

#[test]
fn context_mismatches_precede_snapshot_and_signature_work() {
    let embedded_context = context(1, 2, 3);
    let embedded_position = position(4, 5);
    let proposer = signing_key(6);
    let valid = authorization_bytes(embedded_context, embedded_position, root(7), &proposer);
    let wrong_snapshot = snapshot(position(8, 9), &[(&proposer, 1)]);

    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            context(9, 8, 7),
            ConsensusKey::from_bytes([0; 32]),
            &wrong_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::ChainIdMismatch {
            expected: context(9, 8, 7).chain_id(),
            actual: embedded_context.chain_id(),
        })
    );
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            context(1, 8, 7),
            ConsensusKey::from_bytes([0; 32]),
            &wrong_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::GenesisIdMismatch {
            expected: context(1, 8, 7).genesis_id(),
            actual: embedded_context.genesis_id(),
        })
    );
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            context(1, 2, 7),
            ConsensusKey::from_bytes([0; 32]),
            &wrong_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::ProtocolVersionMismatch {
            expected: ConsensusProtocolVersion::new(7),
            actual: ConsensusProtocolVersion::new(3),
        })
    );
}

#[test]
fn position_and_designated_proposer_checks_precede_membership_and_signature() {
    let expected_context = context(1, 2, 3);
    let embedded_position = position(4, 5);
    let proposer = signing_key(6);
    let other = signing_key(7);
    let proposer_key = consensus_key(&proposer);
    let other_key = consensus_key(&other);
    let valid = authorization_bytes(expected_context, embedded_position, root(8), &proposer);
    let wrong_position_snapshot = snapshot(position(4, 6), &[(&other, 1)]);

    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            expected_context,
            other_key,
            &wrong_position_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::SnapshotPositionMismatch {
            authorization: embedded_position,
            snapshot: position(4, 6),
        })
    );

    let matching_snapshot = snapshot(embedded_position, &[(&other, 1)]);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &valid,
            expected_context,
            other_key,
            &matching_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::UnexpectedProposer {
            expected: other_key,
            actual: proposer_key,
        })
    );
}

#[test]
fn active_membership_precedes_key_parsing_and_signature_verification() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let mut malformed_key_bytes = [0_u8; 32];
    malformed_key_bytes[1] = 3;
    let malformed_key = ConsensusKey::from_bytes(malformed_key_bytes);
    let bytes = bytes_with_raw_key(expected_context, expected_position, root(6), malformed_key);
    let active = signing_key(7);
    let inactive_snapshot = snapshot(expected_position, &[(&active, 1)]);

    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &bytes,
            expected_context,
            malformed_key,
            &inactive_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InactiveProposer {
            proposer: malformed_key,
        })
    );

    let malformed_snapshot = snapshot_with_raw_key(expected_position, malformed_key);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &bytes,
            expected_context,
            malformed_key,
            &malformed_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::MalformedConsensusKey {
            proposer: malformed_key,
        })
    );
}

#[test]
fn signature_binds_every_body_field_and_the_proposer_key() {
    let original_context = context(1, 2, 3);
    let original_position = position(4, 5);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let original = authorization_bytes(original_context, original_position, root(7), &proposer);

    let mut changed_chain = [1_u8; ArtifactChainId::BYTE_LENGTH];
    changed_chain[0] ^= 8;
    let changed_chain_context = ConsensusContextV0::new(
        ArtifactChainId::from_bytes(changed_chain),
        original_context.genesis_id(),
        original_context.protocol_version(),
    );
    let mut changed_genesis = [2_u8; ConsensusGenesisId::BYTE_LENGTH];
    changed_genesis[0] ^= 8;
    let changed_genesis_context = ConsensusContextV0::new(
        original_context.chain_id(),
        ConsensusGenesisId::from_bytes(changed_genesis),
        original_context.protocol_version(),
    );
    let mutations = [
        (CHAIN_ID_OFFSET, changed_chain_context, original_position),
        (
            GENESIS_ID_OFFSET,
            changed_genesis_context,
            original_position,
        ),
        (
            PROTOCOL_VERSION_OFFSET + 3,
            context(1, 2, 11),
            original_position,
        ),
        (HEIGHT_OFFSET + 7, original_context, position(12, 5)),
        (ROUND_OFFSET + 7, original_context, position(4, 13)),
        (PROPOSAL_ROOT_OFFSET, original_context, original_position),
    ];

    for (offset, expected_context, expected_position) in mutations {
        let mut mutated = original;
        mutated[offset] ^= 8;
        let snapshot = snapshot(expected_position, &[(&proposer, 1)]);
        assert_eq!(
            VerifiedProducerAuthorizationV0::decode_and_verify(
                &mutated,
                expected_context,
                proposer_key,
                &snapshot,
            ),
            Err(ProducerAuthorizationVerifyError::InvalidSignature {
                proposer: proposer_key,
            })
        );
    }

    let other = signing_key(8);
    let other_key = consensus_key(&other);
    let mut mutated_key = original;
    mutated_key[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(other_key.as_bytes());
    let other_snapshot = snapshot(original_position, &[(&other, 1)]);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &mutated_key,
            original_context,
            other_key,
            &other_snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InvalidSignature {
            proposer: other_key,
        })
    );
}

#[test]
fn other_domains_and_prehashed_transcripts_cannot_authorize_a_producer() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let body = AuthorizationBody {
        context: expected_context,
        position: expected_position,
        proposal_signing_root: root(7),
    };
    let snapshot = snapshot(expected_position, &[(&proposer, 1)]);

    let mut wrong_domain_transcript = b"naome:consensus-prevote-signing:v0\0".to_vec();
    wrong_domain_transcript.extend_from_slice(&body.to_canonical_bytes());
    wrong_domain_transcript.extend_from_slice(proposer_key.as_bytes());
    let wrong_domain_signature = proposer.sign(&wrong_domain_transcript);

    let transcript = signing_transcript(body, proposer_key);
    let prehash = Sha256::digest(&transcript);
    let prehashed_signature = proposer.sign(&prehash);

    for signature in [wrong_domain_signature, prehashed_signature] {
        let mut bytes = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
        bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body.to_canonical_bytes());
        bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(proposer_key.as_bytes());
        bytes[SIGNATURE_OFFSET..].copy_from_slice(&signature.to_bytes());
        assert_eq!(
            VerifiedProducerAuthorizationV0::decode_and_verify(
                &bytes,
                expected_context,
                proposer_key,
                &snapshot,
            ),
            Err(ProducerAuthorizationVerifyError::InvalidSignature {
                proposer: proposer_key,
            })
        );
    }
}

#[test]
fn strict_verification_rejects_changed_and_noncanonical_signatures() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let valid = authorization_bytes(expected_context, expected_position, root(7), &proposer);
    let snapshot = snapshot(expected_position, &[(&proposer, 1)]);

    let mut changed = valid;
    changed[SIGNATURE_OFFSET] ^= 1;
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &changed,
            expected_context,
            proposer_key,
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InvalidSignature {
            proposer: proposer_key,
        })
    );

    let mut noncanonical_scalar = valid;
    noncanonical_scalar[PRODUCER_AUTHORIZATION_BYTES - 32..].fill(0xff);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &noncanonical_scalar,
            expected_context,
            proposer_key,
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InvalidSignature {
            proposer: proposer_key,
        })
    );
}

#[test]
fn strict_verification_rejects_low_order_authorization_accepted_by_ordinary_ed25519() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let body = AuthorizationBody {
        context: expected_context,
        position: expected_position,
        proposal_signing_root: root(6),
    };
    let mut weak_key_bytes = [0_u8; 32];
    weak_key_bytes[0] = 1;
    let weak_key = ConsensusKey::from_bytes(weak_key_bytes);
    let mut low_order_signature_bytes = [0_u8; 64];
    low_order_signature_bytes[0] = 1;
    let low_order_signature = DalekSignature::from_bytes(&low_order_signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
    let transcript = signing_transcript(body, weak_key);

    assert!(
        verifying_key
            .verify(&transcript, &low_order_signature)
            .is_ok()
    );
    assert!(
        verifying_key
            .verify_strict(&transcript, &low_order_signature)
            .is_err()
    );

    let snapshot = snapshot_with_raw_key(expected_position, weak_key);
    let mut bytes = bytes_with_raw_key(expected_context, expected_position, root(6), weak_key);
    bytes[SIGNATURE_OFFSET..].copy_from_slice(&low_order_signature_bytes);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &bytes,
            expected_context,
            weak_key,
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::InvalidSignature { proposer: weak_key })
    );
}

#[test]
fn every_authorization_byte_is_bound_or_checked_before_success() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let valid = authorization_bytes(expected_context, expected_position, root(7), &proposer);
    let snapshot = snapshot(expected_position, &[(&proposer, 1)]);

    for offset in 0..PRODUCER_AUTHORIZATION_BYTES {
        let mut mutated = valid;
        mutated[offset] ^= 1;
        assert!(
            VerifiedProducerAuthorizationV0::decode_and_verify(
                &mutated,
                expected_context,
                proposer_key,
                &snapshot,
            )
            .is_err(),
            "mutating byte {offset} must invalidate or mismatch the authorization"
        );
    }
}

#[test]
fn verified_authorization_owns_evidence_independently_of_the_input_buffer() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let expected_root = root(7);
    let proposer = signing_key(6);
    let proposer_key = consensus_key(&proposer);
    let mut bytes = authorization_bytes(
        expected_context,
        expected_position,
        expected_root,
        &proposer,
    );
    let original = bytes;
    let snapshot = snapshot(expected_position, &[(&proposer, 1)]);

    let verified = VerifiedProducerAuthorizationV0::decode_and_verify(
        &bytes,
        expected_context,
        proposer_key,
        &snapshot,
    )
    .unwrap();
    bytes.fill(0);

    assert_eq!(verified.context(), expected_context);
    assert_eq!(verified.position(), expected_position);
    assert_eq!(verified.proposal_signing_root(), expected_root);
    assert_eq!(verified.proposer(), proposer_key);
    assert_eq!(verified.to_canonical_bytes(), original);
}

#[test]
fn each_caller_designated_active_key_can_verify_without_selecting_a_proposer() {
    let expected_context = context(1, 2, u32::MAX);
    let expected_position = position(u64::MAX, u64::MAX);
    let first = signing_key(4);
    let second = signing_key(5);
    let first_key = consensus_key(&first);
    let second_key = consensus_key(&second);
    let snapshot = snapshot(expected_position, &[(&first, 7), (&second, 11)]);
    let first_bytes = authorization_bytes(expected_context, expected_position, root(0), &first);
    let second_bytes = authorization_bytes(expected_context, expected_position, root(0), &second);

    let first_verified = VerifiedProducerAuthorizationV0::decode_and_verify(
        &first_bytes,
        expected_context,
        first_key,
        &snapshot,
    )
    .unwrap();
    let second_verified = VerifiedProducerAuthorizationV0::decode_and_verify(
        &second_bytes,
        expected_context,
        second_key,
        &snapshot,
    )
    .unwrap();
    assert_eq!(first_verified.proposer(), first_key);
    assert_eq!(second_verified.proposer(), second_key);
    assert_eq!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &first_bytes,
            expected_context,
            second_key,
            &snapshot,
        ),
        Err(ProducerAuthorizationVerifyError::UnexpectedProposer {
            expected: second_key,
            actual: first_key,
        })
    );
}

#[test]
fn active_membership_does_not_require_agreement_threshold_weight() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(4, 5);
    let proposer = signing_key(6);
    let other = signing_key(7);
    let proposer_key = consensus_key(&proposer);
    let snapshot = snapshot(
        expected_position,
        &[(&proposer, 1), (&other, u128::MAX - 1)],
    );
    let bytes = authorization_bytes(expected_context, expected_position, root(8), &proposer);

    assert!(
        VerifiedProducerAuthorizationV0::decode_and_verify(
            &bytes,
            expected_context,
            proposer_key,
            &snapshot,
        )
        .is_ok()
    );
}
