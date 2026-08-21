use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use naome_chain::ArtifactChainId;
use sha2::{Digest, Sha256};

use super::*;
use crate::{ActiveAgreementEntry, ActiveAgreementSnapshot, CONSENSUS_KEY_BYTES};

fn signing_key(index: u16) -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    seed[2] = 0xa5;
    SigningKey::from_bytes(&seed)
}

fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

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

fn manual_vote_body(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
    let mut bytes = [0_u8; VOTE_BODY_BYTES];
    bytes[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    bytes[1..33].copy_from_slice(context.chain_id().as_bytes());
    bytes[33..65].copy_from_slice(context.genesis_id().as_bytes());
    bytes[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    bytes[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    bytes[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => bytes[85] = 0,
        ConsensusVoteTarget::Proposal(proposal_root) => {
            bytes[85] = 1;
            bytes[86..118].copy_from_slice(proposal_root.as_bytes());
        }
    }
    bytes
}

fn manual_signing_transcript(body: &[u8; VOTE_BODY_BYTES], signer: ConsensusKey) -> Vec<u8> {
    let domain: &[u8] = match body[0] {
        1 => b"naome:consensus-prevote-signing:v0\0",
        2 => b"naome:consensus-precommit-signing:v0\0",
        _ => panic!("test body has a supported role"),
    };
    let mut transcript = Vec::with_capacity(domain.len() + body.len() + CONSENSUS_KEY_BYTES);
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(body);
    transcript.extend_from_slice(signer.as_bytes());
    transcript
}

fn signed_vote_bytes(
    signing_key: &SigningKey,
    body: [u8; VOTE_BODY_BYTES],
) -> [u8; SIGNED_VOTE_BYTES] {
    let signer = consensus_key(signing_key);
    let signature = signing_key
        .sign(&manual_signing_transcript(&body, signer))
        .to_bytes();
    let mut bytes = [0_u8; SIGNED_VOTE_BYTES];
    bytes[..VOTE_BODY_BYTES].copy_from_slice(&body);
    bytes[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET].copy_from_slice(signer.as_bytes());
    bytes[VOTE_SIGNATURE_OFFSET..].copy_from_slice(&signature);
    bytes
}

fn ordered_keys<'a>(keys: impl IntoIterator<Item = &'a SigningKey>) -> Vec<&'a SigningKey> {
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_unstable_by_key(|key| consensus_key(key));
    keys
}

fn certificate_bytes_in_order(
    body: [u8; VOTE_BODY_BYTES],
    signing_keys: &[&SigningKey],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        CERTIFICATE_ENTRIES_OFFSET + signing_keys.len() * CERTIFICATE_ENTRY_BYTES,
    );
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        &u16::try_from(signing_keys.len())
            .expect("test certificates fit the count field")
            .to_be_bytes(),
    );
    for signing_key in signing_keys {
        let signer = consensus_key(signing_key);
        bytes.extend_from_slice(signer.as_bytes());
        bytes.extend_from_slice(
            &signing_key
                .sign(&manual_signing_transcript(&body, signer))
                .to_bytes(),
        );
    }
    bytes
}

fn certificate_bytes(body: [u8; VOTE_BODY_BYTES], signing_keys: &[&SigningKey]) -> Vec<u8> {
    certificate_bytes_in_order(body, &ordered_keys(signing_keys.iter().copied()))
}

fn snapshot(
    position: ConsensusPosition,
    weighted_keys: &[(&SigningKey, u128)],
) -> ActiveAgreementSnapshot {
    let entries = weighted_keys
        .iter()
        .map(|(key, weight)| {
            ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(*weight))
        })
        .collect::<Vec<_>>();
    ActiveAgreementSnapshot::try_from_preselected(position, &entries).unwrap()
}

#[test]
fn context_and_evidence_value_types_preserve_exact_values() {
    let context = context(0x11, 0x22, u32::MAX);
    let proposal_root = root(0x33);
    let signature = ConsensusSignature::from_bytes([0x44; CONSENSUS_SIGNATURE_BYTES]);

    assert_eq!(context.chain_id().as_bytes(), &[0x11; 32]);
    assert_eq!(context.genesis_id().as_bytes(), &[0x22; 32]);
    assert_eq!(context.protocol_version().value(), u32::MAX);
    assert_eq!(proposal_root.as_bytes(), &[0x33; 32]);
    assert_eq!(signature.as_bytes(), &[0x44; 64]);
}

#[test]
fn signed_vote_golden_layout_direct_signature_and_semantic_id_are_exact() {
    // Independently generated with Python cryptography's RFC 8032 implementation.
    const EXPECTED_PUBLIC_KEY: [u8; 32] = [
        0x1a, 0x63, 0xf8, 0x3a, 0x2f, 0xc1, 0xce, 0x57, 0xfc, 0x95, 0x7b, 0x8f, 0xe9, 0xce, 0xca,
        0x74, 0x6b, 0x3a, 0x62, 0x72, 0xa2, 0x39, 0xad, 0xdd, 0x7d, 0x66, 0x81, 0xac, 0x22, 0x90,
        0xd6, 0xde,
    ];
    const EXPECTED_SIGNATURE: [u8; 64] = [
        0xa2, 0x0b, 0x4d, 0x6d, 0x10, 0xa7, 0x35, 0x4f, 0x88, 0xf4, 0x74, 0xa5, 0x57, 0x07, 0x46,
        0xc2, 0xa8, 0x9a, 0x63, 0x3b, 0x6c, 0x84, 0xd9, 0x8a, 0x25, 0xc5, 0x71, 0x54, 0x99, 0xee,
        0x77, 0xf9, 0xa6, 0x4f, 0xf2, 0x9a, 0x99, 0x90, 0x17, 0xb8, 0xd9, 0x95, 0x0a, 0x07, 0xb2,
        0x8d, 0xd5, 0x22, 0x58, 0xac, 0xd2, 0x68, 0x4e, 0x2c, 0xa5, 0x06, 0x1f, 0x5b, 0x26, 0x59,
        0xb9, 0x6b, 0x7e, 0x05,
    ];
    const EXPECTED_ID: [u8; 32] = [
        0x04, 0x26, 0xf2, 0x3b, 0xfe, 0x71, 0xb1, 0x96, 0x22, 0x88, 0x84, 0xf3, 0x04, 0xf9, 0x0b,
        0x3c, 0xb8, 0xee, 0x5e, 0xf9, 0xfe, 0x06, 0xa6, 0xc9, 0x32, 0xe9, 0x51, 0x94, 0x7d, 0xc1,
        0x56, 0xd0,
    ];
    const EXPECTED_CERTIFICATE_ID: [u8; 32] = [
        0xbc, 0xd5, 0xe4, 0x11, 0x34, 0x43, 0x0d, 0xa9, 0x47, 0xf3, 0xd2, 0xcf, 0x9b, 0x5c, 0x3b,
        0xe6, 0x33, 0xbc, 0x35, 0x89, 0xd2, 0x24, 0x3d, 0x69, 0xd9, 0x5e, 0x76, 0xc4, 0x98, 0xec,
        0xb8, 0x39,
    ];

    let expected_context = context(0x11, 0x22, 0x0102_0304);
    let expected_position = position(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    let expected_root = root(0x33);
    let signer = signing_key(7);
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(expected_root),
    );
    let bytes = signed_vote_bytes(&signer, body);

    assert_eq!(bytes.len(), 214);
    assert_eq!(bytes[0], 2);
    assert_eq!(&bytes[1..33], &[0x11; 32]);
    assert_eq!(&bytes[33..65], &[0x22; 32]);
    assert_eq!(&bytes[65..69], &0x0102_0304_u32.to_be_bytes());
    assert_eq!(&bytes[69..77], &0x0102_0304_0506_0708_u64.to_be_bytes());
    assert_eq!(&bytes[77..85], &0x1112_1314_1516_1718_u64.to_be_bytes());
    assert_eq!(bytes[85], 1);
    assert_eq!(&bytes[86..118], &[0x33; 32]);
    assert_eq!(
        &bytes[118..150],
        consensus_key(&signer).as_bytes().as_slice()
    );
    assert_eq!(&bytes[118..150], &EXPECTED_PUBLIC_KEY);
    assert_eq!(&bytes[150..214], &EXPECTED_SIGNATURE);

    let verified = VerifiedConsensusVoteV0::decode_and_verify(&bytes, expected_context).unwrap();
    assert_eq!(verified.context(), expected_context);
    assert_eq!(verified.position(), expected_position);
    assert_eq!(verified.role(), ConsensusVoteRole::Precommit);
    assert_eq!(
        verified.target(),
        ConsensusVoteTarget::Proposal(expected_root)
    );
    assert_eq!(verified.signer(), consensus_key(&signer));
    assert_eq!(verified.id().as_bytes(), &EXPECTED_ID);
    assert_eq!(verified.to_canonical_bytes(), bytes);

    let snapshot = snapshot(expected_position, &[(&signer, 1)]);
    let certificate = certificate_bytes(body, &[&signer]);
    let verified_certificate = VerifiedPrecommitCertificateV0::decode_and_verify(
        &certificate,
        expected_context,
        &snapshot,
    )
    .unwrap();
    assert_eq!(certificate.len(), 216);
    assert_eq!(
        verified_certificate.id().as_bytes(),
        &EXPECTED_CERTIFICATE_ID
    );
}

#[test]
fn nil_prevote_has_one_canonical_representation() {
    let expected_context = context(1, 2, 3);
    let signer = signing_key(1);
    let body = manual_vote_body(
        expected_context,
        position(1, 0),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let bytes = signed_vote_bytes(&signer, body);
    let verified = VerifiedConsensusVoteV0::decode_and_verify(&bytes, expected_context).unwrap();
    assert_eq!(verified.target(), ConsensusVoteTarget::Nil);

    let mut noncanonical = bytes;
    noncanonical[117] = 1;
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&noncanonical, expected_context),
        Err(ConsensusVoteVerifyError::Decode(
            ConsensusVoteDecodeError::NonCanonicalNilTarget
        ))
    );
}

#[test]
fn signed_vote_rejects_every_nonexact_length_and_unknown_tags() {
    let expected_context = context(1, 2, 3);
    let signer = signing_key(1);
    let bytes = signed_vote_bytes(
        &signer,
        manual_vote_body(
            expected_context,
            position(1, 0),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
        ),
    );

    for length in 0..SIGNED_VOTE_BYTES {
        assert!(matches!(
            VerifiedConsensusVoteV0::decode_and_verify(&bytes[..length], expected_context),
            Err(ConsensusVoteVerifyError::Decode(
                ConsensusVoteDecodeError::InvalidLength { .. }
            ))
        ));
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&trailing, expected_context),
        Err(ConsensusVoteVerifyError::Decode(
            ConsensusVoteDecodeError::InvalidLength { .. }
        ))
    ));

    let mut unknown_role = bytes;
    unknown_role[0] = 3;
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&unknown_role, expected_context),
        Err(ConsensusVoteVerifyError::Decode(
            ConsensusVoteDecodeError::UnknownRoleTag { actual: 3 }
        ))
    );
    let mut unknown_target = bytes;
    unknown_target[85] = 2;
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&unknown_target, expected_context),
        Err(ConsensusVoteVerifyError::Decode(
            ConsensusVoteDecodeError::UnknownTargetTag { actual: 2 }
        ))
    );
    let mut genesis_vote = bytes;
    genesis_vote[69..77].fill(0);
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&genesis_vote, expected_context),
        Err(ConsensusVoteVerifyError::Decode(
            ConsensusVoteDecodeError::ReservedGenesisHeight
        ))
    );
}

#[test]
fn signatures_cannot_replay_across_role_context_position_signer_or_target() {
    let expected_context = context(1, 2, 3);
    let signer = signing_key(1);
    let bytes = signed_vote_bytes(
        &signer,
        manual_vote_body(
            expected_context,
            position(7, 8),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root(9)),
        ),
    );

    let mut wrong_role = bytes;
    wrong_role[0] = 2;
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&wrong_role, expected_context),
        Err(ConsensusVoteVerifyError::InvalidSignature { .. })
    ));

    for alternate_context in [context(2, 2, 3), context(1, 3, 3), context(1, 2, 4)] {
        let mut cross_context = bytes;
        cross_context[..VOTE_BODY_BYTES].copy_from_slice(&manual_vote_body(
            alternate_context,
            position(7, 8),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root(9)),
        ));
        assert!(matches!(
            VerifiedConsensusVoteV0::decode_and_verify(&cross_context, alternate_context),
            Err(ConsensusVoteVerifyError::InvalidSignature { .. })
        ));
    }

    for mutation in [70_usize, 78, 86, 118] {
        let mut mutated = bytes;
        mutated[mutation] ^= 1;
        assert!(matches!(
            VerifiedConsensusVoteV0::decode_and_verify(&mutated, expected_context),
            Err(ConsensusVoteVerifyError::InvalidSignature { .. })
                | Err(ConsensusVoteVerifyError::MalformedConsensusKey { .. })
        ));
    }
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&bytes, context(2, 2, 3)),
        Err(ConsensusVoteVerifyError::ChainIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&bytes, context(1, 3, 3)),
        Err(ConsensusVoteVerifyError::GenesisIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&bytes, context(1, 2, 4)),
        Err(ConsensusVoteVerifyError::ProtocolVersionMismatch { .. })
    ));
}

#[test]
fn role_domains_give_valid_prevote_and_precommit_distinct_identities() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let expected_target = ConsensusVoteTarget::Proposal(root(9));
    let signer = signing_key(1);
    let prevote = signed_vote_bytes(
        &signer,
        manual_vote_body(
            expected_context,
            expected_position,
            ConsensusVoteRole::Prevote,
            expected_target,
        ),
    );
    let precommit = signed_vote_bytes(
        &signer,
        manual_vote_body(
            expected_context,
            expected_position,
            ConsensusVoteRole::Precommit,
            expected_target,
        ),
    );
    let prevote = VerifiedConsensusVoteV0::decode_and_verify(&prevote, expected_context).unwrap();
    let precommit =
        VerifiedConsensusVoteV0::decode_and_verify(&precommit, expected_context).unwrap();

    assert_ne!(prevote.id(), precommit.id());
    assert_ne!(prevote.signature(), precommit.signature());
}

#[test]
fn direct_ed25519_transcript_rejects_prehashed_and_mutated_signatures() {
    let expected_context = context(1, 2, 3);
    let signer = signing_key(1);
    let body = manual_vote_body(
        expected_context,
        position(1, 0),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(4)),
    );
    let signer_key = consensus_key(&signer);
    let digest = Sha256::digest(manual_signing_transcript(&body, signer_key));
    let mut prehashed = [0_u8; SIGNED_VOTE_BYTES];
    prehashed[..VOTE_BODY_BYTES].copy_from_slice(&body);
    prehashed[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET].copy_from_slice(signer_key.as_bytes());
    prehashed[VOTE_SIGNATURE_OFFSET..].copy_from_slice(&signer.sign(&digest).to_bytes());
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&prehashed, expected_context),
        Err(ConsensusVoteVerifyError::InvalidSignature { .. })
    ));

    let mut mutated = signed_vote_bytes(&signer, body);
    mutated[VOTE_SIGNATURE_OFFSET] ^= 1;
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&mutated, expected_context),
        Err(ConsensusVoteVerifyError::InvalidSignature { .. })
    ));

    let mut noncanonical_scalar = signed_vote_bytes(&signer, body);
    noncanonical_scalar[SIGNED_VOTE_BYTES - 32..].fill(0xff);
    assert!(matches!(
        VerifiedConsensusVoteV0::decode_and_verify(&noncanonical_scalar, expected_context),
        Err(ConsensusVoteVerifyError::InvalidSignature { .. })
    ));
}

#[test]
fn strict_verification_rejects_low_order_evidence_accepted_by_ordinary_ed25519() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(1, 0);
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(4)),
    );
    let mut weak_key_bytes = [0_u8; CONSENSUS_KEY_BYTES];
    weak_key_bytes[0] = 1; // Compressed Edwards identity.
    let weak_key = ConsensusKey::from_bytes(weak_key_bytes);
    let mut low_order_signature_bytes = [0_u8; CONSENSUS_SIGNATURE_BYTES];
    low_order_signature_bytes[0] = 1; // R = identity, S = 0.
    let low_order_signature = DalekSignature::from_bytes(&low_order_signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
    let transcript = manual_signing_transcript(&body, weak_key);

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

    let mut vote = [0_u8; SIGNED_VOTE_BYTES];
    vote[..VOTE_BODY_BYTES].copy_from_slice(&body);
    vote[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET].copy_from_slice(weak_key.as_bytes());
    vote[VOTE_SIGNATURE_OFFSET..].copy_from_slice(&low_order_signature_bytes);
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&vote, expected_context),
        Err(ConsensusVoteVerifyError::InvalidSignature { signer: weak_key })
    );

    let weak_snapshot = ActiveAgreementSnapshot::try_from_preselected(
        expected_position,
        &[ActiveAgreementEntry::new(weak_key, AgreementWeight::new(1))],
    )
    .unwrap();
    let mut certificate = Vec::with_capacity(216);
    certificate.extend_from_slice(&body);
    certificate.extend_from_slice(&1_u16.to_be_bytes());
    certificate.extend_from_slice(weak_key.as_bytes());
    certificate.extend_from_slice(&low_order_signature_bytes);
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            expected_context,
            &weak_snapshot,
        ),
        Err(PrecommitCertificateVerifyError::InvalidSignature { signer: weak_key })
    );
}

#[test]
fn malformed_ed25519_keys_fail_before_signature_or_threshold_results() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(1, 0);
    let mut malformed_key_bytes = [0_u8; CONSENSUS_KEY_BYTES];
    malformed_key_bytes[1] = 3;
    let malformed_key = ConsensusKey::from_bytes(malformed_key_bytes);
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(4)),
    );

    let mut vote = [0_u8; SIGNED_VOTE_BYTES];
    vote[..VOTE_BODY_BYTES].copy_from_slice(&body);
    vote[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET].copy_from_slice(malformed_key.as_bytes());
    assert_eq!(
        VerifiedConsensusVoteV0::decode_and_verify(&vote, expected_context),
        Err(ConsensusVoteVerifyError::MalformedConsensusKey {
            signer: malformed_key,
        })
    );

    let malformed_snapshot = ActiveAgreementSnapshot::try_from_preselected(
        expected_position,
        &[ActiveAgreementEntry::new(
            malformed_key,
            AgreementWeight::new(1),
        )],
    )
    .unwrap();
    let mut certificate = Vec::with_capacity(MIN_CERTIFICATE_BYTES);
    certificate.extend_from_slice(&body);
    certificate.extend_from_slice(&1_u16.to_be_bytes());
    certificate.extend_from_slice(malformed_key.as_bytes());
    certificate.extend_from_slice(&[0_u8; CONSENSUS_SIGNATURE_BYTES]);
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            expected_context,
            &malformed_snapshot,
        ),
        Err(PrecommitCertificateVerifyError::MalformedConsensusKey {
            signer: malformed_key,
        })
    );
}

#[test]
fn certificate_requires_every_signature_and_strict_supermajority() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let keys = [signing_key(1), signing_key(2), signing_key(3)];
    let snapshot = snapshot(
        expected_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );

    let exact_two_thirds = certificate_bytes(body, &[&keys[0], &keys[1]]);
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &exact_two_thirds,
            expected_context,
            &snapshot
        ),
        Err(
            PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                signed: AgreementWeight::new(2),
                total: AgreementWeight::new(3),
            }
        )
    );

    let all = certificate_bytes(body, &[&keys[0], &keys[1], &keys[2]]);
    let verified =
        VerifiedPrecommitCertificateV0::decode_and_verify(&all, expected_context, &snapshot)
            .unwrap();
    let expected_id: [u8; 32] = Sha256::digest(&all).into();
    assert_eq!(verified.context(), expected_context);
    assert_eq!(verified.position(), expected_position);
    assert_eq!(verified.proposal_signing_root(), root(9));
    assert_eq!(verified.signer_count(), 3);
    assert_eq!(verified.signed_weight(), AgreementWeight::new(3));
    assert_eq!(verified.total_weight(), AgreementWeight::new(3));
    assert_eq!(verified.id().as_bytes(), &expected_id);
    assert_eq!(verified.to_canonical_bytes(), all);

    let mut invalid = verified.to_canonical_bytes();
    invalid[CERTIFICATE_ENTRIES_OFFSET + CONSENSUS_KEY_BYTES] ^= 1;
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&invalid, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::InvalidSignature { .. })
    ));
}

#[test]
fn certificate_rejects_nil_prevote_duplicates_ordering_and_unknown_signers() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let keys = [signing_key(1), signing_key(2), signing_key(3)];
    let unknown = signing_key(4);
    let snapshot = snapshot(
        expected_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let proposal_body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );

    let nil = certificate_bytes(
        manual_vote_body(
            expected_context,
            expected_position,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
        ),
        &[&keys[0]],
    );
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&nil, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::NilCertificateTarget)
    );
    let prevote = certificate_bytes(
        manual_vote_body(
            expected_context,
            expected_position,
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root(9)),
        ),
        &[&keys[0]],
    );
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&prevote, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::WrongVoteRole {
            actual: ConsensusVoteRole::Prevote,
        })
    );

    let duplicate = certificate_bytes_in_order(proposal_body, &[&keys[0], &keys[0]]);
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&duplicate, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::DuplicateSigner { .. })
    ));

    let ascending = ordered_keys([&keys[0], &keys[1]]);
    let descending = [ascending[1], ascending[0]];
    let unordered = certificate_bytes_in_order(proposal_body, &descending);
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&unordered, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::NonAscendingSignerOrder { .. })
    ));

    let unknown_certificate = certificate_bytes(proposal_body, &[&keys[0], &keys[1], &unknown]);
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &unknown_certificate,
            expected_context,
            &snapshot
        ),
        Err(PrecommitCertificateVerifyError::UnknownSigner { .. })
    ));
}

#[test]
fn certificate_framing_is_exact_and_bounded_before_allocation() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let key = signing_key(1);
    let snapshot = snapshot(expected_position, &[(&key, 1)]);
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );
    let valid = certificate_bytes(body, &[&key]);
    assert_eq!(VerifiedConsensusVoteV0::BYTE_LENGTH, 214);
    assert_eq!(VerifiedPrecommitCertificateV0::MIN_BYTE_LENGTH, 216);
    assert_eq!(VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH, 24_696);
    assert_eq!(valid.len(), 216);

    for length in 0..CERTIFICATE_ENTRIES_OFFSET {
        assert!(matches!(
            VerifiedPrecommitCertificateV0::decode_and_verify(
                &valid[..length.min(valid.len())],
                expected_context,
                &snapshot
            ),
            Err(PrecommitCertificateVerifyError::InvalidLength { .. })
        ));
    }

    let empty = [&body[..], &[0, 0]].concat();
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&empty, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::EmptySignerSet)
    );
    let over_count = [&body[..], &257_u16.to_be_bytes()].concat();
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&over_count, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::TooManySigners {
            actual: 257,
            maximum: 256,
        })
    );

    for length in CERTIFICATE_ENTRIES_OFFSET..valid.len() {
        assert!(matches!(
            VerifiedPrecommitCertificateV0::decode_and_verify(
                &valid[..length],
                expected_context,
                &snapshot
            ),
            Err(PrecommitCertificateVerifyError::LengthMismatch { .. })
        ));
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&trailing, expected_context, &snapshot),
        Err(PrecommitCertificateVerifyError::LengthMismatch { .. })
    ));
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &vec![0; MAX_CERTIFICATE_BYTES + 1],
            expected_context,
            &snapshot
        ),
        Err(PrecommitCertificateVerifyError::InputTooLong {
            actual: MAX_CERTIFICATE_BYTES + 1,
            maximum: MAX_CERTIFICATE_BYTES,
        })
    );
}

#[test]
fn certificate_enforces_expected_context_and_snapshot_position_before_crypto() {
    let embedded_context = context(1, 2, 3);
    let embedded_position = position(7, 8);
    let keys = [signing_key(1), signing_key(2), signing_key(3)];
    let body = manual_vote_body(
        embedded_context,
        embedded_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );
    let certificate = certificate_bytes(body, &[&keys[0], &keys[1], &keys[2]]);
    let matching_snapshot = snapshot(
        embedded_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );

    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            context(2, 2, 3),
            &matching_snapshot
        ),
        Err(PrecommitCertificateVerifyError::ChainIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            context(1, 3, 3),
            &matching_snapshot
        ),
        Err(PrecommitCertificateVerifyError::GenesisIdMismatch { .. })
    ));
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            context(1, 2, 4),
            &matching_snapshot
        ),
        Err(PrecommitCertificateVerifyError::ProtocolVersionMismatch { .. })
    ));
    let wrong_position_snapshot = snapshot(
        position(7, 9),
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    assert!(matches!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &certificate,
            embedded_context,
            &wrong_position_snapshot
        ),
        Err(PrecommitCertificateVerifyError::SnapshotPositionMismatch { .. })
    ));
}

#[test]
fn certificate_threshold_is_exact_at_u128_max_without_multiplication() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let keys = [signing_key(1), signing_key(2)];
    let quotient = u128::MAX / 3;
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );

    let exact_snapshot = snapshot(
        expected_position,
        &[(&keys[0], quotient * 2), (&keys[1], quotient)],
    );
    let exact = certificate_bytes(body, &[&keys[0]]);
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(
            &exact,
            expected_context,
            &exact_snapshot
        ),
        Err(
            PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                signed: AgreementWeight::new(quotient * 2),
                total: AgreementWeight::new(u128::MAX),
            }
        )
    );

    let above_snapshot = snapshot(
        expected_position,
        &[(&keys[0], quotient * 2 + 1), (&keys[1], quotient - 1)],
    );
    let above = certificate_bytes(body, &[&keys[0]]);
    let verified = VerifiedPrecommitCertificateV0::decode_and_verify(
        &above,
        expected_context,
        &above_snapshot,
    )
    .unwrap();
    assert_eq!(verified.signed_weight().units(), quotient * 2 + 1);
    assert_eq!(verified.total_weight().units(), u128::MAX);
}

#[test]
fn maximum_active_set_requires_171_of_256_equal_weight_signers() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let keys = (0..256_u16).map(signing_key).collect::<Vec<_>>();
    let snapshot = snapshot(
        expected_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root(9)),
    );
    let ordered = ordered_keys(keys.iter());

    let below = certificate_bytes_in_order(body, &ordered[..170]);
    assert_eq!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&below, expected_context, &snapshot),
        Err(
            PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                signed: AgreementWeight::new(170),
                total: AgreementWeight::new(256),
            }
        )
    );

    let above = certificate_bytes_in_order(body, &ordered[..171]);
    let verified =
        VerifiedPrecommitCertificateV0::decode_and_verify(&above, expected_context, &snapshot)
            .unwrap();
    assert_eq!(verified.signer_count(), 171);

    let maximum = certificate_bytes_in_order(body, &ordered);
    assert_eq!(maximum.len(), 24_696);
    assert!(
        VerifiedPrecommitCertificateV0::decode_and_verify(&maximum, expected_context, &snapshot)
            .is_ok()
    );
}

#[test]
fn valid_signer_subsets_share_target_but_have_distinct_evidence_ids() {
    let expected_context = context(1, 2, 3);
    let expected_position = position(7, 8);
    let keys = [
        signing_key(1),
        signing_key(2),
        signing_key(3),
        signing_key(4),
    ];
    let snapshot = snapshot(
        expected_position,
        &keys.iter().map(|key| (key, 1)).collect::<Vec<_>>(),
    );
    let expected_root = root(9);
    let body = manual_vote_body(
        expected_context,
        expected_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(expected_root),
    );
    let first = certificate_bytes(body, &[&keys[0], &keys[1], &keys[2]]);
    let second = certificate_bytes(body, &[&keys[1], &keys[2], &keys[3]]);
    let first =
        VerifiedPrecommitCertificateV0::decode_and_verify(&first, expected_context, &snapshot)
            .unwrap();
    let second =
        VerifiedPrecommitCertificateV0::decode_and_verify(&second, expected_context, &snapshot)
            .unwrap();

    assert_eq!(first.proposal_signing_root(), expected_root);
    assert_eq!(second.proposal_signing_root(), expected_root);
    assert_ne!(first.id(), second.id());
}
