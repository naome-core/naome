use super::*;
use crate::codec_corpus::check;

#[test]
fn signed_consensus_codecs_have_a_complete_role_mutation_corpus() {
    let fixture = fixture(2);
    check(
        "consensus value",
        &[
            golden_value().to_canonical_bytes().to_vec(),
            fixture.value.to_canonical_bytes().to_vec(),
        ],
        |bytes| {
            ConsensusValueV0::from_canonical_bytes(bytes)
                .ok()
                .map(|v| v.to_canonical_bytes().to_vec())
        },
    );
    let authorization = authorization_bytes(
        fixture.context,
        fixture.position,
        fixture.value.proposal_signing_root(),
        &fixture.proposer,
    );
    check(
        "producer authorization",
        &[authorization.to_vec()],
        |bytes| {
            VerifiedProducerAuthorizationV0::decode_and_verify(
                bytes,
                fixture.context,
                consensus_key(&fixture.proposer),
                &fixture.snapshot,
            )
            .ok()
            .map(|v| v.to_canonical_bytes().to_vec())
        },
    );
    let mut votes = Vec::new();
    let mut certificates = Vec::new();
    for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
        for target in [
            ConsensusVoteTarget::Nil,
            ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        ] {
            votes.push(signed_vote_bytes(
                fixture.context,
                fixture.position,
                role,
                target,
                &fixture.proposer,
            ));
            certificates.push(quorum_certificate_bytes(
                fixture.context,
                fixture.position,
                role,
                target,
                &[&fixture.proposer],
            ));
        }
    }
    check("signed vote: both roles and targets", &votes, |bytes| {
        VerifiedConsensusVoteV0::decode_and_verify(bytes, fixture.context)
            .ok()
            .map(|v| v.to_canonical_bytes().to_vec())
    });
    check(
        "quorum certificate: both roles and targets",
        &certificates,
        |bytes| {
            VerifiedQuorumCertificateV0::decode_and_verify(
                bytes,
                fixture.context,
                &fixture.snapshot,
            )
            .ok()
            .map(|v| v.to_canonical_bytes())
        },
    );
    check(
        "non-nil precommit certificate",
        &certificates[3..],
        |bytes| {
            VerifiedPrecommitCertificateV0::decode_and_verify(
                bytes,
                fixture.context,
                &fixture.snapshot,
            )
            .ok()
            .map(|v| v.to_canonical_bytes())
        },
    );
    let earlier = quorum_certificate_bytes(
        fixture.context,
        position(1, 1),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(fixture.value.proposal_signing_root()),
        &[&fixture.proposer],
    );
    let proposals = [
        proposal_control_bytes(fixture.value, fixture.position, &fixture.proposer, None),
        proposal_control_bytes(
            fixture.value,
            fixture.position,
            &fixture.proposer,
            Some(&earlier),
        ),
    ];
    check(
        "proposal control: fresh and retained",
        &proposals,
        |bytes| {
            let proposal =
                verify_proposal_fixture(&fixture, bytes, fixture.payload.clone()).ok()?;
            // Rebuild from typed value, authorization and the independently
            // decoded embedded proof, not the proposal's retained input buffer.
            let mut encoded = proposal.value().to_canonical_bytes().to_vec();
            encoded.extend_from_slice(&proposal.producer_authorization().to_canonical_bytes());
            match proposal.valid_round_certificate_bytes() {
                None => encoded.push(0),
                Some(proof) => {
                    encoded.push(1);
                    let round = VerifiedQuorumCertificateV0::strictly_peek_position(proof).unwrap();
                    let snapshot = snapshot(round, &[(&fixture.proposer, 1)]);
                    encoded.extend_from_slice(
                        &VerifiedQuorumCertificateV0::decode_and_verify(
                            proof,
                            fixture.context,
                            &snapshot,
                        )
                        .unwrap()
                        .to_canonical_bytes(),
                    );
                }
            }
            Some(encoded)
        },
    );
    check(
        "finality envelope",
        std::slice::from_ref(&fixture.bytes),
        |bytes| {
            verify_fixture(&fixture, bytes, fixture.payload.clone())
                .ok()
                .map(|v| v.to_canonical_bytes())
        },
    );
}

#[test]
fn signed_codec_declared_bounds_precede_nested_crypto_or_artifact_work() {
    let fixture = fixture(2);
    // Invalid first bytes and no valid signature still report the enclosing
    // length bound. These checks exercise decoder guards, not test timeouts.
    let bytes = vec![0xff; VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        VerifiedQuorumCertificateV0::decode_and_verify(&bytes, fixture.context, &fixture.snapshot),
        Err(crate::QuorumCertificateVerifyError::InputTooLong { .. })
    ));
    let bytes = vec![0xff; VerifiedConsensusProposalV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        verify_proposal_fixture(&fixture, &bytes, vec![0xff]),
        Err(ConsensusProposalVerifyError::InputTooLong { .. })
    ));
    let bytes = vec![0xff; VerifiedConsensusEnvelopeV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        verify_fixture(&fixture, &bytes, vec![0xff]),
        Err(ConsensusEnvelopeVerifyError::InputTooLong { .. })
    ));
}
