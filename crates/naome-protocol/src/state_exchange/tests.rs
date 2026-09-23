use super::*;
const MAX: usize = STATE_MAX_FRAME_BYTES;
fn context() -> StateContext {
    StateContext::new([1; 32], [2; 32])
}
#[test]
fn every_state_envelope_roundtrips_and_rejects_all_truncations() {
    let id = ProofId::from_bytes([3; 32]);
    let requests = [
        StateRequestBody::Handshake,
        StateRequestBody::TimeReport(vec![1].into()),
        StateRequestBody::UserAction(vec![2].into()),
        StateRequestBody::Proposal(vec![3].into()),
        StateRequestBody::Vote(vec![4].into()),
        StateRequestBody::Finalized(vec![5].into()),
        StateRequestBody::History {
            from: 1,
            max_records: 2,
        },
        StateRequestBody::Proof { proof_id: id },
        StateRequestBody::Offer(vec![8].into()),
        StateRequestBody::CandidateOffer(vec![9].into()),
        StateRequestBody::Agreement(vec![10].into()),
        StateRequestBody::ReadySignature(vec![11].into()),
        StateRequestBody::TerminalSignature(vec![12].into()),
        StateRequestBody::RecoveryChallenge,
        StateRequestBody::RecoveryHello(vec![13; STATE_RECOVERY_HELLO_BYTES].into()),
        StateRequestBody::PendingAgreement { height: 1 },
    ];
    for body in requests {
        let request = StateRequest::new(context(), body, MAX).unwrap();
        let mut bytes = request.to_wire_bytes();
        assert_eq!(bytes.len(), request.wire_len());
        assert_eq!(
            StateRequest::from_wire_bytes(&bytes, context(), MAX).unwrap(),
            request
        );
        for cut in 0..bytes.len() {
            assert!(StateRequest::from_wire_bytes(&bytes[..cut], context(), MAX).is_err());
        }
        bytes.push(0);
        assert!(StateRequest::from_wire_bytes(&bytes, context(), MAX).is_err());
    }
    let responses = [
        StateResponseBody::Ready,
        StateResponseBody::Accepted,
        StateResponseBody::Busy,
        StateResponseBody::Rejected(StateRejection::Invalid),
        StateResponseBody::Rejected(StateRejection::Unauthorized),
        StateResponseBody::Rejected(StateRejection::Unsupported),
        StateResponseBody::History(vec![
            StateHistoryItem {
                height: 1,
                evidence: vec![7].into(),
            },
            StateHistoryItem {
                height: 2,
                evidence: vec![8].into(),
            },
        ]),
        StateResponseBody::Proof {
            proof_id: id,
            certificate: vec![9].into(),
        },
        StateResponseBody::Unavailable,
        StateResponseBody::RecoveryNonce([15; 32]),
        StateResponseBody::Agreement(None),
        StateResponseBody::Agreement(Some(vec![16].into())),
    ];
    for body in responses {
        let response = StateResponse::new(context(), [4; 32], body, MAX).unwrap();
        let mut bytes = response.to_wire_bytes();
        assert_eq!(bytes.len(), response.wire_len());
        assert_eq!(
            StateResponse::from_wire_bytes(&bytes, context(), MAX).unwrap(),
            response
        );
        for cut in 0..bytes.len() {
            assert!(StateResponse::from_wire_bytes(&bytes[..cut], context(), MAX).is_err());
        }
        bytes.push(0);
        assert!(StateResponse::from_wire_bytes(&bytes, context(), MAX).is_err());
    }
}
#[test]
fn header_rejects_wrong_context_direction_version_tag_and_excess_before_body() {
    let bytes = StateRequest::new(context(), StateRequestBody::Handshake, MAX)
        .unwrap()
        .to_wire_bytes();
    assert_eq!(&bytes[..3], &[0, 3, 0]);
    assert_eq!(&bytes[3..35], &[1; 32]);
    assert_eq!(&bytes[35..67], &[2; 32]);
    assert_eq!(&bytes[67..], &[0, 0, 0, 0, 0]);
    for offset in [0, 2, 3, 35, 67] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(state_frame_length(&bad, false, context(), MAX).is_err());
    }
    let mut oversized = bytes;
    oversized[67] = 3;
    oversized[68..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        state_frame_length(&oversized, false, context(), MAX),
        Err(StateWireError::Limit)
    );
}
#[test]
fn bounded_history_and_response_correlation() {
    for (from, max_records) in [(0, 1), (1, 0), (1, 17), (u64::MAX, 2)] {
        assert!(
            StateRequest::new(
                context(),
                StateRequestBody::History { from, max_records },
                MAX
            )
            .is_err()
        );
    }
    for heights in [[1, 1], [2, 1], [1, 3], [0, 1]] {
        assert!(
            StateResponse::new(
                context(),
                [0; 32],
                StateResponseBody::History(
                    heights
                        .into_iter()
                        .map(|height| StateHistoryItem {
                            height,
                            evidence: vec![1].into()
                        })
                        .collect()
                ),
                MAX
            )
            .is_err()
        );
    }
    let request = StateRequest::new(
        context(),
        StateRequestBody::History {
            from: 2,
            max_records: 1,
        },
        MAX,
    )
    .unwrap();
    for (body, expected) in [
        (StateResponseBody::Ready, false),
        (StateResponseBody::Busy, true),
        (StateResponseBody::Unavailable, true),
        (
            StateResponseBody::History(vec![StateHistoryItem {
                height: 1,
                evidence: vec![1].into(),
            }]),
            false,
        ),
        (
            StateResponseBody::History(vec![StateHistoryItem {
                height: 2,
                evidence: vec![1].into(),
            }]),
            true,
        ),
    ] {
        assert_eq!(
            StateResponse::new(context(), [0; 32], body, MAX)
                .unwrap()
                .matches_request(&request),
            expected
        );
    }
    let request = StateRequest::new(
        context(),
        StateRequestBody::Proof {
            proof_id: ProofId::from_bytes([1; 32]),
        },
        MAX,
    )
    .unwrap();
    assert!(
        !StateResponse::new(
            context(),
            [0; 32],
            StateResponseBody::Proof {
                proof_id: ProofId::from_bytes([2; 32]),
                certificate: vec![1].into()
            },
            MAX
        )
        .unwrap()
        .matches_request(&request)
    );
}

#[test]
fn fixed_v3_proof_and_history_wire_vectors() {
    // Explicit byte layouts independent of the production writer: v3, request,
    // genesis/profile, Proof tag, 32-byte body length, concrete ProofId.
    let expected = [
        &[0, 3, 0][..],
        &[1; 32],
        &[2; 32],
        &[7, 0, 0, 0, 32],
        &[3; 32],
    ]
    .concat();
    let request = StateRequest::new(
        context(),
        StateRequestBody::Proof {
            proof_id: ProofId::from_bytes([3; 32]),
        },
        MAX,
    )
    .unwrap();
    assert_eq!(request.to_wire_bytes(), expected);
    assert_eq!(
        StateRequest::from_wire_bytes(&expected, context(), MAX).unwrap(),
        request
    );
    // Response body includes its exact 32-byte request digest, followed by ID
    // and the opaque three-byte test certificate. Decoding grants no authority.
    let expected = [
        &[0, 3, 1][..],
        &[1; 32],
        &[2; 32],
        &[5, 0, 0, 0, 67],
        &[4; 32],
        &[3; 32],
        &[9, 8, 7],
    ]
    .concat();
    let response = StateResponse::new(
        context(),
        [4; 32],
        StateResponseBody::Proof {
            proof_id: ProofId::from_bytes([3; 32]),
            certificate: vec![9, 8, 7].into(),
        },
        MAX,
    )
    .unwrap();
    assert_eq!(response.to_wire_bytes(), expected);
    assert_eq!(
        StateResponse::from_wire_bytes(&expected, context(), MAX).unwrap(),
        response
    );
    let expected = [
        &[0, 3, 1][..],
        &[1; 32],
        &[2; 32],
        &[4, 0, 0, 0, 47],
        &[4; 32],
        &[0, 1],
        &[0, 0, 0, 0, 0, 0, 0, 5],
        &[0, 0, 0, 1, 9],
    ]
    .concat();
    let response = StateResponse::new(
        context(),
        [4; 32],
        StateResponseBody::History(vec![StateHistoryItem {
            height: 5,
            evidence: vec![9].into(),
        }]),
        MAX,
    )
    .unwrap();
    assert_eq!(response.to_wire_bytes(), expected);
    assert_eq!(
        StateResponse::from_wire_bytes(&expected, context(), MAX).unwrap(),
        response
    );
}

#[test]
fn legacy_research_frame_version_is_rejected_before_body() {
    let mut bytes = StateRequest::new(context(), StateRequestBody::Handshake, MAX)
        .unwrap()
        .to_wire_bytes();
    bytes[..2].copy_from_slice(&1u16.to_be_bytes());
    assert!(state_frame_length(&bytes, false, context(), MAX).is_err());
}

#[test]
fn pending_agreement_rejects_wrong_response_and_malformed_optional_payload() {
    assert!(
        StateRequest::new(
            context(),
            StateRequestBody::PendingAgreement { height: 0 },
            MAX
        )
        .is_err()
    );
    let request = StateRequest::new(
        context(),
        StateRequestBody::PendingAgreement { height: 8 },
        MAX,
    )
    .unwrap();
    for body in [
        StateResponseBody::Agreement(None),
        StateResponseBody::Agreement(Some(vec![1, 2].into())),
    ] {
        let response = StateResponse::new(context(), [0; 32], body, MAX).unwrap();
        assert!(response.matches_request(&request));
        assert!(!response.matches_request(
            &StateRequest::new(context(), StateRequestBody::Handshake, MAX).unwrap()
        ));
    }
    assert!(
        !StateResponse::new(context(), [0; 32], StateResponseBody::Accepted, MAX)
            .unwrap()
            .matches_request(&request)
    );
    assert!(
        StateResponse::new(
            context(),
            [0; 32],
            StateResponseBody::Agreement(Some(Vec::new().into())),
            MAX
        )
        .is_err()
    );
    let valid = StateResponse::new(context(), [0; 32], StateResponseBody::Agreement(None), MAX)
        .unwrap()
        .to_wire_bytes();
    for invalid_tag in [1, 2, 255] {
        let mut bad = valid.clone();
        bad[STATE_FRAME_HEADER_BYTES + 32] = invalid_tag;
        assert!(StateResponse::from_wire_bytes(&bad, context(), MAX).is_err());
    }
    let mut bad = valid;
    bad.push(9);
    bad[68..72].copy_from_slice(&34u32.to_be_bytes());
    assert!(StateResponse::from_wire_bytes(&bad, context(), MAX).is_err());
}
