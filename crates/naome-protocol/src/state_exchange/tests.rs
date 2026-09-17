use super::*;
const MAX: usize = RESEARCH_MAX_FRAME_BYTES;
fn context() -> ResearchContext {
    ResearchContext::new([1; 32], [2; 32])
}
#[test]
fn every_research_envelope_roundtrips_and_rejects_all_truncations() {
    let id = ProofId::from_bytes([3; 32]);
    let requests = [
        ResearchRequestBody::Handshake,
        ResearchRequestBody::TimeReport(vec![1].into()),
        ResearchRequestBody::UserAction(vec![2].into()),
        ResearchRequestBody::Proposal(vec![3].into()),
        ResearchRequestBody::Vote(vec![4].into()),
        ResearchRequestBody::Finalized(vec![5].into()),
        ResearchRequestBody::History {
            from: 1,
            max_records: 2,
        },
        ResearchRequestBody::Proof { proof_id: id },
    ];
    for body in requests {
        let request = ResearchRequest::new(context(), body, MAX).unwrap();
        let mut bytes = request.to_wire_bytes();
        assert_eq!(bytes.len(), request.wire_len());
        assert_eq!(
            ResearchRequest::from_wire_bytes(&bytes, context(), MAX).unwrap(),
            request
        );
        for cut in 0..bytes.len() {
            assert!(ResearchRequest::from_wire_bytes(&bytes[..cut], context(), MAX).is_err());
        }
        bytes.push(0);
        assert!(ResearchRequest::from_wire_bytes(&bytes, context(), MAX).is_err());
    }
    let responses = [
        ResearchResponseBody::Ready,
        ResearchResponseBody::Accepted,
        ResearchResponseBody::Busy,
        ResearchResponseBody::Rejected(ResearchRejection::Invalid),
        ResearchResponseBody::Rejected(ResearchRejection::Unauthorized),
        ResearchResponseBody::Rejected(ResearchRejection::Unsupported),
        ResearchResponseBody::History(vec![
            ResearchHistoryItem {
                height: 1,
                evidence: vec![7].into(),
            },
            ResearchHistoryItem {
                height: 2,
                evidence: vec![8].into(),
            },
        ]),
        ResearchResponseBody::Proof {
            proof_id: id,
            certificate: vec![9].into(),
        },
        ResearchResponseBody::Unavailable,
    ];
    for body in responses {
        let response = ResearchResponse::new(context(), [4; 32], body, MAX).unwrap();
        let mut bytes = response.to_wire_bytes();
        assert_eq!(bytes.len(), response.wire_len());
        assert_eq!(
            ResearchResponse::from_wire_bytes(&bytes, context(), MAX).unwrap(),
            response
        );
        for cut in 0..bytes.len() {
            assert!(ResearchResponse::from_wire_bytes(&bytes[..cut], context(), MAX).is_err());
        }
        bytes.push(0);
        assert!(ResearchResponse::from_wire_bytes(&bytes, context(), MAX).is_err());
    }
}
#[test]
fn header_rejects_wrong_context_direction_version_tag_and_excess_before_body() {
    let bytes = ResearchRequest::new(context(), ResearchRequestBody::Handshake, MAX)
        .unwrap()
        .to_wire_bytes();
    assert_eq!(&bytes[..3], &[0, 1, 0]);
    assert_eq!(&bytes[3..35], &[1; 32]);
    assert_eq!(&bytes[35..67], &[2; 32]);
    assert_eq!(&bytes[67..], &[0, 0, 0, 0, 0]);
    for offset in [0, 2, 3, 35, 67] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(research_frame_length(&bad, false, context(), MAX).is_err());
    }
    let mut oversized = bytes;
    oversized[67] = 3;
    oversized[68..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        research_frame_length(&oversized, false, context(), MAX),
        Err(ResearchWireError::Limit)
    );
}
#[test]
fn bounded_history_and_response_correlation() {
    for (from, max_records) in [(0, 1), (1, 0), (1, 17), (u64::MAX, 2)] {
        assert!(
            ResearchRequest::new(
                context(),
                ResearchRequestBody::History { from, max_records },
                MAX
            )
            .is_err()
        );
    }
    for heights in [[1, 1], [2, 1], [1, 3], [0, 1]] {
        assert!(
            ResearchResponse::new(
                context(),
                [0; 32],
                ResearchResponseBody::History(
                    heights
                        .into_iter()
                        .map(|height| ResearchHistoryItem {
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
    let request = ResearchRequest::new(
        context(),
        ResearchRequestBody::History {
            from: 2,
            max_records: 1,
        },
        MAX,
    )
    .unwrap();
    for (body, expected) in [
        (ResearchResponseBody::Ready, false),
        (ResearchResponseBody::Busy, true),
        (ResearchResponseBody::Unavailable, true),
        (
            ResearchResponseBody::History(vec![ResearchHistoryItem {
                height: 1,
                evidence: vec![1].into(),
            }]),
            false,
        ),
        (
            ResearchResponseBody::History(vec![ResearchHistoryItem {
                height: 2,
                evidence: vec![1].into(),
            }]),
            true,
        ),
    ] {
        assert_eq!(
            ResearchResponse::new(context(), [0; 32], body, MAX)
                .unwrap()
                .matches_request(&request),
            expected
        );
    }
    let request = ResearchRequest::new(
        context(),
        ResearchRequestBody::Proof {
            proof_id: ProofId::from_bytes([1; 32]),
        },
        MAX,
    )
    .unwrap();
    assert!(
        !ResearchResponse::new(
            context(),
            [0; 32],
            ResearchResponseBody::Proof {
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
fn fixed_v1_proof_and_history_wire_vectors() {
    // Explicit byte layouts independent of the production writer: v1, request,
    // genesis/profile, Proof tag, 32-byte body length, concrete ProofId.
    let expected = [
        &[0, 1, 0][..],
        &[1; 32],
        &[2; 32],
        &[7, 0, 0, 0, 32],
        &[3; 32],
    ]
    .concat();
    let request = ResearchRequest::new(
        context(),
        ResearchRequestBody::Proof {
            proof_id: ProofId::from_bytes([3; 32]),
        },
        MAX,
    )
    .unwrap();
    assert_eq!(request.to_wire_bytes(), expected);
    assert_eq!(
        ResearchRequest::from_wire_bytes(&expected, context(), MAX).unwrap(),
        request
    );
    // Response body includes its exact 32-byte request digest, followed by ID
    // and the opaque three-byte test certificate. Decoding grants no authority.
    let expected = [
        &[0, 1, 1][..],
        &[1; 32],
        &[2; 32],
        &[5, 0, 0, 0, 67],
        &[4; 32],
        &[3; 32],
        &[9, 8, 7],
    ]
    .concat();
    let response = ResearchResponse::new(
        context(),
        [4; 32],
        ResearchResponseBody::Proof {
            proof_id: ProofId::from_bytes([3; 32]),
            certificate: vec![9, 8, 7].into(),
        },
        MAX,
    )
    .unwrap();
    assert_eq!(response.to_wire_bytes(), expected);
    assert_eq!(
        ResearchResponse::from_wire_bytes(&expected, context(), MAX).unwrap(),
        response
    );
    let expected = [
        &[0, 1, 1][..],
        &[1; 32],
        &[2; 32],
        &[4, 0, 0, 0, 47],
        &[4; 32],
        &[0, 1],
        &[0, 0, 0, 0, 0, 0, 0, 5],
        &[0, 0, 0, 1, 9],
    ]
    .concat();
    let response = ResearchResponse::new(
        context(),
        [4; 32],
        ResearchResponseBody::History(vec![ResearchHistoryItem {
            height: 5,
            evidence: vec![9].into(),
        }]),
        MAX,
    )
    .unwrap();
    assert_eq!(response.to_wire_bytes(), expected);
    assert_eq!(
        ResearchResponse::from_wire_bytes(&expected, context(), MAX).unwrap(),
        response
    );
}
