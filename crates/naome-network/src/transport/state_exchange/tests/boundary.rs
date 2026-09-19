use super::*;

#[test]
fn exact_default_and_compact_frame_limits_accept_then_reject_one_more_byte() {
    for maximum in [MAX, 192 * 1024] {
        let mut codec = codec();
        codec.maximum = maximum;
        let payload = vec![0x5a; maximum - STATE_FRAME_HEADER_BYTES];
        let request = StateRequest::new(
            context(),
            StateRequestBody::Proposal(payload.into()),
            maximum,
        )
        .unwrap();
        let mut bytes = request.to_wire_bytes();
        assert_eq!(bytes.len(), maximum);
        let received =
            block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
        assert_eq!(received.request, request);
        drop(received);
        assert!(
            InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some()
        );
        bytes.push(0x5a);
        bytes[68..72]
            .copy_from_slice(&((maximum + 1 - STATE_FRAME_HEADER_BYTES) as u32).to_be_bytes());
        let mut input = Cursor::new(&bytes);
        assert_eq!(
            block_on(codec.read_request(&STATE_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), STATE_FRAME_HEADER_BYTES as u64);
        assert!(
            InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some()
        );
    }
}

#[test]
fn exact_64k_proof_payload_accepts_and_next_byte_rejects_before_body() {
    let mut codec = codec();
    let response = StateResponse::new(
        context(),
        [4; 32],
        StateResponseBody::Proof {
            proof_id: naome_proof::ProofId::from_bytes([7; 32]),
            certificate: vec![0x5a; STATE_MAX_PROOF_BYTES].into(),
        },
        MAX,
    )
    .unwrap();
    let mut bytes = response.to_wire_bytes();
    let received =
        block_on(codec.read_response(&STATE_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
    assert_eq!(received.response, response);
    drop(received);
    bytes.push(0x5a);
    let payload_length = (bytes.len() - STATE_FRAME_HEADER_BYTES) as u32;
    bytes[68..72].copy_from_slice(&payload_length.to_be_bytes());
    let mut input = Cursor::new(&bytes);
    assert_eq!(
        block_on(codec.read_response(&STATE_PROTOCOL, &mut input))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(input.position(), STATE_FRAME_HEADER_BYTES as u64);
    assert!(InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some());
}
