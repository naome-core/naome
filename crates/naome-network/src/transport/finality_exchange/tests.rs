use std::{
    io,
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};

use libp2p::{
    futures::{AsyncRead, AsyncWrite, executor::block_on, io::Cursor, task::noop_waker},
    request_response::Codec,
    swarm::ConnectionId,
};
use naome_chain::ArtifactChainId;
use naome_consensus::{ConsensusGenesisId, ConsensusProtocolVersion};
use tokio::time::timeout;

use super::codec::{FINALITY_PROOF_PROTOCOL, FinalityProofCodec};
use super::*;
use crate::tests::{connected_pair, test_network_for_peers};

fn request(height: u64) -> FinalityProofRequest {
    FinalityProofRequest::new(
        ConsensusContextV0::new(
            ArtifactChainId::from_bytes([0x31; 32]),
            ConsensusGenesisId::from_bytes([0x32; 32]),
            ConsensusProtocolVersion::new(0x01020304),
        ),
        ConsensusHeight::new(height),
    )
    .unwrap()
}

fn budget(slots: usize, bytes: usize) -> Arc<InboundRetentionBudget> {
    Arc::new(InboundRetentionBudget::new(slots, bytes))
}

fn codec(slots: usize) -> FinalityProofCodec {
    FinalityProofCodec::new(
        budget(slots, slots * FINALITY_PROOF_REQUEST_BYTES),
        budget(slots, FINALITY_PROOF_MAX_RETAINED_BYTES),
    )
}

fn header(envelope: usize, payload: usize) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(envelope as u32).to_be_bytes());
    bytes.extend_from_slice(&(payload as u32).to_be_bytes());
    bytes
}

fn found(envelope: usize, payload: usize) -> Vec<u8> {
    let mut bytes = header(envelope, payload);
    bytes.extend(std::iter::repeat_n(0xa5, envelope));
    bytes.extend(std::iter::repeat_n(0x5a, payload));
    bytes
}

#[test]
fn finality_codec_exact_request_and_bounded_opaque_responses() {
    assert_eq!(
        FINALITY_PROOF_PROTOCOL.as_ref(),
        "/naome/fixed-validator-finality-proof-v0"
    );
    let mut codec = codec(2);
    let expected = request(0x0102030405060708);
    let mut bytes = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &FINALITY_PROOF_PROTOCOL,
        &mut bytes,
        WireRequest {
            request: expected,
            permit: None,
        },
    ))
    .unwrap();
    let mut golden = vec![0x31; 32];
    golden.extend_from_slice(&[0x32; 32]);
    golden.extend_from_slice(&[1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bytes.get_ref(), &golden);
    assert_eq!(
        block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(golden)))
            .unwrap()
            .request,
        expected
    );
    for frame in [
        vec![0],
        found(FINALITY_PROOF_MIN_ENVELOPE_BYTES, 1),
        found(
            FINALITY_PROOF_MAX_ENVELOPE_BYTES,
            FINALITY_PROOF_MAX_PAYLOAD_BYTES,
        ),
    ] {
        let response =
            block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&frame)))
                .unwrap();
        let mut output = Cursor::new(Vec::new());
        block_on(codec.write_response(&FINALITY_PROOF_PROTOCOL, &mut output, response)).unwrap();
        assert_eq!(output.into_inner(), frame);
    }
}

#[test]
fn finality_codec_rejects_both_lengths_before_body_and_releases_failed_custody() {
    let mut codec = codec(1);
    for (envelope, payload) in [
        (0, 1),
        (FINALITY_PROOF_MIN_ENVELOPE_BYTES - 1, 1),
        (FINALITY_PROOF_MAX_ENVELOPE_BYTES + 1, 1),
        (FINALITY_PROOF_MIN_ENVELOPE_BYTES, 0),
        (
            FINALITY_PROOF_MAX_ENVELOPE_BYTES,
            FINALITY_PROOF_MAX_PAYLOAD_BYTES + 1,
        ),
        (u32::MAX as usize, u32::MAX as usize),
    ] {
        let mut input = Cursor::new([header(envelope, payload), vec![0; 32]].concat());
        assert_eq!(
            block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 9);
    }
    let valid = found(FINALITY_PROOF_MIN_ENVELOPE_BYTES, 1);
    for end in 0..valid.len() {
        assert_eq!(
            block_on(
                codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&valid[..end]))
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    for invalid in [vec![2], vec![0, 0], [valid.clone(), vec![0]].concat()] {
        assert_eq!(
            block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(invalid)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let held =
        block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&valid))).unwrap();
    let mut denied = Cursor::new(&valid);
    assert!(block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut denied)).is_err());
    assert_eq!(denied.position(), 9);
    drop(held);
    assert!(
        block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(valid))).is_ok()
    );
}

#[test]
fn finality_codec_positive_request_exact_eof_and_retention() {
    let mut codec = codec(1);
    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &FINALITY_PROOF_PROTOCOL,
        &mut encoded,
        WireRequest {
            request: request(7),
            permit: None,
        },
    ))
    .unwrap();
    let bytes = encoded.into_inner();
    for end in 0..bytes.len() {
        assert_eq!(
            block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&bytes[..end])))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    for mut invalid in [bytes.clone(), [bytes.clone(), vec![0]].concat()] {
        if invalid.len() == bytes.len() {
            invalid[68..].fill(0);
        }
        assert_eq!(
            block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(invalid)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let held =
        block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
    assert!(
        block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&bytes))).is_err()
    );
    drop(held);
    assert!(
        block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(bytes))).is_ok()
    );
}

struct StalledRead(Cursor<Vec<u8>>);

impl AsyncRead for StalledRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.0).poll_read(cx, buffer) {
            Poll::Ready(Ok(0)) => Poll::Pending,
            result => result,
        }
    }
}

struct StalledWrite(usize);

impl AsyncWrite for StalledWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = bytes.len().min(self.0);
        self.0 -= count;
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn finality_cancelled_reads_and_writes_release_reserved_custody() {
    let protocol = FINALITY_PROOF_PROTOCOL;
    let requests = budget(1, FINALITY_PROOF_REQUEST_BYTES);
    let responses = budget(1, FINALITY_PROOF_MAX_RETAINED_BYTES);
    let mut codec = FinalityProofCodec::new(Arc::clone(&requests), Arc::clone(&responses));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut input = StalledRead(Cursor::new(vec![0x31; 10]));
    let mut read = codec.read_request(&protocol, &mut input);
    assert!(read.as_mut().poll(&mut cx).is_pending());
    assert!(InboundRetentionBudget::try_acquire(&requests, 0).is_none());
    drop(read);
    assert!(InboundRetentionBudget::try_acquire(&requests, FINALITY_PROOF_REQUEST_BYTES).is_some());
    let frame = found(FINALITY_PROOF_MIN_ENVELOPE_BYTES, 1);
    // Cancellation during the envelope, payload, and exact-EOF wait all release.
    for end in [9, frame.len() - 1, frame.len()] {
        let mut input = StalledRead(Cursor::new(frame[..end].to_vec()));
        let mut read = codec.read_response(&protocol, &mut input);
        assert!(read.as_mut().poll(&mut cx).is_pending());
        assert!(InboundRetentionBudget::try_acquire(&responses, 0).is_none());
        drop(read);
        assert!(
            InboundRetentionBudget::try_acquire(&responses, FINALITY_PROOF_MAX_RETAINED_BYTES)
                .is_some()
        );
    }
    for accepted_bytes in [0, 9, frame.len() - 1] {
        let response =
            block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(&frame)))
                .unwrap();
        let mut output = StalledWrite(accepted_bytes);
        let mut write = codec.write_response(&protocol, &mut output, response);
        assert!(write.as_mut().poll(&mut cx).is_pending());
        assert!(InboundRetentionBudget::try_acquire(&responses, 0).is_none());
        drop(write);
        assert!(
            InboundRetentionBudget::try_acquire(&responses, FINALITY_PROOF_MAX_RETAINED_BYTES)
                .is_some()
        );
    }
}

fn terminal(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer: PeerId,
) -> OutboundFinalityProofEvent {
    let response =
        block_on(codec(1).read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(vec![0])))
            .unwrap();
    let event = network
        .handle_finality_exchange_event(request_response::Event::Message {
            peer,
            connection_id: ConnectionId::new_unchecked(81),
            message: request_response::Message::Response {
                request_id,
                response,
            },
        })
        .unwrap();
    let NetworkEvent::OutboundFinalityProof(event) = event else {
        panic!("wrong terminal kind")
    };
    event
}

#[test]
fn finality_tickets_bind_instance_generation_address_and_shared_permits() {
    let peer = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut first = test_network_for_peers(&[peer]);
    let mut second = test_network_for_peers(&[peer]);
    let ticket = first.request_finality_proof(peer, request(7)).unwrap();
    let other = second.request_finality_proof(peer, request(7)).unwrap();
    assert_eq!(ticket.request_id, other.request_id);
    assert!(matches!(
        first.request_finality_proof(peer, request(8)),
        Err(RequestStartError::AlreadyPending(_))
    ));
    let artifact =
        naome_protocol::artifact_exchange::ArtifactRequest::from_wire_bytes(&[1; 32]).unwrap();
    assert!(matches!(
        first.request_artifact(peer, artifact),
        Err(RequestStartError::AlreadyPending(_))
    ));
    let other_event = terminal(&mut second, other.request_id, peer);
    let (ticket, other_event) = ticket.complete(other_event).unwrap_err().into_parts();
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 1);
    assert_eq!(second.pending_budget.active.load(Ordering::Relaxed), 1);
    let response = other.complete(other_event).unwrap().unwrap();
    assert!(matches!(
        response.into_response(),
        FinalityProofResponse::Unavailable
    ));
    assert_eq!(second.pending_budget.active.load(Ordering::Relaxed), 0);
    let old_id = ticket.request_id;
    let event = terminal(&mut first, old_id, peer);
    let later = first.request_finality_proof(peer, request(8)).unwrap();
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 2);
    let (later, event) = later.complete(event).unwrap_err().into_parts();
    assert_eq!(later.request(), request(8));
    assert_eq!(event.request(), request(7));
    drop(ticket.complete(event).unwrap().unwrap());
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 1);
    let later_id = later.request_id;
    drop(later);
    assert!(matches!(
        first.request_finality_proof(peer, request(9)),
        Err(RequestStartError::AlreadyPending(_))
    ));
    drop(terminal(&mut first, later_id, peer));
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
    let ticket = first.request_finality_proof(peer, request(9)).unwrap();
    let wrong_peer = crate::Keypair::generate_ed25519().public().to_peer_id();
    let event = terminal(&mut first, ticket.request_id, wrong_peer);
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(
        matches!(*ticket.complete(event).unwrap().unwrap_err(), OutboundFinalityProofFailure::PeerMismatch { expected, actual } if expected == peer && actual == wrong_peer)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn finality_transport_preserves_exact_opaque_bytes_and_bounded_serving() {
    let (mut client, mut server, client_id, server_id) = connected_pair().await;
    let ticket = client
        .request_finality_proof(server_id, request(3))
        .unwrap();
    let envelope = vec![0x8a; FINALITY_PROOF_MIN_ENVELOPE_BYTES];
    let payload = vec![0x6b; 11];
    let event = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { break event; },
                event = server.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event {
                    assert_eq!(inbound.peer_id(), client_id);
                    assert_eq!(inbound.request(), request(3));
                    server.respond_finality_proof(inbound, Some((&envelope, &payload))).unwrap();
                },
            }
        }
    }).await.unwrap();
    let response = ticket.complete(event).unwrap().unwrap();
    assert_eq!(response.peer_id(), server_id);
    assert_eq!(response.request(), request(3));
    let FinalityProofResponse::Found {
        canonical_envelope,
        canonical_artifact,
    } = response.into_response()
    else {
        panic!("expected opaque proof")
    };
    assert_eq!(canonical_envelope, envelope);
    assert_eq!(canonical_artifact, payload);

    // The same body budget covers reading remote proofs and queued serving.
    // A maximum-byte reservation prevents another response before any copy.
    let occupied = InboundRetentionBudget::try_acquire(
        &server.finality_response_budget,
        FINALITY_PROOF_MAX_RETAINED_BYTES,
    )
    .unwrap();
    let ticket = client
        .request_finality_proof(server_id, request(4))
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                _ = client.next_event() => {},
                event = server.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event {
                    assert!(matches!(server.respond_finality_proof(inbound, Some((&envelope, &payload))), Err(FinalityProofRespondError::RetentionLimit)));
                    break;
                },
            }
        }
    }).await.unwrap();
    drop((ticket, occupied));
}

async fn short_timeout_pair() -> (StaticArtifactNetwork, StaticArtifactNetwork, PeerId, PeerId) {
    use libp2p::request_response::ProtocolSupport;
    crate::tests::connected_pair_with_server(|server| {
        // Install before connecting: libp2p uses a real futures_timer timeout,
        // independent of Tokio virtual time. The client retains its 30s bound.
        server.swarm.behaviour_mut().finality_exchange = request_response::Behaviour::with_codec(
            FinalityProofCodec::new(
                budget(
                    MAX_STATIC_PEERS,
                    MAX_STATIC_PEERS * FINALITY_PROOF_REQUEST_BYTES,
                ),
                Arc::clone(&server.finality_response_budget),
            ),
            [(FINALITY_PROOF_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(2))
                .with_max_concurrent_streams(
                    crate::transport::MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION,
                ),
        );
    })
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn finality_retained_request_survives_actual_timeout_and_reconnect_until_consumed() {
    use crate::PeerSessionEvent;
    use libp2p::request_response::InboundFailure;
    let (mut client, mut server, client_id, server_id) = short_timeout_pair().await;
    let ticket = client
        .request_finality_proof(server_id, request(1))
        .unwrap();
    let held = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                _ = client.next_event() => {},
                event = server.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event { break inbound; },
            }
        }
    }).await.unwrap();
    assert_eq!(held.peer_id(), client_id);
    let mut inbound_timed_out = false;
    let mut terminal = None;
    timeout(Duration::from_secs(10), async {
        while !inbound_timed_out || terminal.is_none() {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { terminal = Some(event); },
                event = server.next_event() => if let NetworkEvent::InboundFinalityProofFailure { peer_id, error, .. } = event {
                    assert_eq!(peer_id, client_id);
                    assert!(matches!(error, InboundFailure::Timeout));
                    inbound_timed_out = true;
                },
            }
        }
    }).await.unwrap();
    assert!(ticket.complete(terminal.unwrap()).unwrap().is_err());
    assert!(!held.channel.is_open());
    client.swarm.disconnect_peer_id(server_id).unwrap();
    let mut disconnected = [false; 2];
    let mut connected = [false; 2];
    timeout(Duration::from_secs(10), async {
        while connected != [true; 2] {
            let (index, event) = tokio::select! {
                event = client.next_event() => (0, event),
                event = server.next_event() => (1, event),
            };
            match event {
                NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { .. }) => {
                    disconnected[index] = true
                }
                NetworkEvent::PeerSession(PeerSessionEvent::Established { .. }) => {
                    assert!(disconnected[index]);
                    connected[index] = true;
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    let ticket = client
        .request_finality_proof(server_id, request(2))
        .unwrap();
    let mut omitted = false;
    let mut terminal = None;
    timeout(Duration::from_secs(10), async {
        while !omitted || terminal.is_none() {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { terminal = Some(event); },
                event = server.next_event() => match event {
                    NetworkEvent::InboundFinalityProof(_) => panic!("retained peer request lost its binding"),
                    NetworkEvent::InboundFinalityProofFailure { error, .. } => {
                        assert!(matches!(error, InboundFailure::ResponseOmission));
                        omitted = true;
                    },
                    _ => {},
                },
            }
        }
    }).await.unwrap();
    assert!(ticket.complete(terminal.unwrap()).unwrap().is_err());
    assert!(matches!(
        server.respond_finality_proof(held, None),
        Err(FinalityProofRespondError::Transport(
            RespondError::ChannelClosed
        ))
    ));
    let ticket = client
        .request_finality_proof(server_id, request(3))
        .unwrap();
    let terminal = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { break event; },
                event = server.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event {
                    assert_eq!(inbound.request(), request(3));
                    server.respond_finality_proof(inbound, None).unwrap();
                },
            }
        }
    }).await.unwrap();
    assert!(matches!(
        ticket.complete(terminal).unwrap().unwrap().into_response(),
        FinalityProofResponse::Unavailable
    ));
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn finality_provider_admission_precedes_unhealthy_history_even_for_foreign_or_missing_requests()
 {
    use crate::tests::{FinalityFixture, TestDirectory};
    use naome_storage::FixedValidatorFinalityJournalErrorV0;
    let fixture = FinalityFixture::new();
    let directory = TestDirectory::new("proof-provider-halted");
    let anchor = TestDirectory::new("proof-provider-halted-anchor");
    let journal = fixture.halted_anchored(&directory, &anchor);
    let images = || {
        (
            directory.journal_bytes(),
            std::fs::read(anchor.path().join("fixed-validator-finality.anchor")).unwrap(),
        )
    };
    let before = images();
    for address in [
        FinalityProofRequest::new(journal.context(), ConsensusHeight::new(1)).unwrap(),
        request(99),
    ] {
        for gate in 0..3 {
            let (mut client, mut server, _, server_id) = short_timeout_pair().await;
            let ticket = client.request_finality_proof(server_id, address).unwrap();
            let inbound = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        _ = client.next_event() => {},
                        event = server.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event { break inbound; },
                    }
                }
            }).await.unwrap();
            if gate == 0 {
                let mut terminal = None;
                timeout(Duration::from_secs(10), async {
                    while terminal.is_none() || inbound.channel.is_open() {
                        tokio::select! {
                            event = client.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { terminal = Some(event); },
                            _ = server.next_event() => {},
                        }
                    }
                }).await.unwrap();
                let tokens = server.application_tokens_for_test();
                assert!(matches!(
                    server.respond_finality_proof_from_selected_history(inbound, &journal),
                    Err(FinalityProofRespondError::Transport(
                        RespondError::ChannelClosed
                    ))
                ));
                assert_eq!(server.application_tokens_for_test(), tokens);
                assert!(ticket.complete(terminal.unwrap()).unwrap().is_err());
            } else {
                tokio::time::pause();
                if gate == 1 {
                    server.exhaust_application_budget_for_test(tokio::time::Instant::now());
                }
                let tokens = server.application_tokens_for_test();
                let result = server.respond_finality_proof_from_selected_history(inbound, &journal);
                if gate == 1 {
                    assert!(matches!(
                        result,
                        Err(FinalityProofRespondError::Transport(
                            RespondError::RateLimited
                        ))
                    ));
                    assert_eq!(server.application_tokens_for_test(), 0);
                } else {
                    assert!(matches!(
                        result,
                        Err(FinalityProofRespondError::Journal(
                            FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. }
                        ))
                    ));
                    assert_eq!(server.application_tokens_for_test(), tokens - 1);
                }
                tokio::time::resume();
                drop(ticket);
            }
            assert_eq!(images(), before);
        }
    }
}

#[test]
fn proof_following_distinguishes_invalid_peer_framing_from_transient_transport_loss() {
    for (kind, invalid) in [
        (io::ErrorKind::InvalidData, true),
        (io::ErrorKind::UnexpectedEof, false),
        (io::ErrorKind::ConnectionReset, false),
        (io::ErrorKind::TimedOut, false),
    ] {
        let failure = OutboundFinalityProofFailure::Transport(
            request_response::OutboundFailure::Io(io::Error::new(kind, "response")),
        );
        assert_eq!(failure.is_invalid_response(), invalid);
    }
    assert!(
        !OutboundFinalityProofFailure::Transport(request_response::OutboundFailure::Timeout)
            .is_invalid_response()
    );
}

#[test]
fn proof_following_local_shared_response_retention_is_retryable_and_release_restores_reads() {
    let responses = budget(2, FINALITY_PROOF_MAX_RETAINED_BYTES);
    let mut codec = FinalityProofCodec::new(
        budget(2, 2 * FINALITY_PROOF_REQUEST_BYTES),
        Arc::clone(&responses),
    );
    // Serving and inbound replies own this same budget. No response body is
    // allocated while a queued serving response holds the available bytes.
    let held =
        InboundRetentionBudget::try_acquire(&responses, FINALITY_PROOF_MAX_RETAINED_BYTES).unwrap();
    let valid = found(FINALITY_PROOF_MIN_ENVELOPE_BYTES, 1);
    let mut input = Cursor::new(&valid);
    let error = block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut input)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(input.position(), 9);
    assert!(
        !OutboundFinalityProofFailure::Transport(request_response::OutboundFailure::Io(error))
            .is_invalid_response()
    );
    // Framing remains invalid even while local custody is exhausted.
    let error = block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(vec![2])))
        .unwrap_err();
    assert!(
        OutboundFinalityProofFailure::Transport(request_response::OutboundFailure::Io(error))
            .is_invalid_response()
    );
    drop(held);
    assert!(
        block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(valid))).is_ok()
    );
}

#[test]
fn finality_exchange_frames_have_a_deterministic_mutation_corpus() {
    let mut codec = codec(1);
    let mut request_bytes = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &FINALITY_PROOF_PROTOCOL,
        &mut request_bytes,
        WireRequest {
            request: request(0x0102030405060708),
            permit: None,
        },
    ))
    .unwrap();
    crate::codec_corpus::check("finality request", &[request_bytes.into_inner()], |bytes| {
        let decoded =
            block_on(codec.read_request(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(bytes))).ok()?;
        let mut output = Cursor::new(Vec::new());
        block_on(codec.write_request(&FINALITY_PROOF_PROTOCOL, &mut output, decoded)).ok()?;
        Some(output.into_inner())
    });
    crate::codec_corpus::check(
        "finality response",
        &[vec![0], found(FINALITY_PROOF_MIN_ENVELOPE_BYTES, 1)],
        |bytes| {
            let decoded =
                block_on(codec.read_response(&FINALITY_PROOF_PROTOCOL, &mut Cursor::new(bytes)))
                    .ok()?;
            let mut output = Cursor::new(Vec::new());
            block_on(codec.write_response(&FINALITY_PROOF_PROTOCOL, &mut output, decoded)).ok()?;
            Some(output.into_inner())
        },
    );
}
