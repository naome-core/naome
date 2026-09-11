use super::*;
use crate::transport::inbound_retention::InboundRetentionBudget;
use libp2p::{
    futures::{executor::block_on, io::Cursor},
    request_response::Codec,
};
use naome_chain::{ArtifactBlockId, ArtifactChainId};
fn offer(n: u8) -> CandidateOffer {
    CandidateOffer::new(
        ArtifactChainId::from_bytes([7; 32]),
        vec![ArtifactBlockId::from_bytes([n; 32])],
    )
    .unwrap()
}

#[test]
fn codec_rejects_every_truncation_trailing_and_oversized_count_without_leaking_custody() {
    let budget = Arc::new(InboundRetentionBudget::new(1, CANDIDATE_OFFER_MAX_BYTES));
    let mut codec = CandidateOfferCodec::new(Arc::clone(&budget));
    let bytes = offer(1).to_wire_bytes();
    for cut in 0..bytes.len() {
        assert!(
            block_on(
                codec.read_request(&CANDIDATE_OFFER_PROTOCOL, &mut Cursor::new(&bytes[..cut]))
            )
            .is_err()
        );
        assert!(InboundRetentionBudget::try_acquire(&budget, CANDIDATE_OFFER_MAX_BYTES).is_some());
    }
    for malformed in [
        {
            let mut extra = bytes.clone();
            extra.push(0);
            extra
        },
        {
            let mut header = vec![0; 33];
            header[32] = 33;
            header
        },
    ] {
        assert!(
            block_on(codec.read_request(&CANDIDATE_OFFER_PROTOCOL, &mut Cursor::new(malformed)))
                .is_err()
        );
        assert!(InboundRetentionBudget::try_acquire(&budget, CANDIDATE_OFFER_MAX_BYTES).is_some());
    }
    let request =
        block_on(codec.read_request(&CANDIDATE_OFFER_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
    assert!(InboundRetentionBudget::try_acquire(&budget, 1).is_none());
    drop(request);
    assert!(InboundRetentionBudget::try_acquire(&budget, CANDIDATE_OFFER_MAX_BYTES).is_some());
    for bytes in [vec![0; 31], vec![0; 33]] {
        assert!(
            block_on(codec.read_response(&CANDIDATE_OFFER_PROTOCOL, &mut Cursor::new(bytes)))
                .is_err()
        );
    }
}

#[test]
fn decoding_budget_exhaustion_is_isolated_before_peer_binding() {
    let budgets: Vec<_> = (0..8)
        .map(|_| {
            Arc::new(InboundRetentionBudget::new(
                2,
                2 * CANDIDATE_OFFER_MAX_BYTES,
            ))
        })
        .collect();
    let mut retained = Vec::new();
    // Queued decoded requests and stalled codec workers can exhaust seven
    // publishers, but cannot charge the eighth authenticated codec's account.
    for budget in &budgets[..7] {
        for _ in 0..2 {
            retained.push(
                InboundRetentionBudget::try_acquire(budget, CANDIDATE_OFFER_MAX_BYTES).unwrap(),
            );
        }
        assert!(InboundRetentionBudget::try_acquire(budget, 1).is_none());
    }
    let mut codec = CandidateOfferCodec::new(Arc::clone(&budgets[7]));
    let request = block_on(codec.read_request(
        &CANDIDATE_OFFER_PROTOCOL,
        &mut Cursor::new(offer(1).to_wire_bytes()),
    ))
    .unwrap();
    drop((request, retained));
    for budget in budgets {
        assert!(InboundRetentionBudget::try_acquire(&budget, CANDIDATE_OFFER_MAX_BYTES).is_some());
    }
}

#[tokio::test]
async fn exact_receipt_and_wrong_digest_stale_and_cross_network_terminals() {
    let (mut client, mut server, _, peer) = crate::tests::connected_pair().await;
    let ticket = client.announce_candidate_offer(peer, offer(1)).unwrap();
    let terminal=tokio::time::timeout(Duration::from_secs(10),async {
        loop {tokio::select! {
            event=server.next_event()=>if let NetworkEvent::InboundCandidateOffer(inbound)=event {assert_eq!(inbound.offer(),&offer(1));server.acknowledge_candidate_offer(inbound).unwrap();},
            event=client.next_event()=>if let NetworkEvent::OutboundCandidateOffer(event)=event {break event;},
        }}
    }).await.unwrap();
    assert!(ticket.complete(terminal).unwrap().is_ok());
    let ticket = client.announce_candidate_offer(peer, offer(2)).unwrap();
    let NetworkEvent::OutboundCandidateOffer(terminal) = client
        .finish_candidate_offer(ticket.id, peer, Some([0; 32]), None)
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        ticket.complete(terminal).unwrap(),
        Err(CandidateOfferFailure::ReceiptMismatch)
    ));
    let older = client.announce_candidate_offer(peer, offer(3)).unwrap();
    let NetworkEvent::OutboundCandidateOffer(old) = client
        .finish_candidate_offer(older.id, peer, Some(fingerprint(older.offer())), None)
        .unwrap()
    else {
        panic!()
    };
    let newer = client.announce_candidate_offer(peer, offer(3)).unwrap();
    let mismatch = newer.complete(old).unwrap_err();
    let (newer, old) = mismatch.into_parts();
    assert!(older.complete(old).unwrap().is_ok());
    let (mut other, _other_server, _, other_peer) = crate::tests::connected_pair().await;
    let foreign = other
        .announce_candidate_offer(other_peer, offer(3))
        .unwrap();
    let NetworkEvent::OutboundCandidateOffer(mut event) = other
        .finish_candidate_offer(
            foreign.id,
            other_peer,
            Some(fingerprint(foreign.offer())),
            None,
        )
        .unwrap()
    else {
        panic!()
    };
    // Equal superficial metadata must still fail network-instance ownership.
    event.id = newer.id;
    event.peer = newer.peer;
    assert!(!newer.accepts_event(&event));
    drop(event);
}

async fn triangle() -> ([StaticArtifactNetwork; 3], [PeerId; 3]) {
    let identities = std::array::from_fn::<_, 3, _>(|_| crate::Keypair::generate_ed25519());
    let peers = identities.each_ref().map(|id| id.public().to_peer_id());
    let listeners =
        std::array::from_fn::<_, 3, _>(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let addresses = listeners.each_ref().map(|listener| {
        format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        )
        .parse::<crate::Multiaddr>()
        .unwrap()
    });
    drop(listeners);
    let mut index = 0;
    let mut networks = identities.map(|identity| {
        let actor = index;
        index += 1;
        let mut network = StaticArtifactNetwork::new(
            identity,
            (0..3)
                .filter(|i| *i != actor)
                .map(|i| crate::StaticPeer::new(peers[i], addresses[i].clone())),
        )
        .unwrap();
        network.listen_on(addresses[actor].clone()).unwrap();
        network
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        let [a, b, c] = &mut networks;
        while ![&*a, &*b, &*c].iter().enumerate().all(|(i, n)| {
            (0..3)
                .filter(|j| *j != i)
                .all(|j| n.swarm.behaviour().candidate_offer.is_connected(&peers[j]))
        }) {
            tokio::select! {_=a.next_event()=>{},_=b.next_event()=>{},_=c.next_event()=>{}}
        }
    })
    .await
    .unwrap();
    (networks, peers)
}

#[tokio::test]
async fn peer_local_equal_request_ids_do_not_alias_and_receipts_route_independently() {
    let ([mut publisher, mut left, mut right], peers) = triangle().await;
    let left_ticket = publisher
        .announce_candidate_offer(peers[1], offer(1))
        .unwrap();
    let right_ticket = publisher
        .announce_candidate_offer(peers[2], offer(2))
        .unwrap();
    assert_eq!(left_ticket.id, right_ticket.id);
    let mut tickets = vec![left_ticket, right_ticket];
    tokio::time::timeout(Duration::from_secs(10),async {
        while !tickets.is_empty() {
            tokio::select! {
                e=publisher.next_event()=>if let NetworkEvent::OutboundCandidateOffer(e)=e {
                    let index=tickets.iter().position(|t|t.accepts_event(&e)).unwrap();
                    assert!(tickets.swap_remove(index).complete(e).unwrap().is_ok());
                },
                e=left.next_event()=>if let NetworkEvent::InboundCandidateOffer(e)=e {assert_eq!(e.offer(),&offer(1));left.acknowledge_candidate_offer(e).unwrap();},
                e=right.next_event()=>if let NetworkEvent::InboundCandidateOffer(e)=e {assert_eq!(e.offer(),&offer(2));right.acknowledge_candidate_offer(e).unwrap();},
            }
        }
    }).await.unwrap();
    assert!(publisher.pending.is_empty());
}

#[tokio::test]
async fn retained_offer_across_disconnect_cannot_take_another_publishers_decode_slots() {
    let ([mut receiver, mut noisy, mut honest], peers) = triangle().await;
    let _old_ticket = noisy.announce_candidate_offer(peers[0], offer(1)).unwrap();
    let held = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                e=receiver.next_event()=>if let NetworkEvent::InboundCandidateOffer(e)=e {break e;},
                _=noisy.next_event()=>{},_=honest.next_event()=>{},
            }
        }
    })
    .await
    .unwrap();
    noisy.swarm.disconnect_peer_id(peers[0]).unwrap();
    tokio::time::timeout(Duration::from_secs(10),async {
        let mut disconnected=false;
        loop {
            tokio::select! {_=receiver.next_event()=>{},_=noisy.next_event()=>{},_=honest.next_event()=>{}}
            let connected=receiver.swarm.behaviour().candidate_offer.is_connected(&peers[1]) && noisy.swarm.behaviour().candidate_offer.is_connected(&peers[0]);
            disconnected |= !connected;
            if disconnected && connected {break;}
        }
    }).await.unwrap();
    let _new_ticket = noisy.announce_candidate_offer(peers[0], offer(2)).unwrap();
    let ticket = honest.announce_candidate_offer(peers[0], offer(3)).unwrap();
    let terminal=tokio::time::timeout(Duration::from_secs(10),async {
        loop {tokio::select! {
            e=receiver.next_event()=>if let NetworkEvent::InboundCandidateOffer(e)=e {
                assert_eq!(e.peer_id(),peers[2],"old noisy custody must stay peer-bound after reconnect");
                assert_eq!(e.offer(),&offer(3));receiver.acknowledge_candidate_offer(e).unwrap();
            },
            e=honest.next_event()=>if let NetworkEvent::OutboundCandidateOffer(e)=e {break e;},
            _=noisy.next_event()=>{},
        }}
    }).await.unwrap();
    assert!(ticket.complete(terminal).unwrap().is_ok());
    drop(held);
}

#[tokio::test]
async fn paced_offer_flood_keeps_an_independent_deadline_pollable() {
    let (mut noisy, mut receiver, _, peer) = crate::tests::connected_pair().await;
    // A malicious peer bypasses this crate's outbound API limits. Keep the
    // attack fixture itself finite while it saturates the single offer stream.
    for _ in 0..256 {
        noisy.swarm.behaviour_mut().candidate_offer.send_request(
            &peer,
            OfferRequest {
                offer: offer(1),
                permit: None,
            },
        );
    }
    let started = std::time::Instant::now();
    let deadline = tokio::time::sleep(Duration::from_millis(200));
    tokio::pin!(deadline);
    let mut delivered = 0;
    tokio::time::timeout(Duration::from_secs(3),async {
        loop {tokio::select! {
            _=&mut deadline=>break,
            e=receiver.next_event()=>if let NetworkEvent::InboundCandidateOffer(e)=e {delivered+=1;drop(e);},
            _=noisy.next_event()=>{},
        }}
    }).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        delivered <= 1,
        "one peer gets at most one delivery during this sub-second flood"
    );
}
