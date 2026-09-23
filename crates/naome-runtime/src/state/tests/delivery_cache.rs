use super::*;
use naome_network::{NetworkEvent, PeerSessionEvent, StateLane};

#[tokio::test]
async fn accepted_offer_is_suppressed_until_same_height_peer_reconnects() {
    let (_directory, _anchors, mut runtime) = runtime();
    let peer = runtime.peers[0];
    let offer = handoff_plan(runtime.state().unwrap()).offers()[0]
        .encode()
        .into();
    let body = StateRequestBody::Offer(offer);
    runtime.enqueue(peer, body.clone()).unwrap();
    let delivery = runtime.outbox.pop_front().unwrap();
    runtime.remember_acknowledged(&delivery).unwrap();
    runtime.sent.insert((peer, delivery.id));

    // The one-second transient retry window must not resend an accepted offer.
    runtime.last_rebroadcast = Instant::now() - Duration::from_secs(2);
    runtime.enqueue_periodic().unwrap();
    assert!(!runtime.sent.contains(&(peer, delivery.id)));
    runtime.enqueue(peer, body.clone()).unwrap();
    assert!(runtime.outbox.iter().all(|queued| queued.id != delivery.id));
    assert!(runtime.acknowledged.contains(&(peer, delivery.id)));

    // A restarted peer has lost its volatile offer pool at the same height.
    runtime
        .network_event(
            NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id: peer }),
            StateLane::Active,
        )
        .unwrap();
    assert!(!runtime.acknowledged.contains(&(peer, delivery.id)));
    runtime.enqueue(peer, body).unwrap();
    assert!(runtime.outbox.iter().any(|queued| queued.id == delivery.id));
}

#[test]
fn accepted_delivery_cache_is_bounded_and_user_actions_remain_retryable() {
    let (_directory, _anchors, mut runtime) = runtime();
    let peer = runtime.peers[0];
    let action = StateRequestBody::UserAction(
        operation(runtime.state().unwrap().genesis(), 1)
            .encode()
            .into(),
    );
    runtime.enqueue(peer, action.clone()).unwrap();
    let delivery = runtime.outbox.pop_front().unwrap();
    runtime.remember_acknowledged(&delivery).unwrap();
    assert!(!runtime.acknowledged.contains(&(peer, delivery.id)));
    runtime.enqueue(peer, action).unwrap();
    assert!(runtime.outbox.iter().any(|queued| queued.id == delivery.id));

    let capacity = runtime
        .state()
        .unwrap()
        .genesis()
        .profile()
        .limits()
        .transport_buffer_frames as usize
        * 4;
    let offer = StateRequestBody::Offer(
        handoff_plan(runtime.state().unwrap()).offers()[0]
            .encode()
            .into(),
    );
    for number in 0..=capacity {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(number as u64).to_le_bytes());
        runtime
            .remember_acknowledged(&Delivery {
                peer,
                body: offer.clone(),
                id,
                height: runtime.state().unwrap().height(),
                queued_at: Instant::now(),
            })
            .unwrap();
    }
    assert_eq!(runtime.acknowledged.len(), capacity);
    assert!(!runtime.acknowledged.contains(&(peer, [0; 32])));
}
