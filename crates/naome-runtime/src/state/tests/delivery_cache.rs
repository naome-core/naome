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

#[tokio::test]
async fn accepted_current_offer_suppresses_only_redundant_same_height_repair() {
    let (_directory, _anchors, mut runtime) = runtime();
    let peer = runtime.peers[0];
    let height = runtime.state().unwrap().height();
    let offer = StateRequestBody::Offer(
        handoff_plan(runtime.state().unwrap()).offers()[0]
            .encode()
            .into(),
    );
    let finality = StateRequestBody::Finalized(vec![1].into());
    runtime.enqueue(peer, offer).unwrap();
    runtime.enqueue(peer, finality.clone()).unwrap();
    runtime
        .enqueue(
            peer,
            StateRequestBody::History {
                from: height + 1,
                max_records: 1,
            },
        )
        .unwrap();
    let offer = runtime.outbox.pop_front().unwrap();
    assert!(matches!(offer.body, StateRequestBody::Offer(_)));
    assert!(
        runtime
            .outbox
            .iter()
            .any(|queued| queued.peer == peer
                && matches!(queued.body, StateRequestBody::Finalized(_)))
    );

    // An old transport ACK cache does not prove the peer has this parent.
    runtime.remember_acknowledged(&offer).unwrap();
    assert!(!runtime.confirmed_parent.contains_key(&peer));
    assert!(
        runtime
            .outbox
            .iter()
            .any(|queued| matches!(queued.body, StateRequestBody::Finalized(_)))
    );
    runtime
        .remember_confirmed_parent(&Delivery {
            peer,
            body: offer.body.clone(),
            id: offer.id,
            height: height + 1,
            queued_at: offer.queued_at,
        })
        .unwrap();
    assert!(!runtime.confirmed_parent.contains_key(&peer));

    // The actual Accepted-Offer response path records this proof only after
    // the peer's canonical offer validation. It removes already queued proof
    // and suppresses periodic copies for this selected height.
    runtime.remember_confirmed_parent(&offer).unwrap();
    assert_eq!(runtime.confirmed_parent.get(&peer), Some(&height));
    assert!(runtime.outbox.iter().all(|queued| !matches!(
        queued.body,
        StateRequestBody::Finalized(_) | StateRequestBody::History { .. }
    )));
    runtime.enqueue(peer, finality.clone()).unwrap();
    assert!(
        runtime
            .outbox
            .iter()
            .all(|queued| !matches!(queued.body, StateRequestBody::Finalized(_)))
    );

    runtime.enqueue_periodic().unwrap();
    assert!(runtime.outbox.iter().all(|queued| {
        queued.peer != peer || !matches!(queued.body, StateRequestBody::History { .. })
    }));
    runtime.last_selected_at = Instant::now() - Duration::from_secs(5);
    runtime.enqueue_periodic().unwrap();
    assert!(runtime.outbox.iter().any(|queued| {
        queued.peer == peer && matches!(queued.body, StateRequestBody::History { .. })
    }));

    // A reconnect invalidates even a same-height offer proof. Finality and
    // immediate history repair become eligible again.
    runtime
        .network_event(
            NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id: peer }),
            StateLane::Active,
        )
        .unwrap();
    assert!(!runtime.confirmed_parent.contains_key(&peer));
    runtime.enqueue(peer, finality).unwrap();
    assert!(runtime.outbox.iter().any(|queued| {
        queued.peer == peer && matches!(queued.body, StateRequestBody::Finalized(_))
    }));
    runtime.outbox.retain(|queued| {
        queued.peer != peer || !matches!(queued.body, StateRequestBody::History { .. })
    });
    runtime.last_selected_at = Instant::now();
    runtime.enqueue_periodic().unwrap();
    assert!(runtime.outbox.iter().any(|queued| {
        queued.peer == peer && matches!(queued.body, StateRequestBody::History { .. })
    }));
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
