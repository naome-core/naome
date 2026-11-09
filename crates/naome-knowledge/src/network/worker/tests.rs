use super::*;
#[test]
fn peer_and_request_revocation_leave_unrelated_roots_and_node_lifetime_valid() {
    let peer_a = PeerId::random();
    let peer_b = PeerId::random();
    let root_a = crate::publication::PeerGrant::new();
    let root_b = crate::publication::PeerGrant::new();
    let mut grants = PeerGrants::default();
    grants.roots.insert(
        (peer_a, ArtifactId::from_bytes([1; 32])),
        Arc::downgrade(&root_a.0),
    );
    grants.roots.insert(
        (peer_b, ArtifactId::from_bytes([2; 32])),
        Arc::downgrade(&root_b.0),
    );
    let lifetime = Arc::new(AtomicU64::new(0));
    let local = crate::publication::CommitGuard::new(lifetime.clone(), 0, None, None);
    grants.revoke_peer(peer_b);
    assert!(root_a.check().is_ok());
    assert_eq!(root_b.check().unwrap_err(), crate::Error::StaleAuthority);
    assert!(local.check().is_ok());
    let mut exchange = request_response::Behaviour::with_codec(
        Codec::default(),
        [(PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    );
    let request = exchange.send_request(&peer_a, Frame::new(Body::Missing));
    grants.requests.insert(request, Arc::downgrade(&root_a.0));
    grants.failed_request(request);
    assert_eq!(root_a.check().unwrap_err(), crate::Error::StaleAuthority);
    assert!(local.check().is_ok());
}

#[tokio::test]
async fn control_shutdown_preserves_owner_failure_and_distinguishes_cancellation() {
    let expected = crate::Error::from(crate::InputFault::ControlSocketPath);
    let failure = expected.clone();
    let mut controls = Controls {
        stop: None,
        task: Some(tokio::spawn(async move { Err(failure) })),
    };
    assert_eq!(controls.shutdown().await.unwrap_err(), expected);

    let task = tokio::spawn(async { std::future::pending::<Result<(), crate::Error>>().await });
    task.abort();
    let mut controls = Controls {
        stop: None,
        task: Some(task),
    };
    assert_eq!(
        controls.shutdown().await.unwrap_err(),
        crate::Error::from(crate::InputFault::ControlTaskCancelled)
    );
}

#[test]
fn owner_thread_panic_has_a_machine_readable_cause() {
    let thread = std::thread::spawn(|| panic!("test owner panic"));
    let mut owner = OwnerThread {
        thread: Some(thread),
        stop: None,
    };
    assert_eq!(
        owner.join(),
        Err(crate::InputFault::StateOwnerPanicked.into())
    );
}
