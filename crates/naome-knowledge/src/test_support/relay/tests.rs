use super::*;

#[test]
fn rate_limits_reject_bursts_and_unknown_identities_until_bounded_window_expires() {
    let mut limiter = rate_limiter();
    let address = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let peer = || identity::Keypair::generate_ed25519().public().to_peer_id();
    let first = peer();
    let now = Instant::now();
    for _ in 0..4 {
        assert!(limiter.try_next(first, &address, now));
    }
    assert!(!limiter.try_next(first, &address, now));
    for _ in 1..crate::resources::limits().contacts {
        assert!(limiter.try_next(peer(), &address, now));
    }
    let extra = peer();
    assert!(!limiter.try_next(extra, &address, now + Duration::from_secs(1)));
    assert!(limiter.try_next(extra, &address, now + Duration::from_secs(2)));
    assert!(limiter.try_next(first, &address, now + Duration::from_secs(2)));
}

#[test]
fn relay_events_preserve_peers_status_and_io_failure_as_codes() {
    use crate::outcome::{IoFaultKind, NodeEvent, RelayEventKind as Kind, RelayStatus};
    let source = identity::Keypair::generate_ed25519().public().to_peer_id();
    let destination = identity::Keypair::generate_ed25519().public().to_peer_id();
    let cases = [
        (
            relay::Event::ReservationReqAccepted {
                src_peer_id: source,
                renewed: true,
            },
            Kind::ReservationAccepted,
        ),
        (
            relay::Event::ReservationReqDenied {
                src_peer_id: source,
                status: relay::StatusCode::PermissionDenied,
            },
            Kind::ReservationDenied,
        ),
        (
            relay::Event::ReservationClosed {
                src_peer_id: source,
            },
            Kind::ReservationClosed,
        ),
        (
            relay::Event::ReservationTimedOut {
                src_peer_id: source,
            },
            Kind::ReservationTimedOut,
        ),
        (
            relay::Event::CircuitReqDenied {
                src_peer_id: source,
                dst_peer_id: destination,
                status: relay::StatusCode::ResourceLimitExceeded,
            },
            Kind::CircuitDenied,
        ),
        (
            relay::Event::CircuitReqAccepted {
                src_peer_id: source,
                dst_peer_id: destination,
            },
            Kind::CircuitAccepted,
        ),
        (
            relay::Event::CircuitClosed {
                src_peer_id: source,
                dst_peer_id: destination,
                error: Some(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            },
            Kind::CircuitClosed,
        ),
    ];
    for (input, kind) in cases {
        let event = relay_event(input);
        assert_eq!(event["event"], u32::from(NodeEvent::RelayService));
        assert_eq!(event["kind"], u32::from(kind));
        assert_eq!(event["source"], source.to_string());
        assert!(event.get("detail").is_none());
        match kind {
            Kind::ReservationAccepted => assert_eq!(event["renewed"], true),
            Kind::ReservationDenied => {
                assert_eq!(event["status"], u32::from(RelayStatus::PermissionDenied))
            }
            Kind::CircuitDenied => {
                assert_eq!(
                    event["status"],
                    u32::from(RelayStatus::ResourceLimitExceeded)
                );
                assert_eq!(event["destination"], destination.to_string());
            }
            Kind::CircuitClosed => {
                assert_eq!(event["destination"], destination.to_string());
                assert_eq!(
                    event["error"]["kind"],
                    u32::from(IoFaultKind::ConnectionReset)
                );
                assert!(event["error"]["os_code"].is_null());
            }
            _ => {}
        }
    }
    let closed = relay_event(relay::Event::CircuitClosed {
        src_peer_id: source,
        dst_peer_id: destination,
        error: None,
    });
    assert!(closed["error"].is_null());
}

#[tokio::test]
async fn relay_startup_failures_keep_distinct_machine_codes() {
    use crate::{Error, InputFault, RuntimeFailure};
    let directory = crate::checkpoint::tests::Directory::new();
    let config = directory.0.join("relay.json");
    assert!(matches!(
        run(&config).await,
        Err(Error::RuntimeContext { code: RuntimeFailure::BoundedFileOpen, cause }) if matches!(*cause, Error::StorageIo { operation: crate::StorageIoOperation::OpenInput, kind: crate::IoFaultKind::NotFound, .. })
    ));
    std::fs::write(&config, b"{").unwrap();
    assert!(matches!(
        run(&config).await,
        Err(Error::RuntimeContext { code: RuntimeFailure::RelayConfigParse, cause }) if matches!(*cause, Error::ConfigDecode { reason: crate::JsonFault::Eof, .. })
    ));
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({"directory":directory.0,"listen":"invalid"})).unwrap(),
    )
    .unwrap();
    std::fs::write(directory.0.join("identity.key"), b"invalid").unwrap();
    assert!(matches!(
        run(&config).await,
        Err(Error::Runtime(RuntimeFailure::RelayIdentity))
    ));
    let key = identity::Keypair::generate_ed25519()
        .to_protobuf_encoding()
        .unwrap();
    std::fs::write(directory.0.join("identity.key"), key).unwrap();
    assert!(matches!(
        run(&config).await,
        Err(Error::InputFault(InputFault::RelayListenAddress))
    ));
}
