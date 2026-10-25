use super::*;
use kad::store::RecordStore;

fn local_config() -> Config {
    Config {
        internet: false,
        allow_private_addresses: true,
        dht: false,
        ..Default::default()
    }
}

fn peer() -> PeerId {
    identity::Keypair::generate_ed25519().public().to_peer_id()
}

#[test]
fn contact_and_address_caps_expire_hints_without_expiring_pinned_or_live_peers() {
    let now = Instant::now();
    let mut book = Book::new(peer(), true, &local_config());
    let pinned = peer();
    book.pin(pinned, &"/ip4/127.0.0.1/tcp/10000".parse().unwrap(), false)
        .unwrap();
    let live = peer();
    book.admit(live, now).unwrap().connected = true;
    for _ in 2..crate::resources::limits().contacts {
        book.admit(peer(), now).unwrap();
    }
    assert!(book.admit(peer(), now).is_err());
    for port in 1..=crate::resources::limits().addresses_per_contact {
        book.hint(
            live,
            &format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap(),
            now,
        )
        .unwrap();
    }
    assert!(
        book.hint(live, &"/ip4/127.0.0.1/tcp/99".parse().unwrap(), now)
            .is_err()
    );
    let expired = book.expired(now + crate::resources::limits().contact_ttl);
    assert_eq!(expired.len(), crate::resources::limits().contacts - 2);
    assert!(!expired.contains(&pinned) && !expired.contains(&live));
}

#[test]
fn routing_hints_reject_wrong_targets_zero_ports_multihop_and_unknown_relays() {
    let target = peer();
    let relay = peer();
    let relays = BTreeSet::from([relay]);
    let direct: Multiaddr = format!("/dns4/example.org/tcp/1234/p2p/{target}")
        .parse()
        .unwrap();
    assert_eq!(
        routing_address(&direct, target, &relays)
            .unwrap()
            .to_string(),
        "/dns4/example.org/tcp/1234"
    );
    let circuit: Multiaddr =
        format!("/ip4/127.0.0.1/tcp/1234/p2p/{relay}/p2p-circuit/p2p/{target}")
            .parse()
            .unwrap();
    assert!(routing_address(&circuit, target, &relays).is_ok());
    assert!(routing_address(&circuit, target, &BTreeSet::new()).is_err());
    for invalid in [
        format!("/ip4/127.0.0.1/tcp/1234/p2p/{relay}"),
        "/ip4/127.0.0.1/tcp/0".into(),
        "/ip4/0.0.0.0/tcp/1234".into(),
        "/ip4/224.0.0.1/tcp/1234".into(),
        "/ip4/127.0.0.1/udp/1234/quic-v1".into(),
        format!("{circuit}/p2p-circuit/p2p/{target}"),
    ] {
        assert!(
            routing_address(&invalid.parse().unwrap(), target, &relays).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn static_and_circuit_policies_apply_at_authenticated_connection_admission() {
    let target = peer();
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let mut book = Book::new(peer(), false, &local_config());
    assert!(book.accepts_endpoint(target, &address).is_err());
    book.pin(target, &address, false).unwrap();
    assert!(book.accepts_endpoint(target, &address).is_ok());
    book.contacts.get_mut(&target).unwrap().enabled = false;
    assert!(book.accepts_endpoint(target, &address).is_err());
    let mut book = Book::new(
        peer(),
        true,
        &Config {
            relay_only: true,
            hole_punch: false,
            ..Default::default()
        },
    );
    assert!(book.accepts_endpoint(target, &address).is_err());
    assert!(book.contacts.is_empty());
}

#[test]
fn inbound_circuits_bind_configured_infrastructure_and_authenticated_sender() {
    let own = peer();
    let sender = peer();
    let relay = peer();
    let mut book = Book::new(
        own,
        true,
        &Config {
            relay_only: true,
            hole_punch: false,
            ..Default::default()
        },
    );
    let local: Multiaddr = format!("/ip4/127.0.0.1/tcp/1234/p2p/{relay}/p2p-circuit")
        .parse()
        .unwrap();
    let remote: Multiaddr = format!("/p2p/{sender}").parse().unwrap();
    assert!(book.accepts_inbound(sender, &local, &remote).is_err());
    assert!(book.contacts.is_empty());
    book.pin(relay, &"/ip4/127.0.0.1/tcp/1234".parse().unwrap(), true)
        .unwrap();
    assert!(
        book.accepts_inbound(sender, &local, &format!("/p2p/{own}").parse().unwrap())
            .is_err()
    );
    let wrong_target: Multiaddr = format!("{local}/p2p/{sender}").parse().unwrap();
    assert!(
        book.accepts_inbound(sender, &wrong_target, &remote)
            .is_err()
    );
    assert!(book.accepts_inbound(sender, &local, &remote).is_ok());
    book.contacts.get_mut(&sender).unwrap().enabled = false;
    assert!(book.accepts_inbound(sender, &local, &remote).is_err());
    book.contacts.get_mut(&sender).unwrap().enabled = true;
    for _ in 2..crate::resources::limits().contacts {
        book.admit(peer(), Instant::now()).unwrap();
    }
    let extra = peer();
    assert!(
        book.accepts_inbound(extra, &local, &format!("/p2p/{extra}").parse().unwrap())
            .is_err()
    );
    assert!(
        book.accepts_inbound(
            sender,
            &"/ip4/127.0.0.1/tcp/1234".parse().unwrap(),
            &"/ip4/127.0.0.1/tcp/4321".parse().unwrap()
        )
        .is_err()
    );
}

#[test]
fn provider_store_scopes_keys_caps_entries_and_bounds_addresses_and_expiry() {
    let own = peer();
    let now = Instant::now();
    let mut store = Providers::new(own);
    let record = |provider| kad::ProviderRecord {
        key: provider_key(),
        provider,
        expires: None,
        addresses: vec!["/ip4/127.0.0.1/tcp/1234".parse().unwrap()],
    };
    for _ in 0..crate::resources::limits().contacts {
        store.add_provider(record(peer())).unwrap();
    }
    assert!(store.add_provider(record(peer())).is_err());
    assert_eq!(
        store.providers(&provider_key()).len(),
        crate::resources::limits().contacts
    );
    assert!(
        store
            .providers(&kad::RecordKey::new(&b"foreign"))
            .is_empty()
    );
    let mut invalid = record(peer());
    invalid.key = kad::RecordKey::new(&b"foreign");
    assert!(store.add_provider(invalid).is_err());
    assert!(
        store
            .put(kad::Record::new(provider_key(), vec![1]))
            .is_err()
    );
    assert!(store.records().next().is_none());
    store.prune(now + crate::resources::limits().provider_ttl + Duration::from_secs(1));
    assert_eq!(store.len(), 0);
    let mut invalid = record(peer());
    invalid.addresses = vec![
        "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        crate::resources::limits().addresses_per_contact + 1
    ];
    assert!(store.add_provider(invalid).is_err());
}

#[test]
fn repeated_stale_hints_do_not_renew_contacts_and_retirement_has_bounded_backoff() {
    let now = Instant::now();
    let target = peer();
    let mut book = Book::new(peer(), true, &local_config());
    let address = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    book.hint(target, &address, now).unwrap();
    book.hint(
        target,
        &address,
        now + crate::resources::limits().contact_ttl - Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        book.expired(now + crate::resources::limits().contact_ttl),
        vec![target]
    );
    book.retire(target, now + crate::resources::limits().contact_ttl)
        .unwrap();
    assert!(
        book.hint(
            target,
            &address,
            now + crate::resources::limits().contact_ttl + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        book.hint(
            target,
            &address,
            now + crate::resources::limits().contact_ttl * 2
        )
        .is_ok()
    );
}

#[test]
fn identify_must_bind_the_authenticated_key_and_exact_proof_namespace() {
    let own = identity::Keypair::generate_ed25519();
    let remote = identity::Keypair::generate_ed25519();
    let peer = remote.public().to_peer_id();
    let config = Config {
        mdns: false,
        dht: false,
        ..Default::default()
    };
    let book = SharedBook::new(Book::new(own.public().to_peer_id(), true, &config));
    book.lock().admit(peer, Instant::now()).unwrap();
    let mut state = State::new(book.clone(), config.clone(), false);
    let mut behaviour = Behaviour::new(&own, &config, false, true).unwrap();
    let info = |public_key, protocol_version| identify::Info {
        public_key,
        protocol_version,
        signed_peer_record: None,
        agent_version: "fixture".into(),
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/1234".parse().unwrap()],
        protocols: vec![crate::wire::PROTOCOL],
        observed_addr: "/ip4/127.0.0.1/tcp/4321".parse().unwrap(),
    };
    for invalid in [
        info(remote.public(), "foreign".into()),
        info(own.public(), protocol_version(false)),
    ] {
        let actions = state.event(
            BehaviourEvent::Identify(identify::Event::Received {
                connection_id: libp2p::swarm::ConnectionId::new_unchecked(1),
                peer_id: peer,
                info: invalid,
            }),
            &mut behaviour,
        );
        assert!(matches!(actions.as_slice(), [Action::Reject(rejected)] if *rejected == peer));
        assert!(!book.lock().contacts[&peer].compatible);
    }
    let actions = state.event(
        BehaviourEvent::Identify(identify::Event::Received {
            connection_id: libp2p::swarm::ConnectionId::new_unchecked(1),
            peer_id: peer,
            info: info(remote.public(), protocol_version(false)),
        }),
        &mut behaviour,
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Compatible(accepted) if *accepted == peer))
    );
    assert!(book.lock().contacts[&peer].compatible);
}

#[test]
fn public_dht_protocol_does_not_authorize_proof_exchange() {
    let remote = identity::Keypair::generate_ed25519();
    let peer = remote.public().to_peer_id();
    let mut info = identify::Info {
        public_key: remote.public(),
        protocol_version: "public-router".into(),
        signed_peer_record: None,
        agent_version: "fixture".into(),
        listen_addrs: vec!["/ip4/8.8.8.1/tcp/4001".parse().unwrap()],
        protocols: vec![StreamProtocol::new(internet::PROTOCOL)],
        observed_addr: "/ip4/9.9.9.1/tcp/4001".parse().unwrap(),
    };
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), true),
        Some((false, true))
    );
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), false),
        None
    );
    info.protocols.push(crate::wire::PROTOCOL);
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), true),
        Some((false, true))
    );
    info.protocol_version = protocol_version(false);
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), true),
        Some((true, false))
    );
    info.public_key = identity::Keypair::generate_ed25519().public();
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), true),
        None
    );
}

#[test]
fn identify_parser_boundaries_do_not_depend_on_transport_work_capacity() {
    let key = identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let mut info = identify::Info {
        public_key: key.public(),
        protocol_version: protocol_version(false),
        signed_peer_record: None,
        agent_version: "fixture".into(),
        listen_addrs: vec![
            "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
            crate::resources::DEFAULT.identify_addresses
        ],
        protocols: vec![crate::wire::PROTOCOL; crate::resources::DEFAULT.identify_protocols],
        observed_addr: "/ip4/127.0.0.1/tcp/4321".parse().unwrap(),
    };
    assert_eq!(
        identified_kind(peer, &info, false, &BTreeSet::new(), false),
        Some((true, false))
    );
    info.protocols.push(crate::wire::PROTOCOL);
    assert!(identified_kind(peer, &info, false, &BTreeSet::new(), false).is_none());
    info.protocols.pop();
    info.listen_addrs
        .push("/ip4/127.0.0.1/tcp/5678".parse().unwrap());
    assert!(identified_kind(peer, &info, false, &BTreeSet::new(), false).is_none());
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.inbound_frames = Some(1);
    profile.tuning.inbound_streams = Some(1);
    profile.tuning.exchange_streams = Some(1);
    let limits = profile.resolve().unwrap();
    assert_eq!(
        limits.identify_protocols,
        crate::resources::DEFAULT.identify_protocols
    );
    assert_eq!(
        limits.identify_addresses,
        crate::resources::DEFAULT.identify_addresses
    );
}
