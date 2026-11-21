use super::*;

impl Node {
    pub(super) fn maintain_routes(&mut self, now: Instant) {
        if self.routing.valid_until.is_some_and(|t| t <= now) {
            self.routing.learned.clear();
            self.routing.valid_until = None;
        }
        if let Some((id, address)) = self.routing.bootstrap.clone() {
            if self.swarm.is_connected(&id) {
                if self.routing.use_relay && self.routing.reservation.is_none() {
                    self.routing.reservation = self
                        .swarm
                        .listen_on(self.routing.circuit().expect("configured relay"))
                        .ok();
                }
                let rv = self
                    .swarm
                    .behaviour_mut()
                    .rendezvous
                    .as_mut()
                    .expect("configured rendezvous");
                if self.routing.next_register.is_none_or(|t| now >= t) {
                    self.routing.next_register = Some(now + discovery::LOOKUP);
                    if rv
                        .register(discovery::namespace(), id, Some(discovery::TTL))
                        .is_ok()
                    {
                        self.routing.next_register =
                            Some(now + Duration::from_secs(discovery::TTL / 2));
                    }
                }
                if !self.routing.lookup_pending && self.routing.next_lookup.is_none_or(|t| now >= t)
                {
                    rv.discover(
                        Some(discovery::namespace()),
                        None,
                        Some(MAX_PEERS as u64),
                        id,
                    );
                    self.routing.lookup_pending = true;
                    self.routing.next_lookup = Some(now + discovery::LOOKUP);
                }
            } else {
                let _ = self.swarm.dial(
                    DialOpts::peer_id(id)
                        .addresses(vec![address])
                        .condition(PeerCondition::DisconnectedAndNotDialing)
                        .build(),
                );
            }
        }
        for (&peer, fixed) in &self.peers {
            if self.swarm.is_connected(&peer) || self.dials.values().any(|(p, _)| *p == peer) {
                continue;
            }
            let mut direct: BTreeSet<_> = fixed.iter().cloned().collect();
            let mut circuits = Vec::new();
            for address in self.routing.learned.get(&peer).into_iter().flatten() {
                if address
                    .iter()
                    .any(|component| component == Protocol::P2pCircuit)
                {
                    circuits.push(address.clone());
                } else {
                    direct.insert(address.clone());
                }
            }
            let relay =
                !circuits.is_empty() && (direct.is_empty() || self.direct_failed.contains(&peer));
            let addresses = if relay {
                circuits
            } else {
                direct.into_iter().collect()
            };
            if addresses.is_empty() {
                continue;
            }
            let opts = DialOpts::peer_id(peer)
                .addresses(addresses)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            let id = opts.connection_id();
            if self.swarm.dial(opts).is_ok() {
                self.dials.insert(id, (peer, relay));
                if relay {
                    self.direct_failed.remove(&peer);
                }
            }
        }
    }

    pub(super) fn discovery_event(&mut self, event: rendezvous::client::Event) {
        match event {
            rendezvous::client::Event::Discovered {
                registrations,
                rendezvous_node,
                ..
            } => {
                self.routing.lookup_pending = false;
                if self
                    .routing
                    .bootstrap
                    .as_ref()
                    .is_some_and(|(id, _)| *id == rendezvous_node)
                {
                    self.routing
                        .discovered(registrations, &self.peers, Instant::now());
                }
            }
            rendezvous::client::Event::DiscoverFailed { .. } => self.routing.lookup_pending = false,
            rendezvous::client::Event::RegisterFailed { .. } => {
                self.routing.next_register = Some(Instant::now() + discovery::LOOKUP)
            }
            _ => {}
        }
    }
}
