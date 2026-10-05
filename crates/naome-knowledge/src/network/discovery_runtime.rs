//! Connect the volatile contact owner to the proof transport's bounded caches.

use super::*;
use libp2p::{multiaddr::Protocol, swarm::dial_opts::DialOpts};

impl Node {
    pub(super) fn contact_status(&self) -> Value {
        let book = self.discovery.book.lock();
        json!(book.contacts.iter().map(|(peer, contact)| json!({
            "peer":peer.to_string(), "addresses":contact.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "compatible":contact.compatible, "infrastructure":contact.infrastructure,
            "pinned":contact.pinned, "connected":contact.connected, "enabled":contact.enabled,
        })).collect::<Vec<_>>())
    }

    pub(super) fn forget_contact(&mut self, peer: PeerId) {
        let contact = self.discovery.book.lock().retire(peer, Instant::now());
        if let Some(contact) = contact {
            for address in contact.addresses {
                remove_exchange_address(&mut self.swarm.behaviour_mut().exchange, &peer, &address);
            }
        }
        if let Some(kad) = self.swarm.behaviour_mut().discovery.kad.as_mut() {
            kad.remove_peer(&peer);
        }
        if let Some(mdns) = self.swarm.behaviour_mut().discovery.mdns.as_mut() {
            discovery::expire_mdns(mdns, &peer);
        }
        self.enabled.remove(&peer);
        self.next_inventory.remove(&peer);
        self.inventory_progress.remove(&peer);
        self.next_automatic_request.remove(&peer);
        self.buckets.remove(&peer);
        self.flights.retain(|_, flight| match flight {
            Flight::Inventory { peer: owner, .. }
            | Flight::Get { peer: owner, .. }
            | Flight::Offer { peer: owner } => *owner != peer,
        });
        let _ = self.swarm.disconnect_peer_id(peer);
        emit(json!({"event":"contact_expired", "peer":peer.to_string()}));
    }

    pub(super) fn discovery_action(&mut self, action: discovery::Action) {
        match action {
            discovery::Action::Contact(peer) | discovery::Action::Compatible(peer) => {
                let book = self.discovery.book.lock();
                let Some(contact) = book.contacts.get(&peer) else {
                    return;
                };
                if contact.compatible && !contact.infrastructure && contact.enabled {
                    self.enabled.insert(peer);
                }
                for address in &contact.addresses {
                    if !contact.infrastructure {
                        add_exchange_address(
                            &mut self.swarm.behaviour_mut().exchange,
                            &peer,
                            address.clone(),
                        );
                    }
                    if contact.compatible
                        && contact.dht
                        && let Some(kad) = self.swarm.behaviour_mut().discovery.kad.as_mut()
                    {
                        kad.add_address(&peer, address.clone());
                    }
                }
                self.next_inventory.remove(&peer);
            }
            discovery::Action::Reject(peer) => {
                self.enabled.remove(&peer);
                if let Some(contact) = self.discovery.book.lock().contacts.get_mut(&peer) {
                    contact.enabled = false;
                    contact.compatible = false;
                }
                if let Some(kad) = self.swarm.behaviour_mut().discovery.kad.as_mut() {
                    kad.remove_peer(&peer);
                }
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }
    }

    pub(super) fn discovery_tick(&mut self, now: Instant) {
        self.discovery
            .tick(&mut self.swarm.behaviour_mut().discovery);
        let expired = self.discovery.book.lock().expired(now);
        for peer in expired {
            self.forget_contact(peer);
        }
        let unidentified: Vec<_> = self
            .discovery
            .book
            .lock()
            .contacts
            .iter()
            .filter_map(|(peer, contact)| {
                (contact.connected
                    && !contact.compatible
                    && contact.connected_at.is_some_and(|since| {
                        now.duration_since(since) >= discovery::IDENTIFY_TIMEOUT
                    }))
                .then_some(*peer)
            })
            .collect();
        for peer in unidentified {
            self.discovery_action(discovery::Action::Reject(peer));
        }

        let targets: Vec<_> = {
            let mut book = self.discovery.book.lock();
            book.contacts
                .iter_mut()
                .filter_map(|(peer, contact)| {
                    if contact.connected
                        || !contact.enabled
                        || contact.addresses.is_empty()
                        || contact.retry_at > now
                    {
                        return None;
                    }
                    contact.retry_at = now + RECONCILE_INTERVAL;
                    Some((*peer, contact.addresses.iter().cloned().collect::<Vec<_>>()))
                })
                .collect()
        };
        for (peer, addresses) in targets {
            if let Err(error) = self.swarm.dial(
                DialOpts::peer_id(peer)
                    .addresses(addresses)
                    .allocate_new_port()
                    .build(),
            ) {
                emit(
                    json!({"event":"dial_failed", "peer":peer.to_string(), "stage":"request", "error":error.to_string()}),
                );
            }
        }

        let relays: Vec<_> = {
            let book = self.discovery.book.lock();
            book.relays
                .iter()
                .filter_map(|peer| {
                    let contact = book.contacts.get(peer)?;
                    if !contact.connected || !contact.compatible || !contact.enabled {
                        return None;
                    }
                    let address = contact
                        .addresses
                        .iter()
                        .find(|address| !discovery::is_relayed(address))?
                        .clone();
                    Some((*peer, address))
                })
                .collect()
        };
        for (peer, mut address) in relays {
            if self.relay_listeners.contains_key(&peer)
                || self
                    .next_relay_attempt
                    .get(&peer)
                    .is_some_and(|next| *next > now)
            {
                continue;
            }
            address.push(Protocol::P2p(peer));
            address.push(Protocol::P2pCircuit);
            self.next_relay_attempt
                .insert(peer, now + RECONCILE_INTERVAL);
            match self.swarm.listen_on(address) {
                Ok(listener) => {
                    self.relay_listeners.insert(peer, (listener, now));
                }
                Err(error) => emit(
                    json!({"event":"relay_listen_failed", "peer":peer.to_string(), "error":error.to_string()}),
                ),
            }
        }
    }
}
