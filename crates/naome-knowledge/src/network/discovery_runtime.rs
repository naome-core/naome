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
        self.discovery.book.lock().retire(peer, Instant::now());
        if let Some(kad) = self.swarm.behaviour_mut().discovery.kad.as_mut() {
            kad.remove_peer(&peer);
        }
        if let Some(mdns) = self.swarm.behaviour_mut().discovery.mdns.as_mut() {
            mdns.retain_nodes(|known| known != &peer);
        }
        self.enabled.remove(&peer);
        self.next_inventory.remove(&peer);
        self.inventory_progress.remove(&peer);
        self.inventory_summaries.remove(&peer);
        self.next_automatic_request.remove(&peer);
        self.buckets.remove(&peer);
        self.outgoing.remove(&peer);
        self.next_relay_attempt.remove(&peer);
        if let Some(listener) = self.relay_listeners.remove(&peer) {
            self.swarm.remove_listener(listener);
        }
        self.intake.disconnected(peer);
        self.flights.retain(|_, flight| match flight {
            Flight::Inventory { peer: owner, .. }
            | Flight::Program { peer: owner, .. }
            | Flight::Get { peer: owner, .. }
            | Flight::Describe { peer: owner, .. }
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
                let (compatible, infrastructure, enabled, dht, addresses) = (
                    contact.compatible,
                    contact.infrastructure,
                    contact.enabled,
                    contact.dht,
                    contact.addresses.iter().cloned().collect::<Vec<_>>(),
                );
                drop(book);
                if compatible && !infrastructure && enabled {
                    self.enabled.insert(peer);
                } else {
                    self.enabled.remove(&peer);
                    self.intake.disconnected(peer);
                    self.outgoing.remove(&peer);
                }
                for address in &addresses {
                    if compatible
                        && dht
                        && let Some(kad) = self.swarm.behaviour_mut().discovery.kad.as_mut()
                    {
                        kad.add_address(&peer, address.clone());
                    }
                }
                self.next_inventory.remove(&peer);
            }
            discovery::Action::Reject(peer) => {
                self.intake.disconnected(peer);
                self.outgoing.remove(&peer);
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
        {
            let book = self.discovery.book.lock();
            self.next_relay_attempt
                .retain(|peer, _| book.contacts.contains_key(peer));
        }
        let removed: Vec<_> = self.discovery.book.lock().removed.drain(..).collect();
        for peer in removed {
            self.forget_contact(peer);
        }
        if self.discovery.config.internet {
            let mut book = self.discovery.book.lock();
            let candidates: Vec<_> = book
                .contacts
                .iter()
                .filter_map(|(peer, contact)| {
                    (contact.connected
                        && contact.compatible
                        && contact.relay_service
                        && !book.relays.contains(peer)
                        && self
                            .next_relay_attempt
                            .get(peer)
                            .is_none_or(|until| *until <= now)
                        && contact.addresses.iter().any(|address| {
                            !discovery::is_relayed(address) && discovery::public_address(address)
                        }))
                    .then_some(*peer)
                })
                .collect();
            for peer in candidates {
                if book.relays.len() >= crate::resources::limits().relay_peers {
                    break;
                }
                book.relays.insert(peer);
            }
        }
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
                        now.duration_since(since) >= crate::resources::limits().identify_timeout
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
                    contact.retry_at = now + crate::resources::limits().reconcile_interval;
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
                .insert(peer, now + crate::resources::limits().reconcile_interval);
            match self.swarm.listen_on(address) {
                Ok(listener) => {
                    self.relay_listeners.insert(peer, listener);
                }
                Err(error) => emit(
                    json!({"event":"relay_listen_failed", "peer":peer.to_string(), "error":error.to_string()}),
                ),
            }
        }
    }

    pub(super) fn relay_failed(&mut self, peer: PeerId) {
        self.relay_listeners.remove(&peer);
        let public = self.discovery.config.internet
            && !self
                .discovery
                .book
                .lock()
                .contacts
                .get(&peer)
                .is_some_and(|contact| contact.pinned);
        let delay = if public {
            self.discovery.book.lock().relays.remove(&peer);
            crate::resources::limits().contact_ttl
        } else {
            crate::resources::limits().reconcile_interval
        };
        self.next_relay_attempt.insert(peer, Instant::now() + delay);
    }
}
