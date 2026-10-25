//! Bound identity churn by observed network origin and reserve outbound capacity.
use super::*;
use crate::quota::{Quota, Rate};
use libp2p::swarm::ConnectionId;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    V4([u8; 3]),
    V6([u8; 8]),
    Circuit(PeerId),
    // Some transports retain the original DNS endpoint in Swarm events.
    // Hostname rotation must not give each identity a fresh origin quota.
    UnresolvedDns,
}
fn group(address: &Multiaddr) -> Option<Group> {
    match address::ip(address)? {
        IpAddr::V4(ip) => Some(Group::V4(ip.octets()[..3].try_into().unwrap())),
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                Some(Group::V4(ip.octets()[..3].try_into().unwrap()))
            } else {
                Some(Group::V6(ip.octets()[..8].try_into().unwrap()))
            }
        }
    }
}
#[derive(Default)]
pub(super) struct Admission {
    connections: BTreeMap<ConnectionId, (PeerId, Group, bool)>,
    attempts: BTreeMap<Group, Quota>,
}

impl Book {
    pub(crate) fn incoming_attempt(
        &mut self,
        remote: &Multiaddr,
        now: Instant,
    ) -> Result<(), String> {
        let Some(group) = group(remote) else {
            // Circuit streams have no source IP. The relay limits pending
            // circuits and the authenticated admission still reserves capacity.
            return if matches!(
                remote.iter().collect::<Vec<_>>().as_slice(),
                [Protocol::P2p(_)]
            ) {
                Ok(())
            } else {
                Err("incoming TCP endpoint required".into())
            };
        };
        let rate = Rate {
            burst: crate::resources::limits().request_burst,
            period: crate::resources::limits().request_rate_window,
        };
        self.admission
            .attempts
            .retain(|_, quota| !quota.expired(now, rate));
        if self.admission.attempts.len() >= crate::resources::limits().contacts
            && !self.admission.attempts.contains_key(&group)
        {
            return Err("handshake rate table capacity".into());
        }
        let quota = self
            .admission
            .attempts
            .entry(group)
            .or_insert_with(|| Quota::new(now));
        if !quota.try_take(now, rate) {
            return Err("network handshake rate limit".into());
        }
        Ok(())
    }

    pub(crate) fn admit_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        remote: &Multiaddr,
        outbound: bool,
        now: Instant,
    ) -> Result<(), String> {
        let group = group(remote).unwrap_or_else(|| {
            if super::is_relayed(remote) || matches!(remote.iter().next(), Some(Protocol::P2p(_))) {
                Group::Circuit(peer)
            } else {
                Group::UnresolvedDns
            }
        });
        let pinned = self
            .contacts
            .get(&peer)
            .is_some_and(|contact| contact.pinned);
        if !pinned {
            let peers: BTreeSet<_> = self
                .admission
                .connections
                .values()
                .filter(|(other, origin, _)| *other != peer && *origin == group)
                .map(|(other, _, _)| *other)
                .collect();
            // Calibrated aggregate capacity may grow, but must not expand the
            // fixed default ceiling for identities from one network origin.
            let group_limit = (crate::resources::limits()
                .contacts
                .min(crate::resources::DEFAULT.contacts)
                / 4)
            .max(1);
            if peers.len() >= group_limit {
                return Err("network group peer limit".into());
            }
            let inbound: BTreeSet<_> = self
                .admission
                .connections
                .values()
                .filter(|(other, _, outgoing)| {
                    !outgoing
                        && *other != peer
                        && !self
                            .contacts
                            .get(other)
                            .is_some_and(|contact| contact.pinned)
                })
                .map(|(other, _, _)| *other)
                .collect();
            let capacity = crate::resources::limits().contacts / if self.internet { 4 } else { 2 };
            if !outbound && inbound.len() >= capacity.max(1) {
                return Err("outbound contact capacity reserved".into());
            }
        }
        if self.admission.connections.len()
            >= crate::resources::limits().established_connections as usize
        {
            return Err("authenticated connection capacity".into());
        }
        if self.internet && self.automatic && outbound && !self.contacts.contains_key(&peer) {
            self.admission
                .connections
                .insert(id, (peer, group, outbound));
            return Ok(());
        }
        self.retain_authenticated(peer, now)?;
        let contact = self
            .contacts
            .get_mut(&peer)
            .expect("retained authenticated peer");
        contact.connected = true;
        contact.connected_at.get_or_insert(now);
        if outbound
            && !super::is_relayed(remote)
            && contact.addresses.len() < crate::resources::limits().addresses_per_contact
            && let Some(endpoint) = address::endpoint(remote)
        {
            contact.addresses.insert(endpoint);
        }
        self.admission
            .connections
            .insert(id, (peer, group, outbound));
        Ok(())
    }

    pub(crate) fn retain_authenticated(
        &mut self,
        peer: PeerId,
        now: Instant,
    ) -> Result<(), String> {
        if !self.contacts.contains_key(&peer)
            && self.contacts.len() >= crate::resources::limits().contacts
        {
            // Authenticated connections may replace unreachable hints. A DHT
            // router is replaceable after a short lease; proof peers and pinned
            // infrastructure are not displaced by a new identity.
            let replace = self
                .contacts
                .iter()
                .filter(|(candidate, contact)| {
                    !contact.pinned
                        && !self.relays.contains(candidate)
                        && (!contact.connected
                            || contact.infrastructure
                                && now.duration_since(contact.seen)
                                    >= crate::resources::limits().request_rate_window * 2)
                })
                .min_by_key(|(_, contact)| contact.seen)
                .map(|(peer, _)| *peer);
            let victim = replace.ok_or("authenticated contact capacity")?;
            if self.removed.len() >= crate::resources::limits().contacts {
                return Err("contact retirement capacity".into());
            }
            self.retire(victim, now);
            self.removed.push_back(victim);
        }
        let contact = self.admit(peer, now)?;
        contact.connected = true;
        contact.connected_at.get_or_insert(now);
        Ok(())
    }

    pub(crate) fn closed_connection(&mut self, id: ConnectionId) {
        if let Some((peer, _, _)) = self.admission.connections.remove(&id)
            && !self
                .admission
                .connections
                .values()
                .any(|(other, _, _)| *other == peer)
            && let Some(contact) = self.contacts.get_mut(&peer)
        {
            contact.connected = false;
            contact.connected_at = None;
        }
    }
}

#[cfg(test)]
mod tests;
