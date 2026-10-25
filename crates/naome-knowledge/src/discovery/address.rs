//! Address policy before dialing, including addresses produced by DNS resolution.
use super::*;
use std::net::IpAddr;

pub(crate) fn ip(address: &Multiaddr) -> Option<IpAddr> {
    match address.iter().next()? {
        Protocol::Ip4(ip) => Some(ip.into()),
        Protocol::Ip6(ip) => Some(ip.into()),
        _ => None,
    }
}

/// Conservatively exclude special-use, local and IP-translation ranges.
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !(a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Only ordinary global unicast; exclude 6to4, Teredo, special-use
            // 2001::/23, documentation and IPv4-mapped/NAT64 encodings.
            segments[0] & 0xe000 == 0x2000
                && segments[0] != 0x2002
                && !(segments[0] == 0x2001 && segments[1] < 0x200)
                && !(segments[0] == 0x2001 && segments[1] == 0xdb8)
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

pub(crate) fn public_address(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => public_ip(ip.into()),
        Some(Protocol::Ip6(ip)) => public_ip(ip.into()),
        // The transport checks every resolved IP again before opening TCP.
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => true,
        _ => false,
    }
}

pub(crate) fn endpoint(address: &Multiaddr) -> Option<Multiaddr> {
    let mut parts = address.iter();
    let host = parts.next()?;
    let port = parts.next()?;
    matches!(host, Protocol::Ip4(_) | Protocol::Ip6(_)).then_some(())?;
    matches!(port, Protocol::Tcp(port) if port != 0).then_some(())?;
    Some(Multiaddr::empty().with(host).with(port))
}

impl Book {
    /// Explicit literal endpoints and observed LAN discovery are the only
    /// exceptions. An untrusted DNS answer cannot create a new exception.
    pub(crate) fn allows_dial(&self, address: &Multiaddr) -> bool {
        let Some(endpoint) = endpoint(address) else {
            return false;
        };
        self.allow_private_addresses
            || public_address(&endpoint)
            || self.contacts.values().any(|contact| {
                contact.local_addresses.contains(&endpoint)
                    || contact.pinned && contact.addresses.contains(&endpoint)
            })
    }

    pub(crate) fn route(&self, address: &Multiaddr, target: PeerId) -> Result<Multiaddr, String> {
        // Public circuits are untrusted paths, not authorities. Noise still
        // authenticates the end peer. Only one hop to a public endpoint is used.
        let extra = self.internet
            && public_address(address)
            && address
                .iter()
                .any(|part| matches!(part, Protocol::P2pCircuit));
        if extra {
            let mut relays = self.relays.clone();
            if let Some(Protocol::P2p(relay)) = address.iter().nth(2) {
                relays.insert(relay);
            }
            routing_address(address, target, &relays)
        } else {
            routing_address(address, target, &self.relays)
        }
    }

    pub(crate) fn local_hint(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        now: Instant,
    ) -> Result<bool, String> {
        let address = self.route(address, peer)?;
        let contact = self.admit(peer, now)?;
        if contact.addresses.len() >= crate::resources::limits().addresses_per_contact
            && !contact.addresses.contains(&address)
        {
            return Err("contact address capacity".into());
        }
        if let Some(endpoint) = endpoint(&address) {
            contact.local_addresses.insert(endpoint);
        }
        Ok(contact.addresses.insert(address))
    }
}

#[cfg(test)]
mod tests;
