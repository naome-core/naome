use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NetworkGroup {
    Ipv4([u8; 2]),
    Ipv6([u8; 4]),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum AddressReason {
    TooLong,
    WrongShape,
    ZeroPort,
    NotGloballyRoutable,
}

impl fmt::Display for AddressReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => formatter.write_str("binary multi-address is too long"),
            Self::WrongShape => formatter.write_str("expected exactly /ip4|ip6/.../tcp/..."),
            Self::ZeroPort => formatter.write_str("TCP port zero is not dialable"),
            Self::NotGloballyRoutable => formatter.write_str("IP address is not globally routable"),
        }
    }
}

pub(super) fn validate_endpoint(
    address: &Multiaddr,
    require_global: bool,
) -> Result<NetworkGroup, AddressReason> {
    if address.len() > MAX_PEER_ADDRESS_BYTES {
        return Err(AddressReason::TooLong);
    }
    endpoint_group(address, require_global)
}

pub(super) fn endpoint_group(
    address: &Multiaddr,
    require_global: bool,
) -> Result<NetworkGroup, AddressReason> {
    let mut protocols = address.iter();
    let first = protocols.next();
    let second = protocols.next();
    if protocols.next().is_some() {
        return Err(AddressReason::WrongShape);
    }
    let port = match second {
        Some(Protocol::Tcp(port)) if port != 0 => port,
        Some(Protocol::Tcp(_)) => return Err(AddressReason::ZeroPort),
        _ => return Err(AddressReason::WrongShape),
    };
    let _ = port;
    match first {
        Some(Protocol::Ip4(address)) => {
            if require_global && !is_global_ipv4(address) {
                return Err(AddressReason::NotGloballyRoutable);
            }
            Ok(NetworkGroup::Ipv4([
                address.octets()[0],
                address.octets()[1],
            ]))
        }
        Some(Protocol::Ip6(address)) => {
            if require_global && !is_global_ipv6(address) {
                return Err(AddressReason::NotGloballyRoutable);
            }
            let octets = address.octets();
            Ok(NetworkGroup::Ipv6([
                octets[0], octets[1], octets[2], octets[3],
            ]))
        }
        _ => Err(AddressReason::WrongShape),
    }
}

pub(super) fn network_group(address: &Multiaddr) -> Option<NetworkGroup> {
    endpoint_group(address, false).ok()
}

pub(super) fn is_global_ipv4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    !in_ipv4(value, [0, 0, 0, 0], 8)
        && !in_ipv4(value, [10, 0, 0, 0], 8)
        && !in_ipv4(value, [100, 64, 0, 0], 10)
        && !in_ipv4(value, [127, 0, 0, 0], 8)
        && !in_ipv4(value, [169, 254, 0, 0], 16)
        && !in_ipv4(value, [172, 16, 0, 0], 12)
        && !in_ipv4(value, [192, 0, 0, 0], 24)
        && !in_ipv4(value, [192, 0, 2, 0], 24)
        && !in_ipv4(value, [192, 168, 0, 0], 16)
        && !in_ipv4(value, [198, 18, 0, 0], 15)
        && !in_ipv4(value, [198, 51, 100, 0], 24)
        && !in_ipv4(value, [203, 0, 113, 0], 24)
        && !in_ipv4(value, [224, 0, 0, 0], 4)
        && !in_ipv4(value, [240, 0, 0, 0], 4)
}

pub(super) fn in_ipv4(value: u32, base: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    value & mask == u32::from(Ipv4Addr::from(base)) & mask
}

pub(super) fn is_global_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    let global_unicast = octets[0] & 0xe0 == 0x20;
    global_unicast
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
}

pub(super) fn in_ipv6(value: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    u128::from(value) & mask == u128::from(base) & mask
}
