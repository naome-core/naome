//! Public routing is a client-only address directory, never proof authority.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) const PROTOCOL: &str = "/ipfs/kad/1.0.0";
pub(crate) const RELAY_HOP: &str = "/libp2p/circuit/relay/0.2.0/hop";

/// IPFS Foundation public-good bootstrappers, with pinned identity keys.
/// Source: https://docs.ipfs.tech/concepts/public-utilities/#amino-dht-bootstrappers
pub(crate) fn bootstrap() -> Vec<Peer> {
    [
        (
            "sg1.bootstrap.libp2p.io",
            "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        ),
        (
            "sv15.bootstrap.libp2p.io",
            "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        ),
        (
            "am6.bootstrap.libp2p.io",
            "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        ),
        (
            "chic-1.bootstrap.ipni.io",
            "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        ),
    ]
    .into_iter()
    .map(|(host, id)| Peer {
        id: id.into(),
        address: format!("/dns4/{host}/tcp/4001"),
    })
    .collect()
}

pub(crate) fn participation_key() -> kad::RecordKey {
    let mut hash = Sha256::new();
    hash.update(b"naome:knowledge:participants:v1\0");
    hash.update(crate::wire::PROTOCOL.as_ref().as_bytes());
    hash.update(b"\0");
    hash.update(crate::compatibility());
    // A valid sha2-256 multihash is interoperable with public provider routing.
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&hash.finalize());
    kad::RecordKey::new(&bytes)
}

pub(crate) fn dht_protocol(internet: bool) -> String {
    if internet {
        PROTOCOL.into()
    } else {
        format!(
            "/naome/knowledge/kad/{}/1",
            crate::hex(&crate::compatibility())
        )
    }
}
