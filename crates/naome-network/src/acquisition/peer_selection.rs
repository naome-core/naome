//! Shared peer-list mechanics with distinct caller-order and fallback diagnostics.

use crate::PeerId;

pub(crate) enum PeerSetError {
    Empty,
    TooMany { actual: usize, maximum: usize },
    Duplicate(PeerId),
}

pub(crate) enum ConfiguredPeerSetError {
    Input(PeerSetError),
    Unknown(PeerId),
}

fn validate_size(peer_ids: &[PeerId], maximum: usize) -> Result<(), PeerSetError> {
    if peer_ids.is_empty() {
        return Err(PeerSetError::Empty);
    }
    if peer_ids.len() > maximum {
        return Err(PeerSetError::TooMany {
            actual: peer_ids.len(),
            maximum,
        });
    }
    Ok(())
}

pub(crate) fn validate_peer_set(peer_ids: &[PeerId], maximum: usize) -> Result<(), PeerSetError> {
    validate_size(peer_ids, maximum)?;
    for (index, &peer_id) in peer_ids.iter().enumerate() {
        if peer_ids[..index].contains(&peer_id) {
            return Err(PeerSetError::Duplicate(peer_id));
        }
    }
    Ok(())
}

pub(crate) fn configured_fallback(
    peer_ids: &[PeerId],
    maximum: usize,
    is_configured: impl Fn(&PeerId) -> bool,
) -> Result<Box<[PeerId]>, ConfiguredPeerSetError> {
    validate_size(peer_ids, maximum).map_err(ConfiguredPeerSetError::Input)?;
    let mut canonical_peer_ids = peer_ids.to_vec();
    canonical_peer_ids.sort_unstable();
    if let Some(peer_id) = canonical_peer_ids
        .windows(2)
        .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
    {
        return Err(ConfiguredPeerSetError::Input(PeerSetError::Duplicate(
            peer_id,
        )));
    }
    if let Some(peer_id) = canonical_peer_ids
        .iter()
        .copied()
        .find(|peer_id| !is_configured(peer_id))
    {
        return Err(ConfiguredPeerSetError::Unknown(peer_id));
    }
    canonical_peer_ids.clone_from_slice(peer_ids);
    Ok(canonical_peer_ids.into_boxed_slice())
}
