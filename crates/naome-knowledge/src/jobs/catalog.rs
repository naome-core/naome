//! Immutable checked-catalog input bound to a local solving request.
use crate::{Error, learning::peer::Packet, resources::MemoryLease};
use naome_proof::ProofId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct CatalogSource(Arc<Retained>);

#[derive(Debug)]
struct Retained {
    packet: Packet,
    _memory: Arc<MemoryLease>,
}

impl CatalogSource {
    pub(crate) fn new(packet: Packet) -> Result<Self, Error> {
        packet.validate_width()?;
        let memory = MemoryLease::acquire(packet.retained_bytes())?;
        Ok(Self(Arc::new(Retained {
            packet,
            _memory: memory,
        })))
    }

    pub(crate) fn proof_id(&self) -> ProofId {
        self.packet().manifest.proof_id()
    }

    pub(crate) fn packet(&self) -> &Packet {
        &self.0.packet
    }
}

impl PartialEq for CatalogSource {
    fn eq(&self, other: &Self) -> bool {
        self.packet() == other.packet()
    }
}
impl Eq for CatalogSource {}

impl Serialize for CatalogSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.packet().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CatalogSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Packet::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
