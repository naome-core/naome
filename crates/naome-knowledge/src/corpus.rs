use crate::compatibility;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An immutable admission-order horizon. Roots are synchronization hints only;
/// the catalog lineage prevents resuming a cursor against a replacement corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventorySnapshot {
    pub lineage: [u8; 32],
    pub root: [u8; 32],
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryCursor {
    pub snapshot: InventorySnapshot,
    pub after: u64,
}

pub(crate) struct InventoryPage {
    pub snapshot: InventorySnapshot,
    pub ids: Vec<naome_proof::ArtifactId>,
    pub next: Option<InventoryCursor>,
}

/// The checked map maintains its key-only Patricia root incrementally. The
/// fingerprint is an untrusted synchronization hint, never proof authority.
pub(crate) fn root(count: usize, fingerprint: [u8; 32]) -> Result<[u8; 32], String> {
    let count = u64::try_from(count).map_err(|_| "corpus count width")?;
    let mut hash = Sha256::new();
    hash.update(ROOT_FORMAT.as_bytes());
    hash.update([0]);
    hash.update(compatibility());
    hash.update(count.to_be_bytes());
    hash.update(fingerprint);
    Ok(hash.finalize().into())
}

pub const ROOT_FORMAT: &str = "naome:knowledge:set";
