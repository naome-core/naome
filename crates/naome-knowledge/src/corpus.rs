use crate::compatibility;
use sha2::{Digest, Sha256};

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

pub const ROOT_FORMAT: &str = "naome:knowledge:set:v3";
