//! Complete native/Meta learning state for the scientific consumer. Source
//! history and Finder SQLite retain their existing, separate owners.
use super::*;
use std::io::Read;

#[derive(Default)]
pub(super) struct Cost {
    pub bytes: u64,
    pub operations: u64,
}

pub(super) fn read(path: &Path, cap: usize, cost: &mut Cost) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    cost.bytes += bytes.len() as u64;
    cost.operations += 1;
    if bytes.len() > cap {
        return Err("learning-state checkpoint exceeds its existing capacity".into());
    }
    Ok(bytes)
}

pub(super) fn export<I: ArtifactIo + ?Sized>(
    path: &Path,
    state: &State,
    io: &mut I,
) -> Result<Cost, String> {
    state.validate()?;
    std::fs::create_dir(path).map_err(|e| e.to_string())?;
    std::fs::create_dir(path.join("blobs")).map_err(|e| e.to_string())?;
    let mut cost = Cost::default();
    let mut seen = BTreeSet::new();
    for blob in state.blobs().filter(|blob| seen.insert(&blob.sha256)) {
        let bytes = artifact::load(io, blob)?;
        std::fs::write(path.join("blobs").join(&blob.sha256), &bytes).map_err(|e| e.to_string())?;
        cost.bytes += bytes.len() as u64;
        cost.operations += 1;
    }
    // Write the canonical State only after every referenced model/Adam blob.
    // Incomplete exports cannot be imported as a complete selected state.
    let bytes = crate::checkpoint::encode(state)?;
    std::fs::write(path.join("state.json"), &bytes).map_err(|e| e.to_string())?;
    cost.bytes += bytes.len() as u64;
    cost.operations += 1;
    Ok(cost)
}

pub(super) fn import(path: &Path) -> Result<(State, MemoryStore, Cost), String> {
    let mut cost = Cost::default();
    let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
    let state: State =
        crate::checkpoint::decode(&read(&path.join("state.json"), capacity, &mut cost)?)?;
    state.validate()?;
    let mut io = MemoryStore::default();
    let mut seen = BTreeSet::new();
    for blob in state.blobs().filter(|blob| seen.insert(&blob.sha256)) {
        let bytes = read(
            &path.join("blobs").join(&blob.sha256),
            blob.bytes,
            &mut cost,
        )?;
        if Blob::of(&bytes) != *blob {
            return Err("learning-state model or Adam bytes differ from their checkpoint".into());
        }
        if artifact::save(&mut io, &bytes)? != *blob {
            return Err("learning-state model or Adam chunk restore differs".into());
        }
    }
    Ok((state, io, cost))
}

#[cfg(test)]
mod tests;
