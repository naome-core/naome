//! Compact owned payload bytes. Mathematical identities always use the decoded bytes.
use lz4_flex::block;

const RAW: u8 = 0;
const COMPRESSED: u8 = 1;
const COMPRESS_MINIMUM: usize = 256;

pub(super) fn encode(raw: &[u8]) -> Result<Vec<u8>, crate::Error> {
    if raw.is_empty() || raw.len() > naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES {
        return Err(crate::InputFault::CatalogPayloadWidth.into());
    }
    let capacity = raw
        .len()
        .checked_add(1)
        .ok_or(crate::InputFault::CatalogPayloadWidth)?;
    if raw.len() >= COMPRESS_MINIMUM {
        let compressed = block::compress(raw);
        if compressed.len() < raw.len() {
            let mut bytes = Vec::with_capacity(compressed.len() + 1);
            bytes.push(COMPRESSED);
            bytes.extend_from_slice(&compressed);
            return Ok(bytes);
        }
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(RAW);
    bytes.extend_from_slice(raw);
    Ok(bytes)
}

pub(in crate::store) fn decode(bytes: &[u8], length: usize) -> Result<Vec<u8>, crate::Error> {
    if length == 0
        || length > naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES
        || bytes.len() > length.saturating_add(1)
    {
        return Err(crate::InputFault::CatalogPayloadDigest.into());
    }
    let (mode, payload) = bytes
        .split_first()
        .ok_or(crate::InputFault::CatalogPayloadDigest)?;
    match *mode {
        RAW if payload.len() == length => Ok(payload.to_vec()),
        COMPRESSED if length >= COMPRESS_MINIMUM && payload.len() < length => {
            let mut raw = vec![0; length];
            let actual = block::decompress_into(payload, &mut raw)
                .map_err(|_| crate::InputFault::CatalogPayloadDigest)?;
            if actual != length || block::compress(&raw) != payload {
                return Err(crate::InputFault::CatalogPayloadDigest.into());
            }
            Ok(raw)
        }
        _ => Err(crate::InputFault::CatalogPayloadDigest.into()),
    }
}

#[cfg(test)]
mod tests;
