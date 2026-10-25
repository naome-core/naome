//! Lossless disposable context bytes; identities and cache charges use raw bytes.
use lz4_flex::block;
use naome_checker::ContextError;

const MAGIC: &[u8; 4] = b"NCX1";
const RAW: u8 = 0;
const COMPRESSED: u8 = 1;
pub(super) const HEADER_BYTES: usize = 13;

pub(super) fn maximum_encoded(raw: usize) -> Result<usize, ContextError> {
    raw.checked_add(HEADER_BYTES).ok_or(ContextError::Limit)
}

pub(super) fn decoded_length(
    header: &[u8],
    encoded: usize,
    maximum: usize,
) -> Result<usize, ContextError> {
    if header.len() != HEADER_BYTES || &header[..4] != MAGIC || header[4] > COMPRESSED {
        return Err(ContextError::Corrupt);
    }
    let length = usize::try_from(u64::from_be_bytes(
        header[5..13]
            .try_into()
            .map_err(|_| ContextError::Corrupt)?,
    ))
    .map_err(|_| ContextError::Limit)?;
    if length > maximum {
        return Err(ContextError::Limit);
    }
    match header[4] {
        RAW if encoded == maximum_encoded(length)? => Ok(length),
        COMPRESSED if encoded > HEADER_BYTES && encoded < length => Ok(length),
        _ => Err(ContextError::Corrupt),
    }
}

pub(super) fn encode(raw: &[u8]) -> Result<Vec<u8>, ContextError> {
    let length = u64::try_from(raw.len()).map_err(|_| ContextError::Limit)?;
    let capacity = maximum_encoded(block::get_maximum_output_size(raw.len()))?;
    let mut encoded = vec![0; capacity];
    let packed = block::compress_into(raw, &mut encoded[HEADER_BYTES..])
        .expect("LZ4 maximum output size must fit the payload slice");
    let packed_length = maximum_encoded(packed)?;
    let mode = if packed_length < raw.len() {
        encoded.truncate(packed_length);
        COMPRESSED
    } else {
        encoded.truncate(maximum_encoded(raw.len())?);
        encoded[HEADER_BYTES..].copy_from_slice(raw);
        RAW
    };
    encoded[..MAGIC.len()].copy_from_slice(MAGIC);
    encoded[4] = mode;
    encoded[5..HEADER_BYTES].copy_from_slice(&length.to_be_bytes());
    Ok(encoded)
}

pub(super) fn decode(encoded: &[u8], maximum: usize) -> Result<Vec<u8>, ContextError> {
    let header = encoded.get(..HEADER_BYTES).ok_or(ContextError::Corrupt)?;
    let length = decoded_length(header, encoded.len(), maximum)?;
    let payload = &encoded[HEADER_BYTES..];
    if header[4] == RAW {
        return Ok(payload.to_vec());
    }
    // Caller bounds were checked before this allocation. Recompression rejects
    // trailing or alternate block encodings even if a decoder accepts them.
    let mut raw = vec![0; length];
    let decoded = block::decompress_into(payload, &mut raw).map_err(|_| ContextError::Corrupt)?;
    if decoded != length || block::compress(&raw) != payload {
        return Err(ContextError::Corrupt);
    }
    Ok(raw)
}

#[cfg(test)]
mod tests;
