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
mod tests {
    use super::*;

    #[test]
    fn raw_and_compressed_roundtrips_preserve_exact_bytes_and_size_bounds() {
        let mut cases = vec![
            Vec::new(),
            vec![0],
            (0u8..=255).collect::<Vec<_>>(),
            vec![0; 32 * 1024],
            (0u8..=255).cycle().take(32 * 1024).collect::<Vec<_>>(),
        ];
        for length in [2, 3, 12, 13, 14, 127, 128, 129, 255, 256, 257] {
            let mut bytes = vec![0; length];
            bytes[length / 2] = 91;
            cases.push(bytes);
        }
        for raw in cases {
            let encoded = encode(&raw).unwrap();
            assert!(encoded.len() <= maximum_encoded(raw.len()).unwrap());
            assert_eq!(decode(&encoded, raw.len()).unwrap(), raw);
            assert_eq!(
                decoded_length(&encoded[..HEADER_BYTES], encoded.len(), raw.len()).unwrap(),
                raw.len()
            );
        }
        assert_eq!(encode(&(0u8..=255).collect::<Vec<_>>()).unwrap()[4], RAW);
        assert_eq!(encode(&vec![0; 32 * 1024]).unwrap()[4], COMPRESSED);
    }

    #[test]
    fn advertised_output_cannot_exceed_the_caller_work_limit() {
        let encoded = encode(&vec![0; 4096]).unwrap();
        assert!(matches!(decode(&encoded, 4095), Err(ContextError::Limit)));
        let mut oversized = encoded;
        oversized[5..13].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(decode(&oversized, 4096), Err(ContextError::Limit)));
        assert!(matches!(
            maximum_encoded(usize::MAX),
            Err(ContextError::Limit)
        ));
    }

    #[test]
    fn unknown_truncated_overlong_and_noncanonical_records_are_refused() {
        for bytes in [Vec::new(), vec![0; HEADER_BYTES - 1], vec![0; HEADER_BYTES]] {
            assert!(matches!(decode(&bytes, 4096), Err(ContextError::Corrupt)));
        }
        let encoded = encode(&vec![0; 4096]).unwrap();
        let mut unknown = encoded.clone();
        unknown[4] = 2;
        assert!(matches!(decode(&unknown, 4096), Err(ContextError::Corrupt)));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode(&trailing, 4096),
            Err(ContextError::Corrupt)
        ));
        assert!(matches!(
            decode(&encoded[..encoded.len() - 1], 4096),
            Err(ContextError::Corrupt)
        ));
        let mut wrong_output = encoded;
        wrong_output[5..13].copy_from_slice(&64u64.to_be_bytes());
        assert!(matches!(
            decode(&wrong_output, 4096),
            Err(ContextError::Corrupt)
        ));
        let mut raw = encode(&(0u8..=255).collect::<Vec<_>>()).unwrap();
        raw.push(0);
        assert!(matches!(decode(&raw, 4096), Err(ContextError::Corrupt)));
    }
}
