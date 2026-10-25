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
