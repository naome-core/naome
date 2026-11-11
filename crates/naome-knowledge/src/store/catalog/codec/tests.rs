use super::*;

#[test]
fn small_payload_is_stored_raw_with_exact_decoded_bytes() {
    let raw = [1, 2, 3, 4];
    assert_eq!(encode(&raw).unwrap(), [RAW, 1, 2, 3, 4]);
    assert_eq!(decode(&[RAW, 1, 2, 3, 4], raw.len()).unwrap(), raw);
}

#[test]
fn repeated_payload_is_compressed_and_corruption_is_rejected() {
    let raw = vec![42; 8192];
    let encoded = encode(&raw).unwrap();
    assert_eq!(encoded[0], COMPRESSED);
    assert!(encoded.len() < raw.len());
    assert_eq!(decode(&encoded, raw.len()).unwrap(), raw);
    assert!(decode(&encoded[..encoded.len() - 1], raw.len()).is_err());
    assert!(decode(&encoded, raw.len() - 1).is_err());
    assert!(decode(&[99, 1, 2], 2).is_err());
    assert!(decode(&[RAW, 1, 2], 3).is_err());
    assert!(decode(&[RAW], 0).is_err());
    assert!(decode(&[RAW, 1], naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES + 1).is_err());
}
