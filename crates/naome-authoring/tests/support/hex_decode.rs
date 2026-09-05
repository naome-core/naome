pub fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    hex_bytes(hex).try_into().unwrap()
}

pub fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}
