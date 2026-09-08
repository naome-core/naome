//! Standalone measurements of two encodings, not a canonical admission API.
//! The length-prefixed big-endian form is the selected draft representation.
use num_bigint::{BigInt, BigUint, Sign};

pub fn encode_uleb(value: &BigUint) -> Vec<u8> {
    let mut groups = Vec::new();
    let mut accumulator = 0_u16;
    let mut bits = 0;
    for byte in value.to_bytes_le() {
        accumulator |= u16::from(byte) << bits;
        bits += 8;
        while bits >= 7 {
            groups.push((accumulator & 0x7f) as u8);
            accumulator >>= 7;
            bits -= 7;
        }
    }
    if bits != 0 {
        groups.push(accumulator as u8);
    }
    while groups.len() > 1 && groups.last() == Some(&0) {
        groups.pop();
    }
    if groups.is_empty() {
        groups.push(0);
    }
    let last = groups.len() - 1;
    for group in &mut groups[..last] {
        *group |= 0x80;
    }
    groups
}

pub fn decode_uleb(bytes: &[u8], maximum_encoded_bytes: usize) -> Option<BigUint> {
    // This is a bounded slice decoder; it does not claim network admission.
    if bytes.is_empty() || bytes.len() > maximum_encoded_bytes {
        return None;
    }
    let last = bytes.len() - 1;
    if bytes[last] & 0x80 != 0
        || (last != 0 && bytes[last] == 0)
        || bytes[..last].iter().any(|byte| byte & 0x80 == 0)
    {
        return None;
    }
    let capacity = bytes.len().checked_mul(7)?.checked_add(7)? / 8;
    let mut magnitude = Vec::with_capacity(capacity);
    let mut accumulator = 0_u16;
    let mut bits = 0;
    for byte in bytes {
        accumulator |= u16::from(byte & 0x7f) << bits;
        bits += 7;
        if bits >= 8 {
            magnitude.push(accumulator as u8);
            accumulator >>= 8;
            bits -= 8;
        }
    }
    if bits != 0 {
        magnitude.push(accumulator as u8);
    }
    Some(BigUint::from_bytes_le(&magnitude))
}

pub fn encode_length_be(value: &BigUint) -> Vec<u8> {
    let magnitude = if value.bits() == 0 {
        Vec::new()
    } else {
        value.to_bytes_be()
    };
    let mut bytes = encode_uleb(&BigUint::from(magnitude.len()));
    bytes.extend_from_slice(&magnitude);
    bytes
}

pub fn decode_length_be(bytes: &[u8], maximum_magnitude_bytes: usize) -> Option<BigUint> {
    let prefix_bound = ((usize::BITS - maximum_magnitude_bytes.leading_zeros()) as usize)
        .div_ceil(7)
        .max(1);
    if bytes.is_empty()
        || (bytes.len() > prefix_bound && bytes.len() - prefix_bound > maximum_magnitude_bytes)
    {
        return None;
    }
    let mut length = 0_usize;
    for (position, byte) in bytes.iter().take(prefix_bound).enumerate() {
        let shift = u32::try_from(position.checked_mul(7)?).ok()?;
        let group = usize::from(byte & 0x7f);
        if shift >= usize::BITS || group > usize::MAX >> shift {
            return None;
        }
        length |= group << shift;
        if length > maximum_magnitude_bytes {
            return None;
        }
        if byte & 0x80 == 0 {
            if position != 0 && group == 0 {
                return None;
            }
            let magnitude = &bytes[position + 1..];
            if magnitude.len() != length || magnitude.first() == Some(&0) {
                return None;
            }
            return Some(BigUint::from_bytes_be(magnitude));
        }
    }
    None
}

pub fn encode_signed(value: &BigInt) -> Vec<u8> {
    let mut encoded = vec![u8::from(value.sign() == Sign::Minus)];
    encoded.extend(encode_length_be(value.magnitude()));
    encoded
}

pub fn decode_signed(bytes: &[u8], maximum_magnitude_bytes: usize) -> Option<BigInt> {
    let (tag, magnitude_bytes) = bytes.split_first()?;
    let sign = match tag {
        0 => Sign::Plus,
        1 => Sign::Minus,
        _ => return None,
    };
    let magnitude = decode_length_be(magnitude_bytes, maximum_magnitude_bytes)?;
    if sign == Sign::Minus && magnitude.bits() == 0 {
        return None;
    }
    Some(BigInt::from_biguint(sign, magnitude))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_vectors_reject_negative_zero_and_unknown_signs() {
        let vectors: &[(i32, &[u8])] = &[
            (0, &[0, 0]),
            (1, &[0, 1, 1]),
            (-1, &[1, 1, 1]),
            (256, &[0, 2, 1, 0]),
            (-256, &[1, 2, 1, 0]),
        ];
        for (value, bytes) in vectors {
            let value = BigInt::from(*value);
            assert_eq!(encode_signed(&value), *bytes);
            assert_eq!(decode_signed(bytes, 2), Some(value));
        }
        for invalid in [vec![], vec![0], vec![1, 0], vec![2, 0], vec![0, 1, 0]] {
            assert!(decode_signed(&invalid, 2).is_none());
        }
        let large = -(BigInt::from(1_u8) << 4096_usize);
        let encoded = encode_signed(&large);
        assert_eq!(decode_signed(&encoded, 513), Some(large));
        assert!(decode_signed(&encoded, 512).is_none());
    }

    #[test]
    fn independent_small_integer_vectors_fix_both_candidate_encodings() {
        let vectors: &[(u32, &[u8], &[u8])] = &[
            (0, &[0], &[0]),
            (1, &[1], &[1, 1]),
            (127, &[0x7f], &[1, 0x7f]),
            (128, &[0x80, 1], &[1, 0x80]),
            (255, &[0xff, 1], &[1, 0xff]),
            (256, &[0x80, 2], &[2, 1, 0]),
            (16384, &[0x80, 0x80, 1], &[2, 0x40, 0]),
        ];
        for (number, leb, be) in vectors {
            let number = BigUint::from(*number);
            assert_eq!(encode_uleb(&number), *leb);
            assert_eq!(encode_length_be(&number), *be);
            assert_eq!(decode_uleb(leb, leb.len()), Some(number.clone()));
            let bound = usize::try_from(number.bits().div_ceil(8)).unwrap();
            assert_eq!(decode_length_be(be, bound), Some(number));
        }
    }

    #[test]
    fn widths_cross_machine_boundaries_without_loss() {
        for bit in [
            7_usize, 8, 63, 64, 127, 128, 255, 256, 511, 512, 4095, 32767,
        ] {
            let power = BigUint::from(1_u8) << bit;
            for number in [
                &power - BigUint::from(1_u8),
                power.clone(),
                &power + BigUint::from(1_u8),
            ] {
                let leb = encode_uleb(&number);
                let be = encode_length_be(&number);
                assert_eq!(decode_uleb(&leb, leb.len()), Some(number.clone()));
                let bound = usize::try_from(number.bits().div_ceil(8)).unwrap();
                assert_eq!(decode_length_be(&be, bound), Some(number));
                assert!(decode_uleb(&leb, leb.len() - 1).is_none());
                assert!(decode_length_be(&be, bound - 1).is_none());
            }
        }
    }

    #[test]
    fn nonminimal_truncated_trailing_and_oversized_encodings_fail() {
        for malformed in [vec![], vec![0x80], vec![0x80, 0], vec![0x81, 0], vec![1, 0]] {
            assert!(decode_uleb(&malformed, 64).is_none());
        }
        for malformed in [vec![], vec![1, 0], vec![0, 0], vec![0x81, 0, 1], vec![2, 1]] {
            assert!(decode_length_be(&malformed, 64).is_none());
        }
        assert!(decode_uleb(&[0x80; 1024], 8).is_none());
        assert!(decode_length_be(&[0x80; 1024], 8).is_none());
        assert!(decode_length_be(&[0xff; 32], usize::MAX).is_none());
        assert_eq!(decode_length_be(&[0], 0), Some(BigUint::from(0_u8)));
        assert_eq!(
            decode_length_be(&[0], usize::MAX),
            Some(BigUint::from(0_u8))
        );
        assert_eq!(
            decode_length_be(&[1, 1], usize::MAX),
            Some(BigUint::from(1_u8))
        );
    }
}
