//! Local design measurements, not a canonical codec, profile, or admission API.
//! Integer limits and tested policy sizes are experimental corpus parameters.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use num_bigint::{BigInt, BigUint};
use std::hint::black_box;
use std::time::{Duration, Instant};

mod numbers;

struct Policy {
    threshold: usize,
    keys: Vec<VerifyingKey>,
}

impl Policy {
    fn parse(threshold: usize, raw: &[[u8; 32]]) -> Option<Self> {
        if threshold == 0 || threshold > raw.len() {
            return None;
        }
        let mut keys = Vec::with_capacity(raw.len());
        let mut previous = None;
        for bytes in raw {
            if previous.is_some_and(|p| p >= *bytes) {
                return None;
            }
            let key = VerifyingKey::from_bytes(bytes).ok()?;
            if key.is_weak() {
                return None;
            }
            keys.push(key);
            previous = Some(*bytes);
        }
        Some(Self { threshold, keys })
    }

    fn verify(&self, message: &[u8], evidence: &[(usize, Signature)]) -> bool {
        if evidence.len() != self.threshold {
            return false;
        }
        let mut previous = None;
        for (index, signature) in evidence {
            if previous.is_some_and(|p| p >= *index) {
                return false;
            }
            let Some(key) = self.keys.get(*index) else {
                return false;
            };
            if key.verify_strict(message, signature).is_err() {
                return false;
            }
            previous = Some(*index);
        }
        true
    }
}

fn fixture_keys(count: usize) -> Vec<SigningKey> {
    let mut keys: Vec<_> = (0..count)
        .map(|index| {
            let mut seed = [0x5a; 32];
            seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
            SigningKey::from_bytes(&seed)
        })
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    keys
}

fn measure(name: &str, mut operation: impl FnMut() -> bool) {
    for _ in 0..3 {
        assert!(black_box(operation()));
    }
    let mut iterations = 1_u32;
    loop {
        let start = Instant::now();
        for _ in 0..iterations {
            assert!(black_box(operation()));
        }
        if start.elapsed() >= Duration::from_millis(10) || iterations >= 131_072 {
            break;
        }
        iterations *= 2;
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            assert!(black_box(operation()));
        }
        samples.push(start.elapsed().as_nanos() / u128::from(iterations));
    }
    samples.sort_unstable();
    println!(
        "{{\"case\":\"{name}\",\"iterations_per_sample\":{iterations},\"samples\":7,\"min_ns\":{},\"median_ns\":{},\"max_ns\":{}}}",
        samples[0], samples[3], samples[6]
    );
}

fn main() {
    println!(
        "{{\"kind\":\"local_design_calibration\",\"scope\":\"authorization core and candidate integer decoders only\",\"canonical_limit_selected\":false}}"
    );
    // A fixed synthetic 96-byte message isolates signature costs. It is not
    // the successor's as-yet-unspecified authorization transcript.
    let message = [0x3c; 96];
    let other_message = [0x3d; 96];
    for count in [1, 4, 16, 64, 256] {
        let keys = fixture_keys(count);
        let raw: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let mut thresholds = vec![1, count.div_ceil(2), count];
        thresholds.sort_unstable();
        thresholds.dedup();
        for threshold in thresholds {
            let policy = Policy::parse(threshold, &raw).unwrap();
            let evidence: Vec<_> = keys
                .iter()
                .take(threshold)
                .enumerate()
                .map(|(index, key)| (index, key.sign(&message)))
                .collect();
            let mut invalid_last = evidence.clone();
            invalid_last[threshold - 1].1 = keys[threshold - 1].sign(&other_message);
            measure(&format!("verified_policy_n{count}_m{threshold}"), || {
                policy.verify(black_box(&message), black_box(&evidence))
            });
            measure(
                &format!("parse_policy_and_verify_n{count}_m{threshold}"),
                || {
                    Policy::parse(black_box(threshold), black_box(&raw))
                        .unwrap()
                        .verify(black_box(&message), black_box(&evidence))
                },
            );
            measure(&format!("wrong_message_last_n{count}_m{threshold}"), || {
                !policy.verify(black_box(&message), black_box(&invalid_last))
            });
        }
    }
    for bits in [0_u64, 7, 8, 64, 128, 256, 512, 1024, 4096, 32768] {
        let value = if bits == 0 {
            BigUint::from(0_u8)
        } else {
            (BigUint::from(1_u8) << usize::try_from(bits).unwrap()) - BigUint::from(1_u8)
        };
        let leb = numbers::encode_uleb(&value);
        let be = numbers::encode_length_be(&value);
        let magnitude_limit = usize::try_from(bits.div_ceil(8)).unwrap();
        println!(
            "{{\"integer_bits\":{bits},\"uleb_bytes\":{},\"length_be_bytes\":{}}}",
            leb.len(),
            be.len()
        );
        measure(&format!("decode_uleb_bits{bits}"), || {
            numbers::decode_uleb(black_box(&leb), leb.len())
                .is_some_and(|decoded| black_box(decoded).bits() == bits)
        });
        measure(&format!("decode_length_be_bits{bits}"), || {
            numbers::decode_length_be(black_box(&be), magnitude_limit)
                .is_some_and(|decoded| black_box(decoded).bits() == bits)
        });
        let signed = -BigInt::from(value);
        let signed_bytes = numbers::encode_signed(&signed);
        let expected_sign = signed.sign();
        measure(&format!("decode_signed_length_be_bits{bits}"), || {
            numbers::decode_signed(black_box(&signed_bytes), magnitude_limit).is_some_and(
                |decoded| {
                    let decoded = black_box(decoded);
                    decoded.bits() == bits && decoded.sign() == expected_sign
                },
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_threshold_accepts_different_subsets_and_checks_every_signature() {
        let keys = fixture_keys(4);
        let raw: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let policy = Policy::parse(2, &raw).unwrap();
        let message = b"fixed test intent";
        for indices in [[0, 2], [1, 3]] {
            let evidence: Vec<_> = indices
                .iter()
                .map(|i| (*i, keys[*i].sign(message)))
                .collect();
            assert!(policy.verify(message, &evidence));
            assert!(!policy.verify(b"changed intent", &evidence));
            let mut wrong_last = evidence.clone();
            wrong_last[1].1 = keys[indices[1]].sign(b"other intent");
            assert!(!policy.verify(message, &wrong_last));
            assert!(!policy.verify(message, &evidence[..1]));
        }
        let all: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (i, key.sign(message)))
            .collect();
        assert!(!policy.verify(message, &all));
        assert!(!policy.verify(message, &[all[0], all[0]]));
        assert!(!policy.verify(message, &[all[2], all[0]]));
        assert!(!policy.verify(message, &[(0, all[0].1), (4, all[1].1)]));
    }

    #[test]
    fn malformed_policy_is_not_a_valid_benchmark_fixture() {
        let keys = fixture_keys(4);
        let raw: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        assert!(Policy::parse(0, &raw).is_none());
        assert!(Policy::parse(5, &raw).is_none());
        assert!(Policy::parse(1, &[]).is_none());
        assert!(Policy::parse(1, &[[0; 32]]).is_none());
        let mut duplicate = raw.clone();
        duplicate[3] = duplicate[2];
        assert!(Policy::parse(2, &duplicate).is_none());
        let mut reversed = raw;
        reversed.reverse();
        assert!(Policy::parse(2, &reversed).is_none());
    }
}
