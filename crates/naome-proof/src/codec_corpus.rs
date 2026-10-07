//! Shared deterministic mutation campaign; compiled only by codec tests.
//!
//! This bounds test generation, not parser work. Each owner separately checks
//! its actual byte/count/depth budgets and rejection ordering.

/// Runs fixed valid seeds, truncations, edits and 512 reproducible byte strings.
/// The callback must encode the decoded typed fields, not echo retained input.
pub fn check(
    name: &str,
    seeds: &[Vec<u8>],
    mut decode_encode: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) {
    assert!(!seeds.is_empty(), "{name}: a valid seed is mandatory");
    let mut cases = 0usize;
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut inspect = |bytes: &[u8], required: bool| {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_encode(bytes)))
                .unwrap_or_else(|_| panic!("{name}: decoder/encoder panicked at case {cases}"));
        match result {
            Some(encoded) => {
                assert_eq!(encoded, bytes, "{name}: noncanonical case {cases}");
                accepted += 1;
            }
            None => {
                assert!(!required, "{name}: valid seed rejected at case {cases}");
                rejected += 1;
            }
        }
        cases += 1;
    };
    for seed in seeds {
        inspect(seed, true);
        // Exhaust every short-frame prefix; sample long-frame prefixes at
        // fixed evenly spaced offsets, including both endpoints.
        let prefix_count = seed.len().min(1_024);
        for index in 0..=prefix_count {
            let end = (index * seed.len()).checked_div(prefix_count).unwrap_or(0);
            inspect(&seed[..end], false);
        }
        let edit_count = seed.len().min(128);
        for index in 0..edit_count {
            let offset = index * seed.len() / edit_count;
            for mask in [0x01, 0x80, 0xff] {
                let mut changed = seed.clone();
                changed[offset] ^= mask;
                inspect(&changed, false);
            }
            let mut removed = seed.clone();
            removed.remove(offset);
            inspect(&removed, false);
            let mut inserted = seed.clone();
            inserted.insert(offset, 0xff);
            inspect(&inserted, false);
        }
        for suffix in [0x00, 0xff] {
            let mut extended = seed.clone();
            extended.push(suffix);
            inspect(&extended, false);
        }
    }
    let mut random = 0x4e41_4f4d_455f_5630_u64;
    for case in 0..512 {
        let length = case * 4_096 / 511;
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            *byte = random as u8;
        }
        inspect(&bytes, false);
    }
    assert!(accepted >= seeds.len(), "{name}: positive corpus is empty");
    assert!(rejected > 0, "{name}: negative corpus is empty");
    assert!(cases <= seeds.len() * (1 + 1_025 + 128 * 5 + 2) + 512);
}
