use crate::compatibility;
use sha2::{Digest, Sha256};

/// Preserve the existing set root through its original count width. Wider
/// corpora use a distinct frame; no count is silently truncated.
pub(crate) fn start_root_hash(count: usize) -> Result<Sha256, String> {
    let mut hash = Sha256::new();
    if let Ok(count) = u32::try_from(count) {
        hash.update(b"naome:knowledge:set:v1\0");
        hash.update(compatibility());
        hash.update(count.to_be_bytes());
    } else {
        let count = u64::try_from(count).map_err(|_| "corpus count width")?;
        hash.update(b"naome:knowledge:set:v2\0");
        hash.update(compatibility());
        hash.update(count.to_be_bytes());
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn narrow_counts_preserve_the_original_root_frame() {
        for count in [0u32, 4096, u32::MAX] {
            let mut expected = Sha256::new();
            expected.update(b"naome:knowledge:set:v1\0");
            expected.update(compatibility());
            expected.update(count.to_be_bytes());
            assert_eq!(
                start_root_hash(count as usize).unwrap().finalize(),
                expected.finalize()
            );
        }
    }
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn wider_counts_use_a_distinct_frame_without_truncation() {
        let count = u64::from(u32::MAX) + 1;
        let mut expected = Sha256::new();
        expected.update(b"naome:knowledge:set:v2\0");
        expected.update(compatibility());
        expected.update(count.to_be_bytes());
        let actual = start_root_hash(usize::try_from(count).unwrap())
            .unwrap()
            .finalize();
        assert_eq!(actual, expected.finalize());
        assert_ne!(actual, start_root_hash(0).unwrap().finalize());
    }
}
