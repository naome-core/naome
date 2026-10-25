use super::*;
use crate::state::persistent_map::PersistentMap;
#[test]
fn streamed_sorted_keys_match_every_patricia_prefix_with_bounded_state() {
    let mut keys = vec![[0; 32], [255; 32]];
    for bit in 0..256 {
        let mut key = [0; 32];
        key[bit / 8] = 1 << (7 - bit % 8);
        keys.push(key);
    }
    for value in 0u64..1024 {
        keys.push(Sha256::digest(value.to_be_bytes()).into());
    }
    keys.sort();
    keys.dedup();
    let mut stream = ProofSetFingerprint::default();
    let mut memory = PersistentMap::new();
    assert_eq!(stream.clone().finish(), memory.fingerprint());
    for key in keys {
        let id = ProofId::from_bytes(key);
        stream.push(id).unwrap();
        memory.insert(id, ());
        assert_eq!(stream.clone().finish(), memory.fingerprint());
        assert!(stream.pending.len() <= 256);
    }
    assert!(stream.push(ProofId::from_bytes([255; 32])).is_err());
    assert!(stream.push(ProofId::from_bytes([0; 32])).is_err());
}
