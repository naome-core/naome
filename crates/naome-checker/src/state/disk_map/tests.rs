use super::*;
use crate::state::persistent_map::{Key256, PersistentMap};
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
struct MemoryStorage {
    bytes: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
    writes_until_failure: Mutex<Option<usize>>,
    failures: Mutex<Vec<ContextError>>,
}

impl ContextStorage for MemoryStorage {
    fn record_failure(&self, error: &ContextError) {
        self.failures.lock().unwrap().push(error.clone());
    }
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let value = self
            .bytes
            .lock()
            .unwrap()
            .get(&address)
            .cloned()
            .ok_or_else(|| ContextError::Storage("missing node".into()))?;
        if value.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(value)
    }

    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let mut budget = self.writes_until_failure.lock().unwrap();
        if let Some(remaining) = budget.as_mut() {
            if *remaining == 0 {
                return Err(ContextError::Storage("injected write failure".into()));
            }
            *remaining -= 1;
        }
        let mut stored = self.bytes.lock().unwrap();
        if let Some(existing) = stored.get(&address) {
            if existing != bytes {
                return Err(ContextError::Corrupt);
            }
        } else {
            stored.insert(address, bytes.to_vec());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TestKey([u8; 32]);

impl Key256 for TestKey {
    fn as_key_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn bit_key(bit: usize) -> [u8; 32] {
    let mut key = [0; 32];
    key[bit / 8] = 1 << (7 - bit % 8);
    key
}

fn restored_node(storage: Arc<MemoryStorage>, node: Node) -> DiskMap {
    let bytes = node.encode();
    let root = Root {
        address: storage_address(&bytes),
        fingerprint: node.fingerprint(),
    };
    storage.bytes.lock().unwrap().insert(root.address, bytes);
    DiskMap::from_root(storage, Some(root))
}

#[test]
fn insertion_orders_match_memory_fingerprints_and_sorted_entries() {
    let keys = [[0; 32], bit_key(0), bit_key(1), bit_key(132), bit_key(255)];
    let mut expected_fingerprint = None;
    for order in [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 4, 0, 3, 1],
        [1, 3, 0, 4, 2],
    ] {
        let storage = Arc::new(MemoryStorage::default());
        let mut disk = DiskMap::new(storage);
        let mut memory = PersistentMap::new();
        for index in order {
            let value = [index as u8];
            assert!(disk.insert(keys[index], &value).unwrap());
            assert!(memory.insert(TestKey(keys[index]), value.to_vec()));
            assert_eq!(disk.fingerprint(), memory.fingerprint());
        }
        let before = disk.root();
        assert!(!disk.insert(keys[2], &[255]).unwrap());
        assert_eq!(disk.root(), before);
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(disk.get(key).unwrap(), Some(vec![index as u8]));
            assert!(disk.contains_key(key).unwrap());
        }
        let entries: Vec<_> = disk.entries().collect::<Result<_, _>>().unwrap();
        let mut expected: Vec<_> = keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, vec![index as u8]))
            .collect();
        expected.sort();
        assert_eq!(entries, expected);
        if let Some(fingerprint) = expected_fingerprint {
            assert_eq!(disk.fingerprint(), fingerprint);
        } else {
            expected_fingerprint = Some(disk.fingerprint());
        }
    }
}

#[test]
fn value_replacement_changes_storage_address_not_key_fingerprint_or_old_handles() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage);
    map.insert([0; 32], b"old").unwrap();
    map.insert(bit_key(0), b"other").unwrap();
    let old = map.clone();
    map.set([0; 32], b"new").unwrap();
    assert_eq!(old.fingerprint(), map.fingerprint());
    assert_ne!(old.root(), map.root());
    assert_eq!(old.get(&[0; 32]).unwrap(), Some(b"old".to_vec()));
    assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"new".to_vec()));
    let reopened = DiskMap::from_root(map.storage(), map.root());
    assert_eq!(
        reopened.entries().collect::<Result<Vec<_>, _>>().unwrap(),
        map.entries().collect::<Result<Vec<_>, _>>().unwrap()
    );
    let same = map.root();
    map.set([0; 32], b"new").unwrap();
    assert_eq!(map.root(), same);
}

#[test]
fn full_256_branch_path_is_bounded_and_retains_clone_isolation() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage);
    let mut memory = PersistentMap::new();
    map.insert([0; 32], b"zero").unwrap();
    memory.insert(TestKey([0; 32]), ());
    for bit in 0..256 {
        map.insert(bit_key(bit), &[bit as u8]).unwrap();
        memory.insert(TestKey(bit_key(bit)), ());
    }
    assert_eq!(map.fingerprint(), memory.fingerprint());
    assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"zero".to_vec()));
    assert_eq!(
        map.entries().collect::<Result<Vec<_>, _>>().unwrap().len(),
        257
    );
    let target = Arc::new(MemoryStorage::default());
    let mut walk = map.walk();
    let mut visited = 0;
    let mut leaves = 0;
    while let Some(visit) = walk.step().unwrap() {
        visited += 1;
        leaves += if visit.entry.is_some() { 1 } else { 0 };
        assert!(visit.bytes.len() <= MAX_NODE_BYTES);
        assert!(
            walk.pending.len() <= 257,
            "DFS memory follows depth, not corpus size"
        );
        target.write(visit.address, &visit.bytes).unwrap();
    }
    assert!(walk.complete());
    assert_eq!(
        (visited, leaves),
        (513, 257),
        "branches consume separate steps"
    );
    assert_eq!(target.bytes.lock().unwrap().len(), 513);
    assert_eq!(
        DiskMap::from_root(target, map.root())
            .get(&[0; 32])
            .unwrap(),
        Some(b"zero".to_vec())
    );
    let old = map.clone();
    let mut new_key = [0; 32];
    new_key[31] = 3;
    map.set(new_key, b"extra").unwrap();
    assert_eq!(old.get(&new_key).unwrap(), None);
    assert_eq!(map.get(&new_key).unwrap(), Some(b"extra".to_vec()));
}

#[test]
fn failed_path_write_does_not_publish_partial_root() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage.clone());
    map.insert([0; 32], b"zero").unwrap();
    map.insert(bit_key(0), b"one").unwrap();
    let before = map.root();
    *storage.writes_until_failure.lock().unwrap() = Some(1);
    assert!(matches!(
        map.set([0; 32], b"changed"),
        Err(ContextError::Storage(_))
    ));
    assert_eq!(map.root(), before);
    assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"zero".to_vec()));
    *storage.writes_until_failure.lock().unwrap() = None;
    map.set([0; 32], b"changed").unwrap();
    assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"changed".to_vec()));
}

#[test]
fn cold_tamper_and_missing_nodes_are_errors_even_for_absent_queries() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage.clone());
    map.insert([0; 32], b"value").unwrap();
    let leaf = map.root().unwrap();
    let original = storage
        .bytes
        .lock()
        .unwrap()
        .get(&leaf.address)
        .unwrap()
        .clone();
    storage
        .bytes
        .lock()
        .unwrap()
        .get_mut(&leaf.address)
        .unwrap()[36] ^= 1;
    assert_eq!(map.get(&[0; 32]), Err(ContextError::Corrupt));
    assert_eq!(
        storage.failures.lock().unwrap().last(),
        Some(&ContextError::Corrupt)
    );
    assert_eq!(map.get(&bit_key(0)), Err(ContextError::Corrupt));
    storage.bytes.lock().unwrap().insert(leaf.address, original);
    map.insert(bit_key(0), b"right").unwrap();
    storage.bytes.lock().unwrap().remove(&leaf.address);
    assert!(matches!(
        map.get(&bit_key(1)),
        Err(ContextError::Storage(_))
    ));
    assert!(matches!(
        map.entries().next(),
        Some(Err(ContextError::Storage(_)))
    ));
}

#[test]
fn iterator_cannot_hide_a_failed_cold_sibling_as_completion() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage.clone());
    map.insert(bit_key(0), b"right").unwrap();
    let right_leaf = map.root().unwrap();
    map.insert([0; 32], b"left").unwrap();
    storage.bytes.lock().unwrap().remove(&right_leaf.address);
    let mut entries = map.entries();
    assert_eq!(entries.next(), Some(Ok(([0; 32], b"left".to_vec()))));
    assert!(matches!(
        entries.next(),
        Some(Err(ContextError::Storage(_)))
    ));
    assert_eq!(entries.next(), None);
    let mut walk = map.walk();
    assert!(walk.step().is_ok()); // root branch
    assert!(walk.step().is_ok()); // left leaf
    assert!(walk.step().is_err());
    assert!(!walk.complete(), "a failed cursor cannot look exhausted");
    assert!(walk.step().is_err());
}

#[test]
fn authenticated_malformed_metadata_and_branch_order_are_rejected() {
    let storage = Arc::new(MemoryStorage::default());
    let map = DiskMap::new(storage.clone());
    let left = map
        .save_node(Node::Leaf {
            key: [0; 32],
            value: vec![],
        })
        .unwrap();
    let right = map
        .save_node(Node::Leaf {
            key: bit_key(0),
            value: vec![],
        })
        .unwrap();
    let invalid_split = restored_node(
        storage.clone(),
        Node::Branch {
            bit: 1,
            left,
            right,
        },
    );
    assert_eq!(invalid_split.get(&[0; 32]), Err(ContextError::Corrupt));
    let mut invalid_fingerprint = left;
    invalid_fingerprint.root.fingerprint[0] ^= 1;
    let bad_child = restored_node(
        storage.clone(),
        Node::Branch {
            bit: 0,
            left: invalid_fingerprint,
            right,
        },
    );
    assert_eq!(bad_child.get(&[0; 32]), Err(ContextError::Corrupt));
    let mut invalid_range = left;
    invalid_range.range.maximum = bit_key(1);
    let bad_range = restored_node(
        storage.clone(),
        Node::Branch {
            bit: 0,
            left: invalid_range,
            right,
        },
    );
    assert_eq!(bad_range.get(&[0; 32]), Err(ContextError::Corrupt));
    let reversed = restored_node(
        storage,
        Node::Branch {
            bit: 0,
            left: right,
            right: left,
        },
    );
    assert_eq!(reversed.entries().next(), Some(Err(ContextError::Corrupt)));
}

#[test]
fn strict_node_codec_and_value_limit_preserve_existing_root() {
    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage.clone());
    assert_eq!(map.fingerprint(), [0; 32]);
    assert_eq!(map.entries().next(), None);
    map.insert([0; 32], &vec![7; MAX_VALUE_BYTES]).unwrap();
    let before = map.root();
    assert_eq!(
        map.set([0; 32], &vec![8; MAX_VALUE_BYTES + 1]),
        Err(ContextError::Limit)
    );
    assert_eq!(map.root(), before);
    let original = Node::Leaf {
        key: [0; 32],
        value: vec![1],
    }
    .encode();
    let mut bad_version = original.clone();
    bad_version[0] = 2;
    let mut bad_type = original.clone();
    bad_type[1] = 2;
    let mut trailing = original.clone();
    trailing.push(0);
    let truncated = original[..original.len() - 1].to_vec();
    for bytes in [bad_version, bad_type, trailing, truncated] {
        let root = Root {
            address: storage_address(&bytes),
            fingerprint: before.unwrap().fingerprint,
        };
        storage.bytes.lock().unwrap().insert(root.address, bytes);
        assert_eq!(
            DiskMap::from_root(storage.clone(), Some(root)).get(&[0; 32]),
            Err(ContextError::Corrupt)
        );
    }
}
#[test]
fn cursor_seeks_authenticated_ranges_and_copy_retains_every_reachable_node() {
    let source = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(source.clone());
    let first = [1; 32];
    let middle = [64; 32];
    let last = [192; 32];
    map.insert(first, b"first").unwrap();
    let first_address = map.root().unwrap().address;
    map.insert(middle, b"middle").unwrap();
    map.insert(last, b"last").unwrap();
    let target = Arc::new(MemoryStorage::default());
    let mut walk = map.walk();
    while let Some(visit) = walk.step().unwrap() {
        target.write(visit.address, &visit.bytes).unwrap();
    }
    let copied = DiskMap::from_root(target, map.root());
    assert_eq!(copied.root(), map.root());
    assert_eq!(
        copied.entries().collect::<Result<Vec<_>, _>>().unwrap(),
        map.entries().collect::<Result<Vec<_>, _>>().unwrap()
    );
    source.bytes.lock().unwrap().remove(&first_address);
    assert_eq!(
        map.entries_after(Some(middle))
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![(last, b"last".to_vec())]
    );
    assert!(map.get(&first).is_err());
    let mut walk = map.walk();
    let error = loop {
        match walk.step() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("missing reachable node was accepted"),
            Err(error) => break error,
        }
    };
    assert_eq!(error, ContextError::Corrupt);
    assert!(!walk.complete());
    assert_eq!(copied.get(&first).unwrap(), Some(b"first".to_vec()));
}
