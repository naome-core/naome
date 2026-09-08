use super::*;
use std::collections::BTreeMap;

fn hex(hash: Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// Independent shape oracle: partition a sorted complete record set, never use
// the path-copy insertion or deletion algorithm under test.
fn rebuilt(map: &Map, records: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
    let mut rows: Vec<_> = records.iter().map(|(k, v)| (map.route(k), k, v)).collect();
    rows.sort_by_key(|r| r.0);
    fn tree(map: &Map, rows: &[(Hash, &Vec<u8>, &Vec<u8>)]) -> Hash {
        if rows.len() == 1 {
            return digest(&[LEAF, &map.tag, &bytes(rows[0].1), &bytes(rows[0].2)]);
        }
        let first = rows.first().unwrap().0;
        let last = rows.last().unwrap().0;
        let bit = (0..256)
            .find(|b| {
                let b = *b as u8;
                side(&first, b) != side(&last, b)
            })
            .unwrap() as u8;
        let middle = rows.partition_point(|r| !side(&r.0, bit));
        let left = tree(map, &rows[..middle]);
        let right = tree(map, &rows[middle..]);
        digest(&[BRANCH, &map.tag, &[bit], &left, &right])
    }
    if rows.is_empty() {
        digest(&[EMPTY, &map.tag])
    } else {
        tree(map, &rows)
    }
}

#[test]
fn independent_python_preimage_vectors_and_namespace_isolation() {
    let mut map = Map::new(BigUint::from(1_u8));
    assert_eq!(
        hex(map.root_hash()),
        "fc32047e7e153547a28f274ce01f903da4d2fb7724eb685c626c437906866eec"
    );
    assert_eq!(
        hex(map.route(b"k")),
        "a85b7d3da01d6efaef0ea3cdd1dddf44ca80d4648959563666e8f4057463c129"
    );
    map.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
    assert_eq!(
        hex(map.root_hash()),
        "7f08c0cdbbdf4026cc3ae5a49758ab89c07df5dd3cfb0a7102128f7654d360fc"
    );
    let mut other = Map::new(BigUint::from(2_u8));
    other.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
    assert_ne!(map.root_hash(), other.root_hash());
    assert_ne!(map.route(b"k"), other.route(b"k"));
    other.root = map.root.clone();
    assert!(!other.validate());
}

#[test]
fn updates_match_independent_rebuild_and_preserve_old_snapshots() {
    let mut map = Map::new(BigUint::from(1_u8));
    let empty = map.root_hash();
    let mut records = BTreeMap::new();
    let mut seed = 17_u64;
    for step in 0..900_u64 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let key = (seed % 129).to_be_bytes().to_vec();
        let old = map.clone();
        let old_records = records.clone();
        if step % 3 == 0 {
            assert_eq!(map.remove(&key).unwrap(), records.remove(&key).is_some());
        } else {
            let value = step.to_be_bytes().to_vec();
            map.insert(key.clone(), value.clone()).unwrap();
            records.insert(key, value);
        }
        assert!(map.validate());
        assert_eq!(map.root_hash(), rebuilt(&map, &records));
        assert_eq!(old.root_hash(), rebuilt(&old, &old_records));
        for (k, v) in &records {
            assert_eq!(map.get(k).unwrap(), Some(v.as_slice()));
        }
    }
    for key in records.keys() {
        assert!(map.remove(key).unwrap());
    }
    assert!(map.validate());
    assert_eq!(map.root_hash(), empty);
    assert!(!map.remove(b"absent").unwrap());
}

#[test]
fn permutations_reinsertion_and_length_boundaries_have_one_root() {
    let entries: Vec<_> = [0, 1, 127, 128, 255, 256]
        .into_iter()
        .map(|n| (vec![0x42; n], vec![0x93; n]))
        .collect();
    let mut expected = None;
    for shift in 0..entries.len() {
        let mut map = Map::new(BigUint::from(256_u16));
        for i in 0..entries.len() {
            let (key, value) = entries[(i + shift) % entries.len()].clone();
            map.insert(key, value).unwrap();
        }
        assert!(map.validate());
        let root = map.root_hash();
        if let Some(e) = expected {
            assert_eq!(root, e)
        } else {
            expected = Some(root)
        }
        for (key, value) in entries.iter().rev() {
            assert!(map.remove(key).unwrap());
            map.insert(key.clone(), value.clone()).unwrap();
            assert_eq!(map.root_hash(), root);
        }
    }
}

#[test]
fn injected_routing_collision_rejects_before_root_mutation() {
    let mut map = Map::new(BigUint::from(1_u8));
    map.insert(b"first".to_vec(), b"value".to_vec()).unwrap();
    let old = map.root.clone().unwrap();
    let result = map.insert_routed(map.route(b"first"), b"second".to_vec(), b"other".to_vec());
    assert_eq!(result, Err(Collision));
    assert!(Arc::ptr_eq(&old, map.root.as_ref().unwrap()));
    assert_eq!(map.get(b"first").unwrap(), Some(b"value".as_slice()));
    assert!(map.validate());
}

#[test]
fn matching_hashes_do_not_admit_noncanonical_memory_trees() {
    let mut map = Map::new(BigUint::from(1_u8));
    for i in 0_u8..8 {
        map.insert(vec![i], vec![i + 1]).unwrap();
    }
    let original = map.root.clone().unwrap();
    let Body::Branch { bit, left, right } = &original.body else {
        panic!()
    };
    let wrong = map.branch(*bit, right.clone(), left.clone());
    map.root = Some(wrong);
    assert!(!map.validate());
    map.root = Some(map.branch(bit.wrapping_add(1), left.clone(), right.clone()));
    assert!(!map.validate());
    map.root = Some(map.branch(*bit, left.clone(), left.clone()));
    assert!(!map.validate());
    let nested = map.branch(*bit, left.clone(), right.clone());
    map.root = Some(map.branch(*bit, nested, right.clone()));
    assert!(!map.validate());
    let empty_child = Arc::new(Node {
        hash: digest(&[EMPTY, &map.tag]),
        body: Body::Leaf {
            route: map.route(b"k"),
            key: b"k".as_slice().into(),
            value: b"v".as_slice().into(),
        },
    });
    map.root = Some(map.branch(*bit, empty_child, right.clone()));
    assert!(!map.validate());
    // A leaf with correct leaf bytes/hash but a dishonest cached routing digest.
    map.root = Some(map.leaf([0; 32], b"k".to_vec(), b"v".to_vec()));
    assert!(!map.validate());
    map.root = Some(original);
    assert!(map.validate());
}

#[test]
fn untouched_leaf_is_shared_across_a_changed_path() {
    let mut map = Map::new(BigUint::from(1_u8));
    map.insert(b"a".to_vec(), b"old".to_vec()).unwrap();
    map.insert(b"b".to_vec(), b"same".to_vec()).unwrap();
    let old = map.clone();
    map.insert(b"a".to_vec(), b"new".to_vec()).unwrap();
    let route = map.route(b"b");
    assert!(Arc::ptr_eq(
        map.terminal(map.root.as_ref().unwrap(), &route),
        old.terminal(old.root.as_ref().unwrap(), &route)
    ));
    assert_eq!(old.get(b"a").unwrap(), Some(b"old".as_slice()));
    assert_eq!(map.get(b"a").unwrap(), Some(b"new".as_slice()));
}
