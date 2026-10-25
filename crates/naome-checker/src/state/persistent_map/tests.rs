use super::{Key256, PersistentMap};

#[derive(Clone, Copy, PartialEq, Eq)]
struct TestKey([u8; 32]);

impl Key256 for TestKey {
    fn as_key_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[test]
fn insertion_permutations_cover_boundary_bits_without_replacement() {
    let mut final_bit = [0; 32];
    final_bit[31] = 0x01;
    let mut middle_bit = [0; 32];
    middle_bit[16] = 0x08;
    let keys = [
        TestKey([0; 32]),
        TestKey([0x80; 32]),
        TestKey({
            let mut bytes = [0; 32];
            bytes[0] = 0x40;
            bytes
        }),
        TestKey(middle_bit),
        TestKey(final_bit),
    ];
    let permutations = [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 4, 0, 3, 1],
        [1, 3, 0, 4, 2],
    ];

    for permutation in permutations {
        let mut map = PersistentMap::new();
        for index in permutation {
            assert!(map.insert(keys[index], index));
        }
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(map.get(key), Some(&index));
        }

        let before_duplicate = map.clone();
        assert!(!map.insert(keys[2], usize::MAX));
        assert!(map.shares_root_with(&before_duplicate));
        assert_eq!(map.get(&keys[2]), Some(&2));
    }
}

#[test]
fn cloned_map_path_copies_only_the_changed_search_path() {
    let mut selected = PersistentMap::new();
    assert!(selected.insert(TestKey([0; 32]), 0));
    assert!(selected.insert(TestKey([0x80; 32]), 1));
    let mut branch = selected.clone();
    assert!(selected.shares_root_with(&branch));

    let mut branch_key = [0; 32];
    branch_key[0] = 0x40;
    assert!(branch.insert(TestKey(branch_key), 2));

    assert!(!selected.shares_root_with(&branch));
    assert!(selected.shares_terminal_for_key_with(&branch, &TestKey([0x80; 32])));
    assert_eq!(selected.get(&TestKey(branch_key)), None);
    assert_eq!(branch.get(&TestKey(branch_key)), Some(&2));
}

#[test]
fn maximum_key_path_round_trips_and_remains_clone_isolated() {
    let zero = TestKey([0; 32]);
    let mut selected = PersistentMap::new();
    assert!(selected.insert(zero, 0));

    for bit in 0..256 {
        let mut bytes = [0; 32];
        bytes[bit / 8] = 1 << (7 - bit % 8);
        assert!(selected.insert(TestKey(bytes), bit + 1));
    }
    assert_eq!(selected.get(&zero), Some(&0));
    for bit in 0..256 {
        let mut bytes = [0; 32];
        bytes[bit / 8] = 1 << (7 - bit % 8);
        assert_eq!(selected.get(&TestKey(bytes)), Some(&(bit + 1)));
    }

    let mut branch = selected.clone();
    let mut branch_key = [0; 32];
    branch_key[31] = 0x03;
    assert!(branch.insert(TestKey(branch_key), usize::MAX));
    assert_eq!(selected.get(&TestKey(branch_key)), None);
    assert_eq!(branch.get(&TestKey(branch_key)), Some(&usize::MAX));
    assert_eq!(selected.get(&zero), Some(&0));
    assert_eq!(branch.get(&zero), Some(&0));
}
