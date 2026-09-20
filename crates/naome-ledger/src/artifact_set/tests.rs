use std::fmt::Write;
use std::sync::Arc;

use super::{
    ArtifactPathStep, ArtifactSetMembership, ArtifactSetProofError, ArtifactSetRoot,
    ArtifactSetValue, AuthenticatedArtifactSet, first_differing_bit, key_bit,
};
use naome_proof::ArtifactId;

impl ArtifactSetValue for ArtifactId {
    fn artifact_id(&self) -> ArtifactId {
        *self
    }
}

fn id(bytes: [u8; 32]) -> ArtifactId {
    ArtifactId::from_bytes(bytes)
}

fn id_with_bit(bit: u8) -> ArtifactId {
    let mut bytes = [0; 32];
    let bit = usize::from(bit);
    bytes[bit / 8] = 1_u8 << (7 - bit % 8);
    id(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn root_for(order: &[ArtifactId]) -> ArtifactSetRoot {
    let mut set = AuthenticatedArtifactSet::new();
    for artifact_id in order {
        assert!(set.insert(*artifact_id).is_some());
    }
    set.root()
}

fn node_for(
    set: &AuthenticatedArtifactSet<ArtifactId>,
    artifact_id: ArtifactId,
) -> &Arc<super::Node<ArtifactId>> {
    let mut node = set.root.as_ref().expect("the test set is not empty");
    loop {
        match node.as_ref() {
            super::Node::Branch(branch) => {
                node = if key_bit(artifact_id, branch.bit) {
                    &branch.right
                } else {
                    &branch.left
                };
            }
            super::Node::Leaf(value) => {
                assert_eq!(*value, artifact_id);
                return node;
            }
        }
    }
}

fn reference_root(keys: &[ArtifactId]) -> ArtifactSetRoot {
    let mut keys = keys.to_vec();
    keys.sort_unstable();
    keys.dedup();
    reference_subtree(&keys)
}

fn reference_subtree(keys: &[ArtifactId]) -> ArtifactSetRoot {
    match keys {
        [] => ArtifactSetRoot::empty(),
        [key] => ArtifactSetRoot(super::leaf_digest(*key)),
        _ => {
            let bit = first_differing_bit(keys[0], keys[keys.len() - 1]);
            let split = keys.partition_point(|key| !key_bit(*key, bit));
            ArtifactSetRoot(super::branch_digest(
                bit,
                reference_subtree(&keys[..split]).0,
                reference_subtree(&keys[split..]).0,
            ))
        }
    }
}

fn permutations(values: &mut [ArtifactId], start: usize, roots: &mut Vec<ArtifactSetRoot>) {
    if start == values.len() {
        roots.push(root_for(values));
        return;
    }
    for index in start..values.len() {
        values.swap(start, index);
        permutations(values, start + 1, roots);
        values.swap(start, index);
    }
}

#[test]
fn empty_leaf_and_branch_roots_have_stable_goldens() {
    let zero = id([0; 32]);
    let mut high = [0; 32];
    high[0] = 0x80;
    let mut low = [0; 32];
    low[31] = 0x01;

    assert_eq!(
        hex(root_for(&[]).as_bytes()),
        "976e576ec6145d57b5e192d1c37a0938bb5c76663532d0354fcd98ba3fbf597a"
    );
    assert_eq!(
        ArtifactSetRoot::empty().as_bytes(),
        &super::tagged_digest(0x00, &[])
    );
    assert_eq!(
        hex(root_for(&[zero]).as_bytes()),
        "f8d94326ff427a5311fd43c28524588f5fa955cb1b1be096a34b1b724c103963"
    );
    assert_eq!(
        hex(root_for(&[zero, id(high)]).as_bytes()),
        "f89fb7c7336af38296e54143f3111c23dc352f8795ed76742549767ea42880a5"
    );
    assert_eq!(
        hex(root_for(&[zero, id(high), id(low)]).as_bytes()),
        "c8ecb7085200b45d99f505bd00fa791d0fdd2bbfc3d65014b89aa9491095d768"
    );
}

#[test]
fn every_insertion_order_matches_an_independent_canonical_root() {
    let mut values = [id([0; 32]), id([0x55; 32]), id([0xaa; 32]), id([0xff; 32])];
    let expected = reference_root(&values);
    let mut roots = Vec::new();
    permutations(&mut values, 0, &mut roots);

    assert_eq!(roots.len(), 24);
    assert!(roots.into_iter().all(|root| root == expected));
}

#[test]
fn long_shared_prefixes_store_only_one_branch() {
    let zero = id([0; 32]);
    let mut last_bit = [0; 32];
    last_bit[31] = 1;
    let mut set = AuthenticatedArtifactSet::new();

    let _ = set.insert(zero).unwrap();
    let _ = set.insert(id(last_bit)).unwrap();

    assert_eq!(set.len(), 2);
    assert_eq!(set.proof(zero).sibling_count(), 1);
    assert_eq!(set.root(), reference_root(&[zero, id(last_bit)]));
}

#[test]
fn clones_share_unchanged_nodes_and_keep_independent_roots() {
    let zero = id([0; 32]);
    let high = id_with_bit(0);
    let quarter = id_with_bit(1);
    let mut selected = AuthenticatedArtifactSet::new();
    let _ = selected.insert(zero).unwrap();
    let _ = selected.insert(high).unwrap();
    let snapshot = selected.clone();
    let snapshot_root = snapshot.root();
    let snapshot_proof = snapshot.proof(high).to_canonical_bytes();

    assert!(Arc::ptr_eq(
        selected.root.as_ref().unwrap(),
        snapshot.root.as_ref().unwrap()
    ));

    let _ = selected.insert(quarter).unwrap();

    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.root(), snapshot_root);
    assert_eq!(snapshot.proof(high).to_canonical_bytes(), snapshot_proof);
    assert_eq!(selected.len(), 3);
    assert_ne!(selected.root(), snapshot_root);
    assert!(!Arc::ptr_eq(
        selected.root.as_ref().unwrap(),
        snapshot.root.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        node_for(&selected, high),
        node_for(&snapshot, high)
    ));
}

#[test]
fn membership_and_nonmembership_proofs_verify_exclusively() {
    let members = [id([0x11; 32]), id([0x77; 32]), id([0xee; 32])];
    let absent = id([0x55; 32]);
    let mut set = AuthenticatedArtifactSet::new();
    for member in members {
        let _ = set.insert(member).unwrap();
    }
    let root = set.root();

    for member in members {
        assert_eq!(
            set.proof(member).verify(root, member),
            Ok(ArtifactSetMembership::Present)
        );
    }
    assert_eq!(
        set.proof(absent).verify(root, absent),
        Ok(ArtifactSetMembership::Absent)
    );
    assert_eq!(
        AuthenticatedArtifactSet::<ArtifactId>::new()
            .proof(absent)
            .verify(ArtifactSetRoot::empty(), absent),
        Ok(ArtifactSetMembership::Absent)
    );
}

#[test]
fn duplicate_insertions_do_not_change_structure_or_root() {
    let artifact_id = id([0x44; 32]);
    let mut set = AuthenticatedArtifactSet::new();
    let _ = set.insert(artifact_id).unwrap();
    let root = set.root();

    assert!(set.insert(artifact_id).is_none());
    assert_eq!(set.len(), 1);
    assert_eq!(set.proof(artifact_id).sibling_count(), 0);
    assert_eq!(set.root(), root);
}

#[test]
fn projected_root_matches_insertion_without_mutating_the_selected_set() {
    let selected = [id([0x10; 32]), id([0x80; 32]), id([0xf0; 32])];
    let additions = [
        id([0x00; 32]),
        id([0x20; 32]),
        id([0x40; 32]),
        id([0x60; 32]),
        id([0xa0; 32]),
        id([0xc0; 32]),
        id([0xe0; 32]),
        id([0xff; 32]),
    ];
    let mut set = AuthenticatedArtifactSet::new();
    for artifact_id in selected {
        let _ = set.insert(artifact_id).unwrap();
    }
    let selected_root = set.root();
    let selected_len = set.len();

    for artifact_id in additions {
        let (projected, existing) = set.projected_root(artifact_id);
        assert!(!existing);
        assert_eq!(set.root(), selected_root);
        assert_eq!(set.len(), selected_len);

        let mut expected = AuthenticatedArtifactSet::new();
        for selected in selected {
            let _ = expected.insert(selected).unwrap();
        }
        let _ = expected.insert(artifact_id).unwrap();
        assert_eq!(projected, expected.root());
    }
}

#[test]
fn scalar_projection_matches_deep_reference_paths() {
    let corpus = [
        id([0; 32]),
        id_with_bit(0),
        id_with_bit(1),
        id_with_bit(7),
        id_with_bit(8),
        id_with_bit(127),
        id_with_bit(254),
        id_with_bit(255),
    ];
    let mut selected = AuthenticatedArtifactSet::new();
    for artifact_id in &corpus[..corpus.len() - 1] {
        let _ = selected.insert(*artifact_id).unwrap();
    }
    let before = selected.root();
    let addition = *corpus.last().unwrap();
    let (projected, existing) = selected.projected_root(addition);
    assert!(!existing);
    assert_eq!(projected, reference_root(&corpus));
    assert_eq!(selected.root(), before);
}

#[test]
fn empty_and_singleton_projections_match_real_insertion_without_mutation() {
    let artifact_id = id([0x5a; 32]);
    let empty = AuthenticatedArtifactSet::<ArtifactId>::new();
    let empty_root = empty.root();
    let (singleton_root, existing) = empty.projected_root(artifact_id);
    assert!(!existing);
    assert_eq!(singleton_root, reference_root(&[artifact_id]));
    assert_eq!(empty.root(), empty_root);
    assert!(empty.is_empty());

    let mut applied = AuthenticatedArtifactSet::new();
    let _ = applied.insert(artifact_id).unwrap();
    assert_eq!(applied.root(), singleton_root);

    let mut selected = AuthenticatedArtifactSet::new();
    let _ = selected.insert(artifact_id).unwrap();
    assert_eq!(
        selected.projected_root(artifact_id),
        (selected.root(), true)
    );
}

#[test]
fn malformed_or_mutated_proofs_fail_closed() {
    let members = [id([0x10; 32]), id([0x40; 32]), id([0xf0; 32])];
    let query = id([0x20; 32]);
    let mut set = AuthenticatedArtifactSet::new();
    for member in members {
        let _ = set.insert(member).unwrap();
    }
    let root = set.root();
    let proof = set.proof(query);

    let mut changed_sibling = proof.clone();
    changed_sibling.path[0].sibling[0] ^= 1;
    assert!(matches!(
        changed_sibling.verify(root, query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    let mut changed_bit = proof.clone();
    changed_bit.path[0].bit = changed_bit.path[1].bit;
    assert!(matches!(
        changed_bit.verify(root, query),
        Err(ArtifactSetProofError::NonIncreasingBits { .. })
    ));

    let mut empty_sibling = proof.clone();
    empty_sibling.path[0].sibling = *ArtifactSetRoot::empty().as_bytes();
    assert!(matches!(
        empty_sibling.verify(root, query),
        Err(ArtifactSetProofError::EmptySibling { .. })
    ));

    let mut wrong_terminal = proof.clone();
    wrong_terminal.terminal = super::ArtifactTerminal::NonMember(id([0xa0; 32]));
    assert!(matches!(
        wrong_terminal.verify(root, query),
        Err(ArtifactSetProofError::TerminalPathMismatch { .. })
    ));

    let mut too_long = proof;
    too_long.path = vec![
        ArtifactPathStep {
            sibling: [0x55; 32],
            bit: 0,
        };
        257
    ]
    .into_boxed_slice();
    assert_eq!(
        too_long.verify(root, query),
        Err(ArtifactSetProofError::PathTooLong)
    );

    let mut wrong_root = *root.as_bytes();
    wrong_root[0] ^= 1;
    assert!(matches!(
        set.proof(query)
            .verify(ArtifactSetRoot::from_bytes(wrong_root), query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));
}
