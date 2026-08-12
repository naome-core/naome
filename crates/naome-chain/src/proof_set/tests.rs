use std::fmt::Write;

use super::{
    AuthenticatedProofSet, ProofPathStep, ProofSetMembership, ProofSetProofError, ProofSetRoot,
    ProofSetValue, first_differing_bit, key_bit,
};
use naome_proof::ProofId;

impl ProofSetValue for ProofId {
    fn proof_id(&self) -> ProofId {
        *self
    }
}

fn id(bytes: [u8; 32]) -> ProofId {
    ProofId::from_bytes(bytes)
}

fn id_with_bit(bit: u8) -> ProofId {
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

fn root_for(order: &[ProofId]) -> ProofSetRoot {
    let mut set = AuthenticatedProofSet::new();
    for proof_id in order {
        assert!(set.insert(*proof_id).is_some());
    }
    set.root()
}

fn reference_root(keys: &[ProofId]) -> ProofSetRoot {
    let mut keys = keys.to_vec();
    keys.sort_unstable();
    keys.dedup();
    reference_subtree(&keys)
}

fn reference_subtree(keys: &[ProofId]) -> ProofSetRoot {
    match keys {
        [] => ProofSetRoot::empty(),
        [key] => ProofSetRoot(super::leaf_digest(*key)),
        _ => {
            let bit = first_differing_bit(keys[0], keys[keys.len() - 1]);
            let split = keys.partition_point(|key| !key_bit(*key, bit));
            ProofSetRoot(super::branch_digest(
                bit,
                reference_subtree(&keys[..split]).0,
                reference_subtree(&keys[split..]).0,
            ))
        }
    }
}

fn permutations(values: &mut [ProofId], start: usize, roots: &mut Vec<ProofSetRoot>) {
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
        "e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca"
    );
    assert_eq!(
        ProofSetRoot::empty().as_bytes(),
        &super::tagged_digest(0x00, &[])
    );
    assert_eq!(
        hex(root_for(&[zero]).as_bytes()),
        "6035299a52844d846d83ca0395e1a7df37e62b7de9adc638ea2cbaf97d799a04"
    );
    assert_eq!(
        hex(root_for(&[zero, id(high)]).as_bytes()),
        "4c77fb731087d077c434cc706d41eea1fc9aa9b324638f709747b492cbb52687"
    );
    assert_eq!(
        hex(root_for(&[zero, id(high), id(low)]).as_bytes()),
        "00d65391369a613d7a56aca448277a0da7cc44e57a12a8b2159f0b1c5712c396"
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
    let mut set = AuthenticatedProofSet::new();

    let _ = set.insert(zero).unwrap();
    let _ = set.insert(id(last_bit)).unwrap();

    assert_eq!(set.leaves.len(), 2);
    assert_eq!(set.branches.len(), 1);
    assert_eq!(set.branches[0].bit, 255);
    assert_eq!(set.root(), reference_root(&[zero, id(last_bit)]));
}

#[test]
fn membership_and_nonmembership_proofs_verify_exclusively() {
    let members = [id([0x11; 32]), id([0x77; 32]), id([0xee; 32])];
    let absent = id([0x55; 32]);
    let mut set = AuthenticatedProofSet::new();
    for member in members {
        let _ = set.insert(member).unwrap();
    }
    let root = set.root();

    for member in members {
        assert_eq!(
            set.proof(member).verify(root, member),
            Ok(ProofSetMembership::Present)
        );
    }
    assert_eq!(
        set.proof(absent).verify(root, absent),
        Ok(ProofSetMembership::Absent)
    );
    assert_eq!(
        AuthenticatedProofSet::<ProofId>::new()
            .proof(absent)
            .verify(ProofSetRoot::empty(), absent),
        Ok(ProofSetMembership::Absent)
    );
}

#[test]
fn duplicate_insertions_do_not_change_structure_or_root() {
    let proof_id = id([0x44; 32]);
    let mut set = AuthenticatedProofSet::new();
    let _ = set.insert(proof_id).unwrap();
    let root = set.root();

    assert!(set.insert(proof_id).is_none());
    assert_eq!(set.len(), 1);
    assert_eq!(set.branches.len(), 0);
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
    let mut set = AuthenticatedProofSet::new();
    for proof_id in selected {
        let _ = set.insert(proof_id).unwrap();
    }
    let selected_root = set.root();
    let selected_len = set.len();
    let selected_branches = set.branches.len();

    let (projected, existing) = set.projected_root(&additions);
    assert_eq!(existing, None);
    let mut combined = selected.to_vec();
    combined.extend_from_slice(&additions);
    assert_eq!(projected, reference_root(&combined));
    assert_eq!(set.root(), selected_root);
    assert_eq!(set.len(), selected_len);
    assert_eq!(set.branches.len(), selected_branches);

    for proof_id in additions {
        let _ = set.insert(proof_id).unwrap();
    }
    assert_eq!(set.root(), projected);
}

#[test]
fn projected_root_is_independent_of_candidate_order() {
    let selected = [id([0x11; 32]), id([0x77; 32]), id([0xee; 32])];
    let mut set = AuthenticatedProofSet::new();
    for proof_id in selected {
        let _ = set.insert(proof_id).unwrap();
    }
    let mut additions = [
        id([0x22; 32]),
        id([0x55; 32]),
        id([0xaa; 32]),
        id([0xdd; 32]),
    ];
    let mut projected = Vec::new();

    fn project_permutations(
        set: &AuthenticatedProofSet<ProofId>,
        values: &mut [ProofId],
        start: usize,
        roots: &mut Vec<ProofSetRoot>,
    ) {
        if start == values.len() {
            let (root, existing) = set.projected_root(values);
            assert_eq!(existing, None);
            roots.push(root);
            return;
        }
        for index in start..values.len() {
            values.swap(start, index);
            project_permutations(set, values, start + 1, roots);
            values.swap(start, index);
        }
    }

    project_permutations(&set, &mut additions, 0, &mut projected);
    let mut combined = selected.to_vec();
    combined.extend_from_slice(&additions);
    let expected = reference_root(&combined);
    assert_eq!(projected.len(), 24);
    assert!(projected.into_iter().all(|root| root == expected));
}

#[test]
fn projection_matches_deep_reference_paths_across_partitions_and_orders() {
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
    let expected_root = reference_root(&corpus);

    for base_mask in 0..(1_u16 << corpus.len()) {
        let mut base = Vec::new();
        let mut additions = Vec::new();
        for (index, proof_id) in corpus.iter().copied().enumerate() {
            if base_mask & (1_u16 << index) == 0 {
                additions.push(proof_id);
            } else {
                base.push(proof_id);
            }
        }

        for reverse_base in [false, true] {
            if reverse_base {
                base.reverse();
            }
            let mut selected = AuthenticatedProofSet::new();
            for proof_id in &base {
                let _ = selected.insert(*proof_id).unwrap();
            }
            let base_root = selected.root();
            let base_leaves = selected.leaves.len();
            let base_branches = selected.branches.len();

            for order in 0..3 {
                let mut ordered = additions.clone();
                if order == 1 {
                    ordered.reverse();
                } else if order == 2 && !ordered.is_empty() {
                    let rotation = usize::from(base_mask) % ordered.len();
                    ordered.rotate_left(rotation);
                }

                let (projected_root, existing) = selected.projected_root(&ordered);
                assert_eq!(existing, None, "base mask {base_mask:#010b}, order {order}");
                assert_eq!(
                    projected_root, expected_root,
                    "base mask {base_mask:#010b}, order {order}"
                );
                assert_eq!(selected.root(), base_root);
                assert_eq!(selected.leaves.len(), base_leaves);
                assert_eq!(selected.branches.len(), base_branches);

                let mut applied = AuthenticatedProofSet::new();
                for proof_id in &base {
                    let _ = applied.insert(*proof_id).unwrap();
                }
                for proof_id in &ordered {
                    let _ = applied.insert(*proof_id).unwrap();
                }
                assert_eq!(applied.root(), projected_root);
            }

            if reverse_base {
                base.reverse();
            }
        }
    }
}

#[test]
fn projected_root_reports_the_first_existing_or_repeated_candidate() {
    let existing = id([0x44; 32]);
    let first = id([0x11; 32]);
    let repeated = id([0x99; 32]);
    let mut set = AuthenticatedProofSet::new();
    let _ = set.insert(existing).unwrap();
    let selected_root = set.root();

    let (projected_existing, first_existing) = set.projected_root(&[first, existing, repeated]);
    assert_eq!(first_existing, Some((1, existing)));
    assert_eq!(
        projected_existing,
        reference_root(&[existing, first, repeated])
    );

    let (projected_repeated, first_existing) =
        set.projected_root(&[first, repeated, repeated, existing]);
    assert_eq!(first_existing, Some((2, repeated)));
    assert_eq!(
        projected_repeated,
        reference_root(&[existing, first, repeated])
    );
    assert_eq!(set.root(), selected_root);
    assert_eq!(set.len(), 1);
    assert_eq!(set.branches.len(), 0);
}

#[test]
fn empty_and_singleton_projections_match_real_insertion_without_mutation() {
    let proof_id = id([0x5a; 32]);
    let empty = AuthenticatedProofSet::<ProofId>::new();
    assert_eq!(empty.projected_root(&[]), (empty.root(), None));
    let empty_root = empty.root();
    let (singleton_root, existing) = empty.projected_root(&[proof_id]);
    assert_eq!(existing, None);
    assert_eq!(singleton_root, reference_root(&[proof_id]));
    assert_eq!(empty.root(), empty_root);
    assert!(empty.is_empty());

    let mut applied = AuthenticatedProofSet::new();
    let _ = applied.insert(proof_id).unwrap();
    assert_eq!(applied.root(), singleton_root);

    let mut selected = AuthenticatedProofSet::new();
    let _ = selected.insert(proof_id).unwrap();
    assert_eq!(selected.projected_root(&[]), (selected.root(), None));
}

#[test]
fn malformed_or_mutated_proofs_fail_closed() {
    let members = [id([0x10; 32]), id([0x40; 32]), id([0xf0; 32])];
    let query = id([0x20; 32]);
    let mut set = AuthenticatedProofSet::new();
    for member in members {
        let _ = set.insert(member).unwrap();
    }
    let root = set.root();
    let proof = set.proof(query);

    let mut changed_sibling = proof.clone();
    changed_sibling.path[0].sibling[0] ^= 1;
    assert!(matches!(
        changed_sibling.verify(root, query),
        Err(ProofSetProofError::RootMismatch { .. })
    ));

    let mut changed_bit = proof.clone();
    changed_bit.path[0].bit = changed_bit.path[1].bit;
    assert!(matches!(
        changed_bit.verify(root, query),
        Err(ProofSetProofError::NonIncreasingBits { .. })
    ));

    let mut empty_sibling = proof.clone();
    empty_sibling.path[0].sibling = *ProofSetRoot::empty().as_bytes();
    assert!(matches!(
        empty_sibling.verify(root, query),
        Err(ProofSetProofError::EmptySibling { .. })
    ));

    let mut wrong_terminal = proof.clone();
    wrong_terminal.terminal = super::ProofTerminal::NonMember(id([0xa0; 32]));
    assert!(matches!(
        wrong_terminal.verify(root, query),
        Err(ProofSetProofError::TerminalPathMismatch { .. })
    ));

    let mut too_long = proof;
    too_long.path = vec![
        ProofPathStep {
            sibling: [0x55; 32],
            bit: 0,
        };
        257
    ]
    .into_boxed_slice();
    assert_eq!(
        too_long.verify(root, query),
        Err(ProofSetProofError::PathTooLong)
    );

    let mut wrong_root = *root.as_bytes();
    wrong_root[0] ^= 1;
    assert!(matches!(
        set.proof(query)
            .verify(ProofSetRoot::from_bytes(wrong_root), query),
        Err(ProofSetProofError::RootMismatch { .. })
    ));
}
