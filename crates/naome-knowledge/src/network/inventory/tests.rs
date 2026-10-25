use super::*;

fn add(graph: &mut Graph, depth: usize) -> ProofId {
    let mut goal = "eq(x0,x0)".to_owned();
    for v in (0..depth).rev() {
        goal = format!("all(x{v},{goal})");
    }
    let mut source = format!("goal={goal} proof: p0=refl(x0)");
    for (step, v) in (0..depth).rev().enumerate() {
        source.push_str(&format!(" p{}=gen(p{step},x{v})", step + 1));
    }
    source.push_str(&format!(" return p{depth}"));
    let (_, result) = graph.produce(&source).unwrap();
    assert_eq!(result.status, "accepted");
    result.id
}

#[test]
fn inventory_reaches_the_original_tail_while_every_page_adds_new_proofs() {
    let mut graph = Graph::default();
    let original: Vec<_> = (1..=9).map(|depth| add(&mut graph, depth)).collect();
    let initial = graph.content_root();
    let mut after = None;
    let mut observed = Vec::new();
    for depth in 10..=14 {
        let Body::InventoryResult {
            snapshot,
            ids,
            next,
        } = response(&graph, None, after, 2).unwrap()
        else {
            panic!("inventory page");
        };
        assert_eq!(snapshot.root, initial);
        assert_eq!(snapshot.count, 9);
        observed.extend(ids.into_iter().map(ProofId::from_bytes));
        let _ = add(&mut graph, depth);
        if next.is_none() {
            break;
        }
        after = next;
    }
    assert_eq!(
        observed, original,
        "the captured tail must not restart or include later admissions"
    );
    let Body::InventoryResult { snapshot, .. } = response(&graph, Some(initial), None, 2).unwrap()
    else {
        panic!("new horizon");
    };
    assert_eq!(snapshot.count, 14);
    assert_eq!(snapshot.root, graph.content_root());
}

#[test]
fn inventory_preserves_unchanged_shortcut_and_rejects_replaced_or_invalid_horizons() {
    let mut graph = Graph::default();
    let empty = graph.content_root();
    assert!(
        matches!(response(&graph, Some(empty), None, 1).unwrap(), Body::InventoryUnchanged { root } if root == empty)
    );
    let id = add(&mut graph, 1);
    let Body::InventoryResult {
        snapshot,
        ids,
        next,
    } = response(&graph, Some(empty), None, 1).unwrap()
    else {
        panic!("new set");
    };
    assert_eq!(ids, [*id.as_bytes()]);
    assert!(next.is_none());
    assert!(matches!(
        response(&graph, Some(snapshot.root), None, 1).unwrap(),
        Body::InventoryUnchanged { .. }
    ));
    let end = InventoryCursor { snapshot, after: 1 };
    assert!(
        matches!(response(&graph, None, Some(end), 1).unwrap(), Body::InventoryResult { ids, next: None, .. } if ids.is_empty())
    );
    let other = Graph::default();
    assert!(matches!(
        response(&other, None, Some(end), 1).unwrap(),
        Body::InventoryRestart
    ));
    for invalid in [
        InventoryCursor { after: 2, ..end },
        InventoryCursor {
            snapshot: InventorySnapshot {
                count: 2,
                ..snapshot
            },
            ..end
        },
    ] {
        assert!(matches!(
            response(&graph, None, Some(invalid), 1).unwrap(),
            Body::InventoryRestart
        ));
    }
    assert!(response(&graph, None, None, 0).is_err());
    assert!(graph.storage_error().is_none());
}

#[test]
fn receiver_rejects_missing_duplicate_and_rebound_inventory_pages() {
    let snapshot = InventorySnapshot {
        lineage: [1; 32],
        root: [2; 32],
        count: 3,
    };
    let ids = [[3; 32], [1; 32], [2; 32]]; // Admission order need not be hash order.
    assert!(valid_page(None, snapshot, &ids, None));
    assert!(!valid_page(None, snapshot, &ids[..2], None));
    assert!(!valid_page(None, snapshot, &[[3; 32]; 3], None));
    let after = InventoryCursor { snapshot, after: 1 };
    assert!(valid_page(Some(after), snapshot, &ids[1..], None));
    assert!(!valid_page(
        Some(after),
        InventorySnapshot {
            root: [9; 32],
            ..snapshot
        },
        &ids[1..],
        None
    ));
    assert!(!valid_page(Some(after), snapshot, &ids[1..], Some(after)));
}

#[test]
fn receiver_accepts_smaller_peer_pages_without_relaxing_progress_or_local_limits() {
    let mut graph = Graph::default();
    let original: Vec<_> = (1..=5).map(|depth| add(&mut graph, depth)).collect();
    let mut after = None;
    let mut observed = Vec::new();
    loop {
        // A peer may have a smaller installed page ceiling than this receiver.
        let Body::InventoryResult {
            snapshot,
            ids,
            next,
        } = response(&graph, None, after, 2).unwrap()
        else {
            panic!("inventory page");
        };
        assert!(valid_page(after, snapshot, &ids, next));
        if after.is_none() {
            assert!(!valid_page(
                None,
                snapshot,
                &[],
                Some(InventoryCursor { snapshot, after: 0 })
            ));
            let mut oversized = Vec::new();
            for index in 0..=crate::resources::limits().inventory_page {
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(index as u64).to_le_bytes());
                oversized.push(id);
            }
            let large = InventorySnapshot {
                count: oversized.len() as u64,
                ..snapshot
            };
            assert!(!valid_page(None, large, &oversized, None));
        }
        observed.extend(ids.into_iter().map(ProofId::from_bytes));
        if next.is_none() {
            break;
        }
        after = next;
    }
    assert_eq!(observed, original);
}
