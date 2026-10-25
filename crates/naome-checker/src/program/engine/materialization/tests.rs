use super::*;
use naome_foundation::{FreeVariable, Logic};
use naome_proof::program::Command;

fn shared(levels: usize, unused: u32) -> Engine {
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    let mut commands = Vec::new();
    for v in 1..=unused {
        commands.push(Command::Equal { left: v, right: v });
    }
    let mut root = commands.len() as u64;
    commands.push(Command::Equal { left: 0, right: 0 });
    for _ in 0..levels {
        let next = commands.len() as u64;
        commands.push(Command::Implies {
            antecedent: root,
            consequent: root,
        });
        root = next;
    }
    let theorem = commands.len() as u64;
    commands.push(Command::Simplification {
        antecedent: root,
        consequent: root,
    });
    let closed = commands.len() as u64;
    commands.push(Command::Generalization {
        premise: theorem,
        variable: 0,
    });
    commands.push(Command::Seal { proof: closed });
    engine.append_group(&commands).unwrap();
    while engine
        .advance(256, 32768, &crate::ArtifactState::new())
        .unwrap()
    {}
    engine
}

#[test]
fn oversized_shared_conclusion_exports_only_its_reachable_dag_in_bounded_quanta() {
    for unused in [0, 1000] {
        let mut engine = shared(20, unused);
        assert_eq!(
            engine.status().unwrap().formula_nodes,
            47 + u64::from(unused)
        );
        let mut previous = 0;
        let mut quanta = 0;
        while !engine.prepare_export(1).unwrap() {
            let reached: u64 = engine
                .connection
                .query_row("SELECT count(*) FROM export_node", [], |r| unsigned(r, 0))
                .unwrap();
            assert!(reached >= previous && reached - previous <= 1);
            previous = reached;
            quanta += 1;
            assert!(quanta < unused as usize + 100);
            let before = engine.export.expect("reverse export").before;
            assert!(!engine.prepare_export(0).unwrap());
            assert_eq!(engine.export.expect("paused export").before, before);
        }
        let proof = engine.checked().unwrap();
        assert!(proof.conclusion().is_none());
        assert_eq!(proof.node_count().unwrap(), 24);
        let nodes = proof.nodes_after(0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(nodes.len(), 24);
        let mut known = std::collections::BTreeSet::new();
        for (_, hash, bytes) in nodes {
            let node = format::decode_graph_node(&bytes).unwrap().0;
            assert!(
                node.children()
                    .into_iter()
                    .flatten()
                    .all(|id| known.contains(&id))
            );
            known.insert(hash);
        }
        assert!(known.contains(&proof.manifest().conclusion));
        if unused == 0 {
            // Current-format golden independently reconstructed from command, DAG, and identity hash domains.
            assert_eq!(
                *proof.manifest().proof_id().as_bytes(),
                [
                    41, 141, 35, 58, 132, 56, 102, 251, 121, 214, 22, 200, 131, 192, 181, 218, 33,
                    121, 84, 1, 179, 16, 70, 246, 169, 241, 79, 106, 142, 188, 132, 128
                ]
            );
            assert_eq!(
                *proof.manifest().statement_id().as_bytes(),
                [
                    217, 155, 50, 194, 240, 11, 90, 2, 10, 37, 16, 64, 192, 48, 23, 242, 94, 99, 2,
                    32, 12, 154, 94, 143, 65, 107, 84, 81, 231, 187, 124, 114
                ]
            );
        }
    }
}

#[test]
fn incremental_tree_projection_preserves_foundation_formula_and_golden_identity() {
    let mut engine = shared(8, 0);
    let mut quanta = 0;
    while !engine.prepare_export(7).unwrap() {
        quanta += 1;
        if quanta == 20 {
            engine
                .advance(0, 4096, &crate::ArtifactState::new())
                .unwrap();
            let tree = engine
                .finalization
                .as_ref()
                .and_then(|state| state.tree.as_ref())
                .unwrap();
            assert!(
                tree.cache.len() * Tree::entry_bytes()
                    + tree.order.capacity() * std::mem::size_of::<u64>()
                    <= Tree::cache_bytes(4096) as usize
            );
        }
    }
    assert!(
        quanta > 100,
        "tree construction must be spread over the supplied quanta"
    );
    let proof = engine.checked().unwrap();
    let variable = FreeVariable::new(0);
    let mut formula = Formula::equal(variable, variable);
    for _ in 0..8 {
        formula = Formula::implies(formula.clone(), formula);
    }
    let expected = Formula::for_all(variable, Logic::simplification(formula.clone(), formula));
    assert_eq!(proof.conclusion(), Some(&expected));
    assert_eq!(
        *proof.manifest().proof_id().as_bytes(),
        [
            248, 194, 122, 199, 182, 226, 150, 220, 193, 151, 250, 161, 83, 2, 119, 222, 246, 48,
            178, 18, 240, 11, 56, 71, 174, 211, 63, 193, 242, 104, 88, 109
        ]
    );
}

#[test]
fn tree_shape_matches_codec_boundaries_and_saturates_without_overflow() {
    let atom = Shape::of(
        Node::Equal(Variable::Bound(0), Variable::Bound(0)),
        [None, None],
    );
    let mut shape = atom;
    for depth in 1..=u64::from(FORMULA_MAX_DEPTH) + 2 {
        shape = Shape::of(Node::ForAll(0), [Some(shape), None]);
        assert_eq!(shape.fits(), depth < u64::from(FORMULA_MAX_DEPTH));
    }
    let mut shape = atom;
    for _ in 0..1024 {
        shape = Shape::of(Node::Implies(0, 0), [Some(shape), Some(shape)]);
    }
    assert_eq!(shape.nodes, FORMULA_MAX_NODES as u64 + 1);
    assert_eq!(shape.bytes, FORMULA_MAX_BYTES as u64 + 1);
    assert!(!shape.fits());
}

#[test]
fn failed_reachability_quantum_rolls_back_its_frontier_and_retries_without_duplicate_nodes() {
    let mut engine = shared(20, 0);
    assert!(!engine.prepare_export(4096).unwrap());
    engine.connection.execute_batch("CREATE TEMP TRIGGER refuse_export BEFORE INSERT ON export_node BEGIN SELECT RAISE(ABORT,'injected export refusal'); END;").unwrap();
    assert!(engine.prepare_export(7).is_err());
    assert_eq!(engine.finalization.as_ref().unwrap().reachable, 0);
    let copied: u64 = engine
        .connection
        .query_row("SELECT count(*) FROM export_node", [], |row| {
            unsigned(row, 0)
        })
        .unwrap();
    assert_eq!(copied, 0);
    engine
        .connection
        .execute_batch("DROP TRIGGER refuse_export")
        .unwrap();
    while !engine.prepare_export(7).unwrap() {}
    assert_eq!(engine.checked().unwrap().node_count().unwrap(), 24);
}
