use super::*;
use crate::learning::graph::Node;
fn case(number: usize) -> Graph {
    Graph {
        binding: String::new(),
        nodes: vec![
            Node {
                kind: 0,
                left: 0,
                right: 0,
                role: 0,
            },
            Node {
                kind: 10,
                left: 0,
                right: 0,
                role: 0,
            },
        ],
        goal: number,
        context: vec![],
        candidates: vec![1],
        expert: 0,
        successes: vec![0],
    }
}
#[test]
fn large_pools_are_fully_reached_after_rebuilds_without_repeating_a_prefix() {
    let graphs = (0..1009).map(case).collect::<Vec<_>>();
    let mut cursor = 0;
    let mut seen = BTreeSet::new();
    for _ in 0..64 {
        let pool = Pool::from_graphs(&graphs);
        for graph in pool.batch(&mut cursor) {
            seen.insert(graph.goal);
        }
    }
    assert_eq!(seen.len(), 1009);
    let pool = Pool::from_graphs(&graphs);
    let mut second = cursor;
    assert_eq!(
        pool.batch(&mut cursor)
            .iter()
            .map(|g| g.goal)
            .collect::<Vec<_>>(),
        pool.batch(&mut second)
            .iter()
            .map(|g| g.goal)
            .collect::<Vec<_>>()
    );
}
#[test]
fn checked_alternatives_merge_only_for_the_same_fully_bound_state() {
    let mut a = case(3);
    a.candidates.push(1);
    a.successes = vec![0];
    let mut b = a.clone();
    b.expert = 1;
    b.successes = vec![1];
    let mut other = b.clone();
    other.context.push(1);
    let mut pool = Pool::default();
    pool.add(false, "d", "f", "first", vec![a]).unwrap();
    pool.add(true, "d", "f", "later", vec![b, other]).unwrap();
    assert_eq!(pool.graphs.len(), 2);
    assert_eq!(pool.graphs[0].successes, vec![0, 1]);
    assert_eq!(pool.graphs[1].successes, vec![1]);
}
#[test]
fn targeting_changes_batches_but_not_states_labels_or_source_coverage() {
    let mut easy = case(0);
    easy.nodes.push(Node {
        kind: 17,
        left: 0,
        right: 0,
        role: 0,
    });
    easy.candidates.push(2);
    let mut hard = easy.clone();
    hard.goal = 1;
    let mut pool = Pool::default();
    pool.add(false, "old", "old", "p0", vec![easy]).unwrap();
    pool.add(false, "weak", "weak", "p1", vec![hard]).unwrap();
    let keys = pool.graphs.iter().map(Graph::key).collect::<Vec<_>>();
    let labels = pool
        .graphs
        .iter()
        .map(|g| g.successes.clone())
        .collect::<Vec<_>>();
    let feedback = crate::training::ability::Feedback::fresh("12".repeat(32));
    pool.focus(&feedback, |g| {
        Ok(if g.goal == 0 {
            vec![1., 0.]
        } else {
            vec![0., 1.]
        })
    })
    .unwrap();
    assert_eq!(keys, pool.graphs.iter().map(Graph::key).collect::<Vec<_>>());
    assert_eq!(
        labels,
        pool.graphs
            .iter()
            .map(|g| g.successes.clone())
            .collect::<Vec<_>>()
    );
    let mut cursor = 0;
    let mut hits = [0usize; 2];
    for _ in 0..256 {
        for graph in pool.batch(&mut cursor) {
            hits[graph.goal] += 1;
        }
    }
    assert_eq!(
        hits[0], hits[1],
        "difficulty must not multiply a family's allocation"
    );
}
#[test]
fn focus_preserves_complete_cycles_and_updates_when_a_decision_is_learned() {
    let mut graphs = (0..16).map(case).collect::<Vec<_>>();
    for g in &mut graphs {
        g.nodes.push(Node {
            kind: 17,
            left: 0,
            right: 0,
            role: 0,
        });
        g.candidates.push(2);
    }
    let mut pool = Pool::from_graphs(&graphs);
    let feedback = crate::training::ability::Feedback::fresh("12".repeat(32));
    pool.focus(&feedback, |g| {
        Ok(if g.goal == 0 {
            vec![-4., 4.]
        } else {
            vec![4., -4.]
        })
    })
    .unwrap();
    let old = pool.priorities[0];
    assert!(old > pool.priorities[1]);
    let mut cursor = 0;
    let mut hits = [0; 16];
    for _ in 0..3 {
        for g in pool.batch(&mut cursor) {
            hits[g.goal] += 1;
        }
    }
    assert_eq!(
        hits, [3; 16],
        "three complete unbiased decision cycles precede targeting"
    );
    pool.focus(&feedback, |_| Ok(vec![8., -8.])).unwrap();
    assert!(
        pool.priorities[0] < old,
        "current candidate scores must retire a solved priority"
    );
}

#[test]
fn preservation_pool_cannot_allocate_beyond_the_training_pools_remaining_allowance() {
    let graph = case(0);
    let bytes = graph.work_bytes();
    let mut training = Pool {
        work_capacity: Some(bytes),
        ..Pool::default()
    };
    training
        .add(false, "own", "family", "proof", vec![graph.clone()])
        .unwrap();
    assert_eq!(training.work_bytes, bytes);
    let mut preservation = training.remaining();
    assert!(
        preservation
            .add(false, "own", "family", "proof", vec![graph])
            .is_err()
    );
    assert!(
        preservation.graphs().is_empty(),
        "reference graphs cannot create an extra allowance"
    );
    assert_eq!(
        training.graphs().len(),
        1,
        "the original training pool stays intact"
    );
}
