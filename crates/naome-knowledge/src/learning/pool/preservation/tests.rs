use super::*;
use crate::learning::{model::*, search};

fn checked(branching: bool) -> Pool {
    struct Ordered(bool);
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(d.candidates
                .iter()
                .map(|c| {
                    if c.rule
                        == if self.0 {
                            Rule::ImplicationBranch
                        } else {
                            Rule::ModusPonens
                        }
                    {
                        1.
                    } else {
                        0.
                    }
                })
                .collect())
        }
    }
    let source = if branching {
        "goal=all(a,all(b,all(c,imp(imp(mem(a,a),mem(b,b)),imp(imp(not(mem(a,a)),mem(b,b)),imp(not(not(mem(c,c))),mem(b,b)))))))"
            .into()
    } else {
        let variables = ["a", "b", "c", "d", "e", "f"];
        let mut body = "imp(mem(a,a),mem(f,f))".to_string();
        for pair in variables.windows(2).rev() {
            body = format!(
                "imp(imp(mem({0},{0}),mem({1},{1})),{body})",
                pair[0], pair[1]
            );
        }
        for variable in variables.into_iter().rev() {
            body = format!("all({variable},{body})");
        }
        format!("goal={body}")
    };
    let question = naome_authoring::CompiledQuestion::compile(&source).unwrap();
    let found = search::solve(question.proved_target(), &mut Ordered(branching), 128).unwrap();
    let tree = found.tree.unwrap();
    let (term, _) = search::compile(question.proved_target(), &tree).unwrap();
    let verified = crate::learning::proof::verify(&term, question.proved_target()).unwrap();
    let derivation = search::derivation::checked(
        question.proved_target(),
        &tree,
        &crate::hex(verified.native_id.as_bytes()),
    )
    .unwrap();
    let mut pool = Pool::default();
    pool.add(
        false,
        "checked-fixture",
        "checked-fixture",
        derivation.source_proof.as_ref().unwrap(),
        derivation
            .steps
            .iter()
            .filter(|s| s.graph.candidates.len() > 1)
            .map(|s| s.graph.clone())
            .collect(),
    )
    .unwrap();
    pool.add_derivation(derivation, true).unwrap();
    pool
}

#[test]
fn checked_reference_prefixes_share_slots_and_never_cross_a_symbolic_branch() {
    for branching in [false, true] {
        let pool = checked(branching);
        if branching {
            assert!(pool.derivations[0].steps.iter().any(|s| s.children == 2));
        } else {
            assert!(pool.derivations[0].steps.len() > 4);
        }
        let mut edges = 0;
        let mut maximum = 0;
        for start in [0, 1, 7, u64::MAX - 8] {
            let mut flat_cursor = start;
            let flat = pool.batch(&mut flat_cursor);
            let mut cursor = start;
            let references = pool.preservation_batch(&mut cursor).unwrap();
            assert_eq!(cursor, flat_cursor);
            assert_eq!(references.samples.len(), flat.len());
            assert_eq!(references.samples.len(), 16);
            let mut depths = Vec::new();
            for (index, sample) in references.samples.iter().enumerate() {
                let source = references.sources[index].as_ref().unwrap();
                let derived = &pool.derivations[0];
                assert_eq!(source.proof, derived.source_proof.as_deref().unwrap());
                assert_eq!(source.tree, derived.source_tree);
                assert_eq!(source.witness, derived.steps[source.step].witness);
                assert!(!sample.auxiliary);
                assert!(sample.graph.successes.contains(&sample.selected));
                let depth = if let Some(parent) = sample.parent {
                    edges += 1;
                    assert!(parent < index);
                    let previous = references.sources[parent].as_ref().unwrap();
                    let (expected, child) = derived.steps[source.step].parent.unwrap();
                    assert_eq!(previous.step, expected);
                    assert_eq!(derived.steps[source.step].branch.last(), Some(&child));
                    depths[parent] + 1
                } else {
                    1
                };
                maximum = maximum.max(depth);
                assert!(depth <= 4);
                depths.push(depth);
            }
        }
        assert!(
            edges > 0,
            "no checked reference ancestry; branching={branching}"
        );
        if !branching {
            assert_eq!(maximum, 4);
        }
        assert!(
            pool.sequences.is_empty(),
            "reconstruction is not observation"
        );
    }
}

#[test]
fn reference_prefixes_require_complete_sources_and_reject_corrupt_ancestry() {
    let mut pool = checked(false);
    pool.derivations[0].source_proof = None;
    let independent = pool.preservation_batch(&mut 0).unwrap();
    assert!(independent.samples.iter().all(|s| s.parent.is_none()));
    assert!(independent.sources.iter().all(Option::is_none));
    for corruption in 0..3 {
        let mut pool = checked(false);
        for (index, step) in pool.derivations[0].steps.iter_mut().enumerate().skip(1) {
            match corruption {
                0 => step.parent = Some((index, 0)),
                1 => step.parent.as_mut().unwrap().1 = usize::MAX,
                _ => step.branch.push(0),
            }
        }
        assert!((0..16).any(|cursor| pool.preservation_batch(&mut { cursor }).is_err()));
    }
}
