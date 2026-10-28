use super::*;

#[test]
fn an_unstarted_job_and_closed_resource_gate_cannot_produce_an_audit() {
    use crate::learning::{State, experience::TerminalEvidence, model::TrainingCost, transfer};
    let state = State::fresh();
    let job = state.job();
    // Deliberately incomplete test metadata; never a trained checkpoint.
    let progress = Progress {
        finder: None,
        prepared: None,
        cost: None,
        training_cost: TrainingCost::default(),
        unit: 0,
        model: state.model.clone(),
        trained: 0,
        promotions: 0,
        rejections: 0,
        candidate: None,
        rng: state.draws,
        first_loss: None,
        last_loss: None,
        incumbent_score: 0,
        candidate_score: 0,
        anchor_regression: false,
        development_regression: false,
        original_score: [0, 0],
        transfer: transfer::Summary::default(),
        development_before: crate::training::ability::Profile::new(digest(&state.model)),
        development_after: crate::training::ability::Profile::new(digest(&state.model)),
        regressions: [0; crate::training::ability::SKILLS],
        gains: [0; crate::training::ability::SKILLS],
        plan: None,
        meta_update: None,
        cpu_micros: 0,
        wall_micros: 0,
        meta_cpu_micros: 0,
        meta_wall_micros: 0,
        result: None,
        diagnostic: "deliberately unstarted test job".into(),
        frontier: None,
        executions: Vec::new(),
        terminal: TerminalEvidence::Unknown,
    };
    let before = digest(&(&job, &progress));
    let mut io = crate::learning::tests::MemoryStore::default();
    assert_eq!(
        audit(
            &job,
            &progress,
            Targets::Actions,
            Recurrence::Carry,
            &mut io,
            || Err("resource owner paused".into())
        )
        .unwrap_err(),
        "resource owner paused"
    );
    assert!(
        audit(
            &job,
            &progress,
            Targets::Actions,
            Recurrence::Carry,
            &mut io,
            || Ok(())
        )
        .unwrap_err()
        .contains("completed balanced native trial")
    );
    assert_eq!(digest(&(&job, &progress)), before);
    assert!(
        io.0.is_empty(),
        "an invalid audit cannot read or write model data"
    );
}

#[test]
fn checked_graph_masks_distinguish_loss_paths_from_constant_objectives() {
    use crate::learning::{Solution, search};
    #[derive(serde::Deserialize)]
    struct Record {
        question: String,
        solution: Solution,
    }
    #[derive(serde::Deserialize)]
    struct Fixture {
        records: Vec<Record>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/native-fragment-capacity.json"
    )))
    .unwrap();
    let record = &fixture.records[0];
    let q = naome_authoring::CompiledQuestion::compile(&record.question).unwrap();
    let target = if record.solution.refuted {
        q.refuted_target()
    } else {
        q.proved_target()
    };
    let (tree, _, checked) = search::core::checked(target, &record.solution.tree).unwrap();
    assert_eq!(
        crate::hex(checked.native_id.as_bytes()),
        record.solution.proof_id
    );
    let graphs = search::compile(target, &tree).unwrap().1;
    let graph = graphs
        .iter()
        .find(|g| g.successes.len() < g.candidates.len())
        .unwrap();
    let pool = Pool::from_graphs(&graphs);
    // The mask/ancestry arrangement is synthetic observer test data. It does
    // not assert that these repeated graphs occurred as a real search chain.
    let sample = (0..3)
        .map(|i| Sample {
            graph,
            selected: graph.expert,
            parent: (i > 0).then(|| i - 1),
            auxiliary: i < 2,
        })
        .collect::<Vec<_>>();
    let (carry, rows) = batch(&pool, &sample, false, Recurrence::Carry).unwrap();
    assert_eq!(carry.masked_slots, 2);
    assert_eq!(carry.edges_with_unmasked_loss_descendants, 2);
    assert_eq!(carry.masked_edges_with_unmasked_loss_descendants, 1);
    assert_eq!(
        carry.carry_edges_with_potentially_nonconstant_loss_descendants,
        2
    );
    assert!(rows[1].ancestor_edge_of_unmasked_loss && !rows[1].unmasked_loss);
    let (reset, _) = batch(&pool, &sample, false, Recurrence::Reset).unwrap();
    assert_eq!(reset.edges_with_unmasked_loss_descendants, 2);
    assert_eq!(reset.carry_edges_with_unmasked_loss_descendants, 0);
    let mut all_positive = graph.clone();
    all_positive.successes = (0..all_positive.candidates.len()).collect();
    let constant = [Sample {
        graph: &all_positive,
        selected: graph.expert,
        parent: None,
        auxiliary: false,
    }];
    let (counts, _) = batch(&Pool::default(), &constant, false, Recurrence::Carry).unwrap();
    assert_eq!(counts.unmasked_loss_slots, 1);
    assert_eq!(counts.potentially_nonconstant_loss_slots, 0);
}

#[test]
fn masked_intermediates_keep_only_real_ancestry_to_active_descendants() {
    let parents = [None, Some(0), Some(1), Some(2), None, Some(4)];
    assert_eq!(
        reachable_edges(&parents, &[false, false, false, true, true, false]).unwrap(),
        vec![false, true, true, true, false, false]
    );
    assert_eq!(
        reachable_edges(&parents, &[true, false, false, false, true, false]).unwrap(),
        vec![false; 6],
        "a loss at the root cannot activate a later child edge"
    );
    assert!(reachable_edges(&[None, Some(1)], &[true; 2]).is_err());
    assert!(reachable_edges(&[Some(1), None], &[true; 2]).is_err());
    assert!(reachable_edges(&[None, Some(0), Some(1), Some(2), Some(3)], &[true; 5]).is_err());
}

#[test]
fn empty_and_disjoint_samples_have_no_cross_branch_influence_claim() {
    assert!(reachable_edges(&[], &[]).unwrap().is_empty());
    assert_eq!(
        reachable_edges(&[None, None, Some(1), None], &[true; 4]).unwrap(),
        vec![false, false, true, false]
    );
    assert!(reachable_edges(&[None], &[]).is_err());
    assert!(reachable_edges(&[None; 17], &[true; 17]).is_err());
}
