use super::*;

fn solver(byte: u8) -> Solver {
    Solver {
        checkpoint: crate::hex(&[byte; 32]),
        budget: SearchBudget {
            horizon_ms: 100,
            work_units: 4,
        },
    }
}
fn request() -> Request {
    Request {
        solver: solver(1),
        training_roots: vec![],
        development: None,
        previous_development: None,
        after: None,
        scan: 16,
        take: 16,
        seed: 41,
        random_only: false,
    }
}
fn fixture() -> (Graph, Vec<(CompiledQuestion, String)>) {
    let mut graph = Graph::default();
    let mut roots = Vec::new();
    for n in 1..=18 {
        let mut formula = "eq(v0,v0)".to_owned();
        let mut proof = "p0=refl(v0)".to_owned();
        for i in 0..n {
            formula = format!("all(v{i},{formula})");
            proof.push_str(&format!(" p{}=gen(p{i},v{i})", i + 1));
        }
        let source = format!("goal={formula} proof: {proof} return p{n}");
        let question = CompiledQuestion::compile(&format!("goal={formula}")).unwrap();
        let root = graph.produce(&source).unwrap().0.artifact_id;
        roots.push((question, root));
    }
    for role in [
        Partition::Training,
        Partition::Development,
        Partition::Reserved,
    ] {
        assert!(roots.iter().any(|(q, _)| partition(q) == role));
    }
    (graph, roots)
}
fn batches(graph: &Graph, mut request: Request) -> Vec<Example> {
    let mut result = vec![];
    loop {
        let batch = select(graph, &request).unwrap();
        request.after = batch.next_after;
        result.extend(batch.examples);
        if request.after.is_none() {
            return result;
        }
    }
}
fn report(graph: &Graph, roots: &[(CompiledQuestion, String)], checkpoint: u8) -> Development {
    Development {
        solver: solver(checkpoint),
        knowledge: crate::hex(&graph.content_root()),
        probes: roots
            .iter()
            .filter(|(q, _)| partition(q) == Partition::Development)
            .map(|(q, root)| Probe {
                spent_ms: 1,
                work_units: 1,
                question: q.source().into(),
                result: Outcome::Verified {
                    artifact: root.clone(),
                },
            })
            .collect(),
    }
}

#[test]
fn exported_targets_are_checked_known_proofs_and_reserved_groups_do_not_leak() {
    let (graph, roots) = fixture();
    let original = graph.content_root();
    let examples = batches(&graph, request());
    let expected = roots
        .iter()
        .filter(|(q, _)| partition(q) == Partition::Training)
        .count();
    assert_eq!(examples.len(), expected);
    assert_eq!(graph.content_root(), original);
    let mut receiver = Graph::default();
    for example in &examples {
        let q = CompiledQuestion::compile(&example.input.question).unwrap();
        assert_eq!(partition(&q), Partition::Training);
        assert!(!example.target.refuted);
        assert!(example.input.context.is_empty());
        assert!(
            example
                .provenance
                .proof_rules
                .contains(&"equality_reflexivity".into())
        );
        assert!(
            example
                .provenance
                .proof_rules
                .contains(&"generalization".into())
        );
        assert_eq!(example.provenance.resolution, crate::hex(q.resolution_id()));
        receiver
            .ingest(example.target.proof.clone(), std::time::Instant::now())
            .unwrap();
    }
    assert_eq!(receiver.accepted_count(), expected);
    let input = serde_json::to_value(&examples[0].input).unwrap();
    assert_eq!(
        input
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["context".into(), "question".into()])
    );
}

#[test]
fn diagnostic_checkpoint_context_budget_and_partition_are_enforced() {
    let (graph, roots) = fixture();
    let mut r = request();
    r.development = Some(report(&graph, &roots, 1));
    assert!(select(&graph, &r).is_ok());
    r.development.as_mut().unwrap().solver.checkpoint = crate::hex(&[9; 32]);
    assert!(select(&graph, &r).is_err());
    r.development = Some(report(&graph, &roots, 1));
    r.development.as_mut().unwrap().solver.budget.work_units += 1;
    assert!(select(&graph, &r).is_err());
    r.development = Some(report(&graph, &roots, 1));
    r.development.as_mut().unwrap().probes[0].work_units = r.solver.budget.work_units + 1;
    assert!(select(&graph, &r).is_err());
    r.development = Some(report(&graph, &roots, 1));
    r.development.as_mut().unwrap().knowledge = crate::hex(&[0; 32]);
    assert!(select(&graph, &r).is_err());
    let (q, root) = roots
        .iter()
        .find(|(q, _)| partition(q) == Partition::Reserved)
        .unwrap();
    r.development = Some(Development {
        solver: solver(1),
        knowledge: crate::hex(&graph.content_root()),
        probes: vec![Probe {
            spent_ms: 1,
            work_units: 1,
            question: q.source().into(),
            result: Outcome::Verified {
                artifact: root.clone(),
            },
        }],
    });
    assert!(select(&graph, &r).is_err());
    r.development = None;
    r.training_roots = vec![root.clone()];
    assert!(select(&graph, &r).is_err());
}

#[test]
fn unsupported_or_mismatched_positive_reports_cannot_create_training_evidence() {
    let (graph, roots) = fixture();
    let mut r = request();
    let mut d = report(&graph, &roots, 1);
    d.probes[0].result = Outcome::Verified {
        artifact: crate::hex(&[0; 32]),
    };
    r.development = Some(d);
    assert!(select(&graph, &r).is_err());
    let mut d = report(&graph, &roots, 1);
    let target = CompiledQuestion::compile(&d.probes[0].question).unwrap();
    let (_, other) = roots
        .iter()
        .find(|(q, _)| q.resolution_id() != target.resolution_id())
        .unwrap();
    d.probes[0].result = Outcome::Verified {
        artifact: other.clone(),
    };
    r.development = Some(d);
    assert!(select(&graph, &r).is_err());
}

#[test]
fn scarcity_and_development_weakness_change_priorities_without_false_labels() {
    let (graph, roots) = fixture();
    let mut r = request();
    let mut d = report(&graph, &roots, 1);
    let target = CompiledQuestion::compile(&d.probes[0].question).unwrap();
    let features = Features::of(&target);
    let rules = [false; signals::RULES];
    r.development = Some(d.clone());
    let mastered = Signals::new(&graph, &r)
        .unwrap()
        .priority(&features, &rules, 1);
    d.probes
        .iter_mut()
        .for_each(|p| p.result = Outcome::Exhausted);
    r.development = Some(d.clone());
    let weak = Signals::new(&graph, &r)
        .unwrap()
        .priority(&features, &rules, 1);
    assert!(weak > mastered);
    d.probes
        .iter_mut()
        .for_each(|p| p.result = Outcome::Unavailable);
    r.development = Some(d.clone());
    let unavailable = Signals::new(&graph, &r)
        .unwrap()
        .priority(&features, &rules, 1);
    d.probes.clear();
    r.development = Some(d);
    let unknown = Signals::new(&graph, &r)
        .unwrap()
        .priority(&features, &rules, 1);
    assert_eq!(
        unavailable, unknown,
        "technical unavailability is not measured failure or mastery"
    );
    let mut signals = Signals::default();
    let before = signals.priority(&features, &rules, 1);
    signals.covered(&features, &rules);
    assert!(signals.priority(&features, &rules, 1) < before);
    assert!(signals::opportunity(2, 4) > signals::opportunity(4, 4));
    assert!(signals::opportunity(2, 4) > signals::opportunity(0, 4));
}

#[test]
fn progress_requires_the_same_development_tasks_and_budgets() {
    let (graph, roots) = fixture();
    let mut r = request();
    let mut before = report(&graph, &roots, 2);
    before
        .probes
        .iter_mut()
        .for_each(|p| p.result = Outcome::Exhausted);
    r.development = Some(report(&graph, &roots, 1));
    r.previous_development = Some(before.clone());
    assert!(select(&graph, &r).is_ok());
    let mut changed_input = before.clone();
    changed_input.probes[0].question.push(' ');
    r.previous_development = Some(changed_input);
    assert!(
        select(&graph, &r).is_err(),
        "paired progress must use identical model inputs"
    );
    before.probes.pop();
    r.previous_development = Some(before);
    assert!(select(&graph, &r).is_err());
}

#[test]
fn paired_evaluation_counts_errors_and_enforces_equal_total_budget() {
    let (graph, roots) = fixture();
    let probes = roots
        .iter()
        .filter(|(q, _)| partition(q) == Partition::Reserved)
        .map(|(q, _)| Probe {
            spent_ms: 1,
            work_units: 1,
            question: q.source().into(),
            result: Outcome::Unavailable,
        })
        .collect::<Vec<_>>();
    let baseline = Evaluation {
        initial_checkpoint: crate::hex(&[4; 32]),
        solver: solver(1),
        knowledge: crate::hex(&graph.content_root()),
        total_budget_micros: 1000,
        compute: Compute {
            selection_micros: 100,
            generation_and_checking_micros: 100,
            training_micros: 500,
            evaluation_micros: 200,
        },
        probes,
    };
    let mut targeted = baseline.clone();
    targeted.solver = solver(2);
    let (_, root) = roots
        .iter()
        .find(|(q, _)| q.source() == targeted.probes[0].question)
        .unwrap();
    targeted.probes[0].result = Outcome::Verified {
        artifact: root.clone(),
    };
    let comparison = compare(&graph, &baseline, &targeted).unwrap();
    assert_eq!(comparison.baseline.unavailable, baseline.probes.len());
    assert_eq!(comparison.targeted.verified, 1);
    assert_eq!(comparison.targeted.total, baseline.probes.len());
    assert_eq!(comparison.paired_new_successes, 1);
    targeted.total_budget_micros += 1;
    assert!(compare(&graph, &baseline, &targeted).is_err());
    targeted.total_budget_micros = 1000;
    targeted.compute.training_micros = 1000;
    assert!(compare(&graph, &baseline, &targeted).is_err());
    targeted.compute.training_micros = 500;
    targeted.probes[0].question.push(' ');
    assert!(
        compare(&graph, &baseline, &targeted).is_err(),
        "equivalent wording is a different paired input"
    );
}

#[test]
fn partition_keeps_renamings_and_opposite_resolution_together() {
    let a = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let b = CompiledQuestion::compile("goal=all(other,eq(other,other))").unwrap();
    let negative = CompiledQuestion::compile("goal=not(all(x,eq(x,x)))").unwrap();
    assert_eq!(group(&a), group(&b));
    assert_eq!(group(&a), group(&negative));
    assert_eq!(partition(&a), partition(&negative));
}

#[test]
fn research_plan_excludes_answers_duplicates_and_reserved_work() {
    let (graph, roots) = fixture();
    let mut sources = roots
        .iter()
        .take(3)
        .map(|(q, _)| q.source().to_owned())
        .collect::<Vec<_>>();
    let x = naome_foundation::FreeVariable::new(0);
    let mut predicate = naome_foundation::Formula::member(x, x);
    for _ in 0..10 {
        let formula = naome_foundation::Separation {
            predicate: predicate.clone(),
            element: x,
            source: naome_foundation::FreeVariable::new(1),
            result: naome_foundation::FreeVariable::new(2),
            parameters: vec![],
        }
        .formula()
        .unwrap();
        let q = CompiledQuestion::from_formula(formula).unwrap();
        sources.push(q.source().into());
        predicate =
            naome_foundation::Formula::implies(predicate, naome_foundation::Formula::equal(x, x));
    }
    sources.push(sources.last().unwrap().clone());
    let before = graph.content_root();
    let plan = plan(&graph, &request(), &sources).unwrap();
    assert!(plan.excluded >= 4);
    assert!(!plan.questions.is_empty());
    let mut unique = BTreeSet::new();
    for selected in plan.questions {
        let q = CompiledQuestion::compile(&selected.question).unwrap();
        assert_eq!(partition(&q), Partition::Training);
        assert!(unique.insert(*q.resolution_id()));
        assert!(
            roots
                .iter()
                .all(|(known, _)| known.resolution_id() != q.resolution_id())
        );
    }
    assert_eq!(graph.content_root(), before);
}

#[test]
fn question_only_suite_pages_cover_the_selected_partition_without_labels() {
    let (graph, roots) = fixture();
    let mut after = None;
    let mut observed = BTreeSet::new();
    loop {
        let page = questions(&graph, Partition::Reserved, after.as_deref(), 8).unwrap();
        let encoded = serde_json::to_value(&page).unwrap();
        assert!(encoded.get("proof").is_none() && encoded.get("probes").is_none());
        for source in page.questions {
            let q = CompiledQuestion::compile(&source).unwrap();
            assert_eq!(partition(&q), Partition::Reserved);
            assert!(observed.insert(*q.resolution_id()));
        }
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(
        observed.len(),
        roots
            .iter()
            .filter(|(q, _)| partition(q) == Partition::Reserved)
            .count()
    );
}

#[test]
fn a_training_theorem_cannot_smuggle_a_reserved_lemma_into_its_context() {
    let (mut graph, roots) = fixture();
    let (reserved, root) = roots
        .iter()
        .find(|(q, _)| partition(q) == Partition::Reserved)
        .unwrap();
    let reference = graph
        .get(root)
        .unwrap()
        .unwrap()
        .proof_id()
        .unwrap()
        .unwrap();
    let reference = crate::hex(reference.as_bytes());
    let mut found = false;
    for n in 1..=12 {
        let mut formula = reserved.formula().clone();
        let mut proof = "p0=cite(base)".to_owned();
        for i in 0..n {
            let variable = naome_foundation::FreeVariable::new(100 + i);
            formula = naome_foundation::Formula::for_all(variable, formula);
            proof.push_str(&format!(" p{}=gen(p{i},f{})", i + 1, 100 + i));
        }
        let target = CompiledQuestion::from_formula(formula.clone()).unwrap();
        if partition(&target) != Partition::Training {
            continue;
        }
        let source = format!(
            "refs: base=\"{reference}\" goal={} proof: {proof} return p{n}",
            formula.to_source()
        );
        let derived = graph.produce(&source).unwrap().0.artifact_id;
        let examples = batches(&graph, request());
        assert!(
            examples
                .iter()
                .all(|e| e.target.proof.artifact_id != derived)
        );
        found = true;
        break;
    }
    assert!(found);
}
