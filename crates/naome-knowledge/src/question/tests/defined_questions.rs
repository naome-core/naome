use super::*;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ArtifactId, DefinedFormula, DefinitionCertificate};

fn variable(id: u32) -> FreeVariable {
    FreeVariable::new(id)
}
fn natural(x: FreeVariable) -> Formula {
    let [s, e, a, b, t] = [10, 11, 12, 13, 14].map(variable);
    let empty = Formula::for_all(t, Formula::negate(Formula::member(t, e)));
    let succ = Formula::for_all(
        t,
        Formula::biconditional(
            Formula::member(t, b),
            Formula::disjunction(Formula::member(t, a), Formula::equal(t, a)),
        ),
    );
    let inductive = Formula::conjunction(
        Formula::exists(e, Formula::conjunction(empty, Formula::member(e, s))),
        Formula::for_all(
            a,
            Formula::implies(
                Formula::member(a, s),
                Formula::exists(b, Formula::conjunction(succ, Formula::member(b, s))),
            ),
        ),
    );
    Formula::for_all(s, Formula::implies(inductive, Formula::member(x, s)))
}
fn addition_graph(m: FreeVariable, n: FreeVariable, z: FreeVariable) -> Formula {
    let [r, i, j, k, p, t, u] = [20, 21, 22, 23, 24, 25, 26].map(variable);
    let tail = |x| {
        Formula::conjunction(
            Formula::member(x, z),
            Formula::negate(Formula::member(x, m)),
        )
    };
    let linked = |a, b| {
        let singleton = Formula::for_all(
            u,
            Formula::biconditional(Formula::member(u, t), Formula::equal(u, a)),
        );
        let doubleton = Formula::for_all(
            u,
            Formula::biconditional(
                Formula::member(u, t),
                Formula::disjunction(Formula::equal(u, a), Formula::equal(u, b)),
            ),
        );
        let pair = Formula::for_all(
            t,
            Formula::biconditional(
                Formula::member(t, p),
                Formula::disjunction(singleton, doubleton),
            ),
        );
        Formula::exists(p, Formula::conjunction(Formula::member(p, r), pair))
    };
    let total = Formula::for_all(
        i,
        Formula::implies(
            Formula::member(i, n),
            Formula::exists(
                j,
                Formula::conjunction(
                    tail(j),
                    Formula::conjunction(
                        linked(i, j),
                        Formula::for_all(
                            k,
                            Formula::implies(
                                Formula::conjunction(tail(k), linked(i, k)),
                                Formula::equal(k, j),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let onto = Formula::for_all(
        j,
        Formula::implies(
            tail(j),
            Formula::exists(
                i,
                Formula::conjunction(
                    Formula::member(i, n),
                    Formula::conjunction(
                        linked(i, j),
                        Formula::for_all(
                            k,
                            Formula::implies(
                                Formula::conjunction(Formula::member(k, n), linked(k, j)),
                                Formula::equal(k, i),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    Formula::conjunction(
        natural(m),
        Formula::conjunction(
            natural(n),
            Formula::conjunction(
                natural(z),
                Formula::conjunction(
                    Formula::disjunction(Formula::member(m, z), Formula::equal(m, z)),
                    Formula::exists(r, Formula::conjunction(total, onto)),
                ),
            ),
        ),
    )
}
#[tokio::test]
async fn node_admits_and_restores_total_unique_natural_addition_with_checked_definitions() {
    let directory = Directory::new();
    let [m, n, z, w] = [0, 1, 2, 3].map(variable);
    let natural_certificate =
        DefinitionCertificate::relation(1, DefinedFormula::from_primitive(&natural(m)).unwrap())
            .unwrap();
    let graph_formula = addition_graph(m, n, z);
    let addition_certificate =
        DefinitionCertificate::relation(3, DefinedFormula::from_primitive(&graph_formula).unwrap())
            .unwrap();
    let natural_id = natural_certificate.definition_id();
    let addition_id = addition_certificate.definition_id();

    let natural_ref = |x| DefinedFormula::defined_relation(natural_id, [x]);
    let add = |output| DefinedFormula::defined_relation(addition_id, [m, n, output]);
    let compact = DefinedFormula::for_all(
        m,
        DefinedFormula::for_all(
            n,
            DefinedFormula::implies(
                DefinedFormula::conjunction(natural_ref(m), natural_ref(n)),
                DefinedFormula::exists(
                    z,
                    DefinedFormula::conjunction(
                        add(z),
                        DefinedFormula::for_all(
                            w,
                            DefinedFormula::implies(add(w), DefinedFormula::equal(z, w)),
                        ),
                    ),
                ),
            ),
        ),
    );
    let expected = Formula::for_all(
        m,
        Formula::for_all(
            n,
            Formula::implies(
                Formula::conjunction(natural(m), natural(n)),
                Formula::exists(
                    z,
                    Formula::conjunction(
                        graph_formula.clone(),
                        Formula::for_all(
                            w,
                            Formula::implies(
                                graph_formula.substitute_free(z, w),
                                Formula::equal(z, w),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let bytes = compact.encode_canonical().unwrap();
    assert!(bytes.len() < expected.encode_canonical().unwrap().len());
    assert!(expected.view().node_count_and_depth().0 > naome_proof::QUESTION_TARGET_MAX_NODES);
    assert!(expected.view().node_count_and_depth().1 > naome_proof::QUESTION_TARGET_MAX_DEPTH);

    // With only Nat checked, the three-argument Add reference is unresolved.
    let mut graph = Graph::open(&directory.0).unwrap();
    let natural = graph
        .author(&crate::test_inputs::definition(&natural_certificate))
        .unwrap();
    graph.ingest(natural, Instant::now()).unwrap();
    drop(graph);
    let (handle, admin, inbox) = channel();
    let task = tokio::spawn(network::test_run(
        directory.config(),
        inbox,
        Some(|_| async { panic!("unresolved references cannot reach selection") }),
    ));
    assert_eq!(context(&handle).await.checked_artifacts, 1);
    let missing = tokio::time::timeout(Duration::from_secs(5), handle.admit_question_bytes(&bytes))
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        missing,
        naome_proof::QuestionError::MissingDefinition(addition_id)
    );
    assert_eq!(context(&handle).await.registered_questions, 0);
    stop(admin, task).await;

    let mut graph = Graph::open(&directory.0).unwrap();
    let addition = graph
        .author(&crate::test_inputs::definition(&addition_certificate))
        .unwrap();
    graph.ingest(addition, Instant::now()).unwrap();
    let compiled =
        ResearchQuestion::from_canonical_bytes_with_context(&bytes, graph.checked_context())
            .unwrap();
    assert_eq!(compiled.formula(), &expected);
    let mut dependencies = [natural_id, addition_id].map(ArtifactId::from_definition_id);
    dependencies.sort_unstable();
    assert_eq!(compiled.dependencies(), dependencies);
    drop(graph);

    let (handle, admin, inbox) = channel();
    let selected = compiled.clone();
    let task = tokio::spawn(network::test_run(
        directory.config(),
        inbox,
        Some(move |question| {
            assert_eq!(question, selected);
            async { Ok(true) }
        }),
    ));
    let admission =
        tokio::time::timeout(Duration::from_secs(5), handle.admit_question_bytes(&bytes))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    assert!(
        matches!(admission.outcome, AdmissionOutcome::Admitted(_)),
        "{:?}",
        admission.assessment
    );
    assert_eq!(context(&handle).await.registered_questions, 1);
    stop(admin, task).await;

    let (handle, admin, inbox) = channel();
    let task = tokio::spawn(network::test_run(
        directory.config(),
        inbox,
        network::NO_TEST_SELECTION,
    ));
    assert_eq!(context(&handle).await.registered_questions, 1);
    let duplicate =
        tokio::time::timeout(Duration::from_secs(5), handle.admit_question_bytes(&bytes))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    assert_eq!(
        duplicate.assessment.prefilter.reason,
        Some(RejectionReason::ExactDuplicate)
    );
    stop(admin, task).await;
}
