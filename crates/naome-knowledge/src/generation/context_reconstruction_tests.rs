//! Real checked snapshots must not depend on the transient ingestion queue size.
use super::*;
use std::time::Instant;

fn closed_predicate(seed: u16) -> String {
    let mut body = "eq(z,z)".to_owned();
    for bit in 0..10 {
        let atom = if seed & (1 << bit) == 0 {
            "eq(z,z)"
        } else {
            "mem(z,z)"
        };
        body = format!("imp({atom},{body})");
    }
    format!("all(z,{body})")
}

#[test]
fn complete_checked_snapshot_reconstructs_more_dependents_than_the_pending_limit() {
    let mut graph = Graph::default();
    let helper = graph
        .author("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap();
    let helper_id = helper.proof_id.clone();
    assert_eq!(
        graph.ingest(helper, Instant::now()).unwrap().admitted.len(),
        1
    );

    // Every child really cites the checked helper and derives a distinct closed
    // theorem C -> T by applying the simplification axiom to the proved T.
    // Select children whose real content addresses sort before the helper so
    // an ID-ordered rebuild would queue all of them before resolving any.
    let wanted = crate::MAX_PENDING + 1;
    let mut children = 0;
    let mut steps = 2;
    for seed in 0..1024_u16 {
        let predicate = closed_predicate(seed);
        let source = format!(
            "let: T=all(x,eq(x,x)) C={predicate} \
             goal=imp(C,T) proof: h=cite(\"{helper_id}\") \
             s=simp(T,C) p=mp(h,s) return p"
        );
        let envelope = graph.author(&source).unwrap();
        if envelope.proof_id >= helper_id {
            continue;
        }
        let candidate = envelope.clone().prepare().unwrap();
        assert_eq!(candidate.dependencies.len(), 1);
        assert_eq!(
            crate::hex(candidate.dependencies.iter().next().unwrap().as_bytes()),
            helper_id
        );
        steps += candidate.normal.certificate().steps().len();
        assert_eq!(
            graph
                .ingest(envelope, Instant::now())
                .unwrap()
                .admitted
                .len(),
            1
        );
        children += 1;
        if children == wanted {
            break;
        }
    }
    assert_eq!(children, wanted, "bounded real-source fixture search");
    assert!(steps <= crate::intake::MAX_CLOSURE_STEPS);

    let questions = crate::question::LocalQuestions::new(Some(crate::mocks::assess_interest));
    let (snapshot, policy) = questions.context_key(&graph);
    let binding = jobs::Binding::new(snapshot, policy);
    let input = jobs::Input::Find { cursor: 0 };
    let request = Request::build(
        &input,
        &binding,
        &graph,
        OwnerContext::Unavailable {
            reason: "regression fixture has no owner profile".into(),
        },
    )
    .unwrap();
    let context = &request.checked_context;
    assert_eq!(context.references.len(), wanted + 1);
    let helper_position = context
        .references
        .iter()
        .position(|reference| reference.proof.proof_id == helper_id)
        .unwrap();
    assert_eq!(helper_position, wanted);
    assert!(
        context.references[..helper_position]
            .iter()
            .all(|reference| reference.dependencies == [helper_id.clone()])
    );
    assert!(serde_json::to_vec(&request).unwrap().len() < MAX_REQUEST_BYTES);

    request.recheck(&input, &binding).unwrap();
    // Exercise the recovery boundary with exact serialized bytes as well as
    // the already constructed immutable value; no fixture fact is trusted.
    let recovered: Request =
        serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
    recovered.recheck(&input, &binding).unwrap();
    assert_eq!(recovered, request);
}
