//! Three replaceable deterministic producers/selectors. Checking is never mocked.
use naome_authoring::CompiledQuestion;

const CATALOG: [(&str, &str); 3] = [
    (
        "foundation = \"naome:zfc\" statement = forall(x,equal(x,x))",
        "foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) return p1",
    ),
    (
        "foundation = \"naome:zfc\" statement = forall(x,implies(member(x,x),member(x,x)))",
        "foundation = \"naome:zfc\" formulas: a = member(x,x) b = implies(a,a) statement = forall(x,b) proof: p0 = simplification(a,a) p1 = simplification(a,b) p2 = frege(a,b,a) p3 = modus_ponens(p1,p2) p4 = modus_ponens(p0,p3) p5 = generalization(p4,x) return p5",
    ),
    (
        "foundation = \"naome:zfc\" statement = forall(x,forall(y,forall(set,implies(equal(x,y),implies(member(x,set),member(y,set))))))",
        "foundation = \"naome:zfc\" statement = forall(x,forall(y,forall(set,implies(equal(x,y),implies(member(x,set),member(y,set)))))) proof: p0 = equality_substitution(x,y,member(x,set)) p1 = generalization(p0,set) p2 = generalization(p1,y) p3 = generalization(p2,x) return p3",
    ),
];

/// Repeated calls cycle through a tiny fixed catalog; the cursor is runtime-owned.
pub fn create_question(cursor: u64) -> String {
    CATALOG[cursor as usize % CATALOG.len()].0.to_owned()
}

/// Unsupported questions have no candidate. This does not establish proof validity.
pub fn create_proof(question: &CompiledQuestion) -> Option<String> {
    CATALOG.iter().find_map(|(source, proof)| {
        let candidate = CompiledQuestion::compile(source).expect("fixed mock question source");
        (candidate == *question).then(|| (*proof).to_owned())
    })
}

/// Placeholder interest selection, called only after the real formal prefilter.
pub fn assess_interest(_: CompiledQuestion) -> std::future::Ready<Result<bool, String>> {
    std::future::ready(Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Graph, question};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn every_catalog_pair_is_formally_admissible_and_really_checked() {
        for cursor in 0..CATALOG.len() {
            let question = CompiledQuestion::compile(&create_question(cursor as u64)).unwrap();
            let mut graph = Graph::default();
            let mut questions = question::LocalQuestions::new(Some(assess_interest));
            let (_, receiver) = questions.begin_exchange(
                &graph,
                question.clone(),
                Instant::now() + Duration::from_secs(5),
            );
            let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
                .await
                .unwrap();
            questions.finish(&graph, interest);
            let assessment = receiver.await.unwrap();
            assert!(
                assessment.prefilter.passed(),
                "{:?}",
                assessment.prefilter.reason
            );
            assert!(assessment.novelty().is_some());
            let candidate = graph
                .author(&create_proof(&question).unwrap())
                .unwrap()
                .prepare()
                .unwrap();
            let root = candidate.id;
            let batch = graph
                .prepare_batch(root, [(root, candidate)].into(), &question)
                .unwrap();
            assert_eq!(graph.apply_batch(batch), vec![root]);
            assert_eq!(graph.ids().len(), 1);
        }
    }

    #[tokio::test]
    async fn catalog_remains_admissible_in_every_cyclic_order_as_knowledge_grows() {
        for offset in 0..CATALOG.len() {
            let mut graph = Graph::default();
            let mut questions = question::LocalQuestions::new(Some(assess_interest));
            for cursor in offset..offset + CATALOG.len() {
                let question = CompiledQuestion::compile(&create_question(cursor as u64)).unwrap();
                let (_, receiver) = questions.begin_exchange(
                    &graph,
                    question.clone(),
                    Instant::now() + Duration::from_secs(5),
                );
                if !questions.available() {
                    let interest =
                        tokio::time::timeout(Duration::from_secs(5), questions.completed())
                            .await
                            .unwrap();
                    questions.finish(&graph, interest);
                }
                let assessment = receiver.await.unwrap();
                assert!(
                    assessment.prefilter.passed(),
                    "offset {offset}, cursor {cursor}: {:?}",
                    assessment.prefilter.reason
                );
                let candidate = graph
                    .author(&create_proof(&question).unwrap())
                    .unwrap()
                    .prepare()
                    .unwrap();
                let root = candidate.id;
                let batch = graph
                    .prepare_batch(root, [(root, candidate)].into(), &question)
                    .unwrap();
                let delta = questions
                    .prepare_exchange(&graph, &question, &assessment)
                    .unwrap();
                graph.apply_batch(batch);
                questions.apply_exchange(delta);
            }
            assert_eq!(graph.ids().len(), CATALOG.len());
        }
    }
}
