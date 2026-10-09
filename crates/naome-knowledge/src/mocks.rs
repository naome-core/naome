//! Three replaceable deterministic producers/selectors. Checking is never mocked.
use naome_authoring::CompiledQuestion;

const CATALOG: [(&str, &str); 3] = [
    (
        "goal = all(x,eq(x,x))",
        "goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1",
    ),
    (
        "goal = all(x,imp(mem(x,x),mem(x,x)))",
        "let: a = mem(x,x) b = imp(a,a) goal = all(x,b) proof: p0 = simp(a,a) p1 = simp(a,b) p2 = frege(a,b,a) p3 = mp(p1,p2) p4 = mp(p0,p3) p5 = gen(p4,x) return p5",
    ),
    (
        "goal = all(x,all(y,all(set,imp(eq(x,y),imp(mem(x,set),mem(y,set))))))",
        "goal = all(x,all(y,all(set,imp(eq(x,y),imp(mem(x,set),mem(y,set)))))) proof: p0 = subst(x,y,mem(x,set)) p1 = gen(p0,set) p2 = gen(p1,y) p3 = gen(p2,x) return p3",
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
