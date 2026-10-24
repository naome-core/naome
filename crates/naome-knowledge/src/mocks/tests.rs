use super::*;
use crate::{Graph, question};
use std::time::{Duration, Instant};

#[tokio::test]
async fn every_catalog_pair_is_formally_admissible_and_really_checked() {
    for cursor in 0..CATALOG_SIZE {
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
        assert_eq!(
            graph
                .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
                .unwrap(),
            vec![root]
        );
        assert_eq!(graph.accepted_count(), 1);
    }
}

#[tokio::test]
async fn catalog_remains_admissible_in_every_cyclic_order_as_knowledge_grows() {
    for offset in 0..CATALOG_SIZE {
        let mut graph = Graph::default();
        let mut questions = question::LocalQuestions::new(Some(assess_interest));
        for cursor in offset..offset + CATALOG_SIZE {
            let question = CompiledQuestion::compile(&create_question(cursor as u64)).unwrap();
            let (_, receiver) = questions.begin_exchange(
                &graph,
                question.clone(),
                Instant::now() + Duration::from_secs(5),
            );
            if !questions.available() {
                let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
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
            graph
                .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
                .unwrap();
            questions.apply_exchange(delta).unwrap();
        }
        assert_eq!(graph.accepted_count(), CATALOG_SIZE);
    }
}
