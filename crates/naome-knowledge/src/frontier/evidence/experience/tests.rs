use super::*;
use crate::learning::experience::{Budget, Capacity, NoSearch, TraceBinding};
use crate::{checkpoint::tests::Directory, frontier::Frontier};

fn reseal(summary: &mut ExperienceSummary) {
    summary.receipt.clear();
    summary.receipt = crate::learning::digest(summary);
}

fn observed(
    question: &CompiledQuestion,
    terminal: TerminalEvidence,
    expansions: usize,
    frontier: Option<crate::learning::SearchFrontier>,
) -> jobs::Completion {
    observed_completion(question, 1, terminal, expansions, frontier)
}

/// Explicit synthetic search receipt for tests of Finder scheduling and storage.
/// This fixture is never a measured search result or model-quality observation.
pub(crate) fn observed_completion(
    question: &CompiledQuestion,
    job: u64,
    terminal: TerminalEvidence,
    expansions: usize,
    frontier: Option<crate::learning::SearchFrontier>,
) -> jobs::Completion {
    let state = crate::learning::State::fresh();
    let checkpoint = state.feedback().checkpoint;
    let binding = jobs::Binding::new([1; 32], [2; 32]);
    let mut summary = ExperienceSummary {
        job,
        question: crate::hex(question.resolution_id()),
        checkpoint: checkpoint.clone(),
        policy: crate::learning::input_specification(),
        request_binding: crate::learning::digest(&binding),
        native_context: crate::learning::digest(&state),
        origin: crate::learning::Origin::Local,
        terminal: terminal.clone(),
        trace: TraceBinding {
            observed_execution: None,
            checked_trajectory: None,
            observed_branches: frontier.as_ref().map(crate::learning::digest),
        },
        cost: Some(crate::learning::GenerationCost {
            search_expansions: expansions,
            ..Default::default()
        }),
        search_limit: 128,
        spent_ms: 7,
        reserved_units: 1,
        receipt: String::new(),
    };
    reseal(&mut summary);
    summary.validate().unwrap();
    jobs::Completion {
        id: job,
        experience: Some(summary),
        model_checkpoint: Some(checkpoint),
        binding,
        spent_ms: 7,
        reserved_units: 1,
        state: jobs::State::Complete,
        result: Ok(jobs::Output::Native {
            solution: None,
            terminal: Box::new(terminal),
            diagnostic: "deliberately unrelated diagnostic text".into(),
            frontier,
        }),
    }
}

fn settings() -> jobs::Settings {
    jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    }
}

#[test]
fn unknown_or_technical_work_does_not_teach_failure_or_open_a_helper_plan() {
    let (goal, _) = crate::learning::tests::helper_goal();
    for (terminal, expansions) in [
        (TerminalEvidence::Unknown, 128),
        (TerminalEvidence::TechnicalFailure, 1),
        (TerminalEvidence::CheckerRejected, 1),
        (TerminalEvidence::Interrupted, 1),
        (TerminalEvidence::Unsupported(Capacity::Graph), 1),
        (TerminalEvidence::NoSearch(NoSearch::ReservedQuestion), 0),
        (TerminalEvidence::Budget(Budget::Depth), 0),
    ] {
        let directory = Directory::new();
        let graph = Graph::default();
        let mut finder = Frontier::open(&directory.0, &graph, 41, settings()).unwrap();
        let before = finder.learning_snapshot();
        let completion = observed(&goal, terminal, expansions, None);
        finder
            .attempted(&goal, &graph, &completion, Outcome::NoCandidate)
            .unwrap();
        assert_eq!(finder.learning_snapshot(), before);
        assert!(!finder.helpers_needed(&goal).unwrap());
        assert!(finder.goals.is_empty());
        let stored = finder.evidence.get(&goal).unwrap().unwrap();
        assert_eq!(stored.spent_ms, completion.spent_ms);
        assert_eq!(
            stored.experience.unwrap().receipt,
            completion.experience.unwrap().receipt
        );
    }
}

#[test]
fn missing_experience_does_not_invent_a_native_search_outcome() {
    let (goal, _) = crate::learning::tests::helper_goal();
    let directory = Directory::new();
    let graph = Graph::default();
    let mut finder = Frontier::open(&directory.0, &graph, 41, settings()).unwrap();
    let mut completion = observed(
        &goal,
        TerminalEvidence::Budget(Budget::Expansions),
        128,
        None,
    );
    completion.experience = None;
    let before = finder.learning_snapshot();
    finder
        .attempted(&goal, &graph, &completion, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(finder.learning_snapshot(), before);
    assert!(!finder.helpers_needed(&goal).unwrap());
}

#[test]
fn observed_budget_receipt_is_durable_idempotent_and_keeps_its_original_context() {
    let (goal, _) = crate::learning::tests::helper_goal();
    let directory = Directory::new();
    let graph = Graph::default();
    let mut finder = Frontier::open(&directory.0, &graph, 41, settings()).unwrap();
    let completion = observed(
        &goal,
        TerminalEvidence::Budget(Budget::Expansions),
        128,
        Some(crate::learning::tests::stalled_frontier(&goal)),
    );
    crate::checkpoint::fail_next_commit();
    assert!(
        finder
            .attempted(&goal, &graph, &completion, Outcome::NoCandidate)
            .is_err()
    );
    assert!(finder.evidence.get(&goal).unwrap().is_none());
    finder
        .attempted(&goal, &graph, &completion, Outcome::NoCandidate)
        .unwrap();
    let learned = finder.learning_snapshot();
    assert_eq!(learned["model"]["unresolved"], 1);
    assert!(finder.helpers_needed(&goal).unwrap());
    finder
        .attempted(&goal, &graph, &completion, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(finder.learning_snapshot(), learned);
    let receipt = completion.experience.as_ref().unwrap();
    drop(finder);
    let finder = Frontier::open(&directory.0, &graph, 99, settings()).unwrap();
    assert_eq!(finder.learning_snapshot(), learned);
    let restored = finder
        .evidence
        .get(&goal)
        .unwrap()
        .unwrap()
        .experience
        .unwrap();
    assert_eq!(restored.receipt, receipt.receipt);
    assert_eq!(restored.native_context, receipt.native_context);
    assert_eq!(restored.request_binding, receipt.request_binding);
    assert_eq!(restored.search_limit, 128);
}

#[test]
fn substituted_completion_bindings_fail_before_learning_or_helper_admission() {
    let (goal, _) = crate::learning::tests::helper_goal();
    let original = observed(
        &goal,
        TerminalEvidence::Budget(Budget::Expansions),
        128,
        Some(crate::learning::tests::stalled_frontier(&goal)),
    );
    for field in 0..9 {
        let directory = Directory::new();
        let graph = Graph::default();
        let mut finder = Frontier::open(&directory.0, &graph, 41, settings()).unwrap();
        let before = finder.learning_snapshot();
        let mut changed = original.clone();
        let summary = changed.experience.as_mut().unwrap();
        match field {
            0 => summary.job += 1,
            1 => summary.question = "22".repeat(32),
            2 => summary.checkpoint = "22".repeat(32),
            3 => summary.policy = "22".repeat(32),
            4 => summary.request_binding = "22".repeat(32),
            5 => summary.spent_ms += 1,
            6 => summary.reserved_units += 1,
            7 => summary.terminal = TerminalEvidence::Unknown,
            _ => summary.trace.observed_branches = None,
        }
        reseal(summary);
        assert!(
            finder
                .attempted(&goal, &graph, &changed, Outcome::NoCandidate)
                .is_err(),
            "field {field}"
        );
        assert_eq!(finder.learning_snapshot(), before);
        assert!(finder.evidence.get(&goal).unwrap().is_none());
        assert!(!finder.helpers_needed(&goal).unwrap());
    }
}

#[test]
fn an_existing_receipt_cannot_be_replaced_or_reclassified() {
    let (goal, _) = crate::learning::tests::helper_goal();
    let directory = Directory::new();
    let graph = Graph::default();
    let mut finder = Frontier::open(&directory.0, &graph, 41, settings()).unwrap();
    let original = observed(&goal, TerminalEvidence::PolicyExhausted, 1, None);
    assert!(
        finder
            .attempted(&goal, &graph, &original, Outcome::Candidate)
            .is_err()
    );
    finder
        .attempted(&goal, &graph, &original, Outcome::NoCandidate)
        .unwrap();
    let before = finder.learning_snapshot();
    let mut changed = original.clone();
    changed.spent_ms += 1;
    let summary = changed.experience.as_mut().unwrap();
    summary.spent_ms = changed.spent_ms;
    reseal(summary);
    assert!(
        finder
            .attempted(&goal, &graph, &changed, Outcome::NoCandidate)
            .is_err()
    );
    assert_eq!(finder.learning_snapshot(), before);
    assert_eq!(
        finder
            .evidence
            .get(&goal)
            .unwrap()
            .unwrap()
            .experience
            .unwrap()
            .receipt,
        original.experience.unwrap().receipt
    );
}
