use super::*;
use crate::learning::experience::{ExperienceSummary, TerminalEvidence, TraceBinding};

fn observation(
    job: u64,
    held_out: bool,
    signal: u8,
    knowledge: u8,
) -> (Decision, ExperienceSummary) {
    let mut resolution = [job as u8; 32];
    resolution[0] = u8::from(!held_out);
    let mut features = Projection::default();
    features.syntax[1] = signal;
    let decision = Decision {
        resolution,
        knowledge: [knowledge; 32],
        goal: None,
        finder_draw: job,
        finder_updates: 0,
        checked_inputs: false,
        forecast: None,
        work_units: 128,
        horizon_ms: 3_000,
        features,
    };
    let receipt = ExperienceSummary {
        job,
        question: crate::hex(&resolution),
        checkpoint: "13".repeat(32),
        policy: String::new(),
        request_binding: String::new(),
        native_context: String::new(),
        origin: crate::learning::Origin::Local,
        terminal: TerminalEvidence::Unknown,
        trace: TraceBinding {
            observed_execution: None,
            checked_trajectory: None,
            observed_branches: None,
        },
        cost: None,
        search_limit: 128,
        spent_ms: 0,
        reserved_units: 1,
        receipt: String::new(),
    };
    (decision, receipt)
}

fn batch(policy: &mut Policy, start: u64, matched: bool, inverse_validation: bool) -> Decision {
    let mut chosen = None;
    for offset in 0..8 {
        let held_out = offset >= 4;
        let checked = offset % 2 == 0;
        let signal = if checked ^ (held_out && inverse_validation) {
            220
        } else {
            12
        };
        let knowledge = if matched {
            1 + u8::from(offset >= 6)
        } else if checked {
            1
        } else {
            2
        };
        let (decision, receipt) = observation(start + offset, held_out, signal, knowledge);
        policy.observe(&decision, &receipt, checked).unwrap();
        if checked {
            chosen = Some(decision);
        }
    }
    chosen.unwrap()
}

#[test]
fn candidate_needs_matched_disjoint_validation_and_retains_previous_checkpoint() {
    let mut different_catalogues = Policy::default();
    let goal = batch(&mut different_catalogues, 1, false, false);
    assert_eq!(different_catalogues.multiplier(&goal), 1024);
    assert!(!different_catalogues.active());

    let mut wrong_order = Policy::default();
    batch(&mut wrong_order, 1, true, true);
    assert!(!wrong_order.active());

    let mut accepted = Policy::default();
    batch(&mut accepted, 1, true, false);
    assert!(accepted.active());
    assert_eq!(accepted.validation_pairs, 2);
    assert_eq!(accepted.protected.len(), 2);
    assert!(accepted.multiplier(&goal) > 1024);

    let weights = accepted.weights;
    let encoded = serde_json::to_vec(&accepted).unwrap();
    let mut reopened: Policy = serde_json::from_slice(&encoded).unwrap();
    reopened.validate().unwrap();
    batch(&mut reopened, 9, true, true);
    assert_eq!(reopened.weights, weights);
    assert_eq!(reopened.promotions, 1);
    reopened.validate().unwrap();
}

#[test]
fn validation_keeps_independent_pairs_when_new_outcomes_fill_both_groups() {
    let mut policy = Policy::default();
    let mut job = 1;
    let mut add = |policy: &mut Policy, knowledge, checked| {
        let (decision, receipt) = observation(job, true, if checked { 220 } else { 12 }, knowledge);
        policy.observe(&decision, &receipt, checked).unwrap();
        job += 1;
    };
    for knowledge in [1, 2] {
        add(&mut policy, knowledge, true);
        add(&mut policy, knowledge, false);
    }
    for offset in 0..(2 * PER_GROUP) as u8 {
        add(&mut policy, 10 + offset, true);
        add(&mut policy, 100 + offset, false);
    }
    add(&mut policy, 3, true);
    add(&mut policy, 3, false);

    let bytes = serde_json::to_vec(&policy).unwrap();
    let reopened: Policy = serde_json::from_slice(&bytes).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened.transitions.len(), 2 * PER_GROUP);
    assert_eq!(
        reopened
            .pairs(true)
            .into_iter()
            .map(|(checked, _)| checked.decision.knowledge[0])
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn real_reuse_upgrades_an_exact_earlier_job_without_replaying_the_label() {
    let mut policy = Policy::default();
    let (decision, receipt) = observation(13, false, 65, 2);
    policy.observe(&decision, &receipt, true).unwrap();
    policy.reused(&decision, &receipt).unwrap();
    policy.reused(&decision, &receipt).unwrap();
    assert_eq!(policy.transitions.len(), 1);
    assert_eq!(policy.transitions[0].outcome, Outcome::Reused);
    assert_eq!(policy.observations, 2);
    policy.validate().unwrap();
}

#[test]
fn captures_the_full_canonical_shape_and_the_context_at_the_draw() {
    let question =
        naome_checker::question::ResearchQuestion::from_hex("040001000000000100000000").unwrap();
    let descriptor = Descriptor::of(&question);
    let context = [19; CONTEXT];
    let decision = Decision::new(
        *question.resolution_id(),
        [22; 32],
        None,
        &descriptor,
        context,
        (9, 3),
        crate::jobs::Limits::default(),
    );
    assert!(decision.features.syntax[25] > 0);
    assert_eq!(
        decision.features.syntax,
        descriptor.features.counts.map(magnitude)
    );
    assert_eq!(&decision.features.context[2 + BINDINGS..], &context);
    assert_eq!(decision.features.values().count(), WIDTH);
}

#[test]
fn solver_ability_keeps_its_resolution_in_the_durable_context() {
    use crate::{Graph, checkpoint::tests::Directory, frontier::Frontier, jobs, training::ability};
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let question = naome_checker::question::ResearchQuestion::from_hex(
        "04040302040301010000000001000000020101000000000100000001040301010000000001000000010101000000000100000002",
    )
    .unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 19, settings).unwrap();
    let feedback = crate::learning::State::fresh().feedback();
    let raw = feedback.priority(&question, 128);
    assert!(raw > 16 * 255 && raw < ability::PRIORITY_SCALE);
    frontier.feedback(Some(feedback));
    let decision = frontier
        .research_decision(&question, &graph, settings.solving.limits, false)
        .unwrap();
    let encoded = decision.features.context[2 + BINDINGS + 10];
    assert_eq!(u64::from(encoded), raw * 255 / ability::PRIORITY_SCALE);
}
