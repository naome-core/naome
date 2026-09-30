use super::*;
use crate::journal::Journal;
use crate::scenario::{equality_answer, equality_question, refutation_answer, refutation_question};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

// These fixed seeds are reproducible test identities, never secret credentials.
struct Harness {
    coordinator: SigningKey,
    participants: [SigningKey; 3],
    state: ResearchState,
}

impl Harness {
    fn new(pool: PoolConfig) -> Self {
        let coordinator = SigningKey::from_bytes(&[11; 32]);
        let participants = [12, 13, 14].map(|seed| SigningKey::from_bytes(&[seed; 32]));
        let genesis = Genesis::new(
            "signed-state-fixture-v1".into(),
            coordinator.verifying_key().to_bytes(),
            participants
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            pool,
        )
        .unwrap();
        let genesis = SignedGenesis::sign(genesis, &coordinator).unwrap();
        Self {
            coordinator,
            participants,
            state: ResearchState::new(genesis).unwrap(),
        }
    }

    fn signed(&self, participant: usize, action: Action) -> SignedAction {
        let key = &self.participants[participant];
        SignedAction::sign(
            self.state.genesis().genesis.id(),
            self.state.next_nonce(key.verifying_key().to_bytes()),
            action,
            key,
        )
    }

    fn accept(&mut self, participant: usize, action: Action) -> Event {
        self.state
            .confirm(self.signed(participant, action), &self.coordinator)
            .unwrap()
    }

    fn reject(&mut self, participant: usize, action: Action) -> String {
        self.reject_signed(self.signed(participant, action))
    }

    fn reject_signed(&mut self, action: SignedAction) -> String {
        let before = snapshot(&self.state);
        let error = self
            .state
            .confirm(action, &self.coordinator)
            .expect_err("adversarial action must fail");
        assert_eq!(
            snapshot(&self.state),
            before,
            "rejected actions cannot reserve order, consume nonces, or change research state"
        );
        error
    }

    fn publish(&mut self, question: Question) -> Id {
        let id = question.id().unwrap();
        self.accept(0, Action::Publish { question });
        id
    }

    fn vote(&mut self, participant: usize, question: Id, yes: bool) {
        self.accept(participant, Action::Vote { question, yes });
    }

    fn tick(&mut self) {
        let action = SignedAction::sign(
            self.state.genesis().genesis.id(),
            self.state
                .next_nonce(self.coordinator.verifying_key().to_bytes()),
            Action::Tick,
            &self.coordinator,
        );
        let event = self.state.confirm(action, &self.coordinator).unwrap();
        assert!(
            event.body.result.is_none(),
            "management entries never become result blocks"
        );
    }

    fn publish_eligible(&mut self, count: u32) -> Vec<Id> {
        (0..count)
            .map(|index| {
                let id = self.publish(equality_question(index));
                self.vote(0, id, true);
                id
            })
            .collect()
    }

    fn answer(&mut self, participant: usize, id: Id, index: u32) -> Event {
        self.accept(
            participant,
            Action::Answer {
                question: id,
                outcome: Outcome::Proof,
                file: equality_answer(index),
            },
        )
    }
}

fn snapshot(state: &ResearchState) -> serde_json::Value {
    json!({
        "genesis":state.genesis(),
        "events":state.events(),
        "questions":state.questions.iter().collect::<Vec<_>>(),
        "votes":state.votes.iter().collect::<Vec<_>>(),
        "nonces":state.nonces.iter().collect::<Vec<_>>(),
        "active":state.active(),
        "results":state.results(),
        "target":state.target(),
        "tick":state.tick(),
        "drought":state.drought,
        "last_adjustment":state.last_adjustment,
        "recent_results":state.recent_results,
        "enabled":state.enabled,
        "answered_interval":state.answered_interval,
        "history_bytes":state.history_bytes,
    })
}

fn answer_action(question: Id, file: AnswerFile) -> Action {
    Action::Answer {
        question,
        outcome: Outcome::Proof,
        file,
    }
}

#[test]
fn signatures_genesis_roster_and_nonces_are_enforced_atomically() {
    let mut h = Harness::new(PoolConfig::default());
    let question = equality_question(0);
    let mut tampered = h.signed(
        0,
        Action::Publish {
            question: question.clone(),
        },
    );
    tampered.body.nonce += 1;
    assert!(h.reject_signed(tampered).contains("signature"));
    let mut tampered = h.signed(
        0,
        Action::Publish {
            question: question.clone(),
        },
    );
    tampered.signature[0] ^= 1;
    assert!(h.reject_signed(tampered).contains("signature"));
    let wrong_genesis = SignedAction::sign(
        [1; 32],
        1,
        Action::Publish {
            question: question.clone(),
        },
        &h.participants[0],
    );
    assert!(h.reject_signed(wrong_genesis).contains("genesis"));
    let future_nonce = SignedAction::sign(
        h.state.genesis().genesis.id(),
        2,
        Action::Publish {
            question: question.clone(),
        },
        &h.participants[0],
    );
    assert!(h.reject_signed(future_nonce).contains("nonce"));
    let unregistered = SigningKey::from_bytes(&[15; 32]);
    let unknown = SignedAction::sign(
        h.state.genesis().genesis.id(),
        1,
        Action::Publish {
            question: question.clone(),
        },
        &unregistered,
    );
    assert!(h.reject_signed(unknown).contains("unregistered"));
    let previous = h.signed(
        0,
        Action::Publish {
            question: question.clone(),
        },
    );
    let event = h.accept(
        0,
        Action::Publish {
            question: question.clone(),
        },
    );
    let before = snapshot(&h.state);
    assert_eq!(
        h.state.confirm(previous, &h.coordinator).unwrap(),
        event,
        "exact retransmission returns the immutable receipt"
    );
    assert_eq!(snapshot(&h.state), before);
    let stale_different_action = SignedAction::sign(
        h.state.genesis().genesis.id(),
        1,
        Action::Vote {
            question: question.id().unwrap(),
            yes: true,
        },
        &h.participants[0],
    );
    assert!(h.reject_signed(stale_different_action).contains("nonce"));
    assert!(h.reject(0, Action::Tick).contains("coordinator"));
    h.tick();
    assert_eq!(h.state.tick(), 1);
    let action = h.signed(
        1,
        Action::Vote {
            question: equality_question(0).id().unwrap(),
            yes: true,
        },
    );
    let before = snapshot(&h.state);
    assert!(h.state.confirm(action, &unregistered).is_err());
    assert_eq!(snapshot(&h.state), before);

    let mut genesis = h.state.genesis().clone();
    genesis.genesis.run_label.push_str("modified");
    assert!(ResearchState::new(genesis).is_err());
    let mut duplicate_roster = h.state.genesis().genesis.participants.clone();
    duplicate_roster.push(duplicate_roster[0]);
    assert!(
        Genesis::new(
            "duplicate-roster".into(),
            h.coordinator.verifying_key().to_bytes(),
            duplicate_roster,
            PoolConfig::default()
        )
        .is_err()
    );
}

#[test]
fn question_identity_ignores_wording_and_bound_variable_names() {
    let mut h = Harness::new(PoolConfig::default());
    let question = equality_question(0);
    let id = h.publish(question.clone());
    let mut alias = question;
    alias.title = "Another description of the same theorem".into();
    alias.context = "Alternate explanatory wording.".into();
    alias.formula = FormulaInput::Forall {
        variable: 987,
        body: Box::new(FormulaInput::Equal {
            left: 987,
            right: 987,
        }),
    };
    assert_eq!(alias.id().unwrap(), id);
    assert!(
        h.reject(1, Action::Publish { question: alias })
            .contains("duplicate")
    );
    let mut open = equality_question(0);
    open.formula = FormulaInput::Equal { left: 0, right: 0 };
    assert!(
        h.reject(1, Action::Publish { question: open })
            .contains("closed")
    );
    let mut invented_context = equality_question(1);
    invented_context.definitions.push(equality_answer(0).source);
    assert!(
        h.reject(
            1,
            Action::Publish {
                question: invented_context
            }
        )
        .contains("conservative definitions")
    );
    h.publish(equality_question(1));
    assert_eq!(h.state.questions().len(), 2);
    assert!(h.state.active().is_empty());
    assert!(h.state.results().is_empty());
}

#[test]
fn boolean_revisions_upvote_order_and_sticky_active_leases_are_distinct() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(4);
    // No admission occurs until Tick; boost a known initial pair first.
    for id in &ids[..2] {
        h.vote(1, *id, true);
    }
    assert!(h.state.active().is_empty());
    h.tick();
    assert_eq!(h.state.active(), &BTreeSet::from([ids[0], ids[1]]));
    h.vote(1, ids[2], false);
    assert_eq!(h.state.yes_count(ids[2]), 1);
    assert_eq!(
        h.state
            .vote(h.participants[2].verifying_key().to_bytes(), ids[2]),
        None
    );
    h.vote(1, ids[2], true);
    h.vote(2, ids[2], true);
    assert_eq!(h.state.yes_count(ids[2]), 3);
    assert_eq!(h.state.ranked_candidates(), vec![ids[2], ids[3]]);
    h.vote(0, ids[0], false);
    h.vote(1, ids[0], false);
    assert_eq!(h.state.yes_count(ids[0]), 0);
    assert!(h.state.active().contains(&ids[0]));
    assert!(
        h.reject(
            1,
            Action::Vote {
                question: ids[0],
                yes: false
            }
        )
        .contains("unchanged")
    );
    h.tick();
    assert!(
        h.state.active().contains(&ids[0]),
        "ranking cannot preempt existing leases"
    );
    assert!(!h.state.active().contains(&ids[2]));

    h.vote(0, ids[2], false);
    h.vote(1, ids[2], false);
    h.vote(2, ids[2], false);
    assert_eq!(h.state.ranked_candidates(), vec![ids[3]]);
    assert_eq!(
        h.state.questions().len(),
        4,
        "irrelevant unanswered questions remain stored"
    );
}

#[test]
fn tied_candidates_use_stable_canonical_identity() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(4);
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(h.state.ranked_candidates(), sorted);
    h.tick();
    assert_eq!(h.state.active(), &BTreeSet::from([sorted[0], sorted[1]]));
    assert_eq!(h.state.ranked_candidates(), sorted[2..]);
}

#[test]
fn invalid_or_inactive_answers_do_not_reserve_a_winner_or_poison_artifacts() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(3);
    h.vote(1, ids[0], true);
    h.vote(1, ids[1], true);
    assert!(
        h.reject(2, answer_action(ids[0], equality_answer(0)))
            .contains("active")
    );
    assert!(
        h.reject(2, answer_action([42; 32], equality_answer(0)))
            .contains("active")
    );
    h.tick();
    assert!(
        h.reject(2, answer_action(ids[2], equality_answer(2)))
            .contains("active")
    );
    let mut invalid = equality_answer(0);
    invalid.source = invalid
        .source
        .replace("equality_reflexivity(x0)", "axiom(equal(x0, x0))");
    h.reject(2, answer_action(ids[0], invalid));
    let mut wrong = equality_answer(1);
    wrong.dependencies.push(equality_answer(0).source);
    assert!(
        h.reject(2, answer_action(ids[0], wrong))
            .contains("exactly match")
    );
    let before_index = h.state.events().len() as u64;
    let event = h.answer(1, ids[0], 0);
    assert_eq!(event.body.index, before_index);
    assert_eq!(
        event.body.result.as_ref().unwrap().confirmation_index,
        before_index
    );
    assert_eq!(h.state.results().len(), 1);
    assert_eq!(
        h.state.results()[0].winner,
        h.participants[1].verifying_key().to_bytes()
    );
    assert!(
        !h.state.active().contains(&ids[2]),
        "Answer does not refill a vacancy outside Tick"
    );
    assert!(
        h.reject(2, answer_action(ids[0], equality_answer(0)))
            .contains("active")
    );
    assert!(
        h.reject(
            2,
            Action::Vote {
                question: ids[0],
                yes: true
            }
        )
        .contains("unanswered")
    );
    h.vote(2, ids[1], true);
    h.tick();
    assert!(h.state.active().contains(&ids[2]));
}

#[test]
fn competing_fully_valid_copies_win_only_in_confirmed_order() {
    let mut h = Harness::new(PoolConfig::default());
    let id = h.publish(equality_question(0));
    h.vote(0, id, true);
    h.tick();
    let a = h.signed(1, answer_action(id, equality_answer(0)));
    let b = h.signed(2, answer_action(id, equality_answer(0)));
    let mut reversed = h.state.clone();
    h.state.confirm(a.clone(), &h.coordinator).unwrap();
    h.reject_signed(b.clone());
    reversed.confirm(b, &h.coordinator).unwrap();
    assert!(reversed.confirm(a, &h.coordinator).is_err());
    assert_eq!(
        h.state.results()[0].winner,
        h.participants[1].verifying_key().to_bytes()
    );
    assert_eq!(
        reversed.results()[0].winner,
        h.participants[2].verifying_key().to_bytes()
    );
    assert_eq!(
        h.state.results()[0].canonical_proof,
        reversed.results()[0].canonical_proof
    );
    assert_eq!(h.state.results().len(), 1);
    assert_eq!(reversed.results().len(), 1);
}

#[test]
fn proof_and_formal_refutation_have_exact_separate_targets() {
    let mut h = Harness::new(PoolConfig::default());
    let proof = h.publish(equality_question(0));
    let refutation = h.publish(refutation_question());
    h.vote(0, proof, true);
    h.vote(1, refutation, true);
    h.tick();
    assert!(
        h.reject(1, answer_action(refutation, refutation_answer()))
            .contains("exactly match")
    );
    assert!(
        h.reject(
            1,
            Action::Answer {
                question: proof,
                outcome: Outcome::Refutation,
                file: equality_answer(0)
            }
        )
        .contains("exactly match")
    );
    h.answer(1, proof, 0);
    h.accept(
        2,
        Action::Answer {
            question: refutation,
            outcome: Outcome::Refutation,
            file: refutation_answer(),
        },
    );
    assert_eq!(
        h.state
            .results()
            .iter()
            .map(|block| block.outcome)
            .collect::<Vec<_>>(),
        vec![Outcome::Proof, Outcome::Refutation]
    );
    assert_eq!(h.state.results()[0].height, 1);
    assert_eq!(h.state.results()[1].height, 2);
    assert_eq!(
        h.state.results()[0].previous,
        h.state.genesis().genesis.id()
    );
    assert_eq!(h.state.results()[1].previous, h.state.results()[0].id());
    let before = h.state.results().to_vec();
    h.tick();
    assert_eq!(h.state.results(), before);
}

#[test]
fn drought_growth_requires_enabled_intervals_and_waiting_candidates() {
    let mut h = Harness::new(PoolConfig::default());
    for _ in 0..6 {
        h.tick();
    }
    assert_eq!(h.state.target(), 2);
    let ids = h.publish_eligible(6);
    h.vote(1, ids[0], true);
    h.vote(1, ids[1], true);
    h.vote(1, ids[2], true);
    h.vote(2, ids[2], true);
    h.tick();
    assert_eq!(
        h.state.target(),
        2,
        "initial admission is not a drought interval"
    );
    for _ in 0..2 {
        h.tick();
        assert_eq!(h.state.target(), 2);
    }
    h.tick();
    assert_eq!(h.state.target(), 3);
    assert!(h.state.active().contains(&ids[2]));
    for _ in 0..2 {
        h.tick();
        assert_eq!(
            h.state.target(),
            3,
            "adjustment cooldown is three Tick boundaries"
        );
    }
    h.tick();
    assert_eq!(h.state.target(), 4);
    for _ in 0..6 {
        h.tick();
    }
    assert_eq!(h.state.target(), 4, "maximum is a hard experimental bound");

    let mut no_backlog = Harness::new(PoolConfig::default());
    no_backlog.publish_eligible(2);
    for _ in 0..8 {
        no_backlog.tick();
    }
    assert_eq!(
        no_backlog.state.target(),
        2,
        "no eligible waiting candidate means no growth"
    );
}

#[test]
fn answers_reset_drought_and_shrink_only_at_tick_with_cooldown() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(5);
    for id in &ids[..2] {
        h.vote(1, *id, true);
    }
    h.vote(1, ids[2], true);
    h.vote(2, ids[2], true);
    for _ in 0..4 {
        h.tick();
    }
    assert_eq!(h.state.target(), 3);
    h.answer(1, ids[0], 0);
    h.answer(2, ids[1], 1);
    assert_eq!(h.state.target(), 3);
    assert_eq!(h.state.active().len(), 1);
    h.tick();
    assert_eq!(h.state.target(), 3);
    assert_eq!(h.state.active().len(), 3);
    h.tick();
    assert_eq!(h.state.target(), 3);
    h.tick();
    assert_eq!(h.state.target(), 2);
    assert_eq!(h.state.active().len(), 2);
    assert_eq!(
        h.state.ranked_candidates().len(),
        1,
        "least relevant lease is demoted, not deleted"
    );
    assert!(h.state.active().contains(&ids[2]));
    assert_eq!(h.state.questions().len(), 5);
    h.answer(0, ids[2], 2);
    h.tick();
    assert_eq!(
        h.state.target(),
        2,
        "no immediate reversal during shrink cooldown"
    );
    assert_eq!(h.state.questions().len() - h.state.results().len(), 2);
}

#[test]
fn quick_result_window_is_half_open_and_minimum_remains_bounded() {
    let mut h = Harness::new(PoolConfig {
        initial: 3,
        maximum: 3,
        ..PoolConfig::default()
    });
    let ids = h.publish_eligible(3);
    h.tick();
    h.answer(1, ids[0], 0); // result recorded at Tick 1.
    for _ in 0..3 {
        h.tick();
    }
    h.answer(2, ids[1], 1); // result recorded at Tick 4.
    assert_eq!(h.state.target(), 3);
    h.tick(); // trailing [2, 5) excludes the result at Tick 1.
    assert_eq!(
        h.state.target(),
        3,
        "old results outside the quick window cannot shrink the pool"
    );
    h.answer(0, ids[2], 2);
    h.tick(); // trailing [3, 6) contains results at Tick 4 and 5.
    assert_eq!(h.state.target(), 2);
    for _ in 0..6 {
        h.tick();
    }
    assert_eq!(h.state.target(), 2);
    assert!(h.state.active().is_empty());
    assert_eq!(h.state.results().len(), 3);
}

#[test]
fn replay_rejects_reordered_history_invalid_signatures_and_resigned_wrong_blocks() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(2);
    h.tick();
    h.answer(1, ids[0], 0);
    h.answer(2, ids[1], 1);
    let replay = ResearchState::replay(h.state.genesis().clone(), h.state.events()).unwrap();
    assert_eq!(snapshot(&replay), snapshot(&h.state));
    let mut reordered = h.state.events().to_vec();
    reordered.swap(0, 1);
    assert!(ResearchState::replay(h.state.genesis().clone(), &reordered).is_err());
    let mut invalid_signature = h.state.events().to_vec();
    invalid_signature[0].signature[0] ^= 1;
    assert!(ResearchState::replay(h.state.genesis().clone(), &invalid_signature).is_err());
    let result_index = h
        .state
        .events()
        .iter()
        .position(|event| event.body.result.is_some())
        .unwrap();
    let mut wrong_result = h.state.events()[..=result_index].to_vec();
    let event = wrong_result.last_mut().unwrap();
    event.body.result.as_mut().unwrap().winner = h.participants[2].verifying_key().to_bytes();
    event.signature = h.coordinator.sign(&event.id()).to_bytes().to_vec();
    let error = ResearchState::replay(h.state.genesis().clone(), &wrong_result)
        .err()
        .unwrap();
    assert!(error.contains("derived result block mismatch"));
    let mut wrong_result = h.state.events()[..=result_index].to_vec();
    let event = wrong_result.last_mut().unwrap();
    event.body.result.as_mut().unwrap().canonical_proof.push(0);
    event.signature = h.coordinator.sign(&event.id()).to_bytes().to_vec();
    assert!(ResearchState::replay(h.state.genesis().clone(), &wrong_result).is_err());
    let mut missing_result = h.state.events()[..=result_index].to_vec();
    let event = missing_result.last_mut().unwrap();
    event.body.result = None;
    event.signature = h.coordinator.sign(&event.id()).to_bytes().to_vec();
    assert!(ResearchState::replay(h.state.genesis().clone(), &missing_result).is_err());
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn cold_journal_restart_checks_result_history_and_rejects_external_tampering() {
    let mut h = Harness::new(PoolConfig::default());
    let ids = h.publish_eligible(2);
    h.tick();
    h.answer(1, ids[0], 0);
    let root = std::env::temp_dir().join(format!(
        "naome-research-state-journal-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let journal = Journal::create(&root, h.state.genesis()).unwrap();
    for event in h.state.events() {
        journal.append(event).unwrap();
    }
    assert!(journal.append(&h.state.events()[0]).is_err());
    let expected = snapshot(&h.state);
    let last = h.state.events().last().unwrap().clone();
    let expected_head = h.state.head();
    let expected_count = h.state.events().len();
    drop(h);
    let (_, restarted) = Journal::open_at(&root, expected_head, expected_count).unwrap();
    assert_eq!(snapshot(&restarted), expected);
    drop(restarted);
    let path = root.join(format!("event-{:06}.json", last.body.index));
    assert!(Journal::open_at(&root, [0; 32], expected_count).is_err());
    assert!(Journal::open_at(&root, expected_head, expected_count + 1).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(
        Journal::open(&root).is_ok(),
        "a valid prefix alone cannot reveal that the journal tail was deleted"
    );
    assert!(
        Journal::open_at(&root, expected_head, expected_count).is_err(),
        "the independent checkpoint detects valid-prefix truncation"
    );
    journal.append(&last).unwrap();
    assert!(Journal::open_at(&root, expected_head, expected_count).is_ok());
    let mut tampered = last;
    tampered.body.result.as_mut().unwrap().height += 1;
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(Journal::open(&root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
