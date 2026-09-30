//! Deterministic local fixtures; fixed keys never represent real participants.

use std::path::Path;

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::formal::{AnswerFile, FormulaInput, Outcome};
use crate::journal::Journal;
use crate::state::{
    Action, Genesis, PoolConfig, Question, ResearchState, SignedAction, SignedGenesis, hex,
};

/// Runs a bounded offline scenario and preserves its complete signed journal.
///
/// The directory must not exist. This fixture uses one honest local coordinator
/// and three deterministic signing identities, with no provider/model turns.
pub fn run_fixture(root: &Path) -> Result<Value, String> {
    let coordinator = SigningKey::from_bytes(&[71; 32]);
    let participants = [72, 73, 74].map(|seed| SigningKey::from_bytes(&[seed; 32]));
    let genesis = SignedGenesis::sign(
        Genesis::new(
            "deterministic-local-research-fixture-v1".into(),
            coordinator.verifying_key().to_bytes(),
            participants
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            PoolConfig::default(),
        )?,
        &coordinator,
    )?;
    let journal = Journal::create(root, &genesis)?;
    let mut state = ResearchState::new(genesis)?;
    let mut rejected = Vec::new();
    let questions = [
        equality_question(0),
        refutation_question(),
        equality_question(1),
        equality_question(2),
        equality_question(3),
    ];
    let ids = questions
        .iter()
        .map(Question::id)
        .collect::<Result<Vec<_>, _>>()?;
    for (index, question) in questions.iter().enumerate() {
        accept(
            &mut state,
            &journal,
            &coordinator,
            &participants[index % 3],
            Action::Publish {
                question: question.clone(),
            },
        )?;
    }

    let mut alternate_wording = questions[0].clone();
    alternate_wording.title = "A differently worded equality question".into();
    alternate_wording.context =
        "Presentation text does not change the exact closed formula.".into();
    reject(
        &mut state,
        &coordinator,
        &participants[1],
        Action::Publish {
            question: alternate_wording,
        },
        "duplicate question",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[0],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: equality_answer(0),
        },
        "inactive answer",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[0],
        Action::Answer {
            question: [91; 32],
            outcome: Outcome::Proof,
            file: equality_answer(0),
        },
        "unpublished answer",
        &mut rejected,
    )?;

    for id in &ids {
        accept(
            &mut state,
            &journal,
            &coordinator,
            &participants[0],
            Action::Vote {
                question: *id,
                yes: true,
            },
        )?;
    }
    ensure(
        state.active().is_empty(),
        "votes admitted questions outside a logical Tick",
    )?;
    // Explicitly rank the first two desired fixtures before initial admission.
    for id in &ids[..2] {
        accept(
            &mut state,
            &journal,
            &coordinator,
            &participants[1],
            Action::Vote {
                question: *id,
                yes: true,
            },
        )?;
    }
    accept(
        &mut state,
        &journal,
        &coordinator,
        &coordinator,
        Action::Tick,
    )?;
    ensure(
        state.active().contains(&ids[0]) && state.active().contains(&ids[1]),
        "initial Tick admitted the wrong candidates",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[1],
        Action::Vote {
            question: ids[0],
            yes: false,
        },
    )?;
    ensure(
        state.yes_count(ids[0]) == 1,
        "a no vote subtracted an affirmative vote",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[0],
        Action::Vote {
            question: ids[0],
            yes: false,
        },
    )?;
    ensure(
        state.yes_count(ids[0]) == 0 && state.active().contains(&ids[0]),
        "an explicit relevance revision preempted an active lease",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[0],
        Action::Vote {
            question: ids[0],
            yes: true,
        },
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[1],
        Action::Vote {
            question: ids[2],
            yes: true,
        },
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[2],
        Action::Vote {
            question: ids[2],
            yes: true,
        },
    )?;
    ensure(
        state.ranked_candidates().first() == Some(&ids[2]),
        "candidate ordering ignored affirmative count",
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[2],
        Action::Answer {
            question: ids[2],
            outcome: Outcome::Proof,
            file: equality_answer(1),
        },
        "highly ranked inactive answer",
        &mut rejected,
    )?;

    let mut wrong_genesis = signed(&state, &participants[2], Action::Tick);
    wrong_genesis.body.genesis[0] ^= 1;
    reject_signed(
        &mut state,
        &coordinator,
        wrong_genesis,
        "signed body tampering",
        &mut rejected,
    )?;
    let wrong_run = SignedAction::sign(
        [0; 32],
        state.next_nonce(participants[2].verifying_key().to_bytes()),
        Action::Vote {
            question: ids[0],
            yes: true,
        },
        &participants[2],
    );
    reject_signed(
        &mut state,
        &coordinator,
        wrong_run,
        "other genesis",
        &mut rejected,
    )?;
    let repeated_nonce = SignedAction::sign(
        state.genesis().genesis.id(),
        1,
        Action::Vote {
            question: ids[0],
            yes: true,
        },
        &participants[0],
    );
    reject_signed(
        &mut state,
        &coordinator,
        repeated_nonce,
        "repeated nonce",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[2],
        Action::Tick,
        "participant clock advance",
        &mut rejected,
    )?;

    for _ in 0..2 {
        accept(
            &mut state,
            &journal,
            &coordinator,
            &coordinator,
            Action::Tick,
        )?;
    }
    ensure(
        state.target() == 2 && !state.active().contains(&ids[2]),
        "growth occurred before drought boundary",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &coordinator,
        Action::Tick,
    )?;
    ensure(
        state.target() == 3 && state.active().contains(&ids[2]),
        "drought boundary did not fill the highest ranked vacancy",
    )?;

    reject(
        &mut state,
        &coordinator,
        &participants[1],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: AnswerFile {
                source: equality_answer(0)
                    .source
                    .replace("equality_reflexivity(x0)", "axiom(equal(x0, x0))"),
                dependencies: vec![],
            },
        },
        "invented axiom",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[1],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: AnswerFile {
                source: format!(
                    "foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = cite(\"{}\")\n return p0\n",
                    hex(&[0; 32])
                ),
                dependencies: vec![],
            },
        },
        "unavailable dependency",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[1],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: equality_answer(1),
        },
        "substituted exact target",
        &mut rejected,
    )?;
    let first = signed(
        &state,
        &participants[1],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: equality_answer(0),
        },
    );
    let competitor = signed(
        &state,
        &participants[2],
        Action::Answer {
            question: ids[0],
            outcome: Outcome::Proof,
            file: equality_answer(0),
        },
    );
    append(&mut state, &journal, &coordinator, first)?;
    reject_signed(
        &mut state,
        &coordinator,
        competitor,
        "copied late answer",
        &mut rejected,
    )?;
    ensure(
        state.results()[0].winner == participants[1].verifying_key().to_bytes(),
        "first confirmed answer did not retain its winner",
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[2],
        Action::Vote {
            question: ids[0],
            yes: true,
        },
        "vote on solved question",
        &mut rejected,
    )?;
    reject(
        &mut state,
        &coordinator,
        &participants[2],
        Action::Answer {
            question: ids[1],
            outcome: Outcome::Proof,
            file: refutation_answer(),
        },
        "refutation mislabeled proof",
        &mut rejected,
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[2],
        Action::Answer {
            question: ids[1],
            outcome: Outcome::Refutation,
            file: refutation_answer(),
        },
    )?;
    ensure(
        state.target() == 3 && state.active().len() == 1,
        "answers changed the target or refilled outside Tick",
    )?;
    for _ in 0..2 {
        accept(
            &mut state,
            &journal,
            &coordinator,
            &coordinator,
            Action::Tick,
        )?;
        ensure(state.target() == 3, "cooldown allowed an early shrink")?;
    }
    accept(
        &mut state,
        &journal,
        &coordinator,
        &coordinator,
        Action::Tick,
    )?;
    ensure(
        state.target() == 2 && state.active().len() == 2 && state.ranked_candidates().len() == 1,
        "Tick did not shrink and demote the least relevant unanswered lease",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &participants[0],
        Action::Answer {
            question: ids[2],
            outcome: Outcome::Proof,
            file: equality_answer(1),
        },
    )?;
    ensure(
        state.active().len() == 1,
        "answer refilled outside a logical Tick",
    )?;
    accept(
        &mut state,
        &journal,
        &coordinator,
        &coordinator,
        Action::Tick,
    )?;
    ensure(
        state.target() == 2
            && state.questions().len() == 5
            && !state.solved(ids[3])
            && !state.solved(ids[4]),
        "shrink deleted unanswered questions or missed its boundary",
    )?;

    let first_event = state.events().first().ok_or("fixture produced no events")?;
    ensure(
        journal.append(first_event).is_err(),
        "journal accepted an event overwrite",
    )?;
    let expected_head = state.head();
    let expected_blocks = state.results().to_vec();
    let expected_active = state.active().clone();
    let expected_events = state.events().len();
    drop(state);
    let (_, restarted) = Journal::open_at(root, expected_head, expected_events)?;
    ensure(
        restarted.head() == expected_head
            && restarted.results() == expected_blocks
            && restarted.active() == &expected_active
            && restarted.events().len() == expected_events,
        "cold replay changed accepted history",
    )?;
    let summary = json!({
        "evidence": "deterministic offline local fixture; one honest fixed coordinator; no public finality or model execution",
        "fixture_signing_keys": "fixed published seeds, unsuitable for real identities",
        "provider_turns": 0,
        "participants": participants.iter().map(|key| hex(&key.verifying_key().to_bytes())).collect::<Vec<_>>(),
        "genesis": hex(&restarted.genesis().genesis.id()),
        "journal_head": hex(&restarted.head()),
        "events": restarted.events().len(),
        "result_blocks": restarted.results().iter().map(|block| json!({"id":hex(&block.id()), "height":block.height, "question":hex(&block.question), "winner":hex(&block.winner), "outcome":block.outcome, "confirmation_index":block.confirmation_index})).collect::<Vec<_>>(),
        "logical_tick": restarted.tick(),
        "active_target": restarted.target(),
        "unanswered_questions": restarted.questions().len() - restarted.results().len(),
        "rejected_cases": rejected,
        "cold_replay": true,
        "independent_in_memory_checkpoint": true,
        "immutable_append": true,
    });
    Ok(summary)
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("fixture invariant failed: {message}"))
    }
}

fn signed(state: &ResearchState, key: &SigningKey, action: Action) -> SignedAction {
    SignedAction::sign(
        state.genesis().genesis.id(),
        state.next_nonce(key.verifying_key().to_bytes()),
        action,
        key,
    )
}

fn append(
    state: &mut ResearchState,
    journal: &Journal,
    coordinator: &SigningKey,
    action: SignedAction,
) -> Result<(), String> {
    let event = state.confirm(action, coordinator)?;
    journal.append(&event)
}

fn accept(
    state: &mut ResearchState,
    journal: &Journal,
    coordinator: &SigningKey,
    key: &SigningKey,
    action: Action,
) -> Result<(), String> {
    let action = signed(state, key, action);
    append(state, journal, coordinator, action)
}

fn reject(
    state: &mut ResearchState,
    coordinator: &SigningKey,
    key: &SigningKey,
    action: Action,
    label: &str,
    cases: &mut Vec<Value>,
) -> Result<(), String> {
    let action = signed(state, key, action);
    reject_signed(state, coordinator, action, label, cases)
}

fn reject_signed(
    state: &mut ResearchState,
    coordinator: &SigningKey,
    action: SignedAction,
    label: &str,
    cases: &mut Vec<Value>,
) -> Result<(), String> {
    let before = state.head();
    let events = state.events().len();
    let blocks = state.results().len();
    let nonce = state.next_nonce(action.body.participant);
    let error = state
        .confirm(action.clone(), coordinator)
        .err()
        .ok_or_else(|| format!("fixture unexpectedly accepted {label}"))?;
    ensure(
        before == state.head()
            && events == state.events().len()
            && blocks == state.results().len()
            && nonce == state.next_nonce(action.body.participant),
        "rejected action reserved a position or nonce",
    )?;
    cases.push(json!({"case":label,"error":error}));
    Ok(())
}

pub(crate) fn equality_question(vacuous_binders: u32) -> Question {
    let mut formula = forall(0, FormulaInput::Equal { left: 0, right: 0 });
    for variable in 1..=vacuous_binders {
        formula = forall(variable, formula);
    }
    Question {
        title: format!("Self equality with {vacuous_binders} unused binders"),
        context: "A fixed mathematical fixture, not a claim of new research.".into(),
        formula,
        definitions: vec![],
    }
}

pub(crate) fn equality_answer(vacuous_binders: u32) -> AnswerFile {
    let formula = equality_question(vacuous_binders)
        .formula
        .to_nao()
        .expect("fixed closed fixture");
    let mut source = format!(
        "foundation = \"naome:zfc\"\nstatement = {formula}\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n"
    );
    for variable in 1..=vacuous_binders {
        source.push_str(&format!(
            " p{} = generalization(p{}, x{variable})\n",
            variable + 1,
            variable
        ));
    }
    source.push_str(&format!(" return p{}\n", vacuous_binders + 1));
    AnswerFile {
        source,
        dependencies: vec![],
    }
}

pub(crate) fn refutation_question() -> Question {
    // Exact primitive expansion of the universal negation underlying Infinity.
    let is_empty = forall(4, not(member(4, 1)));
    let contains_empty = exists(1, and(is_empty, member(1, 0)));
    let successor_members = or(member(4, 2), FormulaInput::Equal { left: 4, right: 2 });
    let is_successor = forall(4, iff(member(4, 3), successor_members));
    let contains_successor = exists(3, and(is_successor, member(3, 0)));
    let successor_closed = forall(2, implies(member(2, 0), contains_successor));
    Question { title: "No inductive set exists".into(), context: "A deliberately false fixed question, formally refuted by the selected Foundation Infinity axiom.".into(), formula: forall(0, not(and(contains_empty, successor_closed))), definitions: vec![] }
}

pub(crate) fn refutation_answer() -> AnswerFile {
    let target = naome_foundation::ZfcAxiom::Infinity.formula();
    AnswerFile {
        source: format!(
            "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = zfc_axiom(\"infinity\")\n return p0\n",
            target.to_source()
        ),
        dependencies: vec![],
    }
}

fn forall(variable: u32, body: FormulaInput) -> FormulaInput {
    FormulaInput::Forall {
        variable,
        body: Box::new(body),
    }
}
fn not(body: FormulaInput) -> FormulaInput {
    FormulaInput::Not {
        body: Box::new(body),
    }
}
fn implies(left: FormulaInput, right: FormulaInput) -> FormulaInput {
    FormulaInput::Implies {
        left: Box::new(left),
        right: Box::new(right),
    }
}
fn and(left: FormulaInput, right: FormulaInput) -> FormulaInput {
    not(implies(left, not(right)))
}
fn or(left: FormulaInput, right: FormulaInput) -> FormulaInput {
    implies(not(left), right)
}
fn iff(left: FormulaInput, right: FormulaInput) -> FormulaInput {
    and(implies(left.clone(), right.clone()), implies(right, left))
}
fn exists(variable: u32, body: FormulaInput) -> FormulaInput {
    not(forall(variable, not(body)))
}
fn member(element: u32, set: u32) -> FormulaInput {
    FormulaInput::Member { element, set }
}

#[cfg(test)]
mod tests {
    use super::*;
    use naome_foundation::{Formula, ZfcAxiom};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn exact_refutation_fixture_is_the_single_negation_of_the_question() {
        assert_eq!(
            Formula::negate(refutation_question().formula().unwrap()),
            ZfcAxiom::Infinity.formula()
        );
    }

    #[test]
    fn complete_local_scenario_is_deterministic_after_cold_restart() {
        let next = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "naome-research-full-fixture-{}-{next}",
            std::process::id()
        ));
        let second = root.with_extension("second");
        let first_summary = run_fixture(&root).unwrap();
        let second_summary = run_fixture(&second).unwrap();
        assert_eq!(first_summary, second_summary);
        assert_eq!(first_summary["result_blocks"].as_array().unwrap().len(), 3);
        assert_eq!(first_summary["provider_turns"], 0);
        assert_eq!(first_summary["active_target"], 2);
        assert!(first_summary["rejected_cases"].as_array().unwrap().len() >= 12);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(second).unwrap();
    }
}
