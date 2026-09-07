//! Deterministic commands to independently owned actors. Restart destroys only
//! the selected actor's driver and journals; the other three owners stay live.
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use naome_chain::ArtifactBlock;
use naome_consensus::FixedValidatorProposalSourceV0;

use super::*;

#[derive(Clone)]
enum Publication {
    Vote(Vec<u8>),
    Proposal(Vec<u8>, Vec<u8>),
}

enum Command {
    Admit(FixedValidatorNodeDriverEventV0),
    Step,
    Author(ArtifactBlock, Vec<u8>),
    Restart,
    Stop,
}

#[derive(Clone, Copy, Debug)]
struct State {
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    ticket: Option<FixedValidatorNodePhaseTimeoutV0>,
    inbox: usize,
}

type ValidImage = (ConsensusRound, Vec<u8>, Vec<u8>);

enum Outcome {
    Started {
        votes: Vec<Vec<u8>>,
        proposals: Vec<(ConsensusPosition, Vec<u8>)>,
        locked: Option<(ConsensusRound, ProposalSigningRoot)>,
        valid: Option<ValidImage>,
    },
    Admitted(bool),
    Advanced,
    Arm,
    Published(Publication),
    Idle,
    Finalized,
}

struct Response {
    state: State,
    outcome: Outcome,
}

struct Actor {
    commands: Sender<Command>,
    responses: Receiver<Response>,
}

impl Actor {
    fn request(&self, command: Command) -> Response {
        self.commands.send(command).unwrap();
        self.receive()
    }
    fn receive(&self) -> Response {
        self.responses
            .recv_timeout(Duration::from_secs(60))
            .expect("actor must answer each deterministic command")
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

fn snapshot(driver: &FixedValidatorNodeDriverV0<'_>) -> State {
    State {
        position: driver.position(),
        phase: driver.phase(),
        ticket: driver.active_timeout(),
        inbox: driver.inbox_len(),
    }
}

fn actor(
    fixture: &Fixture,
    entries: &[ActiveAgreementEntry],
    layout: &TestLayout,
    key: SigningKey,
    commands: Receiver<Command>,
    responses: Sender<Response>,
) {
    let mut create = true;
    loop {
        let provision = provision_with_fixed_entries(fixture, layout, entries);
        let ready = if create {
            provision.create(key.clone()).unwrap()
        } else {
            expect_ready(provision.open(key.clone()).unwrap())
        };
        create = false;
        let mut votes = Vec::new();
        let mut proposals = Vec::new();
        let height = fixed_branch(fixture)
            .begin_round_zero()
            .unwrap()
            .position()
            .height();
        for round in 0..=6 {
            let position = ConsensusPosition::new(height, ConsensusRound::new(round));
            if let Some(proposal) = ready.vote.retained_signed_proposal(position).unwrap() {
                proposals.push((
                    position,
                    proposal.canonical_proposal_control_bytes().to_vec(),
                ));
            }
            for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
                if let Some(vote) = ready
                    .vote
                    .retained_signed_vote(
                        ConsensusPosition::new(height, ConsensusRound::new(round)),
                        role,
                    )
                    .unwrap()
                {
                    votes.push(vote.canonical_bytes().to_vec());
                }
            }
        }
        let restart = ready
            .run_with_signing_session(|mut scope| {
                let signing = scope.signing_session();
                let locked = signing
                    .locked_value()
                    .map(|value| (value.round(), value.proposal_signing_root()));
                let valid = signing.valid_value().map(|value| {
                    (
                        value.round(),
                        value.value().to_canonical_bytes().to_vec(),
                        value.canonical_prevote_certificate().to_vec(),
                    )
                });
                let mut node = driver(scope, 128, 6);
                responses
                    .send(Response {
                        state: snapshot(&node),
                        outcome: Outcome::Started {
                            votes,
                            proposals,
                            locked,
                            valid,
                        },
                    })
                    .unwrap();
                for _ in 0..2000 {
                    let command = match commands.recv() {
                        Ok(command) => command,
                        Err(_) => return false,
                    };
                    let outcome;
                    match command {
                        Command::Restart => return true,
                        Command::Stop => return false,
                        Command::Admit(event) => {
                            let before = layout.images();
                            let (next, accepted) = match node.admit_event(event).unwrap() {
                                FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
                                    driver,
                                    ..
                                } => (*driver, true),
                                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                                    driver,
                                    ..
                                } => (*driver, false),
                            };
                            node = next;
                            assert_eq!(
                                layout.images(),
                                before,
                                "raw admission cannot change authority images"
                            );
                            outcome = Outcome::Admitted(accepted);
                        }
                        Command::Author(block, payload) => {
                            node = match node
                                .author_proposal(FixedValidatorProposalSourceV0::Fresh {
                                    artifact_block: block,
                                    canonical_artifact_bytes: payload,
                                })
                                .unwrap()
                            {
                                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored {
                                    driver,
                                } => *driver,
                                _ => panic!("scheduled fresh proposal must be authored"),
                            };
                            outcome = Outcome::Advanced;
                        }
                        Command::Step => {
                            let (next, result) = match node.step().unwrap() {
                                FixedValidatorNodeDriverStepOutcomeV0::Command {
                                    driver,
                                    command,
                                } => {
                                    let outcome = match command {
                                        FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_) => {
                                            Outcome::Arm
                                        }
                                        FixedValidatorNodeDriverCommandV0::PublishVote {
                                            vote,
                                            released_proposal,
                                        } => {
                                            assert!(released_proposal.is_none());
                                            Outcome::Published(Publication::Vote(
                                                vote.canonical_bytes().to_vec(),
                                            ))
                                        }
                                        FixedValidatorNodeDriverCommandV0::PublishProposal {
                                            proposal,
                                            canonical_artifact_bytes,
                                        } => Outcome::Published(Publication::Proposal(
                                            proposal.canonical_proposal_control_bytes().to_vec(),
                                            canonical_artifact_bytes,
                                        )),
                                    };
                                    (*driver, outcome)
                                }
                                FixedValidatorNodeDriverStepOutcomeV0::Transitioned { driver } => {
                                    (*driver, Outcome::Advanced)
                                }
                                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => {
                                    (*driver, Outcome::Idle)
                                }
                                FixedValidatorNodeDriverStepOutcomeV0::Finality {
                                    driver, ..
                                } => (*driver, Outcome::Finalized),
                                FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                    rejection,
                                    ..
                                } => panic!("unexpected actor step rejection: {rejection:?}"),
                                FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                                    reason, ..
                                } => panic!("unexpected actor blocker: {reason:?}"),
                                _ => panic!("actor cannot stop"),
                            };
                            node = next;
                            outcome = result;
                        }
                    }
                    if responses
                        .send(Response {
                            state: snapshot(&node),
                            outcome,
                        })
                        .is_err()
                    {
                        return false;
                    }
                }
                panic!("actor command budget exceeded");
            })
            .unwrap();
        if !restart {
            break;
        }
    }
}

fn pump(actor: &Actor) -> (State, Vec<Publication>) {
    let mut publications = Vec::new();
    for _ in 0..16 {
        let response = actor.request(Command::Step);
        match response.outcome {
            Outcome::Idle => return (response.state, publications),
            Outcome::Published(publication) => publications.push(publication),
            Outcome::Advanced | Outcome::Arm | Outcome::Finalized => {}
            _ => panic!("step returned a non-step response"),
        }
    }
    panic!("actor did not reach an ordinary idle boundary");
}

fn admit_to(actor: &Actor, event: FixedValidatorNodeDriverEventV0) -> State {
    let response = actor.request(Command::Admit(event));
    assert!(matches!(response.outcome, Outcome::Admitted(true)));
    response.state
}

type Slots = BTreeMap<(usize, ConsensusPosition, Option<ConsensusVoteRole>), Vec<u8>>;
fn remember(fixture: &Fixture, keys: &[SigningKey], slots: &mut Slots, actor: usize, bytes: &[u8]) {
    let vote = naome_consensus::VerifiedConsensusVoteV0::decode_and_verify(bytes, fixture.context)
        .unwrap();
    assert_eq!(vote.signer(), consensus_key(&keys[actor]));
    if let Some(previous) =
        slots.insert((actor, vote.position(), Some(vote.role())), bytes.to_vec())
    {
        assert_eq!(
            previous, bytes,
            "restart released conflicting canonical bytes for an honest signing slot"
        );
    }
}

fn expire(actor: &Actor, state: State) -> (State, Vec<Publication>) {
    admit_to(
        actor,
        FixedValidatorNodeDriverEventV0::TimeoutDue(state.ticket.unwrap()),
    );
    pump(actor)
}

fn restart_actor(
    fixture: &Fixture,
    keys: &[SigningKey],
    slots: &mut Slots,
    actor: usize,
    handle: &Actor,
) -> Response {
    let response = handle.request(Command::Restart);
    let Outcome::Started {
        votes, proposals, ..
    } = &response.outcome
    else {
        panic!("restart must recreate an owner")
    };
    for vote in votes {
        remember(fixture, keys, slots, actor, vote);
    }
    for (position, bytes) in proposals {
        if let Some(previous) = slots.insert((actor, *position, None), bytes.clone()) {
            assert_eq!(
                &previous, bytes,
                "restart changed an honest proposal authorization slot"
            );
        }
    }
    assert_eq!(
        response.state.inbox, 0,
        "restart cannot reconstruct volatile quorum custody"
    );
    response
}

fn run_recovery(weights: &[u16; 4], lagger: usize) {
    let fixture = Fixture::new();
    let mut keys = (0..4)
        .map(|i| SigningKey::from_bytes(&signing_seed(181 + i)))
        .collect::<Vec<_>>();
    keys.sort_by_key(consensus_key);
    let entries = keys
        .iter()
        .zip(weights)
        .map(|(key, weight)| {
            ActiveAgreementEntry::new(
                consensus_key(key),
                AgreementWeight::new(u128::from(*weight)),
            )
        })
        .collect::<Vec<_>>();
    let layouts =
        std::array::from_fn::<_, 4, _>(|i| TestLayout::new(&format!("recovery-actor-{i}")));
    let mut slots = Slots::new();
    std::thread::scope(|threads| {
        let actors = std::array::from_fn::<_, 4, _>(|i| {
            let (send, receive) = mpsc::channel();
            let (reply, replies) = mpsc::channel();
            let fixture = &fixture;
            let entries = &entries;
            let layout = &layouts[i];
            let key = keys[i].clone();
            threads.spawn(move || actor(fixture, entries, layout, key, receive, reply));
            Actor {
                commands: send,
                responses: replies,
            }
        });
        let mut states = actors.each_ref().map(|actor| {
            assert!(matches!(actor.receive().outcome, Outcome::Started { .. }));
            pump(actor).0
        });
        let old_ticket = states[lagger].ticket.unwrap();
        let initial_finality = layouts.each_ref().map(partition::finality_images);
        let active = (0..4).filter(|&i| i != lagger).collect::<Vec<_>>();
        let total: u16 = weights.iter().sum();
        assert!(3 * active.iter().map(|&i| weights[i]).sum::<u16>() > 2 * total);
        // A finite partition lets the three connected actors time out twice.
        // Their votes are captured only from actual anchored publication commands.
        for round in 0..2 {
            for _ in 0..3 {
                for &i in &active {
                    let (next, publications) = expire(&actors[i], states[i]);
                    states[i] = next;
                    for publication in publications {
                        if let Publication::Vote(bytes) = publication {
                            remember(&fixture, &keys, &mut slots, i, &bytes);
                        }
                    }
                }
            }
            assert!(
                active
                    .iter()
                    .all(|&i| states[i].position.round().value() == round + 1)
            );
        }
        let mut higher_prevotes = Vec::new();
        for &i in &active {
            let (next, publications) = expire(&actors[i], states[i]);
            states[i] = next;
            for publication in publications {
                let Publication::Vote(bytes) = publication else {
                    panic!("nil prevote expected")
                };
                remember(&fixture, &keys, &mut slots, i, &bytes);
                higher_prevotes.push((i, bytes));
            }
        }
        for (_, bytes) in &higher_prevotes {
            admit_to(
                &actors[lagger],
                FixedValidatorNodeDriverEventV0::HigherRoundVote {
                    canonical_signed_vote: bytes.clone().into_boxed_slice(),
                },
            );
        }
        let checkpoint = actors[lagger].request(Command::Step);
        assert!(matches!(checkpoint.outcome, Outcome::Advanced));
        assert_eq!(checkpoint.state.position.round().value(), 2);
        assert_eq!(checkpoint.state.phase, FixedValidatorLockPhaseV0::Prevote);
        let checkpoint_images = layouts[lagger].images();
        let restarted = restart_actor(&fixture, &keys, &mut slots, lagger, &actors[lagger]);
        assert_eq!(restarted.state.position, checkpoint.state.position);
        assert_eq!(restarted.state.phase, checkpoint.state.phase);
        assert!(matches!(
            restarted.outcome,
            Outcome::Started {
                locked: None,
                valid: None,
                ..
            }
        ));
        assert_eq!(layouts[lagger].images(), checkpoint_images);
        states[lagger] = pump(&actors[lagger]).0;
        assert!(matches!(
            actors[lagger]
                .request(Command::Admit(FixedValidatorNodeDriverEventV0::TimeoutDue(
                    old_ticket
                )))
                .outcome,
            Outcome::Admitted(false)
        ));
        // Re-delivery is ordinary exact-current admission after the checkpoint.
        let mut nil_precommits = Vec::new();
        for i in 0..4 {
            for (_, bytes) in &higher_prevotes {
                admit_to(&actors[i], current_nil_prevote_event(bytes));
            }
            let (next, publications) = pump(&actors[i]);
            states[i] = next;
            for publication in publications {
                let Publication::Vote(bytes) = publication else {
                    panic!("nil precommit expected")
                };
                remember(&fixture, &keys, &mut slots, i, &bytes);
                nil_precommits.push((i, bytes));
            }
        }
        for i in 0..4 {
            for (_, bytes) in &nil_precommits {
                admit_to(&actors[i], current_nil_precommit_event(bytes));
            }
            states[i] = pump(&actors[i]).0;
            assert_eq!(states[i].position.round().value(), 3);
        }
        // R3 is still volatile: crashing this actor returns exactly to its
        // durable R2 precommit, then the same real nil quorum restores R3.
        let restarted = restart_actor(&fixture, &keys, &mut slots, lagger, &actors[lagger]);
        assert_eq!(restarted.state.position.round().value(), 2);
        assert_eq!(restarted.state.phase, FixedValidatorLockPhaseV0::Precommit);
        pump(&actors[lagger]);
        for (_, bytes) in &nil_precommits {
            admit_to(&actors[lagger], current_nil_precommit_event(bytes));
        }
        states[lagger] = pump(&actors[lagger]).0;
        assert_eq!(states[lagger].position.round().value(), 3);
        for i in 0..4 {
            assert_eq!(partition::finality_images(&layouts[i]), initial_finality[i]);
        }
        // Heal with a real scheduled proposal and actual honest publications.
        let branch = {
            let ready_layout = TestLayout::new("recovery-branch-only");
            let ready = provision_with_fixed_entries(&fixture, &ready_layout, &entries)
                .create(keys[0].clone())
                .unwrap();
            ready
                .run_with_signing_session(|scope| scope.branch().clone())
                .unwrap()
        };
        let round = round_at(&branch, 3);
        let proposer = keys
            .iter()
            .position(|key| consensus_key(key) == round.proposer())
            .unwrap();
        let payload = proof_payload(ZfcAxiom::Pairing);
        let block = ArtifactChainState::new(fixture.definition)
            .prepare_block(artifact_id(&payload))
            .unwrap();
        actors[proposer].request(Command::Author(block, payload.clone()));
        // A completed proposal can also be lost before publication. Strict
        // reopen and explicit exact authoring retry must return the same bytes.
        let before_restart = layouts[proposer].images();
        let restarted = restart_actor(&fixture, &keys, &mut slots, proposer, &actors[proposer]);
        assert_eq!(
            layouts[proposer].images(),
            before_restart,
            "reopen preserves the completed unpublished proposal"
        );
        assert_eq!(restarted.state.phase, FixedValidatorLockPhaseV0::Proposal);
        let before_replay = layouts[proposer].images();
        pump(&actors[proposer]);
        actors[proposer].request(Command::Author(block, payload.clone()));
        let (_, authored) = pump(&actors[proposer]);
        let [Publication::Proposal(control, artifact)] = authored.as_slice() else {
            panic!("one authored proposal")
        };
        assert_eq!(
            Some(control),
            slots.get(&(proposer, round.position(), None))
        );
        assert_eq!(
            layouts[proposer].images(),
            before_replay,
            "exact proposal replay must not append another intent"
        );
        let value = round.value_for_artifact_block(block);
        let mut prevotes = Vec::new();
        for i in 0..4 {
            admit_to(
                &actors[i],
                current_finality_proposal_event(control, artifact),
            );
            admit_to(&actors[i], current_proposal_event(control, artifact));
            let (next, publications) = pump(&actors[i]);
            states[i] = next;
            for publication in publications {
                let Publication::Vote(bytes) = publication else {
                    panic!("prevote")
                };
                remember(&fixture, &keys, &mut slots, i, &bytes);
                prevotes.push((i, bytes));
            }
        }
        let mut precommits = Vec::new();
        for i in 0..4 {
            for (_, bytes) in &prevotes {
                admit_to(&actors[i], current_prevote_event(bytes));
            }
            if i == lagger {
                let signed_but_unpublished = actors[i].request(Command::Step);
                assert!(matches!(signed_but_unpublished.outcome, Outcome::Advanced));
                let before_restart = layouts[i].images();
                let response = restart_actor(&fixture, &keys, &mut slots, i, &actors[i]);
                assert_eq!(
                    layouts[i].images(),
                    before_restart,
                    "reopen preserves the completed unpublished precommit"
                );
                let Outcome::Started {
                    votes,
                    locked,
                    valid,
                    ..
                } = response.outcome
                else {
                    unreachable!()
                };
                assert_eq!(
                    locked,
                    Some((ConsensusRound::new(3), value.proposal_signing_root()))
                );
                let valid = valid.unwrap();
                assert_eq!(valid.0, ConsensusRound::new(3));
                assert_eq!(valid.1, value.to_canonical_bytes());
                let refs = prevotes
                    .iter()
                    .map(|(_, bytes)| bytes.as_slice())
                    .collect::<Vec<_>>();
                assert_eq!(
                    valid.2,
                    round
                        .build_quorum_certificate_from_signed_votes(
                            &refs,
                            ConsensusVoteRole::Prevote,
                            ConsensusVoteTarget::Proposal(value.proposal_signing_root())
                        )
                        .unwrap()
                        .to_canonical_bytes()
                );
                let bytes = votes
                    .into_iter()
                    .find(|bytes| {
                        let vote = naome_consensus::VerifiedConsensusVoteV0::decode_and_verify(
                            bytes,
                            fixture.context,
                        )
                        .unwrap();
                        vote.position() == round.position()
                            && vote.role() == ConsensusVoteRole::Precommit
                    })
                    .expect("completed unpublished signature must survive strict reopen");
                precommits.push((i, bytes));
                states[i] = pump(&actors[i]).0;
                // Lost proposal custody is re-admitted without recreating a vote.
                admit_to(
                    &actors[i],
                    current_finality_proposal_event(control, artifact),
                );
                let response =
                    actors[i].request(Command::Admit(current_prevote_event(&prevotes[0].1)));
                assert!(matches!(response.outcome, Outcome::Admitted(false)));
            } else {
                let (next, publications) = pump(&actors[i]);
                states[i] = next;
                for publication in publications {
                    let Publication::Vote(bytes) = publication else {
                        panic!("precommit")
                    };
                    remember(&fixture, &keys, &mut slots, i, &bytes);
                    precommits.push((i, bytes));
                }
            }
        }
        for i in 0..4 {
            let mut mask = 0_u8;
            for (from, bytes) in &precommits {
                admit_to(&actors[i], current_finality_precommit_event(bytes));
                mask |= 1 << from;
            }
            let weight: u16 = (0..4)
                .filter(|from| mask & (1 << from) != 0)
                .map(|from| weights[from])
                .sum();
            assert!(3 * weight > 2 * total);
            states[i] = pump(&actors[i]).0;
            assert_eq!(states[i].position.height().value(), 2);
        }
        let finality = partition::finality_images(&layouts[0]);
        for layout in &layouts {
            assert_eq!(partition::finality_images(layout), finality);
        }
        for i in 0..4 {
            let response = restart_actor(&fixture, &keys, &mut slots, i, &actors[i]);
            assert_eq!(response.state.position.height().value(), 2);
            assert_eq!(response.state.position.round().value(), 0);
            assert_eq!(partition::finality_images(&layouts[i]), finality);
        }
    });
    assert_eq!(slots.len(), 28);
    for actor in 0..4 {
        for round in 0..4 {
            for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
                let expected = actor != lagger
                    || round == 3
                    || round == 2 && role == ConsensusVoteRole::Precommit;
                let position = ConsensusPosition::new(
                    fixed_branch(&fixture)
                        .begin_round_zero()
                        .unwrap()
                        .position()
                        .height(),
                    ConsensusRound::new(round),
                );
                assert_eq!(slots.contains_key(&(actor, position, Some(role))), expected);
            }
        }
    }
    // All actors are stopped here. Corrupt one complete durable image at a
    // time and require fail-closed reopen without any authority-image change.
    let layout = &layouts[lagger];
    for directory in [
        &layout.finality_journal,
        &layout.finality_anchor,
        &layout.vote_journal,
        &layout.vote_anchor,
    ] {
        for (name, bytes) in directory_image(directory) {
            if bytes.is_empty() {
                continue;
            } // exclusive-owner lock files
            let mut offsets = vec![0, bytes.len() / 2, bytes.len() - 1];
            offsets.sort();
            offsets.dedup();
            for offset in offsets {
                let path = directory.join(&name);
                let mut corrupt = bytes.clone();
                corrupt[offset] ^= 0x80;
                fs::write(&path, &corrupt).unwrap();
                let corrupted = layout.images();
                assert!(
                    provision_with_fixed_entries(&fixture, layout, &entries)
                        .open(keys[lagger].clone())
                        .is_err(),
                    "corruption at {name}:{offset} returned authority"
                );
                assert_eq!(
                    layout.images(),
                    corrupted,
                    "corrupt reopen must not advance or rewrite authority"
                );
                fs::write(&path, &bytes).unwrap();
            }
        }
    }
    drop(expect_ready(
        provision_with_fixed_entries(&fixture, layout, &entries)
            .open(keys[lagger].clone())
            .unwrap(),
    ));
    eprintln!(
        "recovery weights={weights:?} lagger={lagger} verified_honest_slots={} checkpoints=1 isolated_restarts=4 finality_restarts=4",
        slots.len()
    );
}

#[test]
fn independently_restarted_actors_preserve_checkpoints_unpublished_votes_and_heal_to_shared_finality()
 {
    for lagger in 0..4 {
        run_recovery(&[1, 1, 1, 1], lagger);
    }
    for lagger in [2, 3] {
        run_recovery(&[3, 2, 1, 1], lagger);
    }
}
