//! Differential replay of explorer-produced witnesses through real anchored
//! node coordinators. Only the designated faulty key uses raw signatures.

use std::collections::BTreeMap;

use naome_chain::ArtifactBlock;
use naome_consensus::{
    ConsensusAncestryId, ConsensusHeight, ConsensusVoteRole, ConsensusVoteTarget,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0,
};

use super::*;

mod model;
mod profiles;
mod weighted;
use model::{Action, Local, Model, State, proof, proof_round, proposal_value};

const MAX_ROUND: ConsensusRound = ConsensusRound::new(3);

struct Replay {
    model: Model,
    state: State,
    context: ConsensusContextV0,
    branch: FixedConsensusBranchV0,
    faulty_key: SigningKey,
    values: [ConsensusValueV0; 2],
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
    // These are outputs from the three same-execution honest journals.
    proposals: BTreeMap<u8, Vec<u8>>,
    votes: BTreeMap<(u8, u8, u8), Vec<u8>>,
}

impl Replay {
    fn cursor(&self, round: u8) -> FixedConsensusRoundV0<'_> {
        let mut cursor = self.branch.begin_round_zero().unwrap();
        for _ in 0..round {
            cursor = cursor.advance_round().unwrap();
        }
        cursor
    }

    fn target(&self, value: u8) -> ConsensusVoteTarget {
        match value {
            1 | 2 => ConsensusVoteTarget::Proposal(
                self.values[usize::from(value - 1)].proposal_signing_root(),
            ),
            3 => ConsensusVoteTarget::Nil,
            _ => panic!("absent vote is not nil"),
        }
    }

    fn role(role: u8) -> ConsensusVoteRole {
        match role {
            0 => ConsensusVoteRole::Prevote,
            1 => ConsensusVoteRole::Precommit,
            _ => unreachable!(),
        }
    }

    fn faulty_vote(&self, round: u8, role: u8, value: u8) -> Vec<u8> {
        let position = self.cursor(round).position();
        let mut body = [0_u8; VOTE_BODY_BYTES];
        body[0] = role + 1;
        body[1..33].copy_from_slice(self.context.chain_id().as_bytes());
        body[33..65].copy_from_slice(self.context.genesis_id().as_bytes());
        body[65..69].copy_from_slice(&self.context.protocol_version().value().to_be_bytes());
        body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
        body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
        if let ConsensusVoteTarget::Proposal(root) = self.target(value) {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
        let domain: &[u8] = if role == 0 {
            b"naome:consensus-prevote-signing:v0\0"
        } else {
            b"naome:consensus-precommit-signing:v0\0"
        };
        let key = consensus_key(&self.faulty_key);
        let mut transcript = domain.to_vec();
        transcript.extend_from_slice(&body);
        transcript.extend_from_slice(key.as_bytes());
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&self.faulty_key.sign(&transcript).to_bytes());
        bytes
    }

    fn batch(&self, round: u8, role: u8, value: u8) -> Vec<Vec<u8>> {
        assert!(self.model.quorum(self.state, round, role, value));
        let mut batch = Vec::new();
        for actor in 0..4 {
            if actor == self.model.faulty {
                batch.push(self.faulty_vote(round, role, value));
            } else if self.state.vote(actor, round, role) == value {
                batch.push(self.votes[&(actor, round, role)].clone());
            }
        }
        batch
    }

    fn proposal(&self, round: u8, encoded: u8) -> Vec<u8> {
        assert!(self.model.proposals(self.state, round).contains(&encoded));
        let value = self.values[usize::from(proposal_value(encoded) - 1)];
        let mut bytes = if self.model.proposers[usize::from(round)] == self.model.faulty {
            let mut bytes = value.to_canonical_bytes().to_vec();
            bytes.extend_from_slice(&authorization_bytes(
                self.context,
                self.cursor(round).position(),
                value.proposal_signing_root(),
                &self.faulty_key,
            ));
            bytes
        } else {
            // Proof wrappers do not belong to producer authorization. Reuse the
            // exact honest signed prefix when stripping/attaching a valid proof.
            self.proposals[&round][..480].to_vec()
        };
        if encoded <= 2 {
            bytes.push(0);
        } else {
            bytes.push(1);
            let earlier = proof_round(encoded - 2);
            let batch = self.batch(earlier, 0, proposal_value(encoded));
            let refs = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let cursor = self.cursor(earlier);
            let certificate = cursor
                .build_quorum_certificate_from_signed_votes(
                    &refs,
                    ConsensusVoteRole::Prevote,
                    self.target(proposal_value(encoded)),
                )
                .unwrap();
            bytes.extend_from_slice(&certificate.to_canonical_bytes());
        }
        bytes
    }

    fn observe(&self, scope: &mut FixedValidatorNodeSigningScopeV0<'_>) -> Local {
        let session = scope.signing_session();
        assert_eq!(session.position().height().value(), 1);
        let phase = match session.phase() {
            FixedValidatorLockPhaseV0::Proposal => 0,
            FixedValidatorLockPhaseV0::Prevote => 1,
            FixedValidatorLockPhaseV0::Precommit => 2,
        };
        let slot = |round: ConsensusRound, value: ConsensusValueV0| {
            let index = self
                .values
                .iter()
                .position(|&candidate| candidate == value)
                .expect("unknown semantic value");
            proof(u8::try_from(round.value()).unwrap(), index as u8 + 1)
        };
        Local {
            cursor: u8::try_from(session.position().round().value()).unwrap() * 3 + phase,
            locked: session
                .locked_value()
                .map_or(0, |locked| slot(locked.round(), locked.value())),
            valid: session
                .valid_value()
                .map_or(0, |valid| slot(valid.round(), valid.value())),
        }
    }

    fn step<'node>(
        &mut self,
        mut scope: FixedValidatorNodeSigningScopeV0<'node>,
        action: Action,
    ) -> FixedValidatorNodeSigningScopeV0<'node> {
        let actor = action.actor();
        let local = self.state.nodes[usize::from(actor)];
        assert_eq!(self.observe(&mut scope), local, "before {action:?}");
        assert!(
            self.model.actions(self.state).contains(&action),
            "trace action is not enabled: {action:?}"
        );
        let next = self.model.apply(self.state, action).unwrap();
        let round = local.cursor / 3;
        let position = self.cursor(round).position();
        let scope = match action {
            Action::Author { proposal, .. } => {
                let value = usize::from(proposal_value(proposal) - 1);
                let source = if local.valid == 0 {
                    FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: self.blocks[value],
                        canonical_artifact_bytes: self.payloads[value].clone(),
                    }
                } else {
                    assert_eq!(proposal, local.valid + 2);
                    FixedValidatorProposalSourceV0::RetainedValid {
                        canonical_artifact_bytes: self.payloads[value].clone(),
                    }
                };
                match scope.author_proposal(source, MAX_ROUND).unwrap() {
                    FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { scope, proposal } => {
                        assert_eq!(
                            proposal.proposal_signing_root(),
                            self.values[value].proposal_signing_root()
                        );
                        assert!(
                            self.proposals
                                .insert(round, proposal.canonical_proposal_control_bytes().to_vec())
                                .is_none()
                        );
                        *scope
                    }
                    _ => panic!("honest author rejected: {action:?}"),
                }
            }
            Action::Prevote { proposal, .. } => {
                let outcome = if proposal == 0 {
                    scope.sign_prevote_after_proposal_close(self.context, position, MAX_ROUND)
                } else {
                    let bytes = self.proposal(round, proposal);
                    scope.sign_prevote_for_proposal(
                        &bytes,
                        self.payloads[usize::from(proposal_value(proposal) - 1)].clone(),
                        MAX_ROUND,
                    )
                }
                .unwrap();
                self.accept_vote(outcome, actor, round, 0, next)
            }
            Action::Precommit { target, .. } => {
                let outcome = if target == 0 {
                    scope.sign_precommit_after_prevote_close(self.context, position, MAX_ROUND)
                } else {
                    let batch = self.batch(round, 0, target);
                    let refs = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    if target == 3 {
                        scope.sign_precommit_for_nil_vote_batch(&refs, MAX_ROUND)
                    } else {
                        let proposal = self
                            .model
                            .proposals(self.state, round)
                            .into_iter()
                            .find(|&p| proposal_value(p) == target)
                            .unwrap();
                        let bytes = self.proposal(round, proposal);
                        scope.sign_precommit_for_proposal_vote_batch(
                            &bytes,
                            self.payloads[usize::from(target - 1)].clone(),
                            &refs,
                            MAX_ROUND,
                        )
                    }
                }
                .unwrap();
                self.accept_vote(outcome, actor, round, 1, next)
            }
            Action::Advance { nil_quorum, .. } => {
                let outcome = if nil_quorum {
                    let batch = self.batch(round, 1, 3);
                    let refs = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    scope.advance_round_for_nil_precommit_vote_batch(&refs, MAX_ROUND)
                } else {
                    scope.advance_round_after_precommit_close(self.context, position, MAX_ROUND)
                }
                .unwrap();
                Self::accept_advance(outcome)
            }
            Action::Higher {
                round,
                role,
                target,
                ..
            } => {
                let batch = self.batch(round, role, target);
                let refs = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let route = FixedValidatorNodeHigherRoundVoteBatchRouteV0::new(
                    ConsensusRound::new(u64::from(round)),
                    Self::role(role),
                    self.target(target),
                    MAX_ROUND,
                );
                Self::accept_advance(
                    scope
                        .advance_to_higher_round_vote_batch(&refs, route)
                        .unwrap(),
                )
            }
        };
        self.state = next;
        let mut scope = scope;
        assert_eq!(
            self.observe(&mut scope),
            next.nodes[usize::from(actor)],
            "after {action:?}"
        );
        scope
    }

    fn accept_vote<'node>(
        &mut self,
        outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        actor: u8,
        round: u8,
        role: u8,
        next: State,
    ) -> FixedValidatorNodeSigningScopeV0<'node> {
        match outcome {
            FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote } => {
                assert_eq!(vote.position(), self.cursor(round).position());
                assert_eq!(vote.role(), Self::role(role));
                assert_eq!(vote.target(), self.target(next.vote(actor, round, role)));
                assert!(
                    self.votes
                        .insert((actor, round, role), vote.canonical_bytes().to_vec())
                        .is_none()
                );
                *scope
            }
            FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { rejection, .. } => {
                panic!("real coordinator rejected: {rejection:?}")
            }
            FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
                panic!("real signer stopped")
            }
        }
    }

    fn accept_advance(
        outcome: FixedValidatorNodeRoundAdvanceOutcomeV0<'_>,
    ) -> FixedValidatorNodeSigningScopeV0<'_> {
        match outcome {
            FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. } => *scope,
            FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { rejection, .. } => {
                panic!("real round progression rejected: {rejection:?}")
            }
        }
    }

    fn finalize_available(&self, scopes: &mut [Option<FixedValidatorNodeSigningScopeV0<'_>>; 4]) {
        let mut observations = Vec::new();
        for round in 0..model::ROUNDS {
            for value in 1..=2 {
                if !self.model.quorum(self.state, round, 1, value) {
                    continue;
                }
                let Some(proposal) = self
                    .model
                    .proposals(self.state, round)
                    .into_iter()
                    .find(|&p| proposal_value(p) == value)
                else {
                    continue;
                };
                let batch = self.batch(round, 1, value);
                let refs = batch.iter().map(Vec::as_slice).collect::<Vec<_>>();
                observations.extend(self.finalize_batch(round, proposal, &refs, scopes));
                assert!(
                    observations.iter().all(|seen| seen == &observations[0]),
                    "append-only honest finalizations disagree across proofs"
                );
            }
        }
        assert_eq!(
            !observations.is_empty(),
            self.model.certified_values(self.state) != 0
        );
    }

    fn finalize_batch(
        &self,
        round: u8,
        proposal: u8,
        refs: &[&[u8]],
        scopes: &mut [Option<FixedValidatorNodeSigningScopeV0<'_>>; 4],
    ) -> Vec<(ConsensusValueV0, ConsensusAncestryId)> {
        let value = proposal_value(proposal);
        let bytes = self.proposal(round, proposal);
        let cursor = self.cursor(round);
        let mut observations = Vec::new();
        for (actor, slot) in scopes.iter_mut().enumerate() {
            if actor == usize::from(self.model.faulty) {
                continue;
            }
            let scope = slot.take().unwrap();
            let transition = cursor
                .decode_and_verify_proposal_control(
                    &bytes,
                    self.payloads[usize::from(value - 1)].clone(),
                )
                .unwrap()
                .seal_with_precommit_vote_batch(refs)
                .unwrap()
                .into_owned();
            let (mut scope, selection) = match scope.commit_verified_finality(transition).unwrap() {
                FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection } => {
                    (*scope, selection)
                }
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_) => {
                    panic!("conflicting model-supported finality")
                }
            };
            let ancestry = match selection {
                FixedValidatorNodeFinalitySelectionV0::Finalized { ancestry_id, .. }
                | FixedValidatorNodeFinalitySelectionV0::AlreadyFinalized { ancestry_id, .. } => {
                    ancestry_id
                }
                _ => panic!("unexpected candidate-backed selection"),
            };
            let record = scope
                .finality()
                .finality_record(ConsensusHeight::new(1))
                .unwrap()
                .unwrap();
            assert_eq!(record.value(), self.values[usize::from(value - 1)]);
            observations.push((record.value(), ancestry));
            assert!(
                observations.iter().all(|seen| seen == &observations[0]),
                "append-only honest finalizations disagree"
            );
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            *slot = Some(scope);
        }
        assert_eq!(observations.len(), 3);
        observations
    }
}

fn with_replay(
    profile: profiles::Profile,
    label: &str,
    run: impl FnOnce(&mut Replay, &mut [Option<FixedValidatorNodeSigningScopeV0<'_>>; 4]),
) {
    let faulty = profile.faulty;
    let fixture = Fixture::new();
    let mut keys = std::array::from_fn::<_, 4, _>(|index| {
        SigningKey::from_bytes(&signing_seed(index as u16 + 71))
    });
    keys.sort_by_key(consensus_key);
    let entries = std::array::from_fn::<_, 4, _>(|actor| {
        ActiveAgreementEntry::new(
            consensus_key(&keys[actor]),
            AgreementWeight::new(profile.weights[actor]),
        )
    });
    let honest = (0..4).filter(|&actor| actor != faulty).collect::<Vec<_>>();
    let layouts = std::array::from_fn::<_, 3, _>(|index| {
        TestLayout::new(&format!("safety-model-{faulty}-{label}-{index}"))
    });
    let [first, second, third] = std::array::from_fn::<_, 3, _>(|index| {
        FixedValidatorNodeProvisionV0::new(
            fixture.definition,
            fixture.context,
            &entries,
            layouts[index].directories(),
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            FixedValidatorVoteSafetyReplayLimitV0::new(64).unwrap(),
            FixedValidatorProposalReplayLimitV0::new(16).unwrap(),
            FixedValidatorSignerRecoveryRoundLimitV0::new(8),
            FixedValidatorSignerCatchUpHeightLimitV0::new(8),
        )
        .create(keys[usize::from(honest[index])].clone())
        .unwrap()
    });
    first
        .run_with_signing_session(|first| {
            second
                .run_with_signing_session(|second| {
                    third
                        .run_with_signing_session(|third| {
                            let branch = first.branch().clone();
                            let mut cursor = branch.begin_round_zero().unwrap();
                            for actor in profile.proposers {
                                assert_eq!(
                                    cursor.proposer(),
                                    consensus_key(&keys[usize::from(actor)]),
                                    "independent weighted schedule differs: {profile:?}"
                                );
                                cursor = cursor.advance_round().unwrap();
                            }
                            drop(cursor);
                            let selected = ArtifactChainState::new(fixture.definition);
                            let payloads = [
                                proof_payload(ZfcAxiom::Pairing),
                                proof_payload(ZfcAxiom::Union),
                            ];
                            let blocks = payloads.each_ref().map(|payload| {
                                selected.prepare_block(artifact_id(payload)).unwrap()
                            });
                            let values = blocks.map(|block| {
                                branch
                                    .begin_round_zero()
                                    .unwrap()
                                    .value_for_artifact_block(block)
                            });
                            assert_ne!(values[0], values[1]);
                            for round in 1..model::ROUNDS {
                                let mut cursor = branch.begin_round_zero().unwrap();
                                for _ in 0..round {
                                    cursor = cursor.advance_round().unwrap();
                                }
                                assert_eq!(
                                    blocks.map(|block| cursor.value_for_artifact_block(block)),
                                    values
                                );
                            }
                            let mut replay = Replay {
                                model: profile.model(),
                                state: State::default(),
                                context: fixture.context,
                                branch,
                                faulty_key: keys[usize::from(faulty)].clone(),
                                values,
                                blocks,
                                payloads,
                                proposals: BTreeMap::new(),
                                votes: BTreeMap::new(),
                            };
                            let mut scopes = [None, None, None, None];
                            for (actor, scope) in honest.iter().copied().zip([first, second, third])
                            {
                                scopes[usize::from(actor)] = Some(scope);
                            }
                            run(&mut replay, &mut scopes);
                        })
                        .unwrap();
                })
                .unwrap();
        })
        .unwrap();
}

fn replay_witness(profile: profiles::Profile, label: &str, trace: &[Action]) {
    with_replay(profile, label, |replay, scopes| {
        for (index, &action) in trace.iter().enumerate() {
            let actor = usize::from(action.actor());
            let scope = scopes[actor].take().unwrap();
            // Include deterministic provenance and the whole schedule prefix
            // if a real coordinator differs from the model.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                replay.step(scope, action)
            }));
            scopes[actor] = Some(result.unwrap_or_else(|_| panic!("real coordinator differential mismatch: profile={profile:?}, witness={label}, prefix={:?}", &trace[..=index])));
        }
        replay.finalize_available(scopes);
    });
}

#[test]
fn model_witnesses_match_real_anchored_coordinators() {
    for (faulty, report) in model::protocol_explorations().iter().enumerate() {
        assert!(report.counterexample.is_none());
        for (&label, trace) in &report.witnesses {
            replay_witness(profiles::Profile::small([1; 4], faulty as u8), label, trace);
        }
    }
}
