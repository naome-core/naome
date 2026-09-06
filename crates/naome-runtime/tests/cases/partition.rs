use super::*;
use naome_chain::{ArtifactBlock, ArtifactBlockId};
use naome_consensus::{
    ConsensusKey, ConsensusPosition, ConsensusValueV0, ConsensusVoteTarget, ProposalSigningRoot,
    VerifiedConsensusVoteV0,
};
use naome_node::{FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeSigningScopeV0};
use naome_runtime::{
    FixedValidatorRuntimeRoutingErrorV0 as RoutingError, FixedValidatorRuntimeTransportPollV0,
};
use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::task::Poll;
use tokio::time::Instant;

#[path = "partition_restart.rs"]
mod restart;

type DirectoryImage = Vec<(String, Vec<u8>)>;
type AuthorityImages = [DirectoryImage; 4];
type VoteCoordinate = (u64, u64, ProposalSigningRoot);
type RecipientPrevotes = BTreeMap<VoteCoordinate, BTreeMap<ConsensusKey, Vec<u8>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    Cold,
    Precommit,
}

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    weights: [u16; 4],
    groups: [u8; 4],
    winners: u8,
    cut: Cut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Proposal(ProposalSigningRoot),
    Vote(ConsensusVoteRole, ConsensusVoteTarget),
}

struct Envelope {
    from: usize,
    position: ConsensusPosition,
    kind: Kind,
    input: ConsensusPushMessage,
}

impl Envelope {
    fn copy(&self) -> Self {
        Self {
            from: self.from,
            position: self.position,
            kind: self.kind,
            input: copy_message(&self.input),
        }
    }
}

fn same_bytes(left: &ConsensusPushMessage, right: &ConsensusPushMessage) -> bool {
    match (left, right) {
        (
            ConsensusPushMessage::Proposal {
                canonical_proposal: a,
                canonical_artifact: b,
            },
            ConsensusPushMessage::Proposal {
                canonical_proposal: c,
                canonical_artifact: d,
            },
        ) => a == c && b == d,
        (
            ConsensusPushMessage::Vote { canonical_vote: a },
            ConsensusPushMessage::Vote { canonical_vote: b },
        ) => a == b,
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedVote {
    target: ConsensusVoteTarget,
    canonical_vote: Vec<u8>,
    generation: u8,
}

struct Simulation<'layout> {
    layouts: &'layout [TestLayout; 4],
    scenario: Scenario,
    reverse: bool,
    keys: [ConsensusKey; 4],
    branch: FixedConsensusBranchV0,
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
    values: Vec<ConsensusValueV0>,
    genesis: ArtifactBlockId,
    finalized: [u64; 4],
    baseline_height: u64,
    baseline: [AuthorityImages; 4],
    queues: [VecDeque<Envelope>; 4],
    queued: [Option<Envelope>; 4],
    local: [Option<Envelope>; 4],
    produced: Vec<Envelope>,
    intents: BTreeMap<(ConsensusKey, u64, u64, u8), RecordedVote>,
    generations: [u8; 4],
    received: [BTreeMap<VoteCoordinate, u8>; 4],
    prevotes: [RecipientPrevotes; 4],
    precommit_inputs: [RecipientPrevotes; 4],
    events: usize,
    deliveries: usize,
    dropped: usize,
    duplicates: usize,
    local_precommits: usize,
    caller_precommits: usize,
    late: usize,
    due: usize,
    race: bool,
}

impl Simulation<'_> {
    fn accounting(owner: &Runtime<'_>) -> ([usize; 4], [u64; 3]) {
        let driver = owner.driver().unwrap();
        (
            [
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            ],
            [
                driver.current_inbox_canonical_input_bytes(),
                driver.current_finality_inbox_canonical_input_bytes(),
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
            ],
        )
    }

    fn history_owner(&self, actor: usize, owner: &Runtime<'_>) {
        let driver = owner.driver().unwrap();
        let height = self.finalized[actor];
        assert_eq!(driver.position().height().value(), height + 1);
        let expected = if height == 0 {
            self.genesis
        } else {
            self.blocks[height as usize - 1].id()
        };
        assert_eq!(
            driver
                .selected_artifact_history()
                .selected_head_block_id()
                .unwrap(),
            expected
        );
    }

    fn history(&self) {
        for actor in 0..4 {
            let height = self.finalized[actor];
            let images = self.layouts[actor].authority_images();
            if height == self.baseline_height {
                assert_eq!(
                    images[..2],
                    self.baseline[actor][..2],
                    "unfinalized runtime changed finality authority"
                );
            } else {
                assert!(height > self.baseline_height);
                for (name, prefix) in &self.baseline[actor][0] {
                    let (_, bytes) = images[0]
                        .iter()
                        .find(|(current, _)| current == name)
                        .unwrap();
                    assert!(
                        bytes.starts_with(prefix),
                        "finality rewrote its prior journal prefix"
                    );
                }
            }
        }
    }

    fn publication(&self, actor: usize, owner: &Runtime<'_>) -> Envelope {
        let message = owner.pending_publication().unwrap().message();
        let (position, kind) = match message {
            Message::Proposal {
                proposal,
                canonical_artifact_bytes,
            } => {
                let round = self.branch.begin_round_zero().unwrap();
                assert_eq!(proposal.position(), round.position());
                assert_eq!(round.proposer(), self.keys[actor]);
                let verified = round
                    .decode_and_verify_proposal_control(
                        proposal.canonical_proposal_control_bytes(),
                        canonical_artifact_bytes.clone(),
                    )
                    .unwrap();
                assert_eq!(
                    verified.proposal_signing_root(),
                    proposal.proposal_signing_root()
                );
                (
                    proposal.position(),
                    Kind::Proposal(proposal.proposal_signing_root()),
                )
            }
            Message::Vote {
                vote,
                released_proposal,
            } => {
                assert!(released_proposal.is_none());
                let verified = VerifiedConsensusVoteV0::decode_and_verify(
                    vote.canonical_bytes(),
                    self.branch.context(),
                )
                .unwrap();
                assert_eq!(verified.signer(), self.keys[actor]);
                assert_eq!(verified.position(), vote.position());
                assert_eq!(verified.role(), vote.role());
                assert_eq!(verified.target(), vote.target());
                (vote.position(), Kind::Vote(vote.role(), vote.target()))
            }
        };
        Envelope {
            from: actor,
            position,
            kind,
            input: message.copy_message().unwrap(),
        }
    }

    fn enqueue(&mut self, to: usize, envelope: Envelope) {
        assert!(self.queues[to].len() < 256, "simulation queue bound");
        self.queues[to].push_back(envelope);
    }

    fn publish(&mut self, envelope: Envelope) {
        for to in 0..4 {
            // Runtime self-admission is separate. Re-supplying the same signed
            // vote through the caller slot also cannot create a second signer.
            if to == envelope.from && matches!(envelope.kind, Kind::Proposal(_)) {
                continue;
            }
            let cut = envelope.position.height().value() == 2
                && (self.scenario.cut == Cut::Cold
                    || matches!(envelope.kind, Kind::Vote(ConsensusVoteRole::Precommit, _)));
            if cut && self.scenario.groups[to] != self.scenario.groups[envelope.from] {
                self.dropped += 1;
                continue;
            }
            self.enqueue(to, envelope.copy());
            if self.reverse {
                self.enqueue(to, envelope.copy());
            }
        }
    }

    fn admit(
        &mut self,
        actor: usize,
        owner: &Runtime<'_>,
        report: &FixedValidatorRuntimeAdmissionReportV0,
    ) {
        let envelope = match report.source {
            InputSource::LocalPublication => {
                assert!(report.input.is_none());
                self.local[actor].as_ref().unwrap().copy()
            }
            InputSource::CallerInput => {
                let envelope = self.queued[actor].take().unwrap();
                assert!(same_bytes(report.input.as_ref().unwrap(), &envelope.input));
                self.deliveries += 1;
                envelope
            }
            _ => panic!("isolated transport must not supply peer input"),
        };
        assert_eq!(report.receipt_queued, None);
        let driver = owner.driver().unwrap();
        if let Some(error) = &report.routing_error {
            assert_eq!(report.source, InputSource::CallerInput);
            assert!(
                matches!(
                    error,
                    RoutingError::UnsupportedPosition { .. }
                        | RoutingError::UnsupportedHigherVote { .. }
                ),
                "unexpected routing error: {error:?}"
            );
            assert!(
                envelope.position.height() != driver.position().height()
                    || envelope.position.round() != driver.position().round()
            );
            assert!(!report.completed());
            self.late += 1;
            return;
        }
        assert!(report.completed());
        if matches!(envelope.kind, Kind::Proposal(_)) {
            assert_eq!(
                report.results[0].as_ref().unwrap().route,
                Route::CurrentFinalityProposal
            );
            assert_eq!(
                report.results[1].as_ref().unwrap().route,
                Route::CurrentVotingProposal
            );
        }
        for result in report.results.iter().flatten() {
            match &result.result {
                Ok(disposition) => {
                    if *disposition == Disposition::AlreadyRetained {
                        self.duplicates += 1;
                    }
                    if result.route == Route::CurrentProposalPrevote {
                        let Kind::Vote(
                            ConsensusVoteRole::Prevote,
                            ConsensusVoteTarget::Proposal(root),
                        ) = envelope.kind
                        else {
                            panic!("prevote route changed target")
                        };
                        let ConsensusPushMessage::Vote { canonical_vote } = &envelope.input else {
                            unreachable!()
                        };
                        let coordinate = (
                            envelope.position.height().value(),
                            envelope.position.round().value(),
                            root,
                        );
                        let retained = self.prevotes[actor].entry(coordinate).or_default();
                        if let Some(previous) =
                            retained.insert(self.keys[envelope.from], canonical_vote.clone())
                        {
                            assert_eq!(previous, *canonical_vote);
                        }
                    }
                    if result.route == Route::CurrentProposalPrecommit {
                        let Kind::Vote(
                            ConsensusVoteRole::Precommit,
                            ConsensusVoteTarget::Proposal(root),
                        ) = envelope.kind
                        else {
                            panic!("precommit route changed target")
                        };
                        *self.received[actor]
                            .entry((
                                envelope.position.height().value(),
                                envelope.position.round().value(),
                                root,
                            ))
                            .or_default() |= 1 << envelope.from;
                        if report.source == InputSource::LocalPublication {
                            self.local_precommits += 1;
                        } else {
                            self.caller_precommits += 1;
                        }
                    }
                }
                Err(error) => {
                    assert_eq!(report.source, InputSource::CallerInput);
                    assert!(
                        matches!(
                            error.as_ref(),
                            Rejection::CurrentEvidenceWrongPhase { .. }
                                | Rejection::CurrentEvidenceAfterDue { .. }
                        ),
                        "unexpected admission rejection: {error:?}"
                    );
                    assert!(matches!(
                        envelope.kind,
                        Kind::Proposal(_) | Kind::Vote(ConsensusVoteRole::Prevote, _)
                    ));
                    self.late += 1;
                }
            }
        }
    }

    async fn poll(&mut self, actor: usize, owner: &mut Runtime<'_>) -> bool {
        let now = Instant::now();
        let timer = owner.timer();
        let accounting = Self::accounting(owner);
        let images = self.layouts[actor].authority_images();
        let event = poll_fn(|cx| {
            let mut future = std::pin::pin!(owner.next_event());
            Poll::Ready(match future.as_mut().poll(cx) {
                Poll::Ready(event) => Some(event),
                Poll::Pending => None,
            })
        })
        .await;
        assert_eq!(
            Instant::now(),
            now,
            "polling must not auto-advance virtual time"
        );
        let Some(event) = event else {
            self.history_owner(actor, owner);
            self.history();
            return false;
        };
        self.events += 1;
        assert!(self.events < 8_000, "finite event bound exhausted");
        match event {
            Event::TimerArmed(timer) => {
                assert_eq!(
                    timer.ticket().position(),
                    owner.driver().unwrap().position()
                );
                assert!(timer.deadline() > Instant::now());
            }
            Event::TimerDue {
                ticket,
                result: Ok(Disposition::TimeoutMarkedDue),
            } => {
                assert_eq!(Some(ticket), timer.map(|timer| timer.ticket()));
                assert!(timer.unwrap().deadline() <= now);
                assert_eq!(ticket.position(), owner.driver().unwrap().position());
                assert_eq!(self.layouts[actor].authority_images(), images);
                self.due += 1;
            }
            Event::Transitioned { phase, .. } => {
                if phase == FixedValidatorLockPhaseV0::Precommit {
                    // Capture recipient inputs at the consuming transition,
                    // before any later admission or publication can add a vote.
                    self.precommit_inputs[actor] = self.prevotes[actor].clone();
                }
            }
            Event::PublicationPrepared(_) => {
                assert!(self.local[actor].is_none());
                let envelope = self.publication(actor, owner);
                if let Kind::Vote(role, target) = envelope.kind {
                    let role = u8::from(role == ConsensusVoteRole::Precommit);
                    let key = (
                        self.keys[actor],
                        envelope.position.height().value(),
                        envelope.position.round().value(),
                        role,
                    );
                    let ConsensusPushMessage::Vote { canonical_vote } = &envelope.input else {
                        unreachable!()
                    };
                    // The fixed context and actual signer were strictly verified above.
                    // This map outlives any owner generation; only exact completed-byte replay is allowed.
                    let generation = self.generations[actor];
                    if let Some(previous) = self.intents.get_mut(&key) {
                        assert_eq!(previous.target, target, "honest signing intent changed");
                        assert_eq!(
                            &previous.canonical_vote, canonical_vote,
                            "completed vote replay changed bytes"
                        );
                        assert_ne!(
                            previous.generation, generation,
                            "one owner emitted the same vote twice"
                        );
                        previous.generation = generation;
                    } else {
                        self.intents.insert(
                            key,
                            RecordedVote {
                                target,
                                canonical_vote: canonical_vote.clone(),
                                generation,
                            },
                        );
                    }
                }
                self.produced.push(envelope.copy());
                self.local[actor] = Some(envelope);
            }
            Event::Admission(report) => {
                assert_eq!(
                    self.layouts[actor].authority_images(),
                    images,
                    "admission alone changed durable authority"
                );
                if report
                    .results
                    .iter()
                    .flatten()
                    .all(|result| !matches!(result.result, Ok(Disposition::Inserted)))
                {
                    assert_eq!(
                        Self::accounting(owner),
                        accounting,
                        "duplicates and stale input changed inbox accounting"
                    );
                }
                self.admit(actor, owner, &report);
            }
            Event::PublicationComplete(publication) => {
                assert!(publication.is_complete());
                assert_eq!(publication.deliveries().count(), 0);
                let envelope = self.local[actor].take().unwrap();
                assert!(same_bytes(
                    &publication.message().copy_message().unwrap(),
                    &envelope.input
                ));
                self.publish(envelope);
            }
            Event::Finality(FixedValidatorNodeFinalitySelectionV0::Finalized {
                position,
                ancestry_id,
                ..
            }) => {
                let height = position.height().value();
                assert_eq!(height, self.finalized[actor] + 1);
                assert!(height <= 2);
                if height == 2 {
                    assert_ne!(
                        self.scenario.winners & (1 << actor),
                        0,
                        "insufficient partition finalized"
                    );
                }
                let value = self.values[height as usize - 1];
                assert_eq!(ancestry_id, value.ancestry_id());
                let mask = self.received[actor][&(
                    height,
                    position.round().value(),
                    value.proposal_signing_root(),
                )];
                let weight: u16 = self
                    .scenario
                    .weights
                    .iter()
                    .enumerate()
                    .filter(|(key, _)| mask & (1 << key) != 0)
                    .map(|(_, weight)| *weight)
                    .sum();
                let total: u16 = self.scenario.weights.iter().sum();
                assert!(
                    3 * weight > 2 * total,
                    "finality lacks actually admitted recipient-local quorum"
                );
                self.finalized[actor] = height;
            }
            Event::DriverBlocked(reason) => panic!("partition became inbox block: {reason:?}"),
            Event::DriverRejected(error) => panic!("driver rejected: {error:?}"),
            Event::Fatal(error) => panic!("runtime lost authority: {error}"),
            Event::Network(event) => panic!("isolated network event: {event:?}"),
            _ => panic!("unexpected runtime event"),
        }
        self.history_owner(actor, owner);
        self.history();
        true
    }

    async fn visit(&mut self, actor: usize, owner: &mut Runtime<'_>) -> bool {
        let mut progress = false;
        if self.queued[actor].is_none() {
            let envelope = if self.reverse {
                self.queues[actor].pop_back()
            } else {
                self.queues[actor].pop_front()
            };
            if let Some(envelope) = envelope {
                let images = self.layouts[actor].authority_images();
                owner.queue_input(copy_message(&envelope.input)).unwrap();
                self.queued[actor] = Some(envelope);
                assert_eq!(self.layouts[actor].authority_images(), images);
                self.history_owner(actor, owner);
                self.history();
                progress = true;
            }
        }
        progress | self.poll(actor, owner).await
    }

    async fn pump(
        &mut self,
        first: &mut Runtime<'_>,
        second: &mut Runtime<'_>,
        third: &mut Runtime<'_>,
        fourth: &mut Runtime<'_>,
    ) {
        // Separate arguments retain each journal's lifetime, allowing one owner
        // to restart while the other three stay in their original scopes.
        loop {
            let mut progress = false;
            if self.reverse {
                progress |= self.visit(3, fourth).await;
                progress |= self.visit(2, third).await;
                progress |= self.visit(1, second).await;
                progress |= self.visit(0, first).await;
            } else {
                progress |= self.visit(0, first).await;
                progress |= self.visit(1, second).await;
                progress |= self.visit(2, third).await;
                progress |= self.visit(3, fourth).await;
            }
            if !progress {
                break;
            }
        }
        assert!(self.queues.iter().all(VecDeque::is_empty));
        assert!(self.queued.iter().all(Option::is_none));
        assert!(self.local.iter().all(Option::is_none));
    }

    fn author_at(&mut self, actor: usize, height: usize, owner: &mut Runtime<'_>) {
        assert_eq!(
            self.branch
                .begin_round_zero()
                .unwrap()
                .position()
                .height()
                .value(),
            height as u64
        );
        assert!(matches!(
            owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                artifact_block: self.blocks[height - 1],
                canonical_artifact_bytes: self.payloads[height - 1].clone()
            }),
            Event::ProposalAuthored
        ));
        self.history_owner(actor, owner);
        self.history();
    }

    fn author(
        &mut self,
        height: usize,
        first: &mut Runtime<'_>,
        second: &mut Runtime<'_>,
        third: &mut Runtime<'_>,
        fourth: &mut Runtime<'_>,
    ) {
        let proposer = self.branch.begin_round_zero().unwrap().proposer();
        let actor = self.keys.iter().position(|key| *key == proposer).unwrap();
        match actor {
            0 => self.author_at(actor, height, first),
            1 => self.author_at(actor, height, second),
            2 => self.author_at(actor, height, third),
            3 => self.author_at(actor, height, fourth),
            _ => unreachable!(),
        }
    }

    fn prepare_second_height(&mut self) {
        assert_eq!(self.finalized, [1; 4]);
        let proposal = self
            .produced
            .iter()
            .find(|e| matches!(e.kind, Kind::Proposal(_)))
            .unwrap();
        let ConsensusPushMessage::Proposal {
            canonical_proposal,
            canonical_artifact,
        } = &proposal.input
        else {
            unreachable!()
        };
        let votes = self
            .produced
            .iter()
            .filter_map(|e| match (&e.kind, &e.input) {
                (
                    Kind::Vote(ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(_)),
                    ConsensusPushMessage::Vote { canonical_vote },
                ) => Some(canonical_vote.as_slice()),
                _ => None,
            })
            .collect::<Vec<_>>();
        // This private expected branch is derived only after all owners finalized
        // H1, from their actual published proof. It is never installed in an owner.
        self.branch = self
            .branch
            .begin_round_zero()
            .unwrap()
            .decode_and_verify_proposal_control(canonical_proposal, canonical_artifact.clone())
            .unwrap()
            .seal_with_precommit_vote_batch(&votes)
            .unwrap()
            .into_owned()
            .into_branch();
        self.values.push(
            self.branch
                .begin_round_zero()
                .unwrap()
                .value_for_artifact_block(self.blocks[1]),
        );
        self.baseline_height = 1;
        self.baseline = self.layouts.each_ref().map(TestLayout::authority_images);
        self.history();
    }

    async fn advance_deadline(
        &mut self,
        first: &mut Runtime<'_>,
        second: &mut Runtime<'_>,
        third: &mut Runtime<'_>,
        fourth: &mut Runtime<'_>,
    ) {
        let deadline = [first.timer(), second.timer(), third.timer(), fourth.timer()]
            .into_iter()
            .flatten()
            .map(|timer| timer.deadline())
            .min()
            .unwrap();
        assert!(deadline > Instant::now());
        tokio::time::advance(deadline - Instant::now()).await;
        self.history();
        self.pump(first, second, third, fourth).await;
    }

    async fn queued_deadline_race(&mut self, actor: usize, owner: &mut Runtime<'_>) {
        let timer = owner.timer().unwrap();
        assert_eq!(timer.ticket().phase(), FixedValidatorLockPhaseV0::Precommit);
        let input = self
            .produced
            .iter()
            .find(|e| {
                e.from == actor
                    && e.position == timer.ticket().position()
                    && matches!(e.kind, Kind::Vote(ConsensusVoteRole::Precommit, _))
            })
            .unwrap()
            .copy();
        let images = self.layouts[actor].authority_images();
        owner.queue_input(copy_message(&input.input)).unwrap();
        self.queued[actor] = Some(input);
        assert_eq!(self.layouts[actor].authority_images(), images);
        tokio::time::advance(timer.deadline().saturating_duration_since(Instant::now())).await;
        let before = self.due;
        assert!(self.poll(actor, owner).await);
        assert_eq!(
            self.due,
            before + 1,
            "expired deadline must precede buffered caller input"
        );
        assert!(self.queued[actor].is_some());
        assert_eq!(
            owner.poll_transport_once().await,
            FixedValidatorRuntimeTransportPollV0::InputSlotOccupied
        );
        assert_eq!(self.layouts[actor].authority_images(), images);
        self.race = true;
    }
}

fn runtime_owner(scope: FixedValidatorNodeSigningScopeV0<'_>) -> Runtime<'_> {
    let driver = Driver::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(128, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(128, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(128, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(128, 1 << 20).unwrap(),
        ConsensusRound::new(4),
    )
    .unwrap();
    Runtime::new(
        driver,
        isolated_network(),
        vec![],
        timeouts(Duration::from_secs(1)),
    )
    .unwrap()
}

fn simulation<'layout>(
    layouts: &'layout [TestLayout; 4],
    scenario: Scenario,
    reverse: bool,
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    keys: [ConsensusKey; 4],
    entries: &[ActiveAgreementEntry],
) -> Simulation<'layout> {
    let mut selected = ArtifactChainState::new(definition);
    let genesis = selected.head_block_id();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        entries,
        selected.branch_snapshot(),
    )
    .unwrap();
    let payloads = [
        pairing_payload(),
        naome_proof::ArtifactPayload::Proof(
            naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 2]).unwrap(),
        )
        .to_canonical_bytes(),
    ];
    let blocks = payloads.each_ref().map(|payload| {
        let block = selected.prepare_block(artifact_id(payload)).unwrap();
        selected.apply_block(&block, payload.clone()).unwrap();
        block
    });
    let value = branch
        .begin_round_zero()
        .unwrap()
        .value_for_artifact_block(blocks[0]);
    Simulation {
        layouts,
        scenario,
        reverse,
        keys,
        branch,
        blocks,
        payloads,
        values: vec![value],
        genesis,
        finalized: [0; 4],
        baseline_height: 0,
        baseline: layouts.each_ref().map(TestLayout::authority_images),
        queues: std::array::from_fn(|_| VecDeque::new()),
        queued: std::array::from_fn(|_| None),
        local: std::array::from_fn(|_| None),
        produced: vec![],
        intents: BTreeMap::new(),
        generations: [0; 4],
        received: std::array::from_fn(|_| BTreeMap::new()),
        prevotes: std::array::from_fn(|_| BTreeMap::new()),
        precommit_inputs: std::array::from_fn(|_| BTreeMap::new()),
        events: 0,
        deliveries: 0,
        dropped: 0,
        duplicates: 0,
        local_precommits: 0,
        caller_precommits: 0,
        late: 0,
        due: 0,
        race: false,
    }
}

fn run(scenario: Scenario, reverse: bool) {
    let total: u16 = scenario.weights.iter().sum();
    for actor in 0..4 {
        let available: u16 = (0..4)
            .filter(|&other| scenario.groups[actor] == scenario.groups[other])
            .map(|other| scenario.weights[other])
            .sum();
        assert_eq!(
            3 * available > 2 * total,
            scenario.winners & (1 << actor) != 0
        );
    }
    let definition = ArtifactChainDefinition::new([0x91; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x92; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let mut keys =
        std::array::from_fn::<_, 4, _>(|actor| SigningKey::from_bytes(&[0xa0 + actor as u8; 32]));
    keys.sort_by_key(consensus_key);
    let public_keys = keys.each_ref().map(consensus_key);
    let entries = std::array::from_fn::<_, 4, _>(|actor| {
        ActiveAgreementEntry::new(
            public_keys[actor],
            AgreementWeight::new(u128::from(scenario.weights[actor])),
        )
    });
    let layouts = std::array::from_fn::<_, 4, _>(|actor| {
        TestLayout::new(&format!("partition-{}-{actor}", scenario.name))
    });
    let [first, second, third, fourth] = std::array::from_fn::<_, 4, _>(|actor| {
        provision(definition, context, &entries, &layouts[actor])
            .create(keys[actor].clone())
            .unwrap()
    });
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let execute = |scopes: [FixedValidatorNodeSigningScopeV0<'_>; 4]| {
        executor.block_on(async {
            tokio::time::pause();
            let mut owners = scopes.map(runtime_owner);
            let [first_owner, second_owner, third_owner, fourth_owner] = &mut owners;
            let mut sim = simulation(&layouts, scenario, reverse, definition, context, public_keys, &entries);
            sim.pump(first_owner, second_owner, third_owner, fourth_owner).await;
            sim.author(1, first_owner, second_owner, third_owner, fourth_owner);
            sim.pump(first_owner, second_owner, third_owner, fourth_owner).await;
            sim.prepare_second_height();
            sim.author(2, first_owner, second_owner, third_owner, fourth_owner);
            sim.pump(first_owner, second_owner, third_owner, fourth_owner).await;
            if scenario.winners == 0 {
                if scenario.cut == Cut::Precommit {
                    for (actor, key) in public_keys.iter().copied().enumerate() {
                        assert_eq!(
                            sim.intents[&(key, 2, 0, 1)].target,
                            ConsensusVoteTarget::Proposal(sim.values[1].proposal_signing_root())
                        );
                        let expected = (0..4)
                            .filter(|&other| scenario.groups[actor] == scenario.groups[other])
                            .fold(0, |mask, other| mask | (1 << other));
                        assert_eq!(
                            sim.received[actor][&(2, 0, sim.values[1].proposal_signing_root())],
                            expected
                        );
                    }
                }
                for _ in 0..20 {
                    if !sim.race
                        && let Some(actor) = [&*first_owner, &*second_owner, &*third_owner, &*fourth_owner].iter()
                        .position(|owner| owner.driver().unwrap().phase() == FixedValidatorLockPhaseV0::Precommit)
                    {
                        match actor {
                            0 => sim.queued_deadline_race(actor, first_owner).await,
                            1 => sim.queued_deadline_race(actor, second_owner).await,
                            2 => sim.queued_deadline_race(actor, third_owner).await,
                            3 => sim.queued_deadline_race(actor, fourth_owner).await,
                            _ => unreachable!(),
                        }
                        sim.pump(first_owner, second_owner, third_owner, fourth_owner).await;
                        continue;
                    }
                    if [&*first_owner, &*second_owner, &*third_owner, &*fourth_owner].iter()
                        .all(|owner| owner.driver().unwrap().position().round().value() >= 2)
                    {
                        break;
                    }
                    sim.advance_deadline(first_owner, second_owner, third_owner, fourth_owner).await;
                }
                assert!(sim.race && sim.due > 0);
                assert!(
                    [&*first_owner, &*second_owner, &*third_owner, &*fourth_owner].iter()
                        .all(|owner| owner.driver().unwrap().position().round().value() >= 2)
                );
                assert_eq!(sim.finalized, [1; 4]);
                for key in public_keys {
                    for role in 0..2 {
                        assert!(sim.intents.contains_key(&(key, 2, 0, role)));
                    }
                }
            } else {
                for actor in 0..4 {
                    assert_eq!(
                        sim.finalized[actor],
                        if scenario.winners & (1 << actor) != 0 {
                            2
                        } else {
                            1
                        }
                    );
                }
            }
            assert!(
                sim.deliveries > 0
                    && sim.duplicates > 0
                    && sim.local_precommits > 0
                    && sim.caller_precommits > 0
            );
            assert!(sim.dropped > 0);
            sim.history();
            eprintln!(
                "runtime_partition={} reverse={} events={} deliveries={} drops={} duplicate_admissions={} local_precommits={} caller_precommits={} late={} due={} finalized={:?}",
                scenario.name,
                reverse,
                sim.events,
                sim.deliveries,
                sim.dropped,
                sim.duplicates,
                sim.local_precommits,
                sim.caller_precommits,
                sim.late,
                sim.due,
                sim.finalized
            );
        })
    };
    first
        .run_with_signing_session(|first| {
            second
                .run_with_signing_session(|second| {
                    third
                        .run_with_signing_session(|third| {
                            fourth
                                .run_with_signing_session(|fourth| {
                                    execute([first, second, third, fourth])
                                })
                                .unwrap()
                        })
                        .unwrap()
                })
                .unwrap()
        })
        .unwrap();
}

#[test]
fn runtime_partitions_preserve_an_existing_finalized_prefix() {
    for scenario in [
        Scenario {
            name: "unit-split",
            weights: [1, 1, 1, 1],
            groups: [0, 0, 1, 1],
            winners: 0,
            cut: Cut::Cold,
        },
        Scenario {
            name: "exact-threshold",
            weights: [2, 1, 1, 2],
            groups: [0, 0, 0, 1],
            winners: 0,
            cut: Cut::Cold,
        },
        Scenario {
            name: "below-threshold",
            weights: [4, 1, 1, 1],
            groups: [0, 1, 1, 1],
            winners: 0,
            cut: Cut::Cold,
        },
        Scenario {
            name: "unit-majority",
            weights: [1, 1, 1, 1],
            groups: [0, 0, 0, 1],
            winners: 0b0111,
            cut: Cut::Cold,
        },
        Scenario {
            name: "weighted-majority",
            weights: [3, 2, 1, 1],
            groups: [0, 0, 1, 1],
            winners: 0b0011,
            cut: Cut::Cold,
        },
        Scenario {
            name: "precommit-unit",
            weights: [1, 1, 1, 1],
            groups: [0, 0, 1, 1],
            winners: 0,
            cut: Cut::Precommit,
        },
        Scenario {
            name: "precommit-exact",
            weights: [2, 1, 1, 2],
            groups: [0, 0, 0, 1],
            winners: 0,
            cut: Cut::Precommit,
        },
    ] {
        for reverse in [false, true] {
            run(scenario, reverse);
        }
    }
}
