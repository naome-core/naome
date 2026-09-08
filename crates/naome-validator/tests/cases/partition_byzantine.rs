//! Four real honest signers and one explicitly Byzantine transport/signing peer.
use super::*;
use ed25519_dalek::Signer;
use naome_consensus::{
    ConsensusPosition, ConsensusRound, ConsensusValueV0, ConsensusVoteRole, ConsensusVoteTarget,
    VerifiedConsensusVoteV0, VerifiedFixedConsensusProposalV0,
};
use naome_network::ConsensusPushMessage;
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalV0, FixedValidatorVoteSafetyReplayLimitV0,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[path = "partition_byzantine_peer.rs"]
mod peer;
use peer::{Bridge, Wire};

struct Fixture {
    corpus: Corpus,
    entries: Vec<ActiveAgreementEntry>,
    faulty: SigningKey,
    noise: [u8; 32],
    peer: PeerId,
    values: [ConsensusValueV0; 2],
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
    controls: [Vec<u8>; 2],
    next_proposer: usize,
}

impl Fixture {
    fn new() -> Self {
        let corpus = Corpus::new([2; 4]);
        let faulty = SigningKey::from_bytes(&[0xe7; 32]);
        let faulty_key = ConsensusKey::from_bytes(faulty.verifying_key().to_bytes());
        let mut entries = corpus.entries.to_vec();
        entries.push(ActiveAgreementEntry::new(
            faulty_key,
            AgreementWeight::new(3),
        ));
        entries.sort_by_key(|entry| *entry.consensus_key().as_bytes());
        assert_eq!(entries.len(), 5);
        let total: u128 = entries
            .iter()
            .map(|entry| entry.agreement_weight().units())
            .sum();
        assert_eq!(total, 11);
        assert!(3 * 3 < total);
        assert!(3 * 7 <= 2 * total);
        assert!(3 * 8 > 2 * total);
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            corpus.context,
            &entries,
            ArtifactChainState::new(corpus.definition).branch_snapshot(),
        )
        .unwrap();
        let round = branch.begin_round_zero().unwrap();
        assert_eq!(round.proposer(), faulty_key);
        let next = branch
            .begin_round_zero()
            .unwrap()
            .advance_round()
            .unwrap()
            .proposer();
        let next_proposer = corpus
            .entries
            .iter()
            .position(|e| e.consensus_key() == next)
            .unwrap();
        let payloads = [1, 2].map(|axiom| {
            ArtifactPayload::Proof(
                ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom]).unwrap(),
            )
            .to_canonical_bytes()
        });
        let blocks = payloads.each_ref().map(|payload| {
            let id = ArtifactDag::new()
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id();
            ArtifactChainState::new(corpus.definition)
                .prepare_block(id)
                .unwrap()
        });
        let values = blocks.map(|block| round.value_for_artifact_block(block));
        assert_ne!(blocks[0], blocks[1]);
        assert_ne!(values[0], values[1]);
        assert_ne!(
            values[0].proposal_signing_root(),
            values[1].proposal_signing_root()
        );
        let controls = values.map(|value| {
            let mut body = Vec::new();
            body.extend_from_slice(corpus.context.chain_id().as_bytes());
            body.extend_from_slice(corpus.context.genesis_id().as_bytes());
            body.extend_from_slice(&corpus.context.protocol_version().value().to_be_bytes());
            body.extend_from_slice(&1_u64.to_be_bytes());
            body.extend_from_slice(&0_u64.to_be_bytes());
            body.extend_from_slice(value.proposal_signing_root().as_bytes());
            body.extend_from_slice(faulty_key.as_bytes());
            let mut transcript = b"naome:consensus-producer-authorization:v0\0".to_vec();
            transcript.extend_from_slice(&body);
            body.extend_from_slice(&faulty.sign(&transcript).to_bytes());
            let mut control = value.to_canonical_bytes().to_vec();
            control.extend_from_slice(&body);
            control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
            control
        });
        for side in 0..2 {
            assert_eq!(
                round
                    .decode_and_verify_proposal_control(&controls[side], payloads[side].clone())
                    .unwrap()
                    .value(),
                values[side]
            );
        }
        // The bridge owns dialing. All four processes list only this static
        // peer, so no alternative honest cross-group transport path exists.
        let (noise, peer) = (0..=255_u8)
            .find_map(|byte| {
                let noise = [byte; 32];
                let peer = Keypair::ed25519_from_bytes(&mut [byte; 32])
                    .unwrap()
                    .public()
                    .to_peer_id();
                corpus
                    .peers
                    .iter()
                    .all(|p| peer.to_bytes() < p.to_bytes())
                    .then_some((noise, peer))
            })
            .unwrap();
        Self {
            corpus,
            entries,
            faulty,
            noise,
            peer,
            values,
            blocks,
            payloads,
            controls,
            next_proposer,
        }
    }

    fn config(&self, layout: &Layout, actor: usize) -> String {
        layout.seed("signing.seed", &self.corpus.keys[actor].to_bytes());
        layout.seed("noise.seed", &self.corpus.noise[actor]);
        let validators = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "[[validators]]\nconsensus_key = {:?}\nweight = {:?}\n",
                    hex(e.consensus_key().as_bytes()),
                    e.agreement_weight().units().to_string()
                )
            })
            .collect::<String>();
        format!(
            r#"version = 0
mode = "create"
deployment_discriminator = "{deployment}"
genesis_id = "{genesis}"
protocol_version = 7
signing_seed_file = "signing.seed"
{validators}
[directories]
finality_journal = "finality-journal"
finality_anchor = "finality-anchor"
vote_journal = "vote-journal"
vote_anchor = "vote-anchor"
[network]
identity_seed_file = "noise.seed"
listen = "/ip4/127.0.0.1/tcp/0"
peers = [{{ peer_id = "{peer}", address = "/ip4/127.0.0.1/tcp/1" }}]
publication_targets = ["{peer}"]
[limits]
finality_max_round = "8"
vote_preparations = "64"
proposal_preparations = "8"
recovery_max_round = "4"
catch_up_heights = "0"
driver_max_round = "4"
[limits.higher]
entries = "128"
bytes = "1048576"
[limits.current]
entries = "128"
bytes = "1048576"
[limits.finality]
entries = "128"
bytes = "1048576"
[limits.nil_precommit]
entries = "128"
bytes = "1048576"
[timeouts.proposal]
base_millis = "10000"
round_increment_millis = "1"
[timeouts.prevote]
base_millis = "10000"
round_increment_millis = "1"
[timeouts.precommit]
base_millis = "10000"
round_increment_millis = "1"
"#,
            deployment = hex(self.corpus.definition.deployment_discriminator()),
            genesis = hex(self.corpus.context.genesis_id().as_bytes()),
            peer = self.peer
        )
    }

    fn faulty_vote(&self, side: usize, role: ConsensusVoteRole) -> Wire {
        let mut body = vec![match role {
            ConsensusVoteRole::Prevote => 1,
            ConsensusVoteRole::Precommit => 2,
        }];
        body.extend_from_slice(self.corpus.context.chain_id().as_bytes());
        body.extend_from_slice(self.corpus.context.genesis_id().as_bytes());
        body.extend_from_slice(&self.corpus.context.protocol_version().value().to_be_bytes());
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&0_u64.to_be_bytes());
        body.push(1);
        body.extend_from_slice(self.values[side].proposal_signing_root().as_bytes());
        body.extend_from_slice(&self.faulty.verifying_key().to_bytes());
        let mut transcript = match role {
            ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0".to_vec(),
            ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0".to_vec(),
        };
        transcript.extend_from_slice(&body);
        body.extend_from_slice(&self.faulty.sign(&transcript).to_bytes());
        let verified =
            VerifiedConsensusVoteV0::decode_and_verify(&body, self.corpus.context).unwrap();
        assert_eq!(
            verified.target(),
            ConsensusVoteTarget::Proposal(self.values[side].proposal_signing_root())
        );
        Wire::Vote(body)
    }
}

fn vote(
    trace: &peer::Trace,
    fixture: &Fixture,
    actor: usize,
    round: u64,
    role: u8,
) -> Option<ConsensusVoteTarget> {
    trace.votes.get(&(actor, 1, round, role)).map(|bytes| {
        VerifiedConsensusVoteV0::decode_and_verify(bytes, fixture.corpus.context)
            .unwrap()
            .target()
    })
}

fn verify_stopped(
    fixture: &Fixture,
    layout: &Layout,
    actor: usize,
    trace: &peer::Trace,
) -> ConsensusAncestryId {
    let before = layout.images();
    let _guard = PARENT_JOURNALS.read().unwrap();
    let finality = FixedValidatorAnchoredFinalityJournalV0::open(
        layout.root.join("finality-journal"),
        layout.root.join("finality-anchor"),
        fixture.corpus.definition,
        fixture.corpus.context,
        &fixture.entries,
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
    )
    .unwrap();
    assert!(finality.halt().unwrap().is_none());
    assert_eq!(finality.finalized_len().unwrap(), 1);
    let record = finality
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(record.position().round(), ConsensusRound::new(1));
    assert_eq!(record.value().artifact_block(), fixture.blocks[0]);
    assert_eq!(record.canonical_artifact_bytes(), fixture.payloads[0]);
    assert_eq!(
        record.value().parent_ancestry_id(),
        ConsensusAncestryId::virtual_genesis(fixture.corpus.context)
    );
    let ancestry = record.value().ancestry_id();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.corpus.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.corpus.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let proof = round
        .decode_and_verify(
            record.canonical_envelope_bytes(),
            fixture.payloads[0].clone(),
        )
        .unwrap();
    let signed = (0..4)
        .map(|signer| trace.votes[&(signer, 1, 1, 1)].as_slice())
        .collect::<Vec<_>>();
    let actual = round
        .build_quorum_certificate_from_signed_votes(
            &signed,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(fixture.values[0].proposal_signing_root()),
        )
        .unwrap();
    assert_eq!(
        proof.precommit_certificate().to_canonical_bytes(),
        actual.to_canonical_bytes()
    );
    assert_eq!(actual.signer_count(), 4);
    assert_eq!(actual.signed_weight().units(), 8);
    assert_eq!(actual.total_weight().units(), 11);
    let mut selected = ArtifactChainState::new(fixture.corpus.definition);
    selected
        .apply_block(&fixture.blocks[0], fixture.payloads[0].clone())
        .unwrap();
    assert_eq!(
        finality.artifact_set_root().unwrap(),
        selected.branch_snapshot().artifact_set_root()
    );
    let journal = FixedValidatorAnchoredVoteSafetyJournalV0::open(
        layout.root.join("vote-journal"),
        layout.root.join("vote-anchor"),
        fixture.corpus.context,
        finality.fixed_agreement_set_id(),
        fixture.corpus.keys[actor].clone(),
        FixedValidatorVoteSafetyReplayLimitV0::new(64).unwrap(),
    )
    .unwrap();
    assert!(journal.halt().unwrap().is_none());
    assert!(journal.proposal_halt().unwrap().is_none());
    assert!(journal.finality_conflict_stop().unwrap().is_none());
    assert!(journal.pending_vote().unwrap().is_none());
    assert!(journal.pending_proposal().unwrap().is_none());
    for (height, round) in (1..=2).flat_map(|height| (0..=4).map(move |round| (height, round))) {
        for (role_id, role) in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit]
            .into_iter()
            .enumerate()
        {
            let position =
                ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round));
            let retained = journal.retained_signed_vote(position, role).unwrap();
            if height != 1 || round > 1 {
                assert!(
                    retained.is_none(),
                    "unexpected honest signing slot {position:?}/{role:?}"
                );
                continue;
            }
            let retained = retained.unwrap();
            assert_eq!(
                retained.canonical_bytes(),
                trace.votes[&(actor, 1, round, role_id as u8)]
            );
            let checked = VerifiedConsensusVoteV0::decode_and_verify(
                retained.canonical_bytes(),
                fixture.corpus.context,
            )
            .unwrap();
            assert_eq!(
                checked.signer(),
                fixture.corpus.entries[actor].consensus_key()
            );
            assert_eq!(checked.position(), position);
            assert_eq!(checked.role(), role);
        }
    }
    drop(journal);
    drop(finality);
    assert_eq!(
        before,
        layout.images(),
        "strict stopped inspection must not repair state"
    );
    ancestry
}

#[test]
fn byzantine_bridge_equivocation_cannot_finalize_partitioned_honest_processes() {
    let fixture = Fixture::new();
    let layouts: [Layout; 4] = std::array::from_fn(|_| Layout::new());
    let configs = std::array::from_fn::<_, 4, _>(|actor| fixture.config(&layouts[actor], actor));
    let mut nodes =
        std::array::from_fn::<_, 4, _>(|actor| Process::start(&layouts[actor], &configs[actor]));
    let addresses = nodes.each_mut().map(|node| {
        let ready = node.ready();
        assert_eq!(ready["driver"]["height"], "1");
        node.event("listening")["address"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    let bridge = Bridge::start(&fixture, addresses);
    pump_until(&mut nodes, "four bridge sessions", |nodes| {
        nodes.iter().all(|node| {
            node.observed.iter().any(|e| {
                e["event"] == "peer_session"
                    && e["state"] == "established"
                    && e["peer"] == fixture.peer.to_string()
            })
        })
    });
    let baseline = layouts.each_ref().map(Layout::finality_images);
    bridge.inject(
        (0..4)
            .flat_map(|to| {
                let side = to / 2;
                [
                    (
                        to,
                        Wire::Proposal(
                            fixture.controls[side].clone(),
                            fixture.payloads[side].clone(),
                        ),
                    ),
                    (to, fixture.faulty_vote(side, ConsensusVoteRole::Prevote)),
                    (to, fixture.faulty_vote(side, ConsensusVoteRole::Precommit)),
                ]
            })
            .collect(),
    );
    pump_until(
        &mut nodes,
        "both equivocating proposals cause honest prevotes",
        |_| {
            let trace = bridge.snapshot();
            (0..4).all(|actor| {
                vote(&trace, &fixture, actor, 0, 0)
                    == Some(ConsensusVoteTarget::Proposal(
                        fixture.values[actor / 2].proposal_signing_root(),
                    ))
            })
        },
    );
    pump_until(
        &mut nodes,
        "partitioned real deadlines reach round one",
        |nodes| {
            let trace = bridge.snapshot();
            (0..4)
                .all(|actor| vote(&trace, &fixture, actor, 0, 1) == Some(ConsensusVoteTarget::Nil))
                && nodes.iter().all(|node| {
                    node.observed.iter().any(|e| {
                        e["event"] == "transitioned"
                            && e["height"] == "1"
                            && e["round"] == "1"
                            && e["phase"] == "Proposal"
                    })
                })
        },
    );
    let partition = bridge.snapshot();
    assert!(partition.dropped_cross_group >= 16);
    for actor in 0..4 {
        assert_eq!(layouts[actor].finality_images(), baseline[actor]);
        let end = nodes[actor]
            .observed
            .iter()
            .position(|e| e["event"] == "transitioned" && e["round"] == "1")
            .unwrap();
        let round_zero = &nodes[actor].observed[..end];
        let admitted_bytes = |bytes: &[u8], route: &str, local: bool| {
            let digest = hex(&Sha256::digest(bytes));
            if local {
                let Some(end) = round_zero.iter().position(|e| {
                    e["event"] == "publication_complete"
                        && e["disposed"]["message_sha256"]["control"] == digest
                }) else {
                    return false;
                };
                assert_eq!(
                    round_zero[end]["disposed"]["local_admission_attempted"],
                    true
                );
                assert_eq!(
                    round_zero[end]["disposed"]["local_admission_skipped"],
                    false
                );
                let start = round_zero[..end]
                    .iter()
                    .rposition(|e| e["event"] == "publication_complete")
                    .map_or(0, |index| index + 1);
                return round_zero[start..end]
                    .iter()
                    .any(|e| admitted(e, route) && e["source"]["kind"] == "local_publication");
            }
            round_zero.iter().any(|e| {
                admitted(e, route)
                    && e["message_sha256"]["control"] == digest
                    && e["source"]["peer"] == fixture.peer.to_string()
                    && e["receipt_queued"] == true
            })
        };
        assert!(admitted_bytes(
            &fixture.controls[actor / 2],
            "CurrentVotingProposal",
            false
        ));
        assert!(admitted_bytes(
            &fixture.controls[actor / 2],
            "CurrentFinalityProposal",
            false
        ));
        for signer in [actor, actor ^ 1] {
            assert!(admitted_bytes(
                &partition.votes[&(signer, 1, 0, 0)],
                "CurrentProposalPrevote",
                signer == actor
            ));
        }
        for (role, route) in [
            (ConsensusVoteRole::Prevote, "CurrentProposalPrevote"),
            (ConsensusVoteRole::Precommit, "CurrentProposalPrecommit"),
        ] {
            let Wire::Vote(bytes) = fixture.faulty_vote(actor / 2, role) else {
                unreachable!()
            };
            assert!(
                admitted_bytes(&bytes, route, false),
                "actual Byzantine vote must be admitted at actor {actor}"
            );
        }
        assert!(
            !nodes[actor]
                .observed
                .iter()
                .any(|e| e["event"] == "finality")
        );
        assert!(
            nodes[actor]
                .observed
                .iter()
                .filter(|e| e["event"] == "timer_due" && e["admitted"] == true)
                .count()
                >= 2
        );
        let partner = actor ^ 1;
        let expected = Wire::Vote(partition.votes[&(partner, 1, 0, 0)].clone());
        assert_eq!(
            partition
                .delivered
                .iter()
                .filter(|(to, wire)| *to == actor && *wire == expected)
                .count(),
            2
        );
        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
            let expected = fixture.faulty_vote(actor / 2, role);
            assert_eq!(
                partition
                    .delivered
                    .iter()
                    .filter(|(to, wire)| *to == actor && *wire == expected)
                    .count(),
                2
            );
        }
    }
    bridge.heal();
    pump_until(&mut nodes, "bridge healing acknowledged", |_| {
        bridge.snapshot().healed
    });
    let author = fixture.next_proposer;
    layouts[author].write("block.bin", fixture.blocks[0].to_canonical_bytes());
    layouts[author].write("payload.bin", &fixture.payloads[0]);
    nodes[author].send(json!({"command":"author_fresh", "id":77, "block_file":"block.bin", "payload_file":"payload.bin"}));
    pump_until(&mut nodes, "healed honest quorum finality", |nodes| {
        let trace = bridge.snapshot();
        trace.idle
            && nodes
                .iter()
                .all(|node| finality(node, &fixture.blocks[0], "2"))
            && (0..4).all(|actor| trace.votes.contains_key(&(actor, 1, 1, 1)))
    });
    let trace = bridge.snapshot();
    assert_eq!(trace.votes.len(), 16);
    assert!(!trace.proposals.is_empty());
    assert!(trace.proposals.iter().all(|(actor, _)| *actor == author));
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.corpus.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.corpus.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap().advance_round().unwrap();
    for (_, wire) in &trace.proposals {
        let Wire::Proposal(control, payload) = wire else {
            unreachable!()
        };
        assert_eq!(
            round
                .decode_and_verify_proposal_control(control, payload.clone())
                .unwrap()
                .value(),
            fixture.values[0]
        );
    }
    for actor in 0..4 {
        for role in 0..2 {
            assert_eq!(
                vote(&trace, &fixture, actor, 1, role),
                Some(ConsensusVoteTarget::Proposal(
                    fixture.values[0].proposal_signing_root()
                ))
            );
        }
    }
    for node in &mut nodes {
        assert_eq!(node.shutdown()["locks_released"], true);
        for event in &node.observed {
            healthy(event);
        }
    }
    drop(bridge);
    let ancestry = std::array::from_fn::<_, 4, _>(|actor| {
        verify_stopped(&fixture, &layouts[actor], actor, &trace)
    });
    assert!(ancestry.iter().all(|id| *id == ancestry[0]));
}
