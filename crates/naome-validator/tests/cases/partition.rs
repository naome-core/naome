use crate::support::*;
use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactBlock, ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusAncestryId,
    ConsensusContextV0, ConsensusGenesisId, ConsensusHeight, ConsensusKey,
    ConsensusProtocolVersion, FixedConsensusBranchV0, PreselectedProposerStateV0,
};
use naome_network::{Keypair, PeerId};
use naome_proof::{ArtifactPayload, ProofCertificate};
use naome_storage::{FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityReplayLimitV0};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

#[path = "gated_tcp.rs"]
mod gated_tcp;
use gated_tcp::Gate;

const PAIRS: [(usize, usize); 6] = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
const MILESTONE_BOUND: Duration = Duration::from_secs(45);
type Images = Vec<(PathBuf, Vec<u8>)>;

struct Corpus {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    keys: [SigningKey; 4],
    entries: [ActiveAgreementEntry; 4],
    noise: [[u8; 32]; 4],
    peers: [PeerId; 4],
    proposers: [usize; 2],
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
}
impl Corpus {
    fn new(weights: [u16; 4]) -> Self {
        let definition = ArtifactChainDefinition::new([0x91; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x92; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let mut keys =
            std::array::from_fn(|actor| SigningKey::from_bytes(&[0xa0 + actor as u8; 32]));
        keys.sort_by_key(|key| key.verifying_key().to_bytes());
        let entries = std::array::from_fn(|actor| {
            ActiveAgreementEntry::new(
                ConsensusKey::from_bytes(keys[actor].verifying_key().to_bytes()),
                AgreementWeight::new(u128::from(weights[actor])),
            )
        });
        let mut selected = ArtifactChainState::new(definition);
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            context,
            &entries,
            selected.branch_snapshot(),
        )
        .unwrap();
        let round = branch.begin_round_zero().unwrap();
        let snapshot =
            ActiveAgreementSnapshot::try_from_preselected(round.position(), &entries).unwrap();
        let mut arithmetic =
            PreselectedProposerStateV0::from_zeroed_preselected_snapshot(&snapshot);
        // Schedule prediction grants no authority: the real owners must accept
        // author_fresh and establish H1 before the second command is issued.
        let proposers = std::array::from_fn(|_| {
            let (key, successor) = arithmetic.select_next().unwrap();
            arithmetic = successor;
            entries
                .iter()
                .position(|entry| entry.consensus_key() == key)
                .unwrap()
        });
        assert_eq!(entries[proposers[0]].consensus_key(), round.proposer());
        let payloads = [1, 2].map(|value| {
            ArtifactPayload::Proof(
                ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, value]).unwrap(),
            )
            .to_canonical_bytes()
        });
        let blocks = payloads.each_ref().map(|payload| {
            let artifact = ArtifactDag::new()
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id();
            let block = selected.prepare_block(artifact).unwrap();
            selected.apply_block(&block, payload.clone()).unwrap();
            block
        });
        let mut noise = [[101; 32], [102; 32], [103; 32], [104; 32]];
        let identity = |mut seed| {
            Keypair::ed25519_from_bytes(&mut seed)
                .unwrap()
                .public()
                .to_peer_id()
        };
        noise.sort_by_key(|seed| identity(*seed).to_bytes());
        let peers = noise.map(identity);
        Self {
            definition,
            context,
            keys,
            entries,
            noise,
            peers,
            proposers,
            blocks,
            payloads,
        }
    }

    fn config(&self, layout: &Layout, actor: usize, gates: &[Gate; 6]) -> String {
        layout.seed("signing.seed", &self.keys[actor].to_bytes());
        layout.seed("noise.seed", &self.noise[actor]);
        let validators = self
            .entries
            .iter()
            .map(|entry| {
                format!(
                    "[[validators]]\nconsensus_key = {:?}\nweight = {:?}\n",
                    hex(entry.consensus_key().as_bytes()),
                    entry.agreement_weight().units().to_string()
                )
            })
            .collect::<String>();
        let peers = PAIRS
            .iter()
            .enumerate()
            .filter_map(|(index, &(a, b))| {
                let other = if a == actor {
                    b
                } else if b == actor {
                    a
                } else {
                    return None;
                };
                Some(format!(
                    "{{ peer_id = {:?}, address = {:?} }}",
                    self.peers[other].to_string(),
                    gates[index].address()
                ))
            })
            .collect::<Vec<_>>()
            .join(", ");
        let targets = (0..4)
            .filter(|&other| other != actor)
            .map(|other| format!("{:?}", self.peers[other].to_string()))
            .collect::<Vec<_>>()
            .join(", ");
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
peers = [{peers}]
publication_targets = [{targets}]
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
base_millis = "5000"
round_increment_millis = "1"
[timeouts.prevote]
base_millis = "5000"
round_increment_millis = "1"
[timeouts.precommit]
base_millis = "5000"
round_increment_millis = "1"
"#,
            deployment = hex(self.definition.deployment_discriminator()),
            genesis = hex(self.context.genesis_id().as_bytes())
        )
    }

    fn author(&self, nodes: &mut [Process; 4], layouts: &[Layout; 4], index: usize) {
        let actor = self.proposers[index];
        layouts[actor].write("block.bin", self.blocks[index].to_canonical_bytes());
        layouts[actor].write("payload.bin", &self.payloads[index]);
        nodes[actor].send(json!({"command":"author_fresh", "id": index + 1, "block_file":"block.bin", "payload_file":"payload.bin"}));
        pump_until(nodes, "actual proposer authoring", |nodes| {
            nodes[actor]
                .observed
                .iter()
                .any(|event| event["event"] == "command_result" && event["id"] == index + 1)
        });
        let result = nodes[actor]
            .observed
            .iter()
            .find(|event| event["event"] == "command_result" && event["id"] == index + 1)
            .unwrap();
        assert_eq!(
            result["outcome"]["event"], "proposal_authored",
            "actual scheduled author refused: {result}"
        );
    }

    fn verify(&self, layout: &Layout, height: usize) -> Vec<ConsensusAncestryId> {
        let before = layout.images();
        let _guard = PARENT_JOURNALS.read().unwrap();
        let journal = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            self.definition,
            self.context,
            &self.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        assert!(journal.halt().unwrap().is_none());
        assert_eq!(journal.finalized_len().unwrap(), height);
        assert_eq!(
            journal.head().unwrap().verified_height(),
            Some(ConsensusHeight::new(height as u64))
        );
        assert_eq!(
            journal.artifact_head_block_id().unwrap(),
            self.blocks[height - 1].id()
        );
        let mut selected = ArtifactChainState::new(self.definition);
        let mut previous = None;
        let mut ancestry = Vec::new();
        for index in 0..height {
            let record = journal
                .finality_record(ConsensusHeight::new(index as u64 + 1))
                .unwrap()
                .unwrap();
            assert_eq!(record.position().round().value(), 0);
            assert_eq!(record.value().artifact_block(), self.blocks[index]);
            assert_eq!(record.canonical_artifact_bytes(), self.payloads[index]);
            if let Some(ancestry) = previous {
                assert_eq!(record.value().parent_ancestry_id(), ancestry);
            }
            previous = Some(record.value().ancestry_id());
            ancestry.push(record.value().ancestry_id());
            selected
                .apply_block(&self.blocks[index], self.payloads[index].clone())
                .unwrap();
        }
        assert_eq!(
            journal.artifact_set_root().unwrap(),
            selected.branch_snapshot().artifact_set_root()
        );
        drop(journal);
        assert_eq!(
            layout.images(),
            before,
            "healthy replay must not repair authority bytes"
        );
        ancestry
    }
}

fn admitted(event: &Value, route: &str) -> bool {
    event["event"] == "admission"
        && event["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["route"] == route && result["admitted"] == true)
}

fn healthy(event: &Value) {
    for kind in [&event["event"], &event["outcome"]["event"]] {
        assert!(
            !matches!(
                kind.as_str(),
                Some(
                    "error"
                        | "listener_failed"
                        | "driver_rejected"
                        | "allocation_failed"
                        | "timing_failed"
                        | "finality_stopped"
                        | "proof_failed"
                        | "driver_unavailable"
                        | "unsupported_runtime_event"
                        | "command_rejected"
                        | "proposal_rejected"
                )
            ),
            "unexpected process failure: {event}"
        );
    }
    if event["event"] == "timer_due" {
        assert_eq!(event["admitted"], true);
    }
    if event["event"] == "peer_session" {
        assert_ne!(event["state"], "unsupported");
    }
}

fn pump_until(nodes: &mut [Process; 4], label: &str, predicate: impl Fn(&[Process; 4]) -> bool) {
    let deadline = Instant::now() + MILESTONE_BOUND;
    while !predicate(nodes) {
        for (actor, node) in nodes.iter_mut().enumerate() {
            if let Some(event) = node.observe(Duration::from_millis(1)) {
                healthy(&event);
                assert_ne!(event["event"], "stopped", "{label}: actor {actor}");
            }
            assert!(
                node.child.try_wait().unwrap().is_none(),
                "{label}: actor {actor} exited"
            );
        }
        assert!(
            Instant::now() < deadline,
            "{label}: timed out; transcripts: {:?}",
            nodes.each_ref().map(|node| &node.observed)
        );
    }
}

fn finality(node: &Process, block: &ArtifactBlock, next_height: &str) -> bool {
    node.observed.iter().any(|event| {
        event["event"] == "finality"
            && event["state"]["driver"]["head"] == hex(block.id().as_bytes())
            && event["state"]["driver"]["height"] == next_height
            && event["state"]["driver"]["round"] == "0"
            && event["state"]["driver"]["phase"] == "Proposal"
    })
}

fn finality_images(layout: &Layout) -> Images {
    let mut images = Vec::new();
    for directory in ["finality-journal", "finality-anchor"] {
        for entry in fs::read_dir(layout.root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            images.push((
                path.strip_prefix(&layout.root).unwrap().to_path_buf(),
                fs::read(path).unwrap(),
            ));
        }
    }
    images.sort_by(|left, right| left.0.cmp(&right.0));
    images
}

fn run_partition(weights: [u16; 4], groups: [u8; 4], winners: [bool; 4]) {
    let corpus = Corpus::new(weights);
    let total: u32 = weights.iter().map(|&weight| u32::from(weight)).sum();
    for actor in 0..4 {
        let available: u32 = (0..4)
            .filter(|&other| groups[actor] == groups[other])
            .map(|other| u32::from(weights[other]))
            .sum();
        assert_eq!(3 * available > 2 * total, winners[actor]);
    }
    assert!(winners.iter().all(|winner| !winner) || winners[corpus.proposers[1]]);
    // Children drop before gates and directories, including assertion unwinding.
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let mut nodes = std::array::from_fn(|actor| {
        Process::start(
            &layouts[actor],
            &corpus.config(&layouts[actor], actor, &gates),
        )
    });
    let addresses = nodes.each_mut().map(|node| {
        node.ready();
        let event = node.event("listening");
        let port = event["address"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        ([127, 0, 0, 1], port).into()
    });
    for (gate, &(_, higher)) in gates.iter_mut().zip(&PAIRS) {
        gate.start(addresses[higher]);
    }
    pump_until(&mut nodes, "complete authenticated mesh", |nodes| {
        nodes.iter().enumerate().all(|(actor, node)| {
            (0..4).filter(|&other| other != actor).all(|other| {
                node.observed.iter().any(|event| {
                    event["event"] == "peer_session"
                        && event["state"] == "established"
                        && event["peer"] == corpus.peers[other].to_string()
                })
            })
        })
    });
    assert!(gates.iter().all(|gate| gate.counts() == (1, 0)));
    corpus.author(&mut nodes, &layouts, 0);
    pump_until(&mut nodes, "common H1 and drained publications", |nodes| {
        nodes.iter().all(|node| {
            finality(node, &corpus.blocks[0], "2")
                && node
                    .observed
                    .iter()
                    .filter(|event| event["event"] == "publication_prepared")
                    .count()
                    == node
                        .observed
                        .iter()
                        .filter(|event| event["event"] == "publication_complete")
                        .count()
        })
    });
    for node in &mut nodes {
        node.send(json!({"command":"status", "id": 10}));
    }
    pump_until(&mut nodes, "quiescent H2 status", |nodes| {
        nodes.iter().all(|node| {
            node.observed
                .iter()
                .any(|event| event["event"] == "command_result" && event["id"] == 10)
        })
    });
    for (actor, node) in nodes.iter().enumerate() {
        let status = &node
            .observed
            .iter()
            .find(|event| event["event"] == "command_result" && event["id"] == 10)
            .unwrap()["outcome"];
        assert_eq!(
            status["driver"]["head"],
            hex(corpus.blocks[0].id().as_bytes())
        );
        assert_eq!(status["driver"]["height"], "2");
        assert_eq!(status["driver"]["round"], "0");
        assert_eq!(status["driver"]["phase"], "Proposal");
        assert_eq!(status["driver"]["pending_command"], false);
        assert_eq!(status["driver"]["timeout_due"], false);
        assert!(status["publication"].is_null());
        let mut completed = 0;
        for event in node
            .observed
            .iter()
            .filter(|event| event["event"] == "publication_complete")
        {
            completed += 1;
            assert_eq!(event["disposed"]["local_admission_attempted"], true);
            let deliveries = event["disposed"]["deliveries"].as_array().unwrap();
            assert_eq!(deliveries.len(), 3);
            for other in (0..4).filter(|&other| other != actor) {
                assert_eq!(
                    deliveries
                        .iter()
                        .filter(
                            |delivery| delivery["peer"] == corpus.peers[other].to_string()
                                && delivery["state"] == "received"
                        )
                        .count(),
                    1
                );
            }
        }
        assert!(completed >= 1, "each owner actually publishes H1 votes");
        assert_eq!(
            node.observed
                .iter()
                .filter(|event| event["event"] == "peer_completed" && event["received"] == true)
                .count(),
            3 * completed
        );
    }
    let baseline = layouts.each_ref().map(finality_images);
    let cut_start = nodes.each_ref().map(|node| node.observed.len());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if groups[a] != groups[b] {
            gate.cut();
        }
    }
    pump_until(&mut nodes, "all cut endpoints disconnected", |nodes| {
        nodes.iter().enumerate().all(|(actor, node)| {
            (0..4)
                .filter(|&other| groups[actor] != groups[other])
                .all(|other| {
                    node.observed[cut_start[actor]..].iter().any(|event| {
                        event["event"] == "peer_session"
                            && event["state"] == "disconnected"
                            && event["peer"] == corpus.peers[other].to_string()
                    })
                })
        })
    });
    // H1 is drained and every cross endpoint reports disconnected before
    // authoring the only H2 proposal. Real timers continue throughout.
    let proposal_start = nodes.each_ref().map(|node| node.observed.len());
    corpus.author(&mut nodes, &layouts, 1);
    pump_until(
        &mut nodes,
        "partition finality and real timeout round",
        |nodes| {
            for actor in 0..4 {
                if !winners[actor] {
                    assert_eq!(
                        finality_images(&layouts[actor]),
                        baseline[actor],
                        "minority changed finality authority"
                    );
                }
            }
            nodes.iter().enumerate().all(|(actor, node)| {
                if winners[actor] {
                    finality(node, &corpus.blocks[1], "3")
                } else {
                    node.observed[proposal_start[actor]..].iter().any(|event| {
                        event["event"] == "transitioned"
                            && event["height"] == "2"
                            && event["phase"] == "Proposal"
                            && event["round"].as_str().unwrap().parse::<u64>().unwrap() >= 1
                    })
                }
            })
        },
    );
    let observation_end = nodes.each_ref().map(|node| node.observed.len());
    for node in &mut nodes {
        assert_eq!(node.shutdown()["locks_released"], true);
    }
    let mut histories = Vec::new();
    for (actor, node) in nodes.iter().enumerate() {
        for event in &node.observed {
            healthy(event);
        }
        let tail = &node.observed[proposal_start[actor]..observation_end[actor]];
        let stopped = node.observed.last().unwrap();
        assert_eq!(stopped["event"], "stopped");
        assert_eq!(
            stopped["discarded"]["driver"]["head"],
            hex(corpus.blocks[usize::from(winners[actor])].id().as_bytes())
        );
        assert_eq!(
            stopped["discarded"]["driver"]["height"],
            if winners[actor] { "3" } else { "2" }
        );
        assert_eq!(
            node.observed
                .iter()
                .filter(|event| event["event"] == "finality")
                .count(),
            if winners[actor] { 2 } else { 1 }
        );
        if !winners[actor] {
            assert!(
                tail.iter()
                    .any(|event| event["event"] == "timer_due" && event["admitted"] == true)
            );
            assert!(
                tail.iter()
                    .any(|event| admitted(event, "CurrentNilPrecommit")
                        && event["source"]["kind"] == "local_publication")
            );
            assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
        } else {
            let images = finality_images(&layouts[actor]);
            for (path, prefix) in baseline[actor]
                .iter()
                .filter(|(path, _)| path.starts_with("finality-journal"))
            {
                assert!(
                    images
                        .iter()
                        .find(|(current, _)| current == path)
                        .unwrap()
                        .1
                        .starts_with(prefix)
                );
            }
        }
        for event in tail
            .iter()
            .filter(|event| event["event"] == "admission" && event["source"]["kind"] == "peer")
        {
            let sender = corpus
                .peers
                .iter()
                .position(|peer| event["source"]["peer"] == peer.to_string())
                .unwrap();
            assert_eq!(groups[actor], groups[sender]);
        }
        for event in &node.observed[cut_start[actor]..observation_end[actor]] {
            if event["event"] == "peer_session" {
                let other = corpus
                    .peers
                    .iter()
                    .position(|peer| event["peer"] == peer.to_string())
                    .unwrap();
                if groups[actor] == groups[other] {
                    assert_ne!(event["state"], "disconnected", "an internal path failed");
                    assert_ne!(event["state"], "dial_failed", "an internal path failed");
                } else {
                    assert_ne!(event["state"], "established", "a cut path reconnected");
                }
            }
        }
        if groups[actor] == groups[corpus.proposers[1]] {
            let end = tail
                .iter()
                .position(|event| {
                    event["event"] == "finality"
                        || (event["event"] == "transitioned" && event["round"] != "0")
                })
                .unwrap_or(tail.len());
            let round_zero = &tail[..end];
            assert!(
                round_zero
                    .iter()
                    .any(|event| admitted(event, "CurrentProposalPrevote")
                        && event["source"]["kind"] == "local_publication")
            );
            for other in (0..4).filter(|&other| other != actor && groups[actor] == groups[other]) {
                assert!(
                    round_zero
                        .iter()
                        .any(|event| admitted(event, "CurrentProposalPrevote")
                            && event["source"]["kind"] == "peer"
                            && event["source"]["peer"] == corpus.peers[other].to_string()
                            && event["receipt_queued"] == true),
                    "missing H2/R0 peer prevote at actor {actor} from {other}"
                );
                assert!(
                    round_zero
                        .iter()
                        .any(|event| event["event"] == "peer_completed"
                            && event["peer"] == corpus.peers[other].to_string()
                            && event["received"] == true)
                );
            }
            if actor != corpus.proposers[1] {
                assert!(
                    round_zero
                        .iter()
                        .any(|event| admitted(event, "CurrentVotingProposal")
                            && admitted(event, "CurrentFinalityProposal")
                            && event["source"]["kind"] == "peer"
                            && event["source"]["peer"]
                                == corpus.peers[corpus.proposers[1]].to_string()
                            && event["receipt_queued"] == true)
                );
            }
        }
        histories.push(corpus.verify(&layouts[actor], if winners[actor] { 2 } else { 1 }));
    }
    for left in &histories {
        for right in &histories {
            let common = left.len().min(right.len());
            assert_eq!(left[..common], right[..common]);
        }
    }
    for (gate, &(a, b)) in gates.iter_mut().zip(&PAIRS) {
        let (accepted, refused) = gate.counts();
        assert_eq!(accepted, 1, "no replacement path escaped the cut");
        if groups[a] != groups[b] {
            assert!(refused > 0, "redials must encounter the closed path");
        } else {
            assert_eq!(refused, 0);
        }
        gate.finish();
    }
}

#[test]
fn equal_halves_cannot_finalize_after_actual_process_link_cut() {
    run_partition([1, 1, 1, 1], [0, 0, 1, 1], [false; 4]);
}

#[test]
fn exact_two_thirds_component_cannot_finalize_after_actual_process_link_cut() {
    run_partition([2, 1, 1, 2], [0, 1, 1, 1], [false; 4]);
}

#[test]
fn two_validator_weighted_quorum_finalizes_after_actual_process_link_cut() {
    run_partition([3, 2, 1, 1], [0, 0, 1, 1], [true, true, false, false]);
}
