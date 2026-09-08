use super::*;
use naome_network::{ConsensusPushTicket, NetworkEvent, StaticArtifactNetwork, StaticPeer};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Wire {
    Proposal(Vec<u8>, Vec<u8>),
    Vote(Vec<u8>),
}
impl Wire {
    fn message(self) -> ConsensusPushMessage {
        match self {
            Self::Proposal(canonical_proposal, canonical_artifact) => {
                ConsensusPushMessage::Proposal {
                    canonical_proposal,
                    canonical_artifact,
                }
            }
            Self::Vote(canonical_vote) => ConsensusPushMessage::Vote { canonical_vote },
        }
    }
    fn from_message(message: ConsensusPushMessage) -> Self {
        match message {
            ConsensusPushMessage::Proposal {
                canonical_proposal,
                canonical_artifact,
            } => Self::Proposal(canonical_proposal, canonical_artifact),
            ConsensusPushMessage::Vote { canonical_vote } => Self::Vote(canonical_vote),
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct Trace {
    pub votes: BTreeMap<(usize, u64, u64, u8), Vec<u8>>,
    pub proposals: Vec<(usize, Wire)>,
    pub delivered: Vec<(usize, Wire)>,
    pub dropped_cross_group: usize,
    pub healed: bool,
    pub idle: bool,
}
enum Control {
    Inject(Vec<(usize, Wire)>),
    Heal,
    Stop,
}

pub(super) struct Bridge {
    controls: tokio::sync::mpsc::Sender<Control>,
    trace: Arc<Mutex<Trace>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Bridge {
    pub fn start(fixture: &Fixture, addresses: [String; 4]) -> Self {
        let mut seed = fixture.noise;
        let key = Keypair::ed25519_from_bytes(&mut seed).unwrap();
        let peers = fixture.corpus.peers;
        let keys = fixture.corpus.entries.map(|e| e.consensus_key());
        let context = fixture.corpus.context;
        let (controls, mut commands) = tokio::sync::mpsc::channel(4);
        let trace = Arc::new(Mutex::new(Trace::default()));
        let shared = Arc::clone(&trace);
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let configured = peers.into_iter().zip(addresses).map(|(peer, address)| StaticPeer::new(peer, address.parse().unwrap()));
                let mut network = StaticArtifactNetwork::new(key, configured).unwrap();
                let mut queues: [VecDeque<Wire>; 4] = std::array::from_fn(|_| VecDeque::new());
                let mut pending: [Option<(ConsensusPushTicket, Wire)>; 4] = std::array::from_fn(|_| None);
                let mut tick = tokio::time::interval(Duration::from_millis(2));
                loop {
                    for to in 0..4 {
                        assert!(queues[to].len() <= 128, "bounded bridge queue");
                        if pending[to].is_none() && let Some(wire) = queues[to].pop_front() {
                            let ticket = network.push_consensus(peers[to], wire.clone().message()).unwrap();
                            pending[to] = Some((ticket, wire));
                        }
                    }
                    shared.lock().unwrap().idle = queues.iter().all(VecDeque::is_empty) && pending.iter().all(Option::is_none);
                    tokio::select! {
                        control = commands.recv() => match control {
                            Some(Control::Inject(messages)) => {
                                assert!(!shared.lock().unwrap().healed, "faulty signer stays silent after healing");
                                for (to, wire) in messages { queues[to].push_back(wire.clone()); queues[to].push_back(wire); }
                            }
                            Some(Control::Heal) => shared.lock().unwrap().healed = true,
                            Some(Control::Stop) | None => break,
                        },
                        _ = tick.tick() => {},
                        event = network.next_event() => match event {
                            NetworkEvent::InboundConsensusPush(inbound) => {
                                let (from, message) = network.acknowledge_consensus_push(inbound).unwrap().into_parts();
                                let actor = peers.iter().position(|peer| *peer == from).unwrap();
                                let wire = Wire::from_message(message);
                                let mut trace = shared.lock().unwrap();
                                match &wire {
                                    Wire::Vote(bytes) => {
                                        let vote = VerifiedConsensusVoteV0::decode_and_verify(bytes, context).unwrap();
                                        assert_eq!(vote.signer(), keys[actor], "transport label is not a signature");
                                        let role = match vote.role() { ConsensusVoteRole::Prevote => 0, ConsensusVoteRole::Precommit => 1 };
                                        let slot = (actor, vote.position().height().value(), vote.position().round().value(), role);
                                        if let Some(previous) = trace.votes.insert(slot, bytes.clone()) { assert_eq!(previous, *bytes, "honest signer equivocated"); }
                                        assert!(trace.votes.len() <= 64);
                                    }
                                    Wire::Proposal(_, _) => {
                                        assert!(trace.healed, "only Byzantine proposer exists before healing");
                                        assert!(trace.proposals.len() < 16);
                                        trace.proposals.push((actor, wire.clone()));
                                    }
                                }
                                for (to, queue) in queues.iter_mut().enumerate() {
                                    if to == actor { continue; }
                                    if trace.healed || to / 2 == actor / 2 {
                                        queue.push_back(wire.clone());
                                        queue.push_back(wire.clone());
                                    } else { trace.dropped_cross_group += 1; }
                                }
                            }
                            NetworkEvent::OutboundConsensusPush(event) => {
                                let to = pending.iter().position(|entry| entry.as_ref().is_some_and(|(ticket, _)| ticket.accepts_event(&event))).expect("correlated bridge receipt");
                                let (ticket, wire) = pending[to].take().unwrap();
                                let _receipt = ticket.complete(event).unwrap().unwrap();
                                let mut trace = shared.lock().unwrap();
                                assert!(trace.delivered.len() < 512);
                                trace.delivered.push((to, wire));
                            }
                            _ => {},
                        },
                    }
                }
            });
        });
        Self {
            controls,
            trace,
            worker: Some(worker),
        }
    }
    pub fn inject(&self, messages: Vec<(usize, Wire)>) {
        self.controls
            .blocking_send(Control::Inject(messages))
            .unwrap();
    }
    pub fn heal(&self) {
        self.controls.blocking_send(Control::Heal).unwrap();
    }
    pub fn snapshot(&self) -> Trace {
        assert!(
            !self.worker.as_ref().unwrap().is_finished(),
            "bridge worker ended unexpectedly"
        );
        self.trace.lock().unwrap().clone()
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.controls.blocking_send(Control::Stop);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}
