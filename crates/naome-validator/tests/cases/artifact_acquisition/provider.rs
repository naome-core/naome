use std::{
    sync::{RwLockReadGuard, mpsc},
    thread,
};

use naome_chain::{ArtifactBlock, ArtifactChainDefinition, ArtifactDag};
use naome_network::{
    ConsensusPushMessage, InboundArtifactBlockRequest, InboundArtifactRequest,
    InboundConsensusPush, Keypair, NetworkEvent, PeerId, RespondError, StaticArtifactNetwork,
    StaticPeer,
};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
    CanonicalArtifactPayloadStore,
};

use crate::support::{BOUND, Layout, hex};

pub struct Plan {
    key: Keypair,
    pub peer: PeerId,
    consumer: PeerId,
}

impl Plan {
    pub fn new(consumer: PeerId) -> Self {
        loop {
            let key = Keypair::generate_ed25519();
            let peer = key.public().to_peer_id();
            if peer.to_bytes() < consumer.to_bytes() {
                return Self {
                    key,
                    peer,
                    consumer,
                };
            }
        }
    }

    pub fn configure(&self, config: String) -> String {
        let entry = format!(
            "{{ peer_id = {:?}, address = \"/ip4/127.0.0.1/tcp/1\" }}",
            self.peer.to_string()
        );
        if config.contains("peers = []") {
            config.replace("peers = []", &format!("peers = [{entry}]"))
        } else {
            config.replace("peers = [", &format!("peers = [{entry}, "))
        }
    }

    // Spawn actual processes before starting this owner, and stop/join it
    // before any process restart. The SDK has only a Noise key, never a signer.
    pub fn start<'guard>(
        self,
        guard: &'guard RwLockReadGuard<'static, ()>,
        definition: ArtifactChainDefinition,
        address: &str,
        blocks: Vec<ArtifactBlock>,
        payload_bytes: Vec<Vec<u8>>,
        hold: Option<String>,
    ) -> Provider<'guard> {
        let address = address.parse().unwrap();
        let (control, mut commands) = tokio::sync::mpsc::channel(2);
        let (sender, reports) = mpsc::sync_channel(128);
        let handle = thread::spawn(move || {
            let layout = Layout::new();
            let mut candidates = ArtifactBlockCandidateStore::create(
                &layout.root,
                definition,
                ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
            )
            .unwrap();
            let mut payloads = CanonicalArtifactPayloadStore::create(
                &layout.root,
                ArtifactPayloadStoreLimits::new(16, 1 << 20).unwrap(),
            )
            .unwrap();
            for block in blocks {
                let _ = candidates.insert(&block).unwrap();
            }
            let mut dag = ArtifactDag::new();
            for bytes in payload_bytes {
                let _ = payloads
                    .insert(dag.apply_canonical_artifact_bytes(bytes).unwrap())
                    .unwrap();
            }
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut network = StaticArtifactNetwork::new(
                        self.key,
                        [StaticPeer::new(self.consumer, address)],
                    )
                    .unwrap();
                    let mut hold = hold;
                    let mut held = None;
                    loop {
                        let inbound = tokio::select! {
                            command = commands.recv() => match command {
                                Some(Control::Release) => held.take().expect("held exact request"),
                                Some(Control::HoldConsensus) => {
                                    assert!(held.is_none());
                                    hold = Some("consensus".into());
                                    sender.try_send(Report::Armed).expect("bounded SDK transcript");
                                    continue;
                                },
                                Some(Control::Stop) | None => break,
                            },
                            event = network.next_event() => {
                                let (inbound, kind, address) = match event {
                                    NetworkEvent::InboundBlockRequest(request) => {
                                        let address = hex(request.request().block_id().as_bytes());
                                        (Held::Block(request), "block", address)
                                    },
                                    NetworkEvent::InboundArtifactRequest(request) => {
                                        let address = hex(request.request().artifact_id().as_bytes());
                                        (Held::Payload(request), "payload", address)
                                    },
                                    NetworkEvent::InboundConsensusPush(request) => {
                                        (Held::Consensus(request), "consensus", "consensus".into())
                                    },
                                    _ => continue,
                                };
                                sender.try_send(Report::Request { kind, address: address.clone() }).expect("bounded SDK transcript");
                                if let Held::Consensus(request) = &inbound {
                                    let message = match request.message() {
                                        ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } => ConsensusPushMessage::Proposal { canonical_proposal: canonical_proposal.clone(), canonical_artifact: canonical_artifact.clone() },
                                        ConsensusPushMessage::Vote { canonical_vote } => ConsensusPushMessage::Vote { canonical_vote: canonical_vote.clone() },
                                    };
                                    sender.try_send(Report::Message(message)).expect("bounded SDK transcript");
                                }
                                if hold.as_ref() == Some(&address) {
                                    assert!(held.is_none(), "one retained inbound handle");
                                    hold = None;
                                    held = Some(inbound);
                                    continue;
                                }
                                inbound
                            },
                        };
                        match inbound {
                            Held::Block(request) => {
                                // A cancelled consumer may have closed its channel.
                                assert!(matches!(network.respond_block_from_candidate_store(request, &mut candidates), Ok(()) | Err(RespondError::ChannelClosed)));
                            },
                            Held::Payload(request) => {
                                assert!(matches!(network.respond_artifact_from_payload_store(request, &mut payloads), Ok(()) | Err(RespondError::ChannelClosed)));
                            },
                            Held::Consensus(request) => {
                                let _ = network.acknowledge_consensus_push(request).unwrap();
                            },
                        }
                    }
                });
        });
        Provider {
            control,
            reports,
            handle: Some(handle),
            _guard: guard,
        }
    }
}

enum Held {
    Block(InboundArtifactBlockRequest),
    Payload(InboundArtifactRequest),
    Consensus(InboundConsensusPush),
}

enum Control {
    Release,
    HoldConsensus,
    Stop,
}

#[derive(Debug)]
pub enum Report {
    Request { kind: &'static str, address: String },
    Message(ConsensusPushMessage),
    Armed,
}

pub struct Provider<'guard> {
    control: tokio::sync::mpsc::Sender<Control>,
    reports: mpsc::Receiver<Report>,
    handle: Option<thread::JoinHandle<()>>,
    _guard: &'guard RwLockReadGuard<'static, ()>,
}

impl Provider<'_> {
    pub fn request(&self, expected_kind: &str, expected_address: &str) {
        match self.reports.recv_timeout(BOUND).expect("SDK request") {
            Report::Request { kind, address } => {
                assert_eq!(kind, expected_kind);
                assert_eq!(address, expected_address);
            }
            report => panic!("unexpected SDK report {report:?}"),
        }
    }

    pub fn message(&self) -> ConsensusPushMessage {
        self.request("consensus", "consensus");
        match self
            .reports
            .recv_timeout(BOUND)
            .expect("SDK consensus message")
        {
            Report::Message(message) => message,
            report => panic!("expected signed consensus bytes, got {report:?}"),
        }
    }

    pub fn hold_consensus(&self) {
        self.control.blocking_send(Control::HoldConsensus).unwrap();
        assert!(matches!(
            self.reports.recv_timeout(BOUND).unwrap(),
            Report::Armed
        ));
    }

    pub fn release(&self) {
        self.control.blocking_send(Control::Release).unwrap();
    }

    pub fn stop(mut self) {
        self.control.blocking_send(Control::Stop).unwrap();
        self.handle.take().unwrap().join().unwrap();
    }
}

impl Drop for Provider<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.control.blocking_send(Control::Stop);
            let _ = handle.join();
        }
    }
}
