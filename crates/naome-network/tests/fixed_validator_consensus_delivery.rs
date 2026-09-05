#![cfg(unix)]

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProposalVerifyError, ConsensusProtocolVersion, ConsensusRound, ConsensusVoteRole,
    ConsensusVoteTarget, FixedConsensusBranchV0, FixedValidatorLockPhaseV0,
    FixedValidatorProposalSourceV0,
};
use naome_network::{
    ConsensusPushMessage, ConsensusPushStartFailure, Keypair, Multiaddr, NetworkEvent, PeerId,
    PeerSessionEvent, ReceivedConsensusPush, RequestStartError, StaticArtifactNetwork, StaticPeer,
};
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0, FixedValidatorNodeDeferredProposalV0,
    FixedValidatorNodeDirectoriesV0, FixedValidatorNodeDriverAdmissionDispositionV0,
    FixedValidatorNodeDriverAdmissionOutcomeV0, FixedValidatorNodeDriverAdmissionRejectionV0,
    FixedValidatorNodeDriverCommandV0, FixedValidatorNodeDriverEventV0,
    FixedValidatorNodeDriverProposalAuthoringOutcomeV0, FixedValidatorNodeDriverStepOutcomeV0,
    FixedValidatorNodeDriverV0, FixedValidatorNodeHigherRoundInboxLimitsV0,
    FixedValidatorNodePhaseTimeoutV0, FixedValidatorNodeProvisionV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorSignerCatchUpHeightLimitV0,
};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate};
use naome_storage::{
    FixedValidatorFinalityReplayLimitV0, FixedValidatorProposalReplayLimitV0,
    FixedValidatorSignedProposalV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVoteSafetyReplayLimitV0,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{env, fs, io};
use tokio::runtime::Builder;
use tokio::time::timeout;

const STORE_BYTE_LIMIT: u64 = 1 << 20;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestLayout {
    root: PathBuf,
    finality_journal: PathBuf,
    finality_anchor: PathBuf,
    vote_journal: PathBuf,
    vote_anchor: PathBuf,
}

impl TestLayout {
    fn new(label: &str) -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "naome-network-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let finality_journal = root.join("finality-journal");
                    let finality_anchor = root.join("finality-anchor");
                    let vote_journal = root.join("vote-journal");
                    let vote_anchor = root.join("vote-anchor");
                    for directory in [
                        &finality_journal,
                        &finality_anchor,
                        &vote_journal,
                        &vote_anchor,
                    ] {
                        fs::create_dir(directory).unwrap();
                    }
                    return Self {
                        root,
                        finality_journal,
                        finality_anchor,
                        vote_journal,
                        vote_anchor,
                    };
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn node_directories(&self) -> FixedValidatorNodeDirectoriesV0<'_> {
        FixedValidatorNodeDirectoriesV0::new(
            &self.finality_journal,
            &self.finality_anchor,
            &self.vote_journal,
            &self.vote_anchor,
        )
    }

    fn authority_images(&self) -> [Vec<(String, Vec<u8>)>; 4] {
        [
            directory_image(&self.finality_journal),
            directory_image(&self.finality_anchor),
            directory_image(&self.vote_journal),
            directory_image(&self.vote_anchor),
        ]
    }
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn directory_image(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut image = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    image.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    image
}

fn provision<'input>(
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: &'input [ActiveAgreementEntry],
    layout: &'input TestLayout,
) -> FixedValidatorNodeProvisionV0<'input> {
    FixedValidatorNodeProvisionV0::new(
        definition,
        context,
        entries,
        layout.node_directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(8).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(4),
        FixedValidatorSignerCatchUpHeightLimitV0::new(0),
    )
}

fn node_driver<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    FixedValidatorNodeDriverV0::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        ConsensusRound::new(4),
    )
    .unwrap()
}

fn step_arm<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodePhaseTimeoutV0,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(timeout) => (*driver, timeout),
            FixedValidatorNodeDriverCommandV0::PublishVote { .. }
            | FixedValidatorNodeDriverCommandV0::PublishProposal { .. } => {
                panic!("expected timeout-arm command")
            }
            _ => panic!("unexpected future driver command"),
        },
        _ => panic!("expected one timeout-arm command"),
    }
}

fn step_publish<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    naome_storage::FixedValidatorSignedVoteV0,
    Option<Box<FixedValidatorNodeDeferredProposalV0>>,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::PublishVote {
                vote,
                released_proposal,
            } => (*driver, vote, released_proposal),
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_)
            | FixedValidatorNodeDriverCommandV0::PublishProposal { .. } => {
                panic!("expected vote-publication command")
            }
            _ => panic!("unexpected future driver command"),
        },
        _ => panic!("expected one vote-publication command"),
    }
}

fn step_transition<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Transitioned { driver } => *driver,
        _ => panic!("expected exactly one driver transition"),
    }
}

fn admit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    event: FixedValidatorNodeDriverEventV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodeDriverAdmissionDispositionV0,
) {
    match driver.admit_event(event).unwrap() {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
            driver,
            disposition,
        } => (*driver, disposition),
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { .. } => {
            panic!("expected driver event admission")
        }
        _ => panic!("unexpected future driver admission"),
    }
}

fn admit_due<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    timeout: FixedValidatorNodePhaseTimeoutV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodeDriverAdmissionDispositionV0,
) {
    admit(driver, FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
}

fn close_empty_round<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    proposal_timeout: FixedValidatorNodePhaseTimeoutV0,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorNodePhaseTimeoutV0,
) {
    let (driver, _) = admit_due(driver, proposal_timeout);
    let driver = step_transition(driver);
    let (driver, prevote, released_proposal) = step_publish(driver);
    assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
    assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
    assert!(released_proposal.is_none());
    let (driver, prevote_timeout) = step_arm(driver);

    let (driver, _) = admit_due(driver, prevote_timeout);
    let driver = step_transition(driver);
    let (driver, precommit, released_proposal) = step_publish(driver);
    assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
    assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
    assert!(released_proposal.is_none());
    let (driver, precommit_timeout) = step_arm(driver);

    let (driver, _) = admit_due(driver, precommit_timeout);
    let driver = step_transition(driver);
    step_arm(driver)
}

fn authored(
    outcome: FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'_>,
) -> FixedValidatorNodeDriverV0<'_> {
    match outcome {
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored { driver } => *driver,
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Rejected { rejection, .. } => {
            panic!("authoring rejected: {rejection:?}")
        }
        _ => panic!("expected pending durable proposal publication"),
    }
}

fn publish(
    driver: FixedValidatorNodeDriverV0<'_>,
) -> (
    FixedValidatorNodeDriverV0<'_>,
    FixedValidatorSignedProposalV0,
    Vec<u8>,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command {
            driver,
            command:
                FixedValidatorNodeDriverCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                },
        } => (*driver, proposal, canonical_artifact_bytes),
        _ => panic!("expected one proposal publication command"),
    }
}

fn idle(driver: FixedValidatorNodeDriverV0<'_>) -> FixedValidatorNodeDriverV0<'_> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
        _ => panic!("proposal publication must leave ordinary driver idle"),
    }
}

fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

fn pairing_payload() -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::from_canonical_bytes(&[0x00, 0x00, 0x00, 0x01, 0x10, 0x01]).unwrap(),
    )
    .to_canonical_bytes()
}

fn artifact_id(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn address(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn ordered_identities() -> (Keypair, Keypair) {
    let first = Keypair::generate_ed25519();
    let second = Keypair::generate_ed25519();
    if first.public().to_peer_id().to_bytes() < second.public().to_peer_id().to_bytes() {
        (first, second)
    } else {
        (second, first)
    }
}

async fn listening_address(network: &mut StaticArtifactNetwork) -> Multiaddr {
    network.listen_on(address(0)).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match network.next_event().await {
                NetworkEvent::Listening { address } => return address,
                NetworkEvent::ListenerError { error, .. } => {
                    panic!("network listener failed: {error}")
                }
                NetworkEvent::ListenerClosed { reason, .. } => {
                    panic!("network listener closed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("network listener did not start")
}

async fn connected_pair() -> (StaticArtifactNetwork, StaticArtifactNetwork, PeerId) {
    let (client_identity, server_identity) = ordered_identities();
    let client_peer_id = client_identity.public().to_peer_id();
    let server_peer_id = server_identity.public().to_peer_id();
    let mut server = StaticArtifactNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticArtifactNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    let mut client_established = false;
    let mut server_established = false;
    timeout(Duration::from_secs(10), async {
        while !client_established || !server_established {
            tokio::select! {
                event = client.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, server_peer_id);
                        client_established = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed dial to {peer_id} failed")
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("client listener failed: {error}")
                    }
                    _ => {}
                },
                event = server.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, client_peer_id);
                        server_established = true;
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("server listener failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("managed Noise session did not establish");
    (client, server, server_peer_id)
}

async fn deliver(
    sender: &mut StaticArtifactNetwork,
    receiver: &mut StaticArtifactNetwork,
    message: ConsensusPushMessage,
) -> ReceivedConsensusPush {
    let expected = match &message {
        ConsensusPushMessage::Proposal {
            canonical_proposal,
            canonical_artifact,
        } => ConsensusPushMessage::Proposal {
            canonical_proposal: canonical_proposal.clone(),
            canonical_artifact: canonical_artifact.clone(),
        },
        ConsensusPushMessage::Vote { canonical_vote } => ConsensusPushMessage::Vote {
            canonical_vote: canonical_vote.clone(),
        },
    };
    let ticket = sender
        .push_consensus(receiver.local_peer_id(), message)
        .unwrap();
    timeout(Duration::from_secs(10), async {
        let mut received = None;
        loop { tokio::select! {
            event = receiver.next_event() => if let NetworkEvent::InboundConsensusPush(inbound) = event {
                assert_eq!(inbound.peer_id(), sender.local_peer_id());
                assert_eq!(inbound.message(), &expected);
                received = Some(receiver.acknowledge_consensus_push(inbound).unwrap());
            },
            event = sender.next_event() => if let NetworkEvent::OutboundConsensusPush(event) = event {
                let receipt = ticket.complete(event).unwrap().unwrap();
                assert_eq!(receipt.peer_id(), receiver.local_peer_id());
                assert_eq!(receipt.size(), expected.size());
                break received.unwrap();
            },
        }}
    }).await.unwrap()
}

fn current_proposal(message: ConsensusPushMessage) -> FixedValidatorNodeDriverEventV0 {
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = message
    else {
        panic!("expected proposal bytes")
    };
    FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
        canonical_proposal_control_bytes: canonical_proposal.into_boxed_slice(),
        canonical_artifact_bytes: canonical_artifact.into_boxed_slice(),
    }
}

fn proposal_message(
    proposal: &FixedValidatorSignedProposalV0,
    payload: Vec<u8>,
) -> ConsensusPushMessage {
    ConsensusPushMessage::Proposal {
        canonical_proposal: proposal.canonical_proposal_control_bytes().to_vec(),
        canonical_artifact: payload,
    }
}

fn released_observation(
    token: &FixedValidatorNodeDeferredProposalV0,
) -> (Vec<u8>, Vec<u8>, *const u8, *const u8) {
    (
        token.canonical_proposal_control_bytes().to_vec(),
        token.canonical_artifact_bytes().to_vec(),
        token.canonical_proposal_control_bytes().as_ptr(),
        token.canonical_artifact_bytes().as_ptr(),
    )
}

#[test]
fn driver_publications_cross_noise_with_separate_admission_and_released_proposal_custody() {
    let definition = ArtifactChainDefinition::new([0x71; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x72; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let keys = [
        SigningKey::from_bytes(&[0x73; 32]),
        SigningKey::from_bytes(&[0x74; 32]),
    ];
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&keys[0]), AgreementWeight::new(3)),
        ActiveAgreementEntry::new(consensus_key(&keys[1]), AgreementWeight::new(1)),
    ];
    let selected = ArtifactChainState::new(definition);
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        selected.branch_snapshot(),
    )
    .unwrap();
    let initial = branch.begin_round_zero().unwrap();
    let source_index = keys
        .iter()
        .position(|key| consensus_key(key) == initial.proposer())
        .unwrap();
    // This weighted fixture lets a real source prevote establish the higher-round quorum.
    assert_eq!(source_index, 0);
    let source_layout = TestLayout::new("consensus-delivery-source");
    let receiver_layout = TestLayout::new("consensus-delivery-receiver");
    let source_ready = provision(definition, context, &entries, &source_layout)
        .create(keys[source_index].clone())
        .unwrap();
    let receiver_ready = provision(definition, context, &entries, &receiver_layout)
        .create(keys[1 - source_index].clone())
        .unwrap();
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut sender, mut receiver, _) = runtime.block_on(connected_pair());
    // Noise keys were generated independently of both consensus signing keys.
    let sender_peer = sender.local_peer_id();
    let receiver_peer = receiver.local_peer_id();
    let source_initial_images = source_layout.authority_images();
    let receiver_initial_images = receiver_layout.authority_images();
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    source_ready.run_with_signing_session(|source_scope| {
        receiver_ready.run_with_signing_session(|receiver_scope| runtime.block_on(async {
            let (source_driver, source_timeout) = step_arm(node_driver(source_scope));
            let (mut receiver_driver, _) = step_arm(node_driver(receiver_scope));
            let source_driver = authored(source_driver.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload.clone() }).unwrap());
            let (source_driver, proposal, published_payload) = publish(source_driver);
            let mut source_driver = idle(source_driver);
            let source_images = source_layout.authority_images();
            let receiver_images = receiver_layout.authority_images();
            assert_eq!(source_driver.current_inbox_len(), 0);
            assert_eq!(receiver_driver.current_inbox_len(), 0);

            // Correct envelope widths do not confer inner proof or payload validity.
            for corruption in 0..3 {
                let mut control = proposal.canonical_proposal_control_bytes().to_vec();
                let mut bytes = payload.clone();
                match corruption {
                    0 => { let last_signature_byte = control.len() - 2; control[last_signature_byte] ^= 0x80; }
                    1 => { *bytes.last_mut().unwrap() = 0xff; }
                    2 => { control[0] ^= 0x80; } // value begins with its chain identity
                    _ => unreachable!(),
                }
                let received = deliver(&mut sender, &mut receiver, ConsensusPushMessage::Proposal { canonical_proposal: control, canonical_artifact: bytes }).await;
                assert_eq!(source_layout.authority_images(), source_images);
                assert_eq!(receiver_layout.authority_images(), receiver_images);
                assert_eq!(receiver_driver.current_inbox_len(), 0);
                let outcome = receiver_driver.admit_event(current_proposal(received.into_parts().1)).unwrap();
                receiver_driver = match outcome {
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { driver, rejection, .. } => {
                        let FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(error) = *rejection else { panic!("expected full proposal rejection") };
                        assert!(matches!((corruption, *error),
                            (0, ConsensusProposalVerifyError::ProducerAuthorization(_)) |
                            (1, ConsensusProposalVerifyError::ArtifactValidation(_)) |
                            (2, ConsensusProposalVerifyError::ChainIdMismatch { .. })
                        ));
                        *driver
                    }
                    _ => panic!("opaque malformed message must fail strict admission"),
                };
                assert_eq!(receiver_layout.authority_images(), receiver_images);
            }
            let received = deliver(&mut sender, &mut receiver, proposal_message(&proposal, published_payload)).await;
            assert_eq!(received.peer_id(), sender_peer);
            assert_eq!(source_layout.authority_images(), source_images);
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            assert_eq!(source_driver.current_inbox_len(), 0);
            assert_eq!(receiver_driver.current_inbox_len(), 0);
            (receiver_driver, _) = admit(receiver_driver, current_proposal(received.into_parts().1));
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            receiver_driver = step_transition(receiver_driver);
            let (driver, receiver_vote, released) = step_publish(receiver_driver);
            assert!(released.is_none());
            assert_eq!(receiver_vote.role(), ConsensusVoteRole::Prevote);
            assert_ne!(receiver_layout.authority_images(), receiver_images);
            (receiver_driver, _) = step_arm(driver);
            let receiver_images = receiver_layout.authority_images();
            let received = deliver(&mut receiver, &mut sender, ConsensusPushMessage::Vote { canonical_vote: receiver_vote.canonical_bytes().to_vec() }).await;
            assert_eq!(received.peer_id(), receiver_peer);
            assert_eq!(source_layout.authority_images(), source_images);
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            assert_eq!(source_driver.current_inbox_len(), 0);
            let ConsensusPushMessage::Vote { canonical_vote } = received.into_parts().1 else { panic!("vote must not include proposal") };
            (source_driver, _) = admit(source_driver, FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote { canonical_signed_prevote: canonical_vote.into_boxed_slice() });
            assert_eq!(source_driver.current_inbox_len(), 1);
            source_driver = idle(source_driver);
            assert_eq!(source_layout.authority_images(), source_images);

            // Advance only the source using its own exact timeout tickets, while
            // the receiver stays at round-zero Prevote with no due event.
            let mut scheduled = initial.advance_round().unwrap();
            let mut target_round = 1;
            while scheduled.proposer() != consensus_key(&keys[source_index]) {
                scheduled = scheduled.advance_round().unwrap(); target_round += 1;
                assert!(target_round <= 4);
            }
            let mut timer = source_timeout;
            for _ in 0..target_round { (source_driver, timer) = close_empty_round(source_driver, timer); }
            assert_eq!(source_driver.position(), scheduled.position());
            let source_driver = authored(source_driver.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload.clone() }).unwrap());
            let (source_driver, higher_proposal, higher_payload) = publish(source_driver);
            let (source_driver, _) = admit(source_driver, current_proposal(proposal_message(&higher_proposal, higher_payload.clone())));
            let (source_driver, higher_vote, released) = step_publish(step_transition(source_driver));
            assert!(released.is_none());
            assert_eq!(higher_vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(higher_vote.position(), scheduled.position());
            let (source_driver, _) = step_arm(source_driver);
            let source_images = source_layout.authority_images();
            let received = deliver(&mut sender, &mut receiver, proposal_message(&higher_proposal, higher_payload.clone())).await;
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            assert_eq!(source_layout.authority_images(), source_images);
            assert_eq!(receiver_driver.inbox_len(), 0);
            let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = received.into_parts().1 else { panic!("expected higher proposal") };
            (receiver_driver, _) = admit(receiver_driver, FixedValidatorNodeDriverEventV0::HigherRoundProposal { proposal_round: ConsensusRound::new(target_round), canonical_proposal_control_bytes: canonical_proposal.into_boxed_slice(), canonical_artifact_bytes: canonical_artifact.into_boxed_slice() });
            let received = deliver(&mut sender, &mut receiver, ConsensusPushMessage::Vote { canonical_vote: higher_vote.canonical_bytes().to_vec() }).await;
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            assert_eq!(source_layout.authority_images(), source_images);
            let ConsensusPushMessage::Vote { canonical_vote } = received.into_parts().1 else { panic!("expected higher vote") };
            (receiver_driver, _) = admit(receiver_driver, FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote { canonical_signed_prevote: canonical_vote.into_boxed_slice() });
            let (receiver_driver, precommit, released) = step_publish(step_transition(receiver_driver));
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.position(), scheduled.position());
            assert_eq!(receiver_driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let released = released.expect("higher-round checkpoint must return exact proposal custody");
            let observation = released_observation(&released);
            assert_eq!(released.canonical_proposal_control_bytes(), higher_proposal.canonical_proposal_control_bytes());
            assert_eq!(released.canonical_artifact_bytes(), higher_payload);
            let receiver_images = receiver_layout.authority_images();
            let received = deliver(&mut receiver, &mut sender, ConsensusPushMessage::Vote { canonical_vote: precommit.canonical_bytes().to_vec() }).await;
            assert!(matches!(received.message(), ConsensusPushMessage::Vote { canonical_vote } if canonical_vote == precommit.canonical_bytes()));
            assert_eq!(released_observation(&released), observation);
            assert_eq!(source_layout.authority_images(), source_images);
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            // The token is separately owned across both preflight and async errors.
            let unknown = Keypair::generate_ed25519().public().to_peer_id();
            let error = receiver.push_consensus(unknown, ConsensusPushMessage::Vote { canonical_vote: precommit.canonical_bytes().to_vec() }).unwrap_err();
            assert!(matches!(error.reason(), ConsensusPushStartFailure::RequestStart(RequestStartError::UnknownPeer(_))));
            assert_eq!(released_observation(&released), observation);
            let ticket = receiver.push_consensus(sender_peer, error.into_parts().0).unwrap();
            drop(sender);
            timeout(Duration::from_secs(10), async {
                loop { if let NetworkEvent::OutboundConsensusPush(event) = receiver.next_event().await {
                    assert!(ticket.complete(event).unwrap().is_err()); break;
                }}
            }).await.unwrap();
            assert_eq!(released_observation(&released), observation);
            let error = receiver.push_consensus(sender_peer, ConsensusPushMessage::Vote { canonical_vote: precommit.canonical_bytes().to_vec() }).unwrap_err();
            assert!(matches!(error.reason(), ConsensusPushStartFailure::RequestStart(RequestStartError::PeerDisconnected(_))));
            assert_eq!(released_observation(&released), observation);
            assert_eq!(source_layout.authority_images(), source_images);
            assert_eq!(receiver_layout.authority_images(), receiver_images);
            assert_eq!(source_driver.position(), scheduled.position());
            assert_eq!(source_layout.authority_images()[..2], source_initial_images[..2]);
            assert_eq!(receiver_layout.authority_images()[..2], receiver_initial_images[..2]);
        })).unwrap()
    }).unwrap();
}
