#![cfg(unix)]

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusPosition, ConsensusProtocolVersion, ConsensusRound, ConsensusValueV0,
    ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusBranchV0, FixedValidatorLockPhaseV0,
    OwnedVerifiedFixedConsensusTransitionV0, ProposalSigningRoot, VerifiedFixedConsensusProposalV0,
    VerifiedProducerAuthorizationV0,
};
use naome_foundation::ZfcAxiom;
use naome_network::{
    ArtifactBlockCandidateBranchPayloadFillProgress, Keypair, Multiaddr, NetworkEvent, PeerId,
    PeerSessionEvent, StaticArtifactNetwork, StaticPeer,
};
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0, FixedValidatorNodeDirectoriesV0,
    FixedValidatorNodeDriverAdmissionDispositionV0, FixedValidatorNodeDriverAdmissionOutcomeV0,
    FixedValidatorNodeDriverAdmissionRejectionV0,
    FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0,
    FixedValidatorNodeDriverCommandV0, FixedValidatorNodeDriverEventV0,
    FixedValidatorNodeDriverStepOutcomeV0, FixedValidatorNodeDriverV0,
    FixedValidatorNodeFinalityErrorV0, FixedValidatorNodeFinalityOutcomeV0,
    FixedValidatorNodeHigherRoundInboxLimitsV0, FixedValidatorNodeProvisionV0,
    FixedValidatorNodeReadyV0, FixedValidatorNodeSigningScopeV0, FixedValidatorNodeStartupV0,
    FixedValidatorNodeVoteExecutionOutcomeV0, FixedValidatorNodeVoteRejectionV0,
    FixedValidatorSignerCatchUpHeightLimitV0,
};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidateBackedFinalityErrorV0, CandidateBranchReconstructionLimits,
    CanonicalArtifactPayloadStore, FixedValidatorFinalityHaltKindV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorProposalReplayLimitV0,
    FixedValidatorSignedVoteV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVoteSafetyReplayLimitV0, SelectedArtifactHistory,
};
use tokio::runtime::Builder;
use tokio::time::timeout;

const AUTHORIZATION_BODY_BYTES: usize = 116;
const VOTE_BODY_BYTES: usize = 118;
const STORE_ENTRY_LIMIT: usize = 16;
const STORE_BYTE_LIMIT: u64 = 1024 * 1024;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestLayout {
    root: PathBuf,
    finality_journal: PathBuf,
    finality_anchor: PathBuf,
    vote_journal: PathBuf,
    vote_anchor: PathBuf,
    candidate_store: PathBuf,
    payload_store: PathBuf,
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
                    let candidate_store = root.join("candidate-store");
                    let payload_store = root.join("payload-store");
                    for directory in [
                        &finality_journal,
                        &finality_anchor,
                        &vote_journal,
                        &vote_anchor,
                        &candidate_store,
                        &payload_store,
                    ] {
                        fs::create_dir(directory).unwrap();
                    }
                    return Self {
                        root,
                        finality_journal,
                        finality_anchor,
                        vote_journal,
                        vote_anchor,
                        candidate_store,
                        payload_store,
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

    fn source_images(&self) -> [Vec<(String, Vec<u8>)>; 2] {
        [
            directory_image(&self.candidate_store),
            directory_image(&self.payload_store),
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

fn candidate_store(
    directory: &Path,
    definition: ArtifactChainDefinition,
) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        directory,
        definition,
        ArtifactBlockCandidateStoreLimits::new(STORE_ENTRY_LIMIT).unwrap(),
    )
    .unwrap()
}

fn payload_store(directory: &Path) -> CanonicalArtifactPayloadStore {
    CanonicalArtifactPayloadStore::create(
        directory,
        ArtifactPayloadStoreLimits::new(STORE_ENTRY_LIMIT, STORE_BYTE_LIMIT).unwrap(),
    )
    .unwrap()
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
        FixedValidatorVoteSafetyReplayLimitV0::new(8).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(8).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        FixedValidatorSignerCatchUpHeightLimitV0::new(0),
    )
}

fn expect_ready(startup: FixedValidatorNodeStartupV0) -> FixedValidatorNodeReadyV0 {
    match startup {
        FixedValidatorNodeStartupV0::Ready(ready) => *ready,
        FixedValidatorNodeStartupV0::FinalityStopped(_)
        | FixedValidatorNodeStartupV0::SignerStopped(_)
        | FixedValidatorNodeStartupV0::PendingProposal(_)
        | FixedValidatorNodeStartupV0::PendingPreparation(_) => {
            panic!("expected a ready fixed-validator node")
        }
    }
}

fn expect_rejected<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeVoteRejectionV0,
) {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { .. } => {
            panic!("incomplete or invalid acquired input must not sign")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("a pre-effect acquired-input rejection must preserve the signer")
        }
        _ => panic!("unexpected future vote-execution outcome"),
    }
}

fn expect_signed<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorSignedVoteV0,
) {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote } => (*scope, vote),
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { .. } => {
            panic!("complete acquired input must reach the existing signing path")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("the first exact vote intent must not stop the signer")
        }
        _ => panic!("unexpected future vote-execution outcome"),
    }
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
        ConsensusRound::new(0),
    )
    .unwrap()
}

fn transfer_arm<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_) => *driver,
            FixedValidatorNodeDriverCommandV0::PublishVote { .. } => {
                panic!("expected a timeout-arm command")
            }
            _ => panic!("unexpected future driver command"),
        },
        _ => panic!("expected a timeout-arm command"),
    }
}

fn admit_driver_event<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    event: FixedValidatorNodeDriverEventV0,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.admit_event(event).unwrap() {
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
            driver,
            disposition: FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
        } => *driver,
        FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
            panic!("expected one newly inserted driver event")
        }
        FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { .. } => {
            panic!("expected driver event admission")
        }
        _ => panic!("unexpected future driver admission outcome"),
    }
}

fn transition_driver<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Transitioned { driver } => *driver,
        _ => panic!("expected one driver transition"),
    }
}

fn publish_driver_vote<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    FixedValidatorSignedVoteV0,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => match command {
            FixedValidatorNodeDriverCommandV0::PublishVote {
                vote,
                released_proposal: None,
            } => (*driver, vote),
            FixedValidatorNodeDriverCommandV0::PublishVote {
                released_proposal: Some(_),
                ..
            } => panic!("current-round publication must not release proposal custody"),
            FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(_) => {
                panic!("expected a vote-publication command")
            }
            _ => panic!("unexpected future driver command"),
        },
        _ => panic!("expected a vote-publication command"),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration helper keeps each explicit caller-owned network and store boundary visible"
)]
async fn fill_candidate_and_payload(
    selected: &dyn SelectedArtifactHistory,
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    client_candidates: &mut ArtifactBlockCandidateStore,
    client_payloads: &mut CanonicalArtifactPayloadStore,
    server_candidates: &mut ArtifactBlockCandidateStore,
    server_payloads: &mut CanonicalArtifactPayloadStore,
    server_peer_id: PeerId,
    selected_anchor_block_id: Option<ArtifactBlockId>,
    target: ArtifactBlockId,
) {
    let mut ancestry = match selected_anchor_block_id {
        Some(selected_anchor_block_id) => client
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                selected,
                client_candidates,
                server_peer_id,
                selected_anchor_block_id,
                target,
            )
            .unwrap(),
        None => client
            .start_artifact_block_candidate_ancestry_fill(
                selected,
                client_candidates,
                server_peer_id,
                target,
            )
            .unwrap(),
    };
    let mut served_blocks = 0_usize;
    timeout(Duration::from_secs(20), async {
        while ancestry.is_some() {
            tokio::select! {
                event = client.next_event() => {
                    let active = ancestry.take().unwrap();
                    if active.accepts_event(&event) {
                        ancestry = active.on_event(client, selected, event).unwrap();
                    } else {
                        if let NetworkEvent::ListenerError { error, .. } = event {
                            panic!("driver candidate-fill client listener failed: {error}");
                        }
                        ancestry = Some(active);
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        server
                            .respond_block_from_candidate_store(inbound, server_candidates)
                            .unwrap();
                        served_blocks += 1;
                    }
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("driver candidate-fill server request failed: {error}")
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("driver candidate-fill server listener failed: {error}")
                    }
                    NetworkEvent::PeerSession(
                        PeerSessionEvent::DialFailed { peer_id }
                        | PeerSessionEvent::Disconnected { peer_id },
                    ) => panic!("driver candidate-fill server lost peer {peer_id}"),
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("driver-held candidate fill timed out");
    assert_eq!(served_blocks, 1);

    let progress = client
        .start_artifact_block_candidate_branch_payload_fill(
            selected,
            client_candidates,
            client_payloads,
            server_peer_id,
            target,
            CandidateBranchReconstructionLimits::new(1).unwrap(),
        )
        .unwrap();
    let mut payload_fill = match progress {
        ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) => Some(fill),
        ArtifactBlockCandidateBranchPayloadFillProgress::Complete(_) => {
            panic!("the empty driver payload archive unexpectedly completed")
        }
    };
    let mut reconstruction = None;
    let mut served_payloads = 0_usize;
    timeout(Duration::from_secs(20), async {
        while payload_fill.is_some() {
            tokio::select! {
                event = client.next_event() => {
                    if payload_fill.as_ref().unwrap().accepts_event(&event) {
                        let active = payload_fill.take().unwrap();
                        match active.on_event(client, event).unwrap() {
                            ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(next) => {
                                payload_fill = Some(next);
                            }
                            ArtifactBlockCandidateBranchPayloadFillProgress::Complete(complete) => {
                                reconstruction = Some(complete);
                            }
                        }
                    } else if let NetworkEvent::ListenerError { error, .. } = event {
                        panic!("driver payload-fill client listener failed: {error}");
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        server
                            .respond_artifact_from_payload_store(inbound, server_payloads)
                            .unwrap();
                        served_payloads += 1;
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("driver payload-fill server request failed: {error}")
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("driver payload-fill server listener failed: {error}")
                    }
                    NetworkEvent::PeerSession(
                        PeerSessionEvent::DialFailed { peer_id }
                        | PeerSessionEvent::Disconnected { peer_id },
                    ) => panic!("driver payload-fill server lost peer {peer_id}"),
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("driver-held payload fill timed out");
    assert_eq!(served_payloads, 1);
    assert_eq!(
        reconstruction
            .expect("driver-held payload fill must complete")
            .target_block_id(),
        target
    );
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

fn axiom_payload(axiom: ZfcAxiom) -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn artifact_id(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn vote_body_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => body[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }
    body
}

fn signed_vote_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let body = vote_body_bytes(context, position, role, target);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let key = consensus_key(signer);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());

    let mut bytes = body.to_vec();
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn verified_transition_inputs(
    branch: &FixedConsensusBranchV0,
    selected: &ArtifactChainState,
    axiom: ZfcAxiom,
    round_number: u64,
    signer: &SigningKey,
) -> (
    OwnedVerifiedFixedConsensusTransitionV0,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
) {
    let payload = axiom_payload(axiom);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut round = branch.begin_round_zero().unwrap();
    for _ in 0..round_number {
        round = round.advance_round().unwrap();
    }
    let value = round.value_for_artifact_block(block);
    let control = proposal_control_bytes(value, round.position(), signer);
    let precommit = signed_vote_bytes(
        value.context(),
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        signer,
    );
    let transition = round
        .decode_and_verify_proposal_control(&control, payload.clone())
        .unwrap()
        .seal_with_precommit_vote_batch(&[precommit.as_slice()])
        .unwrap()
        .into_owned();
    (transition, control, precommit, payload)
}

fn expect_finality_continues<'node>(
    outcome: FixedValidatorNodeFinalityOutcomeV0<'node>,
) -> FixedValidatorNodeSigningScopeV0<'node> {
    match outcome {
        FixedValidatorNodeFinalityOutcomeV0::Continues { scope, .. } => *scope,
        FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_) => {
            panic!("a new direct child must not stop finality")
        }
    }
}

fn proposal_control_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        proposer,
    ));
    bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    bytes
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    proposer: &SigningKey,
) -> [u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH] {
    let mut body = [0_u8; AUTHORIZATION_BODY_BYTES];
    body[..32].copy_from_slice(context.chain_id().as_bytes());
    body[32..64].copy_from_slice(context.genesis_id().as_bytes());
    body[64..68].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[68..76].copy_from_slice(&position.height().value().to_be_bytes());
    body[76..84].copy_from_slice(&position.round().value().to_be_bytes());
    body[84..].copy_from_slice(root.as_bytes());
    let proposer_key = consensus_key(proposer);
    let mut transcript = b"naome:consensus-producer-authorization:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(proposer_key.as_bytes());
    let mut bytes = [0_u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body);
    bytes[AUTHORIZATION_BODY_BYTES..AUTHORIZATION_BODY_BYTES + 32]
        .copy_from_slice(proposer_key.as_bytes());
    bytes[AUTHORIZATION_BODY_BYTES + 32..].copy_from_slice(&proposer.sign(&transcript).to_bytes());
    bytes
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

#[test]
fn authenticated_candidate_and_payload_fill_gate_store_backed_votes() {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x42; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let mut seed = [0_u8; 32];
    seed[0] = 1;
    seed[2] = 0xa5;
    let signing_key = SigningKey::from_bytes(&seed);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&signing_key),
        AgreementWeight::new(1),
    )];
    let selected = ArtifactChainState::new(definition);
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let target = block.id();

    let client_layout = TestLayout::new("fixed-validator-filled-vote-client");
    let server_layout = TestLayout::new("fixed-validator-filled-vote-server");
    let mut client_candidates = candidate_store(&client_layout.candidate_store, definition);
    let mut client_payloads = payload_store(&client_layout.payload_store);
    let mut server_candidates = candidate_store(&server_layout.candidate_store, definition);
    let mut server_payloads = payload_store(&server_layout.payload_store);
    assert!(matches!(
        server_candidates.insert(&block).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    ));
    assert!(matches!(
        server_payloads
            .validate_and_insert_branch_payload(
                &selected.branch_snapshot(),
                &block,
                payload.clone(),
            )
            .unwrap()
            .insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    ));
    let server_sources = server_layout.source_images();

    let ready = provision(definition, context, &entries, &client_layout)
        .create(signing_key.clone())
        .unwrap();
    let authority_before = client_layout.authority_images();
    let empty_client_sources = client_layout.source_images();
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut client, mut server, server_peer_id) = runtime.block_on(connected_pair());
    let client_layout_ref = &client_layout;
    let server_layout_ref = &server_layout;
    let authority_before_in_session = authority_before.clone();
    let server_sources_in_session = server_sources.clone();

    let (position, root, certificate, complete_client_sources) = ready
        .run_with_signing_session(|scope| {
            runtime.block_on(async move {
                let branch = scope.branch().clone();
                let round = branch.begin_round_zero().unwrap();
                let position = round.position();
                let value = round.value_for_artifact_block(block);
                let root = value.proposal_signing_root();
                let control = proposal_control_bytes(value, position, &signing_key);

                let (scope, rejection) = expect_rejected(
                    scope
                        .sign_candidate_backed_prevote_for_proposal(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &control,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeVoteRejectionV0::CandidateUnavailable { target: actual }
                        if actual == target
                ));
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(client_layout_ref.source_images(), empty_client_sources);

                let mut ancestry = client
                    .start_artifact_block_candidate_ancestry_fill(
                        scope.finality(),
                        &mut client_candidates,
                        server_peer_id,
                        target,
                    )
                    .unwrap();
                let mut served_blocks = 0_usize;
                timeout(Duration::from_secs(20), async {
                    while ancestry.is_some() {
                        tokio::select! {
                            event = client.next_event() => {
                                let active = ancestry.take().unwrap();
                                if active.accepts_event(&event) {
                                    ancestry = active
                                        .on_event(&mut client, scope.finality(), event)
                                        .unwrap();
                                } else {
                                    if let NetworkEvent::ListenerError { error, .. } = event {
                                        panic!("candidate-fill client listener failed: {error}");
                                    }
                                    ancestry = Some(active);
                                }
                            }
                            event = server.next_event() => match event {
                                NetworkEvent::InboundBlockRequest(inbound) => {
                                    server
                                        .respond_block_from_candidate_store(
                                            inbound,
                                            &mut server_candidates,
                                        )
                                        .unwrap();
                                    served_blocks += 1;
                                }
                                NetworkEvent::InboundBlockFailure { error, .. } => {
                                    panic!("candidate-fill server request failed: {error}")
                                }
                                NetworkEvent::ListenerError { error, .. } => {
                                    panic!("candidate-fill server listener failed: {error}")
                                }
                                NetworkEvent::PeerSession(
                                    PeerSessionEvent::DialFailed { peer_id }
                                    | PeerSessionEvent::Disconnected { peer_id },
                                ) => panic!("candidate-fill server lost peer {peer_id}"),
                                _ => {}
                            },
                        }
                    }
                })
                .await
                .expect("authenticated candidate fill timed out");
                assert_eq!(served_blocks, 1);
                assert_eq!(client_candidates.get(target).unwrap(), Some(block));
                assert!(!client_payloads.contains(block.artifact_id()).unwrap());
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );

                let candidate_only_sources = client_layout_ref.source_images();
                let (scope, rejection) = expect_rejected(
                    scope
                        .sign_candidate_backed_prevote_for_proposal(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &control,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeVoteRejectionV0::PayloadUnavailable { target: actual }
                        if actual == target
                ));
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(client_layout_ref.source_images(), candidate_only_sources);

                let progress = client
                    .start_artifact_block_candidate_branch_payload_fill(
                        scope.finality(),
                        &mut client_candidates,
                        &mut client_payloads,
                        server_peer_id,
                        target,
                        CandidateBranchReconstructionLimits::new(1).unwrap(),
                    )
                    .unwrap();
                let mut payload_fill = match progress {
                    ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) => {
                        Some(fill)
                    }
                    ArtifactBlockCandidateBranchPayloadFillProgress::Complete(_) => {
                        panic!("the empty client payload archive unexpectedly completed")
                    }
                };
                let mut reconstruction = None;
                let mut served_payloads = 0_usize;
                timeout(Duration::from_secs(20), async {
                    while payload_fill.is_some() {
                        tokio::select! {
                            event = client.next_event() => {
                                if payload_fill.as_ref().unwrap().accepts_event(&event) {
                                    let active = payload_fill.take().unwrap();
                                    match active.on_event(&mut client, event).unwrap() {
                                        ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(next) => {
                                            payload_fill = Some(next);
                                        }
                                        ArtifactBlockCandidateBranchPayloadFillProgress::Complete(complete) => {
                                            reconstruction = Some(complete);
                                        }
                                    }
                                } else if let NetworkEvent::ListenerError { error, .. } = event {
                                    panic!("payload-fill client listener failed: {error}");
                                }
                            }
                            event = server.next_event() => match event {
                                NetworkEvent::InboundArtifactRequest(inbound) => {
                                    server
                                        .respond_artifact_from_payload_store(
                                            inbound,
                                            &mut server_payloads,
                                        )
                                        .unwrap();
                                    served_payloads += 1;
                                }
                                NetworkEvent::InboundArtifactFailure { error, .. } => {
                                    panic!("payload-fill server request failed: {error}")
                                }
                                NetworkEvent::ListenerError { error, .. } => {
                                    panic!("payload-fill server listener failed: {error}")
                                }
                                NetworkEvent::PeerSession(
                                    PeerSessionEvent::DialFailed { peer_id }
                                    | PeerSessionEvent::Disconnected { peer_id },
                                ) => panic!("payload-fill server lost peer {peer_id}"),
                                _ => {}
                            },
                        }
                    }
                })
                .await
                .expect("authenticated payload fill timed out");
                let reconstructed = reconstruction.expect("payload fill must complete");
                assert_eq!(served_payloads, 1);
                assert_eq!(reconstructed.target_block_id(), target);
                assert!(client_payloads.contains(block.artifact_id()).unwrap());
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(
                    server_layout_ref.source_images(),
                    server_sources_in_session
                );

                let complete_client_sources = client_layout_ref.source_images();
                let mut invalid_control = control.clone();
                let signature_byte = ConsensusValueV0::BYTE_LENGTH
                    + VerifiedProducerAuthorizationV0::BYTE_LENGTH
                    - 1;
                invalid_control[signature_byte] ^= 1;
                let (scope, rejection) = expect_rejected(
                    scope
                        .sign_candidate_backed_prevote_for_proposal(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &invalid_control,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeVoteRejectionV0::Proposal(_)
                ));
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(client_layout_ref.source_images(), complete_client_sources);

                let (scope, prevote) = expect_signed(
                    scope
                        .sign_candidate_backed_prevote_for_proposal(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &control,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert_eq!(prevote.position(), position);
                assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
                assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
                let after_prevote = client_layout_ref.authority_images();
                assert_eq!(after_prevote[0], authority_before_in_session[0]);
                assert_eq!(after_prevote[1], authority_before_in_session[1]);
                assert_ne!(after_prevote[2], authority_before_in_session[2]);
                assert_ne!(after_prevote[3], authority_before_in_session[3]);
                assert_eq!(client_layout_ref.source_images(), complete_client_sources);

                let prevote_bytes = prevote.canonical_bytes().to_vec();
                let (mut scope, precommit) = expect_signed(
                    scope
                        .sign_candidate_backed_precommit_for_proposal_vote_batch(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &control,
                            &[prevote_bytes.as_slice()],
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert_eq!(precommit.position(), position);
                assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
                assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Precommit
                );
                assert_eq!(
                    scope
                        .signing_session()
                        .locked_value()
                        .unwrap()
                        .proposal_signing_root(),
                    root
                );
                let certificate = scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate()
                    .to_vec();
                let after_precommit = client_layout_ref.authority_images();
                assert_eq!(after_precommit[0], authority_before_in_session[0]);
                assert_eq!(after_precommit[1], authority_before_in_session[1]);
                assert_ne!(after_precommit[2], after_prevote[2]);
                assert_ne!(after_precommit[3], after_prevote[3]);
                assert_eq!(client_layout_ref.source_images(), complete_client_sources);
                assert_eq!(
                    server_layout_ref.source_images(),
                    server_sources_in_session
                );
                (position, root, certificate, complete_client_sources)
            })
        })
        .unwrap();

    let completed_authority = client_layout.authority_images();
    assert_eq!(completed_authority[0], authority_before[0]);
    assert_eq!(completed_authority[1], authority_before[1]);
    assert_ne!(completed_authority[2], authority_before[2]);
    assert_ne!(completed_authority[3], authority_before[3]);
    assert_eq!(client_layout.source_images(), complete_client_sources);
    assert_eq!(server_layout.source_images(), server_sources);

    let mut reopened_candidates = ArtifactBlockCandidateStore::open(
        &client_layout.candidate_store,
        definition,
        ArtifactBlockCandidateStoreLimits::new(STORE_ENTRY_LIMIT).unwrap(),
    )
    .unwrap();
    let mut reopened_payloads = CanonicalArtifactPayloadStore::open(
        &client_layout.payload_store,
        ArtifactPayloadStoreLimits::new(STORE_ENTRY_LIMIT, STORE_BYTE_LIMIT).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened_candidates.get(target).unwrap(), Some(block));
    let reopened_payload = reopened_payloads
        .get(block.artifact_id())
        .unwrap()
        .expect("the acquired payload must reopen");
    assert_eq!(reopened_payload.artifact_id(), block.artifact_id());
    assert_eq!(reopened_payload.canonical_artifact_bytes(), payload);
    drop(reopened_candidates);
    drop(reopened_payloads);

    let reopened = expect_ready(
        provision(definition, context, &entries, &client_layout)
            .open(SigningKey::from_bytes(&seed))
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(client_layout.authority_images(), completed_authority);
            assert_eq!(client_layout.source_images(), complete_client_sources);
            assert_eq!(scope.signing_session().position(), position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                root
            );
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                certificate
            );
        })
        .unwrap();
}

#[test]
fn driver_owned_history_supports_caller_acquisition_and_explicit_vote_loopback() {
    let definition = ArtifactChainDefinition::new([0x51; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x62; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let mut seed = [0_u8; 32];
    seed[0] = 2;
    seed[2] = 0xb6;
    let signing_key = SigningKey::from_bytes(&seed);
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&signing_key),
        AgreementWeight::new(1),
    )];
    let selected = ArtifactChainState::new(definition);
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let target = block.id();

    let client_layout = TestLayout::new("fixed-validator-driver-fill-client");
    let server_layout = TestLayout::new("fixed-validator-driver-fill-server");
    let mut client_candidates = candidate_store(&client_layout.candidate_store, definition);
    let mut client_payloads = payload_store(&client_layout.payload_store);
    let mut server_candidates = candidate_store(&server_layout.candidate_store, definition);
    let mut server_payloads = payload_store(&server_layout.payload_store);
    assert!(matches!(
        server_candidates.insert(&block).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    ));
    assert!(matches!(
        server_payloads
            .validate_and_insert_branch_payload(
                &selected.branch_snapshot(),
                &block,
                payload.clone(),
            )
            .unwrap()
            .insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    ));
    let server_sources = server_layout.source_images();

    let ready = provision(definition, context, &entries, &client_layout)
        .create(signing_key.clone())
        .unwrap();
    let authority_before = client_layout.authority_images();
    let empty_client_sources = client_layout.source_images();
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut client, mut server, server_peer_id) = runtime.block_on(connected_pair());
    let client_layout_ref = &client_layout;
    let server_layout_ref = &server_layout;
    let authority_before_in_session = authority_before.clone();
    let server_sources_in_session = server_sources.clone();

    let (position, root, certificate, completed_sources) = ready
        .run_with_signing_session(|scope| {
            runtime.block_on(async move {
                let branch = scope.branch().clone();
                let round = branch.begin_round_zero().unwrap();
                let position = round.position();
                let value = round.value_for_artifact_block(block);
                let root = value.proposal_signing_root();
                let control = proposal_control_bytes(value, position, &signing_key);

                let driver = node_driver(scope);
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                let driver = transfer_arm(driver);
                assert!(!driver.has_pending_command());
                assert_eq!(client_layout_ref.source_images(), empty_client_sources);

                fill_candidate_and_payload(
                    driver.selected_artifact_history(),
                    &mut client,
                    &mut server,
                    &mut client_candidates,
                    &mut client_payloads,
                    &mut server_candidates,
                    &mut server_payloads,
                    server_peer_id,
                    None,
                    target,
                )
                .await;
                assert_eq!(client_candidates.get(target).unwrap(), Some(block));
                let acquired_payload = client_payloads
                    .get(block.artifact_id())
                    .unwrap()
                    .expect("the driver caller must read the acquired payload")
                    .canonical_artifact_bytes()
                    .to_vec();
                assert_eq!(acquired_payload, payload);
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(server_layout_ref.source_images(), server_sources_in_session);
                let completed_sources = client_layout_ref.source_images();

                let mut invalid_payload = acquired_payload.clone();
                invalid_payload[0] ^= 1;
                let driver = match driver
                    .admit_event(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                        canonical_proposal_control_bytes: control.clone().into_boxed_slice(),
                        canonical_artifact_bytes: invalid_payload.clone().into_boxed_slice(),
                    })
                    .unwrap()
                {
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                        driver,
                        event,
                        rejection,
                    } => {
                        assert!(matches!(
                            *rejection,
                            FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(_)
                        ));
                        assert!(matches!(
                            *event,
                            FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                                canonical_proposal_control_bytes,
                                canonical_artifact_bytes,
                            } if canonical_proposal_control_bytes.as_ref() == control.as_slice()
                                && canonical_artifact_bytes.as_ref() == invalid_payload.as_slice()
                        ));
                        *driver
                    }
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
                        panic!("tampered acquired payload must not be admitted")
                    }
                    _ => panic!("unexpected future driver admission outcome"),
                };
                assert_eq!(driver.current_inbox_len(), 0);
                assert_eq!(
                    client_layout_ref.authority_images(),
                    authority_before_in_session
                );
                assert_eq!(client_layout_ref.source_images(), completed_sources);

                let driver = admit_driver_event(
                    driver,
                    FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                        canonical_proposal_control_bytes: control.into_boxed_slice(),
                        canonical_artifact_bytes: acquired_payload.into_boxed_slice(),
                    },
                );
                assert_eq!(driver.current_inbox_len(), 1);
                let driver = transition_driver(driver);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
                let (driver, prevote) = publish_driver_vote(driver);
                assert_eq!(prevote.position(), position);
                assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
                assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
                let prevote_bytes = prevote.canonical_bytes().to_vec();
                let after_prevote = client_layout_ref.authority_images();
                assert_eq!(after_prevote[0], authority_before_in_session[0]);
                assert_eq!(after_prevote[1], authority_before_in_session[1]);
                assert_ne!(after_prevote[2], authority_before_in_session[2]);
                assert_ne!(after_prevote[3], authority_before_in_session[3]);
                assert_eq!(client_layout_ref.source_images(), completed_sources);

                let driver = transfer_arm(driver);
                let driver = admit_driver_event(
                    driver,
                    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                        canonical_signed_prevote: prevote_bytes.clone().into_boxed_slice(),
                    },
                );
                assert_eq!(driver.current_inbox_len(), 2);
                let driver = transition_driver(driver);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                let (driver, precommit) = publish_driver_vote(driver);
                assert_eq!(precommit.position(), position);
                assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
                assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
                let driver = transfer_arm(driver);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                assert!(!driver.has_pending_command());

                let certificate = round
                    .build_quorum_certificate_from_signed_votes(
                        &[prevote_bytes.as_slice()],
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Proposal(root),
                    )
                    .unwrap()
                    .to_canonical_bytes();
                let after_precommit = client_layout_ref.authority_images();
                assert_eq!(after_precommit[0], authority_before_in_session[0]);
                assert_eq!(after_precommit[1], authority_before_in_session[1]);
                assert_ne!(after_precommit[2], after_prevote[2]);
                assert_ne!(after_precommit[3], after_prevote[3]);
                assert_eq!(client_layout_ref.source_images(), completed_sources);
                assert_eq!(server_layout_ref.source_images(), server_sources_in_session);
                (position, root, certificate, completed_sources)
            })
        })
        .unwrap();

    let completed_authority = client_layout.authority_images();
    assert_eq!(completed_authority[0], authority_before[0]);
    assert_eq!(completed_authority[1], authority_before[1]);
    assert_ne!(completed_authority[2], authority_before[2]);
    assert_ne!(completed_authority[3], authority_before[3]);
    assert_eq!(client_layout.source_images(), completed_sources);
    assert_eq!(server_layout.source_images(), server_sources);

    let reopened = expect_ready(
        provision(definition, context, &entries, &client_layout)
            .open(SigningKey::from_bytes(&seed))
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(client_layout.authority_images(), completed_authority);
            assert_eq!(client_layout.source_images(), completed_sources);
            assert_eq!(scope.signing_session().position(), position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                root
            );
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                certificate
            );
        })
        .unwrap();
}

#[test]
fn network_filled_historical_sibling_needs_full_evidence_after_command_custody() {
    for valid_terminal_evidence in [false, true] {
        let case = if valid_terminal_evidence {
            "valid-terminal"
        } else {
            "invalid-terminal"
        };
        let definition = ArtifactChainDefinition::new([0x71; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x82; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let mut seed = [0_u8; 32];
        seed[0] = 3;
        seed[2] = 0xc7;
        let signing_key = SigningKey::from_bytes(&seed);
        let entries = [ActiveAgreementEntry::new(
            consensus_key(&signing_key),
            AgreementWeight::new(1),
        )];
        let client_layout = TestLayout::new(&format!(
            "fixed-validator-network-filled-conflict-client-{case}"
        ));
        let server_layout = TestLayout::new(&format!(
            "fixed-validator-network-filled-conflict-server-{case}"
        ));
        let mut client_candidates = candidate_store(&client_layout.candidate_store, definition);
        let mut client_payloads = payload_store(&client_layout.payload_store);
        let mut server_candidates = candidate_store(&server_layout.candidate_store, definition);
        let mut server_payloads = payload_store(&server_layout.payload_store);
        let empty_client_sources = client_layout.source_images();

        let ready = provision(definition, context, &entries, &client_layout)
            .create(signing_key.clone())
            .unwrap();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let (mut client, mut server, server_peer_id) = runtime.block_on(connected_pair());
        let client_layout_ref = &client_layout;
        let server_layout_ref = &server_layout;
        let empty_client_sources_in_session = empty_client_sources.clone();

        let (
            expected_position,
            target,
            sibling_block,
            sibling_payload,
            stopped,
            terminal_authority,
            completed_sources,
        ) = ready
            .run_with_signing_session(|scope| {
                runtime.block_on(async move {
                    let genesis_branch = scope.branch().clone();
                    let mut selected = ArtifactChainState::new(definition);
                    let (first, _, _, first_payload) = verified_transition_inputs(
                        &genesis_branch,
                        &selected,
                        ZfcAxiom::Pairing,
                        0,
                        &signing_key,
                    );
                    let first_block = first.value().artifact_block();
                    let selected_ancestry = first.value().ancestry_id();
                    let (sibling, control, precommit, sibling_payload) =
                        verified_transition_inputs(
                            &genesis_branch,
                            &selected,
                            ZfcAxiom::Union,
                            0,
                            &signing_key,
                        );
                    let sibling_block = sibling.value().artifact_block();
                    let target = sibling_block.id();
                    let sibling_ancestry = sibling.value().ancestry_id();
                    let sibling_envelope_id = sibling.envelope_id();
                    let selected_anchor = definition.id().virtual_genesis_block_id();

                    assert!(matches!(
                        server_candidates.insert(&sibling_block).unwrap(),
                        ArtifactBlockCandidateInsertOutcome::Inserted
                    ));
                    assert!(matches!(
                        server_payloads
                            .validate_and_insert_branch_payload(
                                &selected.branch_snapshot(),
                                &sibling_block,
                                sibling_payload.clone(),
                            )
                            .unwrap()
                            .insertion_outcome(),
                        ArtifactPayloadInsertOutcome::Inserted
                    ));
                    let server_sources = server_layout_ref.source_images();

                    let scope = expect_finality_continues(
                        scope.commit_verified_finality(first).unwrap(),
                    );
                    selected.apply_block(&first_block, first_payload).unwrap();
                    let (second, _, _, second_payload) = verified_transition_inputs(
                        scope.branch(),
                        &selected,
                        ZfcAxiom::PowerSet,
                        0,
                        &signing_key,
                    );
                    let second_block = second.value().artifact_block();
                    let scope = expect_finality_continues(
                        scope.commit_verified_finality(second).unwrap(),
                    );
                    selected.apply_block(&second_block, second_payload).unwrap();

                    let driver = node_driver(scope);
                    let expected_position = driver.position();
                    assert_eq!(expected_position.height().value(), 3);
                    assert_eq!(expected_position.round(), ConsensusRound::new(0));
                    assert_eq!(
                        driver
                            .selected_artifact_history()
                            .selected_head_block_id()
                            .unwrap(),
                        second_block.id()
                    );
                    assert_ne!(second_block.id(), selected_anchor);
                    assert!(driver.has_pending_command());
                    let authority_before_fill = client_layout_ref.authority_images();

                    fill_candidate_and_payload(
                        driver.selected_artifact_history(),
                        &mut client,
                        &mut server,
                        &mut client_candidates,
                        &mut client_payloads,
                        &mut server_candidates,
                        &mut server_payloads,
                        server_peer_id,
                        Some(selected_anchor),
                        target,
                    )
                    .await;
                    assert_eq!(
                        client_candidates.get(target).unwrap(),
                        Some(sibling_block)
                    );
                    assert_eq!(
                        client_payloads
                            .get(sibling_block.artifact_id())
                            .unwrap()
                            .expect("the acquired sibling payload must be archived")
                            .canonical_artifact_bytes(),
                        sibling_payload.as_slice()
                    );
                    assert_eq!(
                        client_layout_ref.authority_images(),
                        authority_before_fill
                    );
                    assert_eq!(server_layout_ref.source_images(), server_sources);
                    let completed_sources = client_layout_ref.source_images();
                    assert_ne!(completed_sources[0], empty_client_sources_in_session[0]);
                    assert_ne!(completed_sources[1], empty_client_sources_in_session[1]);

                    let command_gate_batch = [precommit.as_slice()];
                    let driver = match driver
                        .commit_candidate_backed_finality_conflict_vote_batch(
                            &mut client_candidates,
                            &mut client_payloads,
                            target,
                            &control,
                            &command_gate_batch,
                            ConsensusRound::new(0),
                        )
                        .unwrap()
                    {
                        FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                            driver,
                        } => *driver,
                        FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                            _,
                        ) => panic!("the initial arm command must retain custody"),
                        _ => panic!("unexpected future candidate-conflict outcome"),
                    };
                    assert_eq!(
                        client_layout_ref.authority_images(),
                        authority_before_fill
                    );
                    assert_eq!(client_layout_ref.source_images(), completed_sources);

                    let driver = transfer_arm(driver);
                    let authority_before_terminal = client_layout_ref.authority_images();
                    let stopped = if valid_terminal_evidence {
                        let batch = [precommit.as_slice()];
                        let stopped = match driver
                            .commit_candidate_backed_finality_conflict_vote_batch(
                                &mut client_candidates,
                                &mut client_payloads,
                                target,
                                &control,
                                &batch,
                                ConsensusRound::new(0),
                            )
                            .unwrap()
                        {
                            FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                                stopped,
                            ) => *stopped,
                            FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                                ..
                            } => panic!("the transferred arm must not block terminal evidence"),
                            _ => panic!("unexpected future candidate-conflict outcome"),
                        };
                        let authority_after_terminal = client_layout_ref.authority_images();
                        for (index, (before, after)) in authority_before_terminal
                            .iter()
                            .zip(&authority_after_terminal)
                            .enumerate()
                        {
                            assert_ne!(before, after, "authority image {index} did not advance");
                        }
                        assert_eq!(
                            stopped.finality_halt().kind(),
                            FixedValidatorFinalityHaltKindV0::SelectedSibling
                        );
                        assert_eq!(stopped.finality_halt().height().value(), 1);
                        assert_eq!(
                            stopped.finality_halt().first_ancestry(),
                            selected_ancestry
                        );
                        assert_eq!(
                            stopped.finality_halt().second_ancestry(),
                            sibling_ancestry
                        );
                        assert_eq!(
                            stopped.finality_halt().second_envelope_id(),
                            sibling_envelope_id
                        );
                        assert_eq!(
                            stopped.signer_stop().finality_state_id(),
                            stopped.finality_halt().state_id()
                        );
                        Some(stopped)
                    } else {
                        assert!(matches!(
                            driver.commit_candidate_backed_finality_conflict_vote_batch(
                                &mut client_candidates,
                                &mut client_payloads,
                                target,
                                &control,
                                &[],
                                ConsensusRound::new(0),
                            ),
                            Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                                if matches!(
                                    source.as_ref(),
                                    CandidateBackedFinalityErrorV0::PrecommitBatch(_)
                                )
                        ));
                        assert_eq!(
                            client_layout_ref.authority_images(),
                            authority_before_terminal
                        );
                        None
                    };
                    assert_eq!(client_layout_ref.source_images(), completed_sources);
                    assert_eq!(server_layout_ref.source_images(), server_sources);
                    (
                        expected_position,
                        target,
                        sibling_block,
                        sibling_payload,
                        stopped,
                        client_layout_ref.authority_images(),
                        completed_sources,
                    )
                })
            })
            .unwrap();

        let mut reopened_candidates = ArtifactBlockCandidateStore::open(
            &client_layout.candidate_store,
            definition,
            ArtifactBlockCandidateStoreLimits::new(STORE_ENTRY_LIMIT).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened_candidates.get(target).unwrap(),
            Some(sibling_block)
        );
        let mut reopened_payloads = CanonicalArtifactPayloadStore::open(
            &client_layout.payload_store,
            ArtifactPayloadStoreLimits::new(STORE_ENTRY_LIMIT, STORE_BYTE_LIMIT).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened_payloads
                .get(sibling_block.artifact_id())
                .unwrap()
                .expect("the acquired sibling payload must survive strict reopen")
                .canonical_artifact_bytes(),
            sibling_payload.as_slice()
        );
        assert_eq!(client_layout.source_images(), completed_sources);
        drop(reopened_candidates);
        drop(reopened_payloads);

        match stopped {
            Some(stopped) => match provision(definition, context, &entries, &client_layout)
                .open(SigningKey::from_bytes(&seed))
                .unwrap()
            {
                FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                    assert_eq!(reopened, stopped);
                }
                _ => panic!("valid acquired conflict evidence must strictly reopen terminal"),
            },
            None => {
                let reopened = expect_ready(
                    provision(definition, context, &entries, &client_layout)
                        .open(SigningKey::from_bytes(&seed))
                        .unwrap(),
                );
                reopened
                    .run_with_signing_session(|mut scope| {
                        assert_eq!(scope.signing_session().position(), expected_position);
                    })
                    .unwrap();
            }
        }
        assert_eq!(client_layout.authority_images(), terminal_authority);
    }
}
