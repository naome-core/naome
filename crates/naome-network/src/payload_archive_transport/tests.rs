use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

use naome::artifact_exchange::{ARTIFACT_RESPONSE_MAX_BYTES, ArtifactRequest, ArtifactResponse};
use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag, ArtifactSetRoot};
use naome_foundation::{FOUNDATION_ID, FreeVariable};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidateBranchReconstructionLimits, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError, ReconstructedCandidateBranch,
};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout};

use super::*;
use crate::tests::{
    TestDirectory, assert_snapshot, connected_pair, create_journal, pairing_bytes, snapshot,
    test_chain_definition,
};
use crate::{
    ArtifactBlockCandidateBranchPayloadFill, ArtifactBlockCandidateBranchPayloadFillProgress,
    INBOUND_APPLICATION_REQUEST_BURST, NetworkEvent, OutboundArtifactEvent,
    OutboundArtifactOutcome, PeerId,
};

const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";
const PAYLOAD_STORE_HEADER: &[u8] = b"naome:artifact-payload-store:v1\0";
const PAYLOAD_STORE_ENTRY_DOMAIN: &[u8] = b"naome:artifact-payload-store-entry:v1\0";

struct DependencyBranch {
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
    root: ArtifactSetRoot,
}

fn payload_limits(entries: usize, bytes: u64) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(entries, bytes).unwrap()
}

fn candidate_store(directory: &TestDirectory) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
    )
    .unwrap()
}

fn referenced_generalization_bytes(parent: naome_proof::ProofId) -> Vec<u8> {
    let normal = ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id: parent },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    ArtifactPayload::Proof(normal.certificate().clone()).to_canonical_bytes()
}

fn dependency_branch() -> DependencyBranch {
    let first_bytes = pairing_bytes();
    let mut identities = ArtifactDag::new();
    let first_record = identities
        .apply_canonical_artifact_bytes(first_bytes.clone())
        .unwrap();
    let first_id = first_record.artifact_id();
    let first_proof_id = first_record.as_proof().unwrap().proof_id();
    let second_bytes = referenced_generalization_bytes(first_proof_id);
    let second_id = identities
        .apply_canonical_artifact_bytes(second_bytes.clone())
        .unwrap()
        .artifact_id();

    let mut branch = ArtifactChainState::new(test_chain_definition());
    let first = branch.prepare_block(first_id).unwrap();
    branch.apply_block(&first, first_bytes.clone()).unwrap();
    let second = branch.prepare_block(second_id).unwrap();
    branch.apply_block(&second, second_bytes.clone()).unwrap();

    DependencyBranch {
        blocks: [first, second],
        payloads: [first_bytes, second_bytes],
        root: branch.artifact_dag().artifact_set_root(),
    }
}

fn insert_candidates(store: &mut ArtifactBlockCandidateStore, blocks: &[ArtifactBlock]) {
    for block in blocks {
        assert_eq!(
            store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
}

fn seed_payloads(
    store: &mut CanonicalArtifactPayloadStore,
    payloads: &[Vec<u8>],
) -> Vec<ArtifactId> {
    let mut source = ArtifactDag::new();
    payloads
        .iter()
        .map(|payload| {
            let record = source
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap();
            assert_eq!(
                store.insert(record).unwrap(),
                ArtifactPayloadInsertOutcome::Inserted
            );
            record.artifact_id()
        })
        .collect()
}

fn payload_store_bytes(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.path().join(PAYLOAD_STORE_FILE_NAME)).unwrap()
}

fn flip_first_payload_byte(directory: &TestDirectory) {
    let offset = u64::try_from(
        PAYLOAD_STORE_HEADER.len() + FOUNDATION_ID.len() + 4 + ArtifactId::BYTE_LENGTH,
    )
    .unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(PAYLOAD_STORE_FILE_NAME))
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

async fn complete_branch_fill<'store>(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_payloads: &mut CanonicalArtifactPayloadStore,
    progress: ArtifactBlockCandidateBranchPayloadFillProgress<'store>,
) -> ReconstructedCandidateBranch {
    let ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) = progress else {
        panic!("an empty client archive unexpectedly completed the branch fill")
    };
    let mut fill: Option<ArtifactBlockCandidateBranchPayloadFill<'store>> = Some(fill);

    timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    let active = fill.as_ref().expect("a branch fill remains active");
                    if !active.accepts_event(&event) {
                        continue;
                    }
                    let active = fill.take().unwrap();
                    match active.on_event(client, event).unwrap() {
                        ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(next) => {
                            fill = Some(next);
                        }
                        ArtifactBlockCandidateBranchPayloadFillProgress::Complete(reconstructed) => {
                            return reconstructed;
                        }
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        server
                            .respond_artifact_from_payload_store(inbound, server_payloads)
                            .unwrap();
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("inbound archive response failed: {error}")
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("candidate branch payload recovery timed out")
}

async fn archive_round_trip(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_payloads: &mut CanonicalArtifactPayloadStore,
    server_peer_id: PeerId,
    artifact_id: ArtifactId,
) -> OutboundArtifactEvent {
    client
        .request_artifact(server_peer_id, ArtifactRequest::new(artifact_id))
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundArtifact(event) = event {
                        return event;
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        server
                            .respond_artifact_from_payload_store(inbound, server_payloads)
                            .unwrap();
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("inbound archive response failed: {error}")
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("archive artifact exchange timed out")
}

fn into_response(event: OutboundArtifactEvent) -> ArtifactResponse {
    match event.outcome {
        OutboundArtifactOutcome::Response { response, .. } => response,
        OutboundArtifactOutcome::Failure(error) => {
            panic!("archive artifact request failed: {error}")
        }
        OutboundArtifactOutcome::DeadlineExceeded => {
            panic!("archive artifact request exceeded its deadline")
        }
    }
}

async fn receive_inbound_request(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_peer_id: PeerId,
    artifact_id: ArtifactId,
) -> InboundArtifactRequest {
    client
        .request_artifact(server_peer_id, ArtifactRequest::new(artifact_id))
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundArtifact(event) = event {
                        panic!("artifact request terminated before reaching the responder: {event:?}");
                    }
                }
                event = server.next_event() => {
                    if let NetworkEvent::InboundArtifactRequest(inbound) = event {
                        return inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("inbound archive request timed out")
}

async fn assert_request_failed_without_unavailable(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
) {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundArtifact(event) = event {
                        match event.outcome {
                            OutboundArtifactOutcome::Failure(_) => return,
                            OutboundArtifactOutcome::DeadlineExceeded => {
                                panic!("omitted archive response reached the absolute deadline")
                            }
                            OutboundArtifactOutcome::Response { response, .. } => {
                                panic!(
                                    "archive responder error became a response (unavailable={})",
                                    response.is_unavailable()
                                )
                            }
                        }
                    }
                }
                _ = server.next_event() => {}
            }
        }
    })
    .await
    .expect("failed archive request did not terminate")
}

async fn wait_for_closed_channel(
    server: &mut StaticArtifactNetwork,
    inbound: &InboundArtifactRequest,
) {
    timeout(Duration::from_secs(10), async {
        while inbound.channel.is_open() {
            let _ = server.next_event().await;
        }
    })
    .await
    .expect("dropped requester did not close the response channel")
}

fn write_maximum_payload_store(directory: &TestDirectory, artifact_id: ArtifactId) {
    // The transport cap is deliberately larger than any artifact currently
    // produced by the checked authoring path. Build one integrity-valid local
    // archive image to exercise that framing boundary; the received bytes stay
    // an untrusted transport candidate and are never admitted by this test.
    let payload_length = u32::try_from(ARTIFACT_RESPONSE_MAX_BYTES)
        .unwrap()
        .to_be_bytes();
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_STORE_ENTRY_DOMAIN);
    hasher.update(u32::try_from(FOUNDATION_ID.len()).unwrap().to_be_bytes());
    hasher.update(FOUNDATION_ID.as_bytes());
    hasher.update(payload_length);
    hasher.update(artifact_id.as_bytes());

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(directory.path().join(PAYLOAD_STORE_FILE_NAME))
        .unwrap();
    file.write_all(PAYLOAD_STORE_HEADER).unwrap();
    file.write_all(FOUNDATION_ID.as_bytes()).unwrap();
    file.write_all(&payload_length).unwrap();
    file.write_all(artifact_id.as_bytes()).unwrap();

    let chunk = [0x5a; 8 * 1024];
    let mut remaining = ARTIFACT_RESPONSE_MAX_BYTES;
    while remaining != 0 {
        let chunk_len = remaining.min(chunk.len());
        let bytes = &chunk[..chunk_len];
        hasher.update(bytes);
        file.write_all(bytes).unwrap();
        remaining -= chunk_len;
    }
    file.write_all(&hasher.finalize()).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn reopened_archive_recovers_branch_only_dependency_and_preserves_both_selected_journals() {
    let branch = dependency_branch();
    let target = branch.blocks[1];
    let limits = payload_limits(2, 1_000_000);

    let server_directory = TestDirectory::new("payload-archive-relay-server");
    let server_journal = create_journal(server_directory.path()).unwrap();
    let server_selected = snapshot(&server_directory, &server_journal);
    let mut server_payloads =
        CanonicalArtifactPayloadStore::create(server_directory.path(), limits).unwrap();
    let archived_ids = seed_payloads(&mut server_payloads, &branch.payloads);
    assert_eq!(
        archived_ids,
        branch
            .blocks
            .iter()
            .map(ArtifactBlock::artifact_id)
            .collect::<Vec<_>>()
    );
    for artifact_id in archived_ids.iter().copied() {
        assert!(server_journal.artifact(artifact_id).unwrap().is_none());
    }
    let server_archive_bytes = payload_store_bytes(&server_directory);
    let server_archive_count = server_payloads.len().unwrap();
    let server_archive_payload_bytes = server_payloads.total_payload_bytes().unwrap();
    drop(server_payloads);
    let mut server_payloads =
        CanonicalArtifactPayloadStore::open(server_directory.path(), limits).unwrap();

    let client_directory = TestDirectory::new("payload-archive-relay-client");
    let client_journal = create_journal(client_directory.path()).unwrap();
    let client_selected = snapshot(&client_directory, &client_journal);
    let mut candidates = candidate_store(&client_directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let mut client_payloads =
        CanonicalArtifactPayloadStore::create(client_directory.path(), limits).unwrap();

    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let progress = client
        .start_artifact_block_candidate_branch_payload_fill(
            &client_journal,
            &mut candidates,
            &mut client_payloads,
            server_peer_id,
            target.id(),
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        )
        .unwrap();
    let reconstructed =
        complete_branch_fill(&mut client, &mut server, &mut server_payloads, progress).await;

    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.block_count(), 2);
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert_snapshot(&client_directory, &client_journal, &client_selected);
    assert_snapshot(&server_directory, &server_journal, &server_selected);
    for artifact_id in archived_ids.iter().copied() {
        assert!(client_payloads.contains(artifact_id).unwrap());
        assert!(client_journal.artifact(artifact_id).unwrap().is_none());
    }

    let absent_id = ArtifactId::from_bytes([0xff; ArtifactId::BYTE_LENGTH]);
    assert!(!archived_ids.contains(&absent_id));
    let unavailable = archive_round_trip(
        &mut client,
        &mut server,
        &mut server_payloads,
        server_peer_id,
        absent_id,
    )
    .await;
    assert_eq!(unavailable.peer_id(), server_peer_id);
    assert_eq!(unavailable.request(), ArtifactRequest::new(absent_id));
    assert!(into_response(unavailable).is_unavailable());

    assert_eq!(payload_store_bytes(&server_directory), server_archive_bytes);
    assert_eq!(server_payloads.len().unwrap(), server_archive_count);
    assert_eq!(
        server_payloads.total_payload_bytes().unwrap(),
        server_archive_payload_bytes
    );
    assert_snapshot(&client_directory, &client_journal, &client_selected);
    assert_snapshot(&server_directory, &server_journal, &server_selected);

    drop(client_payloads);
    let reopened_client =
        CanonicalArtifactPayloadStore::open(client_directory.path(), limits).unwrap();
    assert_eq!(reopened_client.len().unwrap(), 2);
}

#[tokio::test]
async fn indexed_corruption_is_typed_poisoned_and_precedes_closed_channel_and_rate() {
    let directory = TestDirectory::new("payload-archive-corruption");
    let payload = pairing_bytes();
    let limits = payload_limits(1, u64::try_from(payload.len()).unwrap());
    let mut payloads = CanonicalArtifactPayloadStore::create(directory.path(), limits).unwrap();
    let artifact_id = seed_payloads(&mut payloads, &[payload])[0];

    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let inbound =
        receive_inbound_request(&mut client, &mut server, server_peer_id, artifact_id).await;
    flip_first_payload_byte(&directory);
    let error = server
        .respond_artifact_from_payload_store(inbound, &mut payloads)
        .unwrap_err();
    let RespondError::PayloadStore(source) = &error else {
        panic!("indexed corruption lost its payload-store type: {error}")
    };
    assert!(matches!(
        source,
        CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id: actual }
            if *actual == artifact_id
    ));
    assert_eq!(
        error.to_string(),
        format!("cannot read canonical artifact-payload store: {source}")
    );
    assert!(error.source().is_some());
    assert!(matches!(
        payloads.len(),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
    assert_request_failed_without_unavailable(&mut client, &mut server).await;

    let (mut closed_client, mut closed_server, _, closed_server_peer_id) = connected_pair().await;
    let closed_inbound = receive_inbound_request(
        &mut closed_client,
        &mut closed_server,
        closed_server_peer_id,
        artifact_id,
    )
    .await;
    closed_server
        .inbound_application_request_budget
        .exhaust(Instant::now());
    drop(closed_client);
    wait_for_closed_channel(&mut closed_server, &closed_inbound).await;
    assert!(matches!(
        closed_server.respond_artifact_from_payload_store(closed_inbound, &mut payloads),
        Err(RespondError::PayloadStore(
            CanonicalArtifactPayloadStoreError::Poisoned
        ))
    ));
    assert_eq!(closed_server.inbound_application_request_budget.tokens(), 0);
}

#[tokio::test]
async fn closed_channel_precedes_the_shared_inbound_token() {
    let directory = TestDirectory::new("payload-archive-closed-channel");
    let mut payloads =
        CanonicalArtifactPayloadStore::create(directory.path(), payload_limits(1, 1_000_000))
            .unwrap();
    let absent_id = ArtifactId::from_bytes([0x71; ArtifactId::BYTE_LENGTH]);
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let inbound =
        receive_inbound_request(&mut client, &mut server, server_peer_id, absent_id).await;
    server
        .inbound_application_request_budget
        .exhaust(Instant::now());
    drop(client);
    wait_for_closed_channel(&mut server, &inbound).await;

    assert!(matches!(
        server.respond_artifact_from_payload_store(inbound, &mut payloads),
        Err(RespondError::ChannelClosed)
    ));
    assert_eq!(server.inbound_application_request_budget.tokens(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
}

#[tokio::test]
async fn rate_limit_precedes_payload_read_and_later_admitted_request_detects_corruption() {
    let directory = TestDirectory::new("payload-archive-rate-before-read");
    let payload = pairing_bytes();
    let limits = payload_limits(1, u64::try_from(payload.len()).unwrap());
    let mut payloads = CanonicalArtifactPayloadStore::create(directory.path(), limits).unwrap();
    let artifact_id = seed_payloads(&mut payloads, &[payload])[0];
    flip_first_payload_byte(&directory);

    let (mut limited_client, mut limited_server, _, limited_server_peer_id) =
        connected_pair().await;
    let limited_inbound = receive_inbound_request(
        &mut limited_client,
        &mut limited_server,
        limited_server_peer_id,
        artifact_id,
    )
    .await;
    limited_server
        .inbound_application_request_budget
        .exhaust(Instant::now());
    assert!(matches!(
        limited_server.respond_artifact_from_payload_store(limited_inbound, &mut payloads),
        Err(RespondError::RateLimited)
    ));
    assert_eq!(
        payloads.len().unwrap(),
        1,
        "rate rejection read the payload"
    );
    assert_request_failed_without_unavailable(&mut limited_client, &mut limited_server).await;

    let (mut admitted_client, mut admitted_server, _, admitted_server_peer_id) =
        connected_pair().await;
    let admitted_inbound = receive_inbound_request(
        &mut admitted_client,
        &mut admitted_server,
        admitted_server_peer_id,
        artifact_id,
    )
    .await;
    assert_eq!(
        admitted_server.inbound_application_request_budget.tokens(),
        INBOUND_APPLICATION_REQUEST_BURST
    );
    assert!(matches!(
        admitted_server.respond_artifact_from_payload_store(admitted_inbound, &mut payloads),
        Err(RespondError::PayloadStore(
            CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id: actual }
        )) if actual == artifact_id
    ));
    assert_eq!(
        admitted_server.inbound_application_request_budget.tokens(),
        INBOUND_APPLICATION_REQUEST_BURST - 1
    );
    assert!(matches!(
        payloads.len(),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
    assert_request_failed_without_unavailable(&mut admitted_client, &mut admitted_server).await;
}

#[tokio::test]
async fn exact_maximum_payload_crosses_the_real_wire_frame_without_archive_mutation() {
    let directory = TestDirectory::new("payload-archive-maximum-frame");
    let artifact_id = ArtifactId::from_bytes([0x9a; ArtifactId::BYTE_LENGTH]);
    write_maximum_payload_store(&directory, artifact_id);
    let mut payloads = CanonicalArtifactPayloadStore::open(
        directory.path(),
        payload_limits(1, u64::try_from(ARTIFACT_RESPONSE_MAX_BYTES).unwrap()),
    )
    .unwrap();
    assert_eq!(payloads.len().unwrap(), 1);
    assert_eq!(
        payloads.total_payload_bytes().unwrap(),
        u64::try_from(ARTIFACT_RESPONSE_MAX_BYTES).unwrap()
    );

    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let event = archive_round_trip(
        &mut client,
        &mut server,
        &mut payloads,
        server_peer_id,
        artifact_id,
    )
    .await;
    let received = into_response(event).into_wire_bytes();
    assert_eq!(received.len(), ARTIFACT_RESPONSE_MAX_BYTES);
    assert!(received.iter().all(|byte| *byte == 0x5a));
    assert_eq!(payloads.len().unwrap(), 1);
}
