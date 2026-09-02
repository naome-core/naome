use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusPosition, ConsensusProtocolVersion, ConsensusRound, ConsensusValueV0,
    FixedConsensusBranchCoordinateV0, FixedConsensusBranchV0,
    OwnedVerifiedFixedConsensusTransitionV0, ProposalSigningRoot, VerifiedProducerAuthorizationV0,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
    CanonicalArtifactPayloadStore, FixedValidatorAnchoredFinalityJournalV0,
    FixedValidatorAnchoredVoteSafetyJournalV0, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorPreparedVoteV0,
    FixedValidatorProposalReplayLimitV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyReplayLimitV0,
};

use super::*;

const AUTHORIZATION_BODY_BYTES: usize = 116;
const VOTE_BODY_BYTES: usize = 118;
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
                "naome-node-startup-{label}-{}-{sequence}",
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
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("temporary directory failed: {error}"),
            }
        }
    }

    fn directories(&self) -> FixedValidatorNodeDirectoriesV0<'_> {
        FixedValidatorNodeDirectoriesV0::new(
            &self.finality_journal,
            &self.finality_anchor,
            &self.vote_journal,
            &self.vote_anchor,
        )
    }

    fn is_empty(&self) -> bool {
        [
            &self.finality_journal,
            &self.finality_anchor,
            &self.vote_journal,
            &self.vote_anchor,
            &self.candidate_store,
            &self.payload_store,
        ]
        .into_iter()
        .all(|directory| fs::read_dir(directory).unwrap().next().is_none())
    }

    fn images(&self) -> [Vec<(String, Vec<u8>)>; 4] {
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

struct Fixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: [ActiveAgreementEntry; 1],
    seed: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let definition = ArtifactChainDefinition::new([0x31; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x42; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let seed = signing_seed(1);
        let key = SigningKey::from_bytes(&seed);
        let entries = [ActiveAgreementEntry::new(
            consensus_key(&key),
            AgreementWeight::new(1),
        )];
        Self {
            definition,
            context,
            entries,
            seed,
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    fn provision<'layout>(
        &'layout self,
        layout: &'layout TestLayout,
        recovery_round_limit: u64,
    ) -> FixedValidatorNodeProvisionV0<'layout> {
        self.provision_with_limits(layout, recovery_round_limit, 8, 32)
    }

    fn provision_with_catch_up_limit<'layout>(
        &'layout self,
        layout: &'layout TestLayout,
        recovery_round_limit: u64,
        catch_up_height_limit: u64,
    ) -> FixedValidatorNodeProvisionV0<'layout> {
        self.provision_with_limits(layout, recovery_round_limit, catch_up_height_limit, 32)
    }

    fn provision_with_proposal_limit<'layout>(
        &'layout self,
        layout: &'layout TestLayout,
        recovery_round_limit: u64,
        proposal_limit: u64,
    ) -> FixedValidatorNodeProvisionV0<'layout> {
        self.provision_with_limits(layout, recovery_round_limit, 8, proposal_limit)
    }

    fn provision_with_limits<'layout>(
        &'layout self,
        layout: &'layout TestLayout,
        recovery_round_limit: u64,
        catch_up_height_limit: u64,
        proposal_limit: u64,
    ) -> FixedValidatorNodeProvisionV0<'layout> {
        FixedValidatorNodeProvisionV0::new(
            self.definition,
            self.context,
            &self.entries,
            layout.directories(),
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
            FixedValidatorProposalReplayLimitV0::new(proposal_limit).unwrap(),
            FixedValidatorSignerRecoveryRoundLimitV0::new(recovery_round_limit),
            FixedValidatorSignerCatchUpHeightLimitV0::new(catch_up_height_limit),
        )
    }

    fn transition(
        &self,
        branch: &FixedConsensusBranchV0,
        selected: &ArtifactChainState,
        axiom: ZfcAxiom,
        round: u64,
    ) -> OwnedVerifiedFixedConsensusTransitionV0 {
        let payload = proof_payload(axiom);
        let block = selected.prepare_block(artifact_id(&payload)).unwrap();
        let mut cursor = branch.begin_round_zero().unwrap();
        for _ in 0..round {
            cursor = cursor.advance_round().unwrap();
        }
        let value = cursor.value_for_artifact_block(block);
        let bytes = envelope_bytes(value, cursor.position(), &self.signing_key());
        cursor
            .decode_and_verify(&bytes, payload)
            .unwrap()
            .into_owned()
    }

    fn open_finality(&self, layout: &TestLayout) -> FixedValidatorAnchoredFinalityJournalV0 {
        FixedValidatorAnchoredFinalityJournalV0::open(
            &layout.finality_journal,
            &layout.finality_anchor,
            self.definition,
            self.context,
            &self.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap()
    }
}

fn signing_seed(index: u16) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    seed[2] = 0xa5;
    seed
}

fn directory_image(directory: &PathBuf) -> Vec<(String, Vec<u8>)> {
    let mut image = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            (name, bytes)
        })
        .collect::<Vec<_>>();
    image.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    image
}

fn create_candidate_store(
    layout: &TestLayout,
    definition: ArtifactChainDefinition,
) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        &layout.candidate_store,
        definition,
        ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
    )
    .unwrap()
}

fn create_payload_store(layout: &TestLayout) -> CanonicalArtifactPayloadStore {
    CanonicalArtifactPayloadStore::create(
        &layout.payload_store,
        ArtifactPayloadStoreLimits::new(16, 1024 * 1024).unwrap(),
    )
    .unwrap()
}

fn retain_transition_inputs(
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    parent: &FixedConsensusBranchV0,
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
) {
    let block = transition.value().artifact_block();
    let _ = candidates.insert(&block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            parent.artifact_snapshot(),
            &block,
            transition.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
}

fn consensus_key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}

fn proof_payload(axiom: ZfcAxiom) -> Vec<u8> {
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

fn certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = 2;
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    body[85] = 1;
    body[86..].copy_from_slice(root.as_bytes());
    let key = consensus_key(signer);
    let mut transcript = b"naome:consensus-precommit-signing:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn envelope_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let root = value.proposal_signing_root();
    let authorization = authorization_bytes(value.context(), position, root, proposer);
    let certificate = certificate_bytes(value.context(), position, root, proposer);
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization);
    bytes.extend_from_slice(&certificate);
    bytes
}

fn expect_ready(startup: FixedValidatorNodeStartupV0) -> FixedValidatorNodeReadyV0 {
    match startup {
        FixedValidatorNodeStartupV0::Ready(ready) => *ready,
        FixedValidatorNodeStartupV0::FinalityStopped(_)
        | FixedValidatorNodeStartupV0::SignerStopped(_)
        | FixedValidatorNodeStartupV0::PendingProposal(_)
        | FixedValidatorNodeStartupV0::PendingPreparation(_) => {
            panic!("expected a ready node startup")
        }
    }
}

// Existing tests whose subject is not close-event routing use the exact live
// identity; adversarial identity tests invoke the production methods directly.
trait ExactCurrentPhaseCloseTestExt<'node> {
    fn sign_prevote_after_current_proposal_close(
        self,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    >;

    fn sign_precommit_after_current_prevote_close(
        self,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    >;
}

impl<'node> ExactCurrentPhaseCloseTestExt<'node> for FixedValidatorNodeSigningScopeV0<'node> {
    fn sign_prevote_after_current_proposal_close(
        mut self,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let context = self.branch().context();
        let position = self.signing_session().position();
        self.sign_prevote_after_proposal_close(context, position, inclusive_maximum_round)
    }

    fn sign_precommit_after_current_prevote_close(
        mut self,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let context = self.branch().context();
        let position = self.signing_session().position();
        self.sign_precommit_after_prevote_close(context, position, inclusive_maximum_round)
    }
}

fn prepare_and_sign(
    session: &mut FixedValidatorNodeVotingSessionV0<'_>,
    round: &naome_consensus::FixedConsensusRoundV0<'_>,
    prepared: FixedValidatorPreparedVoteV0,
) {
    let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(signed.position(), round.position());
}

#[test]
fn preflight_rejects_a_foreign_signing_key_before_file_access() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("preflight-key");
    let foreign_key = SigningKey::from_bytes(&signing_seed(2));
    assert!(matches!(
        fixture.provision(&layout, 8).create(foreign_key),
        Err(FixedValidatorNodeStartupErrorV0::SignerNotInFixedSet { .. })
    ));
    assert!(layout.is_empty());
}

#[test]
fn preflight_rejects_an_invalid_fixed_snapshot_before_file_access() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("preflight-fixed-set");
    let invalid_entries = [ActiveAgreementEntry::new(
        fixture.entries[0].consensus_key(),
        AgreementWeight::ZERO,
    )];
    let provision = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &invalid_entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    );
    assert!(matches!(
        provision.create(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::Genesis(_))
    ));
    assert!(layout.is_empty());
}

#[test]
fn fresh_create_and_exact_restart_issue_only_scoped_round_zero() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("create-reopen");
    let initial = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let initial_coordinate = initial
        .run_with_signing_session(|mut scope| {
            assert!(scope.branch().artifact_snapshot().is_virtual_genesis());
            let coordinate = scope.branch().coordinate();
            assert_eq!(scope.signing_session().position().height().value(), 1);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(scope.finality().head().unwrap().coordinate(), coordinate);
            coordinate
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), initial_coordinate);
            assert_eq!(scope.signing_session().position().height().value(), 1);
            assert_eq!(scope.signing_session().position().round().value(), 0);
        })
        .unwrap();
}

#[test]
fn live_owner_holds_the_finality_pair_lock() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lock");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(_))
    ));
    drop(ready);
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Ok(FixedValidatorNodeStartupV0::Ready(_))
    ));
}

#[test]
fn vote_pair_lock_failure_releases_the_transient_finality_lock() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("vote-lock");
    drop(
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap(),
    );
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let held_vote = FixedValidatorAnchoredVoteSafetyJournalV0::open(
        &layout.vote_journal,
        &layout.vote_anchor,
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.signing_key(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(_))
    ));
    drop(held_vote);
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Ok(FixedValidatorNodeStartupV0::Ready(_))
    ));
}

#[test]
fn incomplete_preparation_reopens_as_diagnostic_only() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let expected = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let session = scope.signing_session_mut();
            let effect = session.decide_prevote_without_proposal().unwrap();
            match session.prepare_vote(&round, effect).unwrap() {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(_)
                | FixedValidatorVotePrepareOutcomeV0::AlreadySigned(_)
                | FixedValidatorVotePrepareOutcomeV0::Halted(_) => {
                    panic!("the first vote must create one preparation")
                }
            }
        })
        .unwrap();
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), expected.position());
            assert_eq!(pending.role(), expected.role());
            assert_eq!(pending.target(), expected.target());
            assert_eq!(pending.state_id(), expected.state_id());
        }
        FixedValidatorNodeStartupV0::Ready(_)
        | FixedValidatorNodeStartupV0::FinalityStopped(_)
        | FixedValidatorNodeStartupV0::SignerStopped(_)
        | FixedValidatorNodeStartupV0::PendingProposal(_) => {
            panic!("an incomplete preparation must not publish a ready signer")
        }
    }
}

#[test]
fn selected_finality_suffix_catches_the_signer_up_in_height_order() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("height-recovery");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    drop(ready);
    let mut finality = fixture.open_finality(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(finality.head().unwrap(), &selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    assert!(matches!(
        finality.commit_verified(first).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(finality.head().unwrap(), &selected, ZfcAxiom::Union, 0);
    assert!(matches!(
        finality.commit_verified(second).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let selected_coordinate = finality.head().unwrap().coordinate();
    drop(finality);

    let before_rejected_catch_up = layout.images();
    let too_low = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let callback_ran = AtomicBool::new(false);
    assert!(matches!(
        too_low.run_with_signing_session(|_| {
            callback_ran.store(true, Ordering::Relaxed);
        }),
        Err(
            FixedValidatorNodeStartupErrorV0::SignerCatchUpHeightLimitExceeded {
                required: 2,
                maximum: 1,
            }
        )
    ));
    assert!(!callback_ran.load(Ordering::Relaxed));
    assert_eq!(layout.images(), before_rejected_catch_up);

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
        })
        .unwrap();
}

#[test]
fn anchored_finality_conflict_stops_the_signer_before_recovery() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("conflict-stop");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    drop(ready);
    let mut finality = fixture.open_finality(&layout);
    let selected = ArtifactChainState::new(fixture.definition);
    let left = fixture.transition(finality.head().unwrap(), &selected, ZfcAxiom::Pairing, 0);
    let right = fixture.transition(finality.head().unwrap(), &selected, ZfcAxiom::Union, 0);
    assert!(matches!(
        finality.commit_verified(left).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let expected_halt = match finality.commit_verified(right).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        | FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { .. } => {
            panic!("distinct finalized siblings must halt")
        }
    };
    drop(finality);

    let assert_stopped = |startup| match startup {
        FixedValidatorNodeStartupV0::FinalityStopped(stopped) => {
            assert_eq!(stopped.finality_halt(), expected_halt);
            assert_eq!(stopped.signer_stop().height(), expected_halt.height());
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                expected_halt.state_id()
            );
        }
        FixedValidatorNodeStartupV0::Ready(_)
        | FixedValidatorNodeStartupV0::SignerStopped(_)
        | FixedValidatorNodeStartupV0::PendingProposal(_)
        | FixedValidatorNodeStartupV0::PendingPreparation(_) => {
            panic!("halted finality must stop the signer before recovery")
        }
    };
    assert_stopped(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let after_first_stop = layout.images();
    assert_stopped(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    assert_eq!(layout.images(), after_first_stop);
}

#[test]
fn recovery_round_ceiling_rejects_before_issuing_the_session_latch() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("round-limit");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let session = scope.signing_session_mut();

            let prevote = session.decide_prevote_without_proposal().unwrap();
            let prepared = match session.prepare_vote(&round_zero, prevote).unwrap() {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("round-zero prevote must prepare"),
            };
            prepare_and_sign(session, &round_zero, prepared);

            let precommit = session.decide_precommit_without_quorum().unwrap();
            let prepared = match session.prepare_vote(&round_zero, precommit).unwrap() {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("round-zero precommit must prepare"),
            };
            prepare_and_sign(session, &round_zero, prepared);

            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            session.advance_round(&round_one).unwrap();
            let prevote = session.decide_prevote_without_proposal().unwrap();
            let prepared = match session.prepare_vote(&round_one, prevote).unwrap() {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("round-one prevote must prepare"),
            };
            prepare_and_sign(session, &round_one, prepared);
        })
        .unwrap();

    let before_low_ceiling = layout.images();
    let too_low = expect_ready(
        fixture
            .provision(&layout, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let callback_ran = AtomicBool::new(false);
    assert!(matches!(
        too_low.run_with_signing_session(|_| {
            callback_ran.store(true, Ordering::Relaxed);
        }),
        Err(FixedValidatorNodeStartupErrorV0::Vote(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                    required: 1,
                    maximum: 0,
                }
            )
    ));
    assert!(!callback_ran.load(Ordering::Relaxed));
    assert_eq!(layout.images(), before_low_ceiling);

    let admitted = expect_ready(
        fixture
            .provision(&layout, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    admitted
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position().round(),
                ConsensusRound::new(1)
            );
        })
        .unwrap();
}

#[test]
fn mismatched_context_and_limits_never_publish_ready_state() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("mismatch");
    drop(
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap(),
    );

    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_provision = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        wrong_context,
        &fixture.entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    );
    assert!(matches!(
        wrong_context_provision.open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(_))
    ));

    let wrong_limit = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(7).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    );
    assert!(matches!(
        wrong_limit.open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(_))
    ));

    let wrong_vote_limit = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(31).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    );
    assert!(matches!(
        wrong_vote_limit.open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(_))
    ));
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Ok(FixedValidatorNodeStartupV0::Ready(_))
    ));
}

#[test]
fn later_creation_failure_preserves_the_earlier_finality_pair() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("partial-create");
    fs::remove_dir(&layout.vote_journal).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).create(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(_))
    ));
    assert!(
        fs::read_dir(&layout.finality_journal)
            .unwrap()
            .next()
            .is_some()
    );
    assert!(
        fs::read_dir(&layout.finality_anchor)
            .unwrap()
            .next()
            .is_some()
    );
    assert!(fs::read_dir(&layout.vote_anchor).unwrap().next().is_none());
    let reopened_finality = fixture.open_finality(&layout);
    assert!(
        reopened_finality
            .head()
            .unwrap()
            .artifact_snapshot()
            .is_virtual_genesis()
    );
    drop(reopened_finality);
    assert!(matches!(
        fixture.provision(&layout, 8).create(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(_))
    ));
}

#[test]
fn public_scope_components_name_one_exact_recovered_branch() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("scope-parts");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let observed: (FixedConsensusBranchCoordinateV0, ConsensusPosition) = ready
        .run_with_signing_session(|mut scope| {
            let (finality, branch, session) = scope.parts();
            assert_eq!(finality.head().unwrap().coordinate(), branch.coordinate());
            (branch.coordinate(), session.position())
        })
        .unwrap();
    assert_eq!(observed.1.height().value(), 1);
    assert_eq!(observed.1.round().value(), 0);
    assert_eq!(observed.0.context(), fixture.context);
}

mod finality;
mod proposal_authoring;
mod proposal_buffer;
mod proposal_deferral;
mod round_progression;
mod voting;
