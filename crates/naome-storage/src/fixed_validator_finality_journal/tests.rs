use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, ConsensusValueV0, OwnedVerifiedFixedConsensusTransitionV0,
    ProposalSigningRoot, VerifiedProducerAuthorizationV0,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
use crate::ArtifactChainJournal;
use crate::fault_io::{Fault, ScriptedIo, all_append_faults};

const AUTHORIZATION_BODY_BYTES: usize = 116;
const VOTE_BODY_BYTES: usize = 118;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-fixed-finality-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("temporary directory failed: {error}"),
            }
        }
    }

    fn journal(&self) -> PathBuf {
        self.0.join(JOURNAL_FILE_NAME)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn signing_key(index: u16) -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_be_bytes());
    seed[2] = 0xa5;
    SigningKey::from_bytes(&seed)
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

struct Fixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    proposer: SigningKey,
    entries: [ActiveAgreementEntry; 1],
    limit: FixedValidatorFinalityReplayLimitV0,
}

impl Fixture {
    fn new() -> Self {
        let definition = ArtifactChainDefinition::new([0x31; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x42; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let proposer = signing_key(1);
        let entries = [ActiveAgreementEntry::new(
            consensus_key(&proposer),
            AgreementWeight::new(1),
        )];
        Self {
            definition,
            context,
            proposer,
            entries,
            limit: FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        }
    }

    fn create(&self, directory: &TestDirectory) -> FixedValidatorFinalityJournalV0 {
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
        )
        .unwrap()
    }

    fn open(
        &self,
        directory: &TestDirectory,
        expected: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorFinalityJournalV0, FixedValidatorFinalityJournalErrorV0> {
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            self.definition,
            self.context,
            &self.entries,
            self.limit,
            expected,
        )
    }

    fn transition(
        &self,
        branch: &FixedConsensusBranchV0,
        selected: &mut ArtifactChainState,
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
        let bytes = envelope_bytes(value, cursor.position(), &self.proposer);
        cursor
            .decode_and_verify(&bytes, payload)
            .unwrap()
            .into_owned()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn finalizes_two_heights_and_reopens_exact_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("two-heights");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let expected_head = second.value().ancestry_id();
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(reopened.head().unwrap().ancestry_id(), expected_head);
}

#[test]
fn state_id_goldens_cover_genesis_and_two_steps() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("goldens");
    let mut journal = fixture.create(&directory);
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "9beeb687529f3dbd5e91b8ccc9aeca3ef8321b1c7a10601be4e5eb22d0f1fe53"
    );
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let block = first.value().artifact_block();
    let payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "f56cb626eb72a336f4cc19ef5cf7b84b2fc70252de39ed653302e3f64d683c5d"
    );
    selected.apply_block(&block, payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "63764e2271be86b357c4dcd56f997674950e99d7a3dc3a85d56e5ea105195940"
    );
}

#[test]
fn same_value_later_round_is_idempotent_without_write() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("same-value");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_envelope_id = first.envelope_id();
    let first_envelope = first.canonical_envelope_bytes().to_vec();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let variant = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let _ = journal.commit_verified(first).unwrap();
    let image = fs::read(directory.journal()).unwrap();
    let state = journal.state_id().unwrap();
    assert!(matches!(
        journal.commit_verified(variant).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
            retained_envelope_id,
            state_id,
            ..
        } if retained_envelope_id == first_envelope_id && state_id == state
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), image);
    let retained = journal
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(retained.envelope_id(), first_envelope_id);
    assert_eq!(retained.canonical_envelope_bytes(), first_envelope);
    assert_eq!(retained.canonical_artifact_bytes(), first_payload);
}

#[test]
fn conflicting_valid_sibling_durably_halts_and_denies_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("halt");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let conflict = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let denied_commit =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let _ = journal.commit_verified(first).unwrap();
    let pre_halt_image = fs::read(directory.journal()).unwrap();
    let halt = match journal.commit_verified(conflict).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert!(matches!(
        journal.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.parent_for_height(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finality_record(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finalized_len(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.commit_verified(denied_commit),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let state = journal.state_id().unwrap();
    let halt_image = fs::read(directory.journal()).unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert!(matches!(
        reopened.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    drop(reopened);

    let mut incomplete_after_halt = halt_image.clone();
    incomplete_after_halt.push(0);
    fs::write(directory.journal(), &incomplete_after_halt).unwrap();
    let recovered_halt = fixture.open(&directory, state).unwrap();
    assert_eq!(recovered_halt.halt().unwrap(), Some(halt));
    drop(recovered_halt);
    assert_eq!(fs::read(directory.journal()).unwrap(), halt_image);

    let mut complete_after_halt = halt_image.clone();
    complete_after_halt.extend_from_slice(&pre_halt_image[JOURNAL_PREFIX_BYTES..]);
    fs::write(directory.journal(), &complete_after_halt).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::RecordAfterHalt { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), complete_after_halt);

    fs::write(directory.journal(), &pre_halt_image).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn trusted_anchor_controls_incomplete_tail_recovery_and_suffix_rollback() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("anchor");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(first).unwrap();
    let committed = fs::read(directory.journal()).unwrap();
    let first_state = journal.state_id().unwrap();
    drop(journal);

    let cut = committed.len() - 7;
    fs::write(directory.journal(), &committed[..cut]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), &committed[..cut]);
    let recovered = fixture.open(&directory, genesis).unwrap();
    drop(recovered);
    assert_eq!(
        fs::read(directory.journal()).unwrap().len(),
        JOURNAL_PREFIX_BYTES
    );

    fs::write(directory.journal(), &committed).unwrap();
    assert!(matches!(
        fixture.open(&directory, genesis),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed);
    fs::write(directory.journal(), &committed[..JOURNAL_PREFIX_BYTES]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn mutation_duplicate_and_reorder_fail_closed() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("tamper");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let image = fs::read(directory.journal()).unwrap();
    let first_len = 4
        + u32::from_be_bytes(
            image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
                .try_into()
                .unwrap(),
        ) as usize
        + 32;
    let first = &image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + first_len];
    let second = &image[JOURNAL_PREFIX_BYTES + first_len..];
    for altered in [
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + 5] ^= 1;
            bytes
        },
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + first_len - 1] ^= 1;
            bytes
        },
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            first.to_vec(),
            first.to_vec(),
            second.to_vec(),
        ]
        .concat(),
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            second.to_vec(),
            first.to_vec(),
        ]
        .concat(),
    ] {
        fs::write(directory.journal(), &altered).unwrap();
        assert!(fixture.open(&directory, state).is_err());
        assert_eq!(fs::read(directory.journal()).unwrap(), altered);
    }
}

#[test]
fn recomputed_state_ids_cannot_authorize_invalid_tags_or_artifact_semantics() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("semantic-tamper");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    drop(journal);

    let image = fs::read(directory.journal()).unwrap();
    let body_length_bytes: [u8; 4] = image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
        .try_into()
        .unwrap();
    let body_length = u32::from_be_bytes(body_length_bytes) as usize;
    let body_start = JOURNAL_PREFIX_BYTES + 4;
    let body_end = body_start + body_length;

    let mut invalid_tag = image.clone();
    invalid_tag[body_start] = 3;
    let tag_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_tag[body_start..body_end],
    );
    invalid_tag[body_end..body_end + 32].copy_from_slice(tag_state.as_bytes());
    fs::write(directory.journal(), &invalid_tag).unwrap();
    assert!(matches!(
        fixture.open(&directory, tag_state),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_tag);

    let mut invalid_payload = image;
    invalid_payload[body_end - 1] ^= 1;
    let payload_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_payload[body_start..body_end],
    );
    invalid_payload[body_end..body_end + 32].copy_from_slice(payload_state.as_bytes());
    fs::write(directory.journal(), &invalid_payload).unwrap();
    assert!(matches!(
        fixture.open(&directory, payload_state),
        Err(FixedValidatorFinalityJournalErrorV0::Replay { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_payload);
}

#[test]
fn every_incomplete_first_entry_cut_obeys_the_trusted_anchor() {
    let fixture = Fixture::new();
    let source = TestDirectory::new("all-cuts-source");
    let mut journal = fixture.create(&source);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    let committed = fs::read(source.journal()).unwrap();
    let finalized = journal.state_id().unwrap();
    drop(journal);

    for cut in JOURNAL_PREFIX_BYTES + 1..committed.len() {
        let directory = TestDirectory::new("all-cuts");
        fs::write(directory.journal(), &committed[..cut]).unwrap();
        assert!(
            matches!(
                fixture.open(&directory, finalized),
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ),
            "cut={cut}"
        );
        assert_eq!(
            fs::read(directory.journal()).unwrap(),
            &committed[..cut],
            "cut={cut}"
        );
        let recovered = fixture.open(&directory, genesis).unwrap();
        assert_eq!(recovered.finalized_len().unwrap(), 0, "cut={cut}");
        drop(recovered);
        assert_eq!(
            fs::read(directory.journal()).unwrap().len(),
            JOURNAL_PREFIX_BYTES,
            "cut={cut}"
        );
    }
}

#[test]
fn max_round_is_header_bound_and_shared_namespace_rejects_old_format() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("namespace");
    let old = ArtifactChainJournal::create(&directory.0, fixture.definition).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            fixture.limit,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Locked)
    ));
    drop(old);
    assert!(matches!(
        fixture.open(
            &directory,
            FixedValidatorFinalityJournalStateIdV0::from_bytes([0; 32]),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidHeader)
            | Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));

    fs::remove_file(directory.journal()).unwrap();
    let journal = fixture.create(&directory);
    let state = journal.state_id().unwrap();
    drop(journal);
    let other_limit = FixedValidatorFinalityReplayLimitV0::new(9).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            other_limit,
            state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));
}

#[test]
fn round_limit_accepts_maximum_and_rejects_max_plus_one_before_io_and_replay() {
    assert_eq!(
        FixedValidatorFinalityReplayLimitV0::new(0),
        Err(FixedValidatorFinalityReplayLimitErrorV0)
    );
    let fixture = Fixture::new();
    let directory = TestDirectory::new("round-limit");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let at_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        fixture.limit.max_round(),
    );
    let above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    let replay_above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    assert!(matches!(
        journal.commit_verified(at_limit).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let committed_image = fs::read(directory.journal()).unwrap();
    assert!(matches!(
        journal.commit_verified(above_limit),
        Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
            round,
            maximum,
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed_image);
    drop(journal);

    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);
    let body = canonical_record_body(FINALIZE_RECORD, &replay_above_limit, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let state = step_state_id(genesis, body_length_bytes, &body);
    let mut image = prefix.clone();
    image.extend_from_slice(&body_length_bytes);
    image.extend_from_slice(&body);
    image.extend_from_slice(state.as_bytes());
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(image.clone(), image),
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ReplayRoundLimitExceeded {
            round,
            maximum,
            ..
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
}

#[test]
fn every_append_fault_poisons_and_never_publishes_memory_state() {
    let fixture = Fixture::new();
    let genesis_branch =
        fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        genesis_branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis_id = genesis_state_id(&prefix);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let probe = fixture.transition(&genesis_branch, &mut selected, ZfcAxiom::Pairing, 0);
    let body = canonical_record_body(FINALIZE_RECORD, &probe, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let proposed_state = step_state_id(genesis_id, body_length_bytes, &body);

    for fault in all_append_faults(
        RECORD_LENGTH_BYTES as usize + body.len(),
        STATE_ID_BYTES as usize,
    ) {
        let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = FixedValidatorFinalityJournalCore::empty(
            io,
            fixture.context,
            fixture.limit,
            vec![branch],
            genesis_id,
        );
        let mut selected = ArtifactChainState::new(fixture.definition);
        let transition = fixture.transition(
            core.branches.last().unwrap(),
            &mut selected,
            ZfcAxiom::Pairing,
            0,
        );
        assert!(
            matches!(
                core.commit_verified(transition),
                Err(FixedValidatorFinalityJournalErrorV0::Commit { .. })
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert_eq!(core.state_id, genesis_id, "fault={fault:?}");
        assert_eq!(core.records.len(), 0, "fault={fault:?}");
        assert_eq!(core.branches.len(), 1, "fault={fault:?}");
        assert!(
            matches!(
                core.ensure_operational(),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );

        let durable = core.file.durable.clone();
        let durable_commit = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let old_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable.clone()),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            genesis_id,
        );
        if durable_commit {
            assert!(matches!(
                old_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        } else {
            assert_eq!(old_anchor.unwrap().state_id, genesis_id);
        }

        let new_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            proposed_state,
        );
        if durable_commit {
            assert_eq!(new_anchor.unwrap().state_id, proposed_state);
        } else {
            assert!(matches!(
                new_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        }
    }
}

#[test]
fn replay_recovery_and_stabilization_io_fail_closed() {
    let fixture = Fixture::new();
    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);

    let mut incomplete = prefix.clone();
    incomplete.push(0);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            recovery_io,
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![branch.clone()],
            genesis,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Recovery { .. })
    ));

    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix.clone());
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            stabilize_io,
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            genesis,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Stabilize { .. })
    ));
}
