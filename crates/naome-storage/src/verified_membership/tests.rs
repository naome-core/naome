use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "naome-verified-membership-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("journal")).unwrap();
        fs::create_dir(root.join("anchor")).unwrap();
        Self(root)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal")
    }
    fn anchor(&self) -> PathBuf {
        self.0.join("anchor")
    }
    fn create(&self, id: u8) -> MembershipJournal {
        MembershipJournal::create(
            &self.journal(),
            &self.anchor(),
            genesis(),
            Some(keys(id)[0].clone()),
            limits(),
        )
        .unwrap()
    }
    fn open(&self, id: u8) -> Result<MembershipJournal, MembershipJournalError> {
        MembershipJournal::open(
            &self.journal(),
            &self.anchor(),
            genesis(),
            Some(keys(id)[0].clone()),
            limits(),
        )
    }
    fn recover(&self, id: u8) -> Result<MembershipJournal, MembershipJournalError> {
        MembershipJournal::recover_pair(
            &self.journal(),
            &self.anchor(),
            genesis(),
            Some(keys(id)[0].clone()),
            limits(),
        )
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn keys(id: u8) -> [SigningKey; 3] {
    std::array::from_fn(|role| {
        let mut bytes = [id; 32];
        bytes[0] = role as u8;
        SigningKey::from_bytes(&bytes)
    })
}
fn member(id: u8) -> Member {
    let keys = keys(id);
    Member {
        organization: [id; 32],
        consensus_key: keys[0].verifying_key().to_bytes(),
        approval_key: keys[1].verifying_key().to_bytes(),
        network_key: keys[2].verifying_key().to_bytes(),
    }
}
fn genesis() -> MembershipBranch {
    MembershipBranch::genesis(
        ArtifactChainState::new(ArtifactChainDefinition::new([61; 32])).branch_snapshot(),
        (1..=4).map(member).collect(),
    )
    .unwrap()
}
fn limits() -> MembershipJournalLimits {
    MembershipJournalLimits {
        maximum_round: 64,
        maximum_records: 1000,
        maximum_bytes: 100_000_000,
    }
}
fn timeout() -> MembershipMachineEvent {
    MembershipMachineEvent::Timeout {
        height: 1,
        round: 0,
        phase: MembershipPhase::Proposal,
    }
}

fn proof() -> MembershipFinalityProof {
    proof_with_axiom(ZfcAxiom::Pairing)
}
fn proof_with_axiom(axiom: ZfcAxiom) -> MembershipFinalityProof {
    let branch = genesis();
    let snapshot = branch.next_snapshot().unwrap();
    let applicant = keys(5);
    let request = MembershipRequest::join(
        snapshot,
        member(5),
        [&applicant[0], &applicant[1], &applicant[2]],
    )
    .unwrap();
    let approvals = (1..=3)
        .map(|id| MembershipApproval::sign(&request, snapshot, [id; 32], &keys(id)[1]).unwrap())
        .collect();
    let approved = ApprovedMembershipRequest::new(request, approvals, snapshot).unwrap();
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    let payload = ArtifactPayload::Proof(certificate).to_canonical_bytes();
    let id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let artifact = ArtifactChainState::new(ArtifactChainDefinition::new([61; 32]))
        .prepare_block(id)
        .unwrap();
    let value = branch.value(artifact, Some(approved)).unwrap();
    let signer = (1..=4)
        .map(keys)
        .find(|keys| keys[0].verifying_key().to_bytes() == branch.proposer(0, 64).unwrap())
        .unwrap();
    let coordinate = branch
        .vote_coordinate(0, MembershipVoteRole::Precommit, Some(value.root()))
        .unwrap();
    let votes: Vec<_> = (1..=3)
        .map(|id| MembershipVote::sign(coordinate, &keys(id)[0]))
        .collect();
    MembershipFinalityProof {
        proposal: MembershipProposal::sign(value, 0, None, &signer[0]),
        payload,
        certificate: MembershipCertificate::from_votes(&votes, snapshot).unwrap(),
    }
}

#[test]
fn only_verified_historical_conflict_anchors_a_terminal_stop() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    let selected = proof();
    journal
        .process(MembershipMachineEvent::Finality(selected.clone()))
        .unwrap();
    journal.observe_historical_finality(selected).unwrap();
    let conflict = proof_with_axiom(ZfcAxiom::Extensionality);
    let before = journal.state_id().unwrap();
    let mut invalid = conflict.clone();
    invalid.proposal.signature[0] ^= 1;
    assert!(journal.observe_historical_finality(invalid).is_err());
    assert_eq!(journal.state_id().unwrap(), before);
    assert_eq!(journal.machine().unwrap().branch().height(), 1);
    assert!(matches!(
        journal.observe_historical_finality(conflict),
        Err(MembershipJournalError::ConflictingFinality)
    ));
    assert!(matches!(
        journal.machine(),
        Err(MembershipJournalError::ConflictingFinality)
    ));
    assert!(matches!(
        journal.process(timeout()),
        Err(MembershipJournalError::ConflictingFinality)
    ));
    drop(journal);
    let journal = directory.open(1).unwrap();
    assert!(matches!(
        journal.machine(),
        Err(MembershipJournalError::ConflictingFinality)
    ));
    drop(journal);
    let journal = directory.recover(1).unwrap();
    assert!(matches!(
        journal.machine(),
        Err(MembershipJournalError::ConflictingFinality)
    ));
}

#[test]
fn terminal_conflict_suppresses_pending_signature_and_remains_replayable() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    journal
        .process(MembershipMachineEvent::Finality(proof()))
        .unwrap();
    let timeout = MembershipMachineEvent::Timeout {
        height: 2,
        round: 0,
        phase: MembershipPhase::Proposal,
    };
    journal
        .append(&records::event_body(&timeout, None))
        .unwrap();
    assert!(journal.has_pending_signature());
    drop(journal);
    let mut journal = directory.open(1).unwrap();
    assert!(journal.has_pending_signature());
    assert!(matches!(
        journal.observe_historical_finality(proof_with_axiom(ZfcAxiom::Extensionality)),
        Err(MembershipJournalError::ConflictingFinality)
    ));
    assert!(!journal.has_pending_signature());
    drop(journal);
    let mut journal = directory.recover(1).unwrap();
    assert!(matches!(
        journal.resume_prepared(),
        Err(MembershipJournalError::ConflictingFinality)
    ));
}

#[cfg(unix)]
#[test]
fn writable_membership_files_reject_symlinks_and_hardlinks() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    drop(directory.create(1));
    let journal = directory.journal().join(JOURNAL_NAME);
    let retained = directory.0.join("retained-journal");
    fs::rename(&journal, &retained).unwrap();
    let bytes = fs::read(&retained).unwrap();
    symlink(&retained, &journal).unwrap();
    assert!(directory.open(1).is_err());
    fs::remove_file(&journal).unwrap();
    fs::hard_link(&retained, &journal).unwrap();
    assert!(directory.recover(1).is_err());
    assert_eq!(fs::read(&retained).unwrap(), bytes);
}

#[test]
fn signed_bytes_and_lineage_survive_restart_and_duplicate_timeout_cannot_resign() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    assert!(matches!(
        directory.open(1),
        Err(MembershipJournalError::Locked)
    ));
    let publications = journal.process(timeout()).unwrap();
    assert_eq!(publications.len(), 1);
    let state = journal.state_id().unwrap();
    drop(journal);
    let mut journal = directory.open(1).unwrap();
    assert_eq!(journal.publications().unwrap(), publications);
    assert_eq!(journal.state_id().unwrap(), state);
    assert!(!journal.has_pending_signature());
    assert!(journal.process(timeout()).is_err());
    assert_eq!(journal.state_id().unwrap(), state);
    assert!(journal.resume_prepared().unwrap().is_empty());
}

#[test]
fn pending_intent_refuses_new_work_and_explicit_recovery_repeats_exact_bytes() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    let prepared = journal.machine.prepare(timeout()).unwrap();
    let expected = prepared.intents()[0].complete(&keys(1)[0]).unwrap();
    journal
        .append(&records::event_body(&timeout(), None))
        .unwrap();
    drop(journal);
    let mut journal = directory.open(1).unwrap();
    assert!(journal.has_pending_signature());
    assert!(matches!(
        journal.process(timeout()),
        Err(MembershipJournalError::PendingSignature)
    ));
    assert_eq!(journal.resume_prepared().unwrap(), vec![expected.clone()]);
    drop(journal);
    let journal = directory.open(1).unwrap();
    assert_eq!(journal.publications().unwrap(), vec![expected]);
}

#[test]
fn unadmitted_key_observes_without_signing_and_finality_replays_membership() {
    let directory = Directory::new();
    let mut journal = directory.create(5);
    assert!(!journal.machine().unwrap().is_active());
    assert!(journal.process(timeout()).unwrap().is_empty());
    let proof = proof();
    journal
        .process(MembershipMachineEvent::Finality(proof.clone()))
        .unwrap();
    let state = journal.state_id().unwrap();
    assert_eq!(
        journal
            .machine()
            .unwrap()
            .branch()
            .membership()
            .pending_activation(),
        Some(16385)
    );
    assert!(!journal.machine().unwrap().is_active());
    assert_eq!(journal.finalized_proof(1).unwrap(), Some(proof.clone()));
    drop(journal);
    let mut journal = directory.open(5).unwrap();
    assert_eq!(journal.state_id().unwrap(), state);
    assert_eq!(journal.machine().unwrap().branch().height(), 1);
    assert_eq!(journal.finalized_proof(1).unwrap(), Some(proof));
    assert!(journal.finalized_proof(2).unwrap().is_none());
}

#[test]
fn anchor_gaps_require_explicit_forward_recovery_and_never_allow_journal_rollback() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    let initial_end = journal.end;
    journal
        .append(&records::event_body(&timeout(), None))
        .unwrap();
    let expected = journal.state_id().unwrap();
    drop(journal);
    let anchor_path = directory.anchor().join(ANCHOR_NAME);
    let anchor = OpenOptions::new().write(true).open(&anchor_path).unwrap();
    anchor
        .set_len(anchor.metadata().unwrap().len() - 72)
        .unwrap();
    anchor.sync_all().unwrap();
    drop(anchor);
    assert!(matches!(
        directory.open(1),
        Err(MembershipJournalError::Anchor)
    ));
    let recovered = directory.recover(1).unwrap();
    assert_eq!(recovered.state_id().unwrap(), expected);
    assert!(recovered.has_pending_signature());
    drop(recovered);
    let file = OpenOptions::new()
        .write(true)
        .open(directory.journal().join(JOURNAL_NAME))
        .unwrap();
    file.set_len(initial_end).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(matches!(
        directory.recover(1),
        Err(MembershipJournalError::Anchor)
    ));
}

#[test]
fn torn_uncommitted_tail_recovers_but_committed_corruption_and_key_substitution_refuse() {
    let directory = Directory::new();
    let mut journal = directory.create(1);
    journal.process(timeout()).unwrap();
    let state = journal.state_id().unwrap();
    let end = journal.end;
    drop(journal);
    let path = directory.journal().join(JOURNAL_NAME);
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0, 0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let journal = directory.open(1).unwrap();
    assert_eq!(journal.state_id().unwrap(), state);
    assert_eq!(fs::metadata(&path).unwrap().len(), end);
    drop(journal);
    assert!(matches!(
        directory.open(2),
        Err(MembershipJournalError::Binding)
    ));
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        directory.open(1),
        Err(MembershipJournalError::Integrity)
    ));
    assert!(matches!(
        directory.recover(1),
        Err(MembershipJournalError::Integrity)
    ));
}

#[test]
fn proof_source_mutation_poisoning_prevents_serving_changed_bytes() {
    let directory = Directory::new();
    let mut journal = directory.create(5);
    journal
        .process(MembershipMachineEvent::Finality(proof()))
        .unwrap();
    let (offset, _, _) = journal.proofs[&1];
    let mut file = OpenOptions::new()
        .write(true)
        .open(directory.journal().join(JOURNAL_NAME))
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        journal.finalized_proof(1),
        Err(MembershipJournalError::Integrity)
    ));
    assert!(matches!(
        journal.machine(),
        Err(MembershipJournalError::Poisoned)
    ));
}
