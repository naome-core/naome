use std::env;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::{ProofDag, ProofSetMembership};
use naome_checker::{CheckError, ProofStateError};
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofCertificate, ProofId, ProofStep};

use super::{
    AppendPhase, ENTRY_DOMAIN, FRAME_FIXED_BYTES, GENESIS_DOMAIN, JOURNAL_FILE_NAME,
    JOURNAL_HEADER, JournalCore, JournalError, JournalIo, ProofDagJournal, entry_digest,
    genesis_digest,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("naome-storage-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.path.join(JOURNAL_FILE_NAME)
    }

    fn write_image(&self, bytes: &[u8]) {
        fs::write(self.journal_path(), bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    certificate(steps)
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec()
}

fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    canonical_bytes(vec![ProofStep::ZfcAxiom(axiom)])
}

fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn frame(previous: [u8; 32], payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let digest = entry_digest(previous, length, payload);
    let mut frame = Vec::with_capacity(FRAME_FIXED_BYTES as usize + payload.len());
    frame.extend_from_slice(&length);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&digest);
    (frame, digest)
}

fn journal_image(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut image = JOURNAL_HEADER.to_vec();
    let mut previous = genesis_digest();
    for payload in payloads {
        let (encoded, digest) = frame(previous, payload);
        image.extend_from_slice(&encoded);
        previous = digest;
    }
    image
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct RecordSnapshot {
    bytes: Vec<u8>,
    proof_id: ProofId,
    dependencies: Vec<ProofId>,
}

fn snapshot(record: &naome_ledger::AcceptedProofRecord) -> RecordSnapshot {
    RecordSnapshot {
        bytes: record.canonical_proof_bytes().to_vec(),
        proof_id: record.proof_id(),
        dependencies: record.direct_dependencies().to_vec(),
    }
}

#[test]
fn journal_header_and_entry_are_exact_golden_bytes() {
    assert_eq!(JOURNAL_HEADER.len(), 24);
    assert_eq!(GENESIS_DOMAIN.len(), 32);
    assert_eq!(ENTRY_DOMAIN.len(), 30);
    assert_eq!(
        genesis_digest().as_slice(),
        hex_bytes("e1712a2358d91e869a2c3d865deccd7fc4f3557a8c7327febc470becd78684ab")
    );

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    assert_eq!(pairing, hex_bytes("000000011001"));
    let (pairing_frame, digest) = frame(genesis_digest(), &pairing);
    assert_eq!(
        digest.as_slice(),
        hex_bytes("31d98be3372c21576e6ff70b6796e965924ec358746f1efdd22c2dad1345c73a")
    );
    assert_eq!(
        pairing_frame,
        hex_bytes(
            "0000000600000001100131d98be3372c21576e6ff70b6796e965924ec358746f1efdd22c2dad1345c73a"
        )
    );

    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap();
    drop(journal);
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        journal_image(&[pairing])
    );
}

#[test]
fn create_open_and_exclusive_lock_preserve_one_empty_journal() {
    let directory = TestDirectory::new();
    let journal = ProofDagJournal::create(&directory.path).unwrap();
    assert!(journal.is_empty().unwrap());
    assert_eq!(journal.len().unwrap(), 0);
    let empty_root = journal.proof_set_root().unwrap();
    let unknown = ProofId::from_bytes([0x55; 32]);
    assert_eq!(
        journal
            .proof_set_proof(unknown)
            .unwrap()
            .verify(empty_root, unknown),
        Ok(ProofSetMembership::Absent)
    );

    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.is_empty().unwrap());
    assert_eq!(reopened.proof_set_root().unwrap(), empty_root);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(reopened);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Create { .. })
    ));
}

#[test]
fn reopen_replays_dependency_chain_exactly() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root = snapshot(
        journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap(),
    );
    let child_bytes = referenced_generalization(root.proof_id, FreeVariable::new(0));
    let child = snapshot(
        journal
            .apply_canonical_proof_bytes(child_bytes.clone())
            .unwrap(),
    );
    let grandchild_bytes = referenced_generalization(child.proof_id, FreeVariable::new(1));
    let grandchild = snapshot(
        journal
            .apply_canonical_proof_bytes(grandchild_bytes.clone())
            .unwrap(),
    );
    assert_eq!(child.dependencies, [root.proof_id]);
    assert_eq!(grandchild.dependencies, [child.proof_id]);
    let expected_root = journal.proof_set_root().unwrap();
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(reopened.len().unwrap(), 3);
    assert_eq!(
        snapshot(reopened.proof(root.proof_id).unwrap().unwrap()),
        root
    );
    assert_eq!(
        snapshot(reopened.proof(child.proof_id).unwrap().unwrap()),
        child
    );
    assert_eq!(
        snapshot(reopened.proof(grandchild.proof_id).unwrap().unwrap()),
        grandchild
    );
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for proof_id in [root.proof_id, child.proof_id, grandchild.proof_id] {
        assert_eq!(
            reopened
                .proof_set_proof(proof_id)
                .unwrap()
                .verify(expected_root, proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn verified_open_checks_the_exact_replayed_set_after_all_format_checks() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap();
    let prefix_root = journal.proof_set_root().unwrap();
    let prefix_len = fs::metadata(directory.journal_path()).unwrap().len();
    let _ = journal
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap();
    let complete_root = journal.proof_set_root().unwrap();
    drop(journal);

    let verified = ProofDagJournal::open_verified(&directory.path, complete_root).unwrap();
    assert_eq!(verified.len().unwrap(), 2);
    drop(verified);

    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == prefix_root && actual == complete_root
    ));

    let mut corrupt = journal_image(&[root_bytes.clone(), union_bytes]);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    directory.write_image(&corrupt);
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::EntryDigestMismatch { .. })
    ));

    directory.write_image(&journal_image(&[root_bytes]));
    fs::OpenOptions::new()
        .write(true)
        .open(directory.journal_path())
        .unwrap()
        .set_len(prefix_len)
        .unwrap();
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, complete_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == complete_root && actual == prefix_root
    ));
}

#[test]
fn physical_journal_order_does_not_change_the_proof_set_root() {
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);

    let mut first = ProofDagJournal::create(&first_directory.path).unwrap();
    let _ = first.apply_canonical_proof_bytes(pairing.clone()).unwrap();
    let _ = first.apply_canonical_proof_bytes(union.clone()).unwrap();
    let first_root = first.proof_set_root().unwrap();
    drop(first);

    let mut second = ProofDagJournal::create(&second_directory.path).unwrap();
    let _ = second.apply_canonical_proof_bytes(union).unwrap();
    let _ = second.apply_canonical_proof_bytes(pairing).unwrap();
    let second_root = second.proof_set_root().unwrap();
    drop(second);

    assert_eq!(first_root, second_root);
    assert_ne!(
        fs::read(first_directory.journal_path()).unwrap(),
        fs::read(second_directory.journal_path()).unwrap()
    );
}

#[test]
fn rejected_admissions_write_nothing_and_leave_the_journal_healthy() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut union_control = ProofDag::new();
    let union_id = union_control
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap()
        .proof_id();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root_id = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let committed_len = fs::metadata(directory.journal_path()).unwrap().len();
    let committed_root = journal.proof_set_root().unwrap();
    let committed_image = fs::read(directory.journal_path()).unwrap();

    assert_ne!(root_id, union_id);
    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(union_bytes.clone(), root_id),
        Err(JournalError::Admission {
            source: LedgerError::ProofIdMismatch {
                expected,
                actual,
            },
        }) if expected == root_id && actual == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(union_id).unwrap().is_none());

    let locked_child = referenced_generalization(union_id, FreeVariable::new(1));
    assert!(matches!(
        journal.apply_canonical_proof_bytes(locked_child.clone()),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    assert!(matches!(
        journal.apply_canonical_proof_bytes(root_bytes),
        Err(JournalError::Admission {
            source: LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            }
        })
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    let missing_id = ProofId::from_bytes([0x55; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    assert!(matches!(
        journal.apply_canonical_proof_bytes(missing),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == missing_id
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(root_id).unwrap().is_some());

    let child = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = journal
        .apply_canonical_proof_bytes(child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(child_id).unwrap().is_some());

    let accepted_union = journal
        .apply_canonical_proof_bytes_with_expected_id(union_bytes, union_id)
        .unwrap();
    assert_eq!(accepted_union.proof_id(), union_id);
    let locked_child_id = journal
        .apply_canonical_proof_bytes(locked_child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(locked_child_id).unwrap().is_some());

    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(root_id).unwrap().is_some());
    assert!(reopened.proof(union_id).unwrap().is_some());
    assert!(reopened.proof(locked_child_id).unwrap().is_some());
}

#[test]
fn every_incomplete_final_frame_recovers_only_the_committed_prefix() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let full = journal_image(&[root_bytes.clone(), union_bytes.clone()]);
    let prefix = journal_image(std::slice::from_ref(&root_bytes));
    let (root_id, prefix_root) = {
        let directory = TestDirectory::new();
        let mut journal = ProofDagJournal::create(&directory.path).unwrap();
        let root_id = journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        (root_id, journal.proof_set_root().unwrap())
    };

    for cut in prefix.len()..full.len() {
        let directory = TestDirectory::new();
        directory.write_image(&full[..cut]);
        let mut recovered = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(recovered.len().unwrap(), 1, "cut={cut}");
        assert!(recovered.proof(root_id).unwrap().is_some(), "cut={cut}");
        assert_eq!(
            recovered.proof_set_root().unwrap(),
            prefix_root,
            "cut={cut}"
        );
        assert_eq!(
            fs::metadata(directory.journal_path()).unwrap().len(),
            prefix.len() as u64,
            "cut={cut}"
        );

        let child_bytes = referenced_generalization(root_id, FreeVariable::new(3));
        let child_id = recovered
            .apply_canonical_proof_bytes(child_bytes)
            .unwrap()
            .proof_id();
        drop(recovered);
        let reopened = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(reopened.len().unwrap(), 2, "cut={cut}");
        assert!(reopened.proof(child_id).unwrap().is_some(), "cut={cut}");
    }

    let directory = TestDirectory::new();
    directory.write_image(&full);
    assert_eq!(
        ProofDagJournal::open(&directory.path)
            .unwrap()
            .len()
            .unwrap(),
        2
    );
}

#[test]
fn complete_corruption_deletion_and_reordering_fail_closed() {
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let infinity = axiom_bytes(ZfcAxiom::Infinity);
    let (root_frame, root_digest) = frame(genesis_digest(), &root);
    let (union_frame, union_digest) = frame(root_digest, &union);
    let (infinity_frame, _) = frame(union_digest, &infinity);

    for index in 4..union_frame.len() {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&root_frame);
        let union_start = image.len();
        image.extend_from_slice(&union_frame);
        image.extend_from_slice(&infinity_frame);
        image[union_start + index] ^= 0x01;
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::EntryDigestMismatch { entry: 1, .. })
        ));
    }

    for frames in [
        vec![root_frame.clone(), infinity_frame.clone()],
        vec![
            root_frame.clone(),
            infinity_frame.clone(),
            union_frame.clone(),
        ],
        vec![
            root_frame.clone(),
            union_frame.clone(),
            union_frame.clone(),
            infinity_frame.clone(),
        ],
    ] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        for frame in frames {
            image.extend_from_slice(&frame);
        }
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::EntryDigestMismatch { .. })
        ));
    }

    let directory = TestDirectory::new();
    let mut bad_header = journal_image(&[root]);
    bad_header[0] ^= 1;
    directory.write_image(&bad_header);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::InvalidHeader)
    ));
}

#[test]
fn frame_lengths_are_preflighted_before_payload_allocation() {
    for actual in [0, CERTIFICATE_MAX_BYTES as u32 + 1, u32::MAX] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&actual.to_be_bytes());
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidFrameLength {
                entry: 0,
                actual: found,
                ..
            }) if found == actual
        ));
    }

    let directory = TestDirectory::new();
    let mut short_maximum = JOURNAL_HEADER.to_vec();
    short_maximum.extend_from_slice(&(CERTIFICATE_MAX_BYTES as u32).to_be_bytes());
    directory.write_image(&short_maximum);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert!(recovered.is_empty().unwrap());
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        JOURNAL_HEADER.len() as u64
    );
}

#[test]
fn committed_frames_are_strictly_revalidated_in_physical_order() {
    let malformed = vec![0x00];
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[malformed]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay {
            entry: 0,
            source: LedgerError::Decode { .. },
            ..
        })
    ));

    let noncanonical = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
    ])
    .to_canonical_bytes();
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[noncanonical]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay {
            entry: 0,
            source: LedgerError::NonCanonicalProof,
            ..
        })
    ));

    let missing_id = ProofId::from_bytes([0x77; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[missing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay {
            entry: 0,
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            },
            ..
        }) if proof_id == missing_id
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing.clone(), pairing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay {
            entry: 1,
            source: LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            },
            ..
        })
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = {
        let mut dag = ProofDag::new();
        dag.apply_canonical_proof_bytes(pairing.clone())
            .unwrap()
            .proof_id()
    };
    let alias = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: pairing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing, alias]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay {
            entry: 1,
            source: LedgerError::State {
                source: ProofStateError::DuplicateDerivation { .. }
            },
            ..
        })
    ));
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fault {
    Write { phase: AppendPhase, after: usize },
    SyncBefore { phase: AppendPhase },
    SyncAfter { phase: AppendPhase },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Trace {
    Write(AppendPhase, usize),
    Sync(AppendPhase),
}

struct ScriptedIo {
    volatile: Cursor<Vec<u8>>,
    durable: Vec<u8>,
    fault: Option<Fault>,
    plain_sync_failure: bool,
    body_written: usize,
    commit_written: usize,
    trace: Vec<Trace>,
}

impl ScriptedIo {
    fn new(fault: Option<Fault>) -> Self {
        Self {
            volatile: Cursor::new(JOURNAL_HEADER.to_vec()),
            durable: JOURNAL_HEADER.to_vec(),
            fault,
            plain_sync_failure: false,
            body_written: 0,
            commit_written: 0,
            trace: Vec::new(),
        }
    }

    fn from_images(visible: Vec<u8>, durable: Vec<u8>) -> Self {
        Self {
            volatile: Cursor::new(visible),
            durable,
            fault: None,
            plain_sync_failure: false,
            body_written: 0,
            commit_written: 0,
            trace: Vec::new(),
        }
    }

    fn phase_written(&mut self, phase: AppendPhase) -> &mut usize {
        match phase {
            AppendPhase::Body => &mut self.body_written,
            AppendPhase::Commit => &mut self.commit_written,
        }
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.volatile.read(buffer)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.volatile.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for ScriptedIo {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.volatile.seek(position)
    }
}

impl JournalIo for ScriptedIo {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.volatile.get_mut().truncate(size as usize);
        if self.volatile.position() > size {
            self.volatile.set_position(size);
        }
        Ok(())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        if self.plain_sync_failure {
            self.plain_sync_failure = false;
            return Err(io::Error::other("injected stabilization failure"));
        }
        self.durable = self.volatile.get_ref().clone();
        Ok(())
    }

    fn append_write_all(&mut self, phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.trace.push(Trace::Write(phase, bytes.len()));
        let fault = self.fault.clone();
        if let Some(Fault::Write {
            phase: fault_phase,
            after,
        }) = fault
            && fault_phase == phase
        {
            let written_before = *self.phase_written(phase);
            if after <= written_before + bytes.len() {
                let allowed = after.saturating_sub(written_before);
                self.volatile.write_all(&bytes[..allowed])?;
                *self.phase_written(phase) += allowed;
                self.fault = None;
                return Err(io::Error::other("injected append write failure"));
            }
        }

        self.volatile.write_all(bytes)?;
        *self.phase_written(phase) += bytes.len();
        Ok(())
    }

    fn append_sync_all(&mut self, phase: AppendPhase) -> io::Result<()> {
        self.trace.push(Trace::Sync(phase));
        match self.fault.clone() {
            Some(Fault::SyncBefore { phase: fault_phase }) if fault_phase == phase => {
                self.fault = None;
                Err(io::Error::other("injected pre-sync failure"))
            }
            Some(Fault::SyncAfter { phase: fault_phase }) if fault_phase == phase => {
                self.durable = self.volatile.get_ref().clone();
                self.fault = None;
                Err(io::Error::other("injected post-sync failure"))
            }
            _ => {
                self.durable = self.volatile.get_ref().clone();
                Ok(())
            }
        }
    }
}

#[test]
fn expected_proof_id_mismatch_consumes_no_journal_io_or_fault() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut control = ProofDag::new();
    let actual = control
        .apply_canonical_proof_bytes(payload.clone())
        .unwrap()
        .proof_id();
    let expected = ProofId::from_bytes([0x95; 32]);
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
    let volatile_before = core.file.volatile.get_ref().clone();
    let position_before = core.file.volatile.position();
    let committed_end_before = core.committed_end;
    let chain_digest_before = core.chain_digest;

    assert!(matches!(
        core.apply_canonical_proof_bytes_with_expected_id(payload.clone(), expected),
        Err(JournalError::Admission {
            source: LedgerError::ProofIdMismatch {
                expected: mismatch_expected,
                actual: mismatch_actual,
            },
        }) if mismatch_expected == expected && mismatch_actual == actual
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault, Some(fault));
    assert_eq!(core.file.volatile.get_ref(), &volatile_before);
    assert_eq!(core.file.volatile.position(), position_before);
    assert_eq!(core.file.durable, JOURNAL_HEADER);
    assert_eq!(core.committed_end, committed_end_before);
    assert_eq!(core.chain_digest, chain_digest_before);
    assert!(core.ensure_healthy().is_ok());
    assert!(core.dag.is_empty());

    assert!(matches!(
        core.apply_canonical_proof_bytes_with_expected_id(payload, actual),
        Err(JournalError::Commit { proof_id, .. }) if proof_id == actual
    ));
    assert!(core.file.fault.is_none());
    assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
}

#[test]
fn append_barriers_are_ordered_and_every_ambiguous_failure_poisons() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let body_len = 4 + payload.len();
    let faults = [
        Fault::Write {
            phase: AppendPhase::Body,
            after: 0,
        },
        Fault::Write {
            phase: AppendPhase::Body,
            after: 1,
        },
        Fault::Write {
            phase: AppendPhase::Body,
            after: body_len,
        },
        Fault::SyncBefore {
            phase: AppendPhase::Body,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Body,
        },
        Fault::Write {
            phase: AppendPhase::Commit,
            after: 0,
        },
        Fault::Write {
            phase: AppendPhase::Commit,
            after: 1,
        },
        Fault::Write {
            phase: AppendPhase::Commit,
            after: 31,
        },
        Fault::Write {
            phase: AppendPhase::Commit,
            after: 32,
        },
        Fault::SyncBefore {
            phase: AppendPhase::Commit,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Commit,
        },
    ];

    for fault in faults {
        let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
        assert!(
            matches!(
                core.apply_canonical_proof_bytes(payload.clone()),
                Err(JournalError::Commit { .. })
            ),
            "fault={fault:?}"
        );
        assert!(
            core.file.fault.is_none(),
            "fault was not consumed: {fault:?}"
        );
        assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
        assert!(matches!(
            core.apply_canonical_proof_bytes(payload.clone()),
            Err(JournalError::Poisoned)
        ));

        let durable = core.file.durable.clone();
        let visible = core.file.volatile.get_ref().clone();
        let durable_contains_proof = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let visible_contains_proof = matches!(
            fault,
            Fault::Write {
                phase: AppendPhase::Commit,
                after: 32..
            } | Fault::SyncBefore {
                phase: AppendPhase::Commit
            } | Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );

        for (name, image, expected_present) in [
            ("durable", durable.clone(), durable_contains_proof),
            ("visible", visible, visible_contains_proof),
        ] {
            let mut replayed =
                JournalCore::replay(ScriptedIo::from_images(image, durable.clone())).unwrap();
            assert_eq!(
                replayed.dag.len(),
                usize::from(expected_present),
                "fault={fault:?} image={name}"
            );
            let expected_image = if expected_present {
                journal_image(std::slice::from_ref(&payload))
            } else {
                JOURNAL_HEADER.to_vec()
            };
            assert_eq!(
                replayed.file.durable, expected_image,
                "fault={fault:?} image={name} was not stabilized"
            );

            let retry = replayed.apply_canonical_proof_bytes(payload.clone());
            if expected_present {
                assert!(matches!(
                    retry,
                    Err(JournalError::Admission {
                        source: LedgerError::State {
                            source: ProofStateError::DuplicateProof { .. }
                        }
                    })
                ));
            } else {
                assert!(retry.is_ok(), "fault={fault:?} image={name}");
            }
        }
    }

    let mut success = JournalCore::empty(ScriptedIo::new(None));
    let _ = success
        .apply_canonical_proof_bytes(payload.clone())
        .unwrap();
    assert_eq!(
        success.file.trace,
        [
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, payload.len()),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, 32),
            Trace::Sync(AppendPhase::Commit),
        ]
    );
    assert_eq!(success.file.durable, journal_image(&[payload]));
}

#[test]
fn replay_stabilization_failure_returns_no_handle() {
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let visible = journal_image(&[payload]);
    let mut file = ScriptedIo::from_images(visible, JOURNAL_HEADER.to_vec());
    file.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(file),
        Err(JournalError::Stabilize { .. })
    ));
}

#[test]
fn exclusive_lock_child_probe() {
    let Some(path) = env::var_os("NAOME_JOURNAL_LOCK_PROBE") else {
        return;
    };
    assert!(matches!(
        ProofDagJournal::open(PathBuf::from(path)),
        Err(JournalError::Locked)
    ));
    println!("NAOME_JOURNAL_LOCK_PROBE_OK");
}

#[test]
fn exclusive_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let journal = ProofDagJournal::create(&directory.path).unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::exclusive_lock_child_probe")
        .arg("--nocapture")
        .env("NAOME_JOURNAL_LOCK_PROBE", &directory.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NAOME_JOURNAL_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(journal);
    assert!(ProofDagJournal::open(&directory.path).is_ok());
}

#[test]
fn incomplete_header_and_existing_garbage_never_auto_initialize() {
    for prefix_len in 0..JOURNAL_HEADER.len() {
        let directory = TestDirectory::new();
        directory.write_image(&JOURNAL_HEADER[..prefix_len]);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidHeader)
        ));
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            JOURNAL_HEADER[..prefix_len]
        );
    }

    let directory = TestDirectory::new();
    directory.write_image(b"not a journal");
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Create { .. })
    ));
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        b"not a journal"
    );
}

#[test]
fn complete_footer_mutation_is_never_recovered_as_a_torn_tail() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let mut image = journal_image(&[pairing]);
    let footer_start = image.len() - 32;
    for index in footer_start..image.len() {
        let directory = TestDirectory::new();
        let mut corrupted = image.clone();
        corrupted[index] ^= 0x80;
        directory.write_image(&corrupted);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::EntryDigestMismatch { entry: 0, .. })
        ));
    }
    image.truncate(footer_start + 31);
    let directory = TestDirectory::new();
    directory.write_image(&image);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert!(recovered.is_empty().unwrap());
}

#[test]
fn in_range_length_damage_is_explicitly_treated_as_an_incomplete_suffix() {
    let directory = TestDirectory::new();
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let infinity = axiom_bytes(ZfcAxiom::Infinity);
    let prefix = journal_image(std::slice::from_ref(&root));
    let mut image = journal_image(&[root, union, infinity]);
    image[prefix.len()..prefix.len() + 4].copy_from_slice(&100_u32.to_be_bytes());
    directory.write_image(&image);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(recovered.len().unwrap(), 1);
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        prefix.len() as u64
    );
}

#[test]
fn poisoned_public_handle_hides_state_and_keeps_its_lock() {
    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let proof_id = journal
        .apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Pairing))
        .unwrap();
    let proof_id = proof_id.proof_id();
    journal.core.poisoned = true;

    assert!(matches!(
        journal.proof(proof_id),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(journal.len(), Err(JournalError::Poisoned)));
    assert!(matches!(journal.is_empty(), Err(JournalError::Poisoned)));
    assert!(matches!(
        journal.proof_set_root(),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.proof_set_proof(proof_id),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_canonical_proof_bytes(axiom_bytes(ZfcAxiom::Union)),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(
            axiom_bytes(ZfcAxiom::Union),
            ProofId::from_bytes([0x96; 32]),
        ),
        Err(JournalError::Poisoned)
    ));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Locked)
    ));

    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(proof_id).unwrap().is_some());
}
