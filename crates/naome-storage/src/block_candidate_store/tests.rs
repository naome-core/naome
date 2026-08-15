use std::env;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use super::*;
use crate::ArtifactChainJournal;
use crate::fault_io::{Fault, ScriptedIo, Trace, all_append_faults};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-block-candidate-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn store_path(&self) -> PathBuf {
        self.path.join(STORE_FILE_NAME)
    }

    fn journal_path(&self) -> PathBuf {
        self.path.join("artifact-chain.journal")
    }

    fn write_image(&self, bytes: &[u8]) {
        fs::write(self.store_path(), bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn chain_definition(byte: u8) -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([byte; 32])
}

fn limits(max_entries: usize) -> ArtifactBlockCandidateStoreLimits {
    ArtifactBlockCandidateStoreLimits::new(max_entries).unwrap()
}

fn artifact_id(byte: u8) -> ArtifactId {
    ArtifactId::from_bytes([byte; ArtifactId::BYTE_LENGTH])
}

fn block(parent: u8, proof: u8) -> ArtifactBlock {
    ArtifactBlock::new(
        ArtifactBlockId::from_bytes([parent; ArtifactBlockId::BYTE_LENGTH]),
        ArtifactSetRoot::from_bytes([proof.wrapping_add(1); ArtifactSetRoot::BYTE_LENGTH]),
        ArtifactSetRoot::from_bytes([proof.wrapping_add(2); ArtifactSetRoot::BYTE_LENGTH]),
        artifact_id(proof),
    )
}

fn prefix(definition: ArtifactChainDefinition) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORE_PREFIX_BYTES as usize);
    bytes.extend_from_slice(STORE_HEADER);
    bytes.extend_from_slice(definition.id().as_bytes());
    bytes
}

fn encoded_entry(block: &ArtifactBlock) -> Vec<u8> {
    let canonical = block.to_canonical_bytes();
    let mut bytes = Vec::with_capacity(ENTRY_BYTES as usize);
    bytes.extend_from_slice(&canonical);
    bytes.extend_from_slice(block.id().as_bytes());
    bytes
}

fn image(definition: ArtifactChainDefinition, blocks: &[ArtifactBlock]) -> Vec<u8> {
    let mut bytes = prefix(definition);
    for block in blocks {
        bytes.extend_from_slice(&encoded_entry(block));
    }
    bytes
}

#[test]
fn limits_round_trip_idempotence_and_create_without_replacement_are_exact() {
    assert_eq!(
        ArtifactBlockCandidateStoreLimits::new(0),
        Err(ArtifactBlockCandidateStoreLimitsError::ZeroMaxEntries)
    );

    let chain_definition = chain_definition(0x11);
    let candidate = block(0x22, 0x33);
    let policy = limits(1);
    assert_eq!(policy.max_entries(), 1);

    let directory = TestDirectory::new("basics");
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, chain_definition, policy).unwrap();
    assert_eq!(store.chain_id(), chain_definition.id());
    assert_eq!(store.limits(), policy);
    assert!(store.is_empty().unwrap());
    assert!(
        store
            .get(ArtifactBlockId::from_bytes([0xff; 32]))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let committed = fs::read(directory.store_path()).unwrap();
    assert_eq!(store.get(candidate.id()).unwrap(), Some(candidate));
    assert!(store.contains(candidate.id()).unwrap());
    assert_eq!(store.len().unwrap(), 1);
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    assert!(matches!(
        ArtifactBlockCandidateStore::create(&directory.path, chain_definition, policy),
        Err(ArtifactBlockCandidateStoreError::Locked)
    ));
    drop(store);
    assert!(matches!(
        ArtifactBlockCandidateStore::create(&directory.path, chain_definition, policy),
        Err(ArtifactBlockCandidateStoreError::Create { .. })
    ));

    let mut reopened =
        ArtifactBlockCandidateStore::open(&directory.path, chain_definition, limits(2)).unwrap();
    assert_eq!(reopened.get(candidate.id()).unwrap(), Some(candidate));
    assert_eq!(reopened.len().unwrap(), 1);
}

#[test]
fn exact_format_golden_binds_chain_block_and_footer() {
    assert_eq!(STORE_HEADER, b"naome:artifact-block-candidate-store:v0\0");
    assert_eq!(ARTIFACT_BLOCK_BYTES, 128);
    assert_eq!(ENTRY_BYTES, 160);
    let definition = chain_definition(0x11);
    let candidate = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([
            0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc,
            0x97, 0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10,
            0x34, 0xc5, 0xf6, 0x2d,
        ]),
        ArtifactSetRoot::from_bytes([0x11; 32]),
        ArtifactSetRoot::from_bytes([0x22; 32]),
        artifact_id(0x33),
    );
    let expected_id = ArtifactBlockId::from_bytes([
        0xc7, 0x13, 0x2e, 0x96, 0x14, 0xc3, 0xf1, 0xbc, 0x96, 0x28, 0x86, 0x0e, 0xca, 0xf6, 0xb0,
        0x81, 0x8c, 0x49, 0x57, 0x30, 0x93, 0xe7, 0xea, 0x01, 0x5c, 0x1d, 0xe6, 0x61, 0xc9, 0x3e,
        0x24, 0x0e,
    ]);
    assert_eq!(candidate.id(), expected_id);

    let directory = TestDirectory::new("golden");
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, limits(1)).unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );

    let bytes = fs::read(directory.store_path()).unwrap();
    let mut expected = prefix(definition);
    expected.extend_from_slice(&candidate.to_canonical_bytes());
    expected.extend_from_slice(expected_id.as_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(
        bytes.len(),
        STORE_PREFIX_BYTES as usize + ARTIFACT_BLOCK_BYTES + ArtifactBlockId::BYTE_LENGTH
    );
}

#[test]
fn fixed_canonical_block_round_trips_and_reopens() {
    let definition = chain_definition(0x11);
    let candidate = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x22; ArtifactBlockId::BYTE_LENGTH]),
        ArtifactSetRoot::from_bytes([0x31; ArtifactSetRoot::BYTE_LENGTH]),
        ArtifactSetRoot::from_bytes([0x32; ArtifactSetRoot::BYTE_LENGTH]),
        artifact_id(0x40),
    );
    assert_eq!(candidate.to_canonical_bytes().len(), ARTIFACT_BLOCK_BYTES);

    let directory = TestDirectory::new("maximum-block");
    let policy = limits(1);
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, policy).unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    assert_eq!(store.get(candidate.id()).unwrap(), Some(candidate));
    drop(store);

    let mut reopened =
        ArtifactBlockCandidateStore::open(&directory.path, definition, policy).unwrap();
    assert_eq!(reopened.get(candidate.id()).unwrap(), Some(candidate));
}

#[test]
fn siblings_and_orphans_are_retained_without_touching_selected_state() {
    let definition = chain_definition(0x11);
    let directory = TestDirectory::new("structural-only");
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let selected_before = fs::read(directory.journal_path()).unwrap();
    let head_before = journal.head_block_id().unwrap();
    let root_before = journal.artifact_set_root().unwrap();
    let len_before = journal.len().unwrap();

    let sibling_a = block(0x42, 0x51);
    let sibling_b = block(0x42, 0x52);
    let orphan = block(0xee, 0x53);
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, limits(3)).unwrap();
    for candidate in [&sibling_a, &sibling_b, &orphan] {
        assert_eq!(
            store.insert(candidate).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
        assert_eq!(store.get(candidate.id()).unwrap(), Some(*candidate));
    }
    assert_eq!(store.len().unwrap(), 3);
    assert_eq!(journal.head_block_id().unwrap(), head_before);
    assert_eq!(journal.artifact_set_root().unwrap(), root_before);
    assert_eq!(journal.len().unwrap(), len_before);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_before);
    assert!(matches!(journal.block(sibling_a.id()), Ok(None)));
}

#[test]
fn wrong_chain_and_complete_corruption_precede_recovery_and_local_capacity() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let mut corrupt = image(definition, &[first, second]);
    *corrupt.last_mut().unwrap() ^= 0x01;
    corrupt.push(0xff);
    let directory = TestDirectory::new("precedence");
    directory.write_image(&corrupt);

    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, chain_definition(0x12), limits(1)),
        Err(ArtifactBlockCandidateStoreError::ChainIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), corrupt);
    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, definition, limits(1)),
        Err(ArtifactBlockCandidateStoreError::BlockIdMismatch { entry: 1, .. })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), corrupt);
}

#[test]
fn invalid_prefixes_and_reopen_entry_capacity_fail_without_mutation() {
    let definition = chain_definition(0x11);
    let exact_prefix = prefix(definition);
    for cut in 0..exact_prefix.len() {
        let directory = TestDirectory::new("short-prefix");
        directory.write_image(&exact_prefix[..cut]);
        assert!(matches!(
            ArtifactBlockCandidateStore::open(&directory.path, definition, limits(2)),
            Err(ArtifactBlockCandidateStoreError::InvalidHeader)
        ));
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            exact_prefix[..cut]
        );
    }

    let directory = TestDirectory::new("wrong-magic");
    let mut wrong_magic = exact_prefix.clone();
    wrong_magic[0] ^= 0x01;
    directory.write_image(&wrong_magic);
    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, definition, limits(2)),
        Err(ArtifactBlockCandidateStoreError::InvalidHeader)
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), wrong_magic);

    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let committed = image(definition, &[first, second]);
    let directory = TestDirectory::new("reopen-entry-limit");
    directory.write_image(&committed);
    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, definition, limits(1)),
        Err(ArtifactBlockCandidateStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1,
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
}

#[test]
fn mismatched_footers_and_duplicate_entries_fail_closed() {
    let definition = chain_definition(0x11);
    let candidate = block(0x21, 0x31);
    let canonical_len = candidate.to_canonical_bytes().len();
    let mut malformed = prefix(definition);
    malformed.extend_from_slice(&vec![0xff; canonical_len]);
    malformed.extend_from_slice(candidate.id().as_bytes());
    let directory = TestDirectory::new("invalid-block");
    directory.write_image(&malformed);
    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, definition, limits(2)),
        Err(ArtifactBlockCandidateStoreError::BlockIdMismatch { .. })
    ));

    let entry = encoded_entry(&candidate);
    let mut duplicate = prefix(definition);
    duplicate.extend_from_slice(&entry);
    duplicate.extend_from_slice(&entry);
    let directory = TestDirectory::new("duplicate");
    directory.write_image(&duplicate);
    assert!(matches!(
        ArtifactBlockCandidateStore::open(&directory.path, definition, limits(2)),
        Err(ArtifactBlockCandidateStoreError::DuplicateBlockId { entry: 1, .. })
    ));
}

#[test]
fn every_incomplete_append_cut_recovers_only_the_committed_prefix() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let committed = image(definition, std::slice::from_ref(&first));
    let second_entry = encoded_entry(&second);

    for cut in 0..second_entry.len() {
        let directory = TestDirectory::new("tail-cut");
        let mut visible = committed.clone();
        visible.extend_from_slice(&second_entry[..cut]);
        directory.write_image(&visible);
        let mut store =
            ArtifactBlockCandidateStore::open(&directory.path, definition, limits(2)).unwrap();
        assert_eq!(store.len().unwrap(), 1, "cut={cut}");
        assert_eq!(store.get(first.id()).unwrap(), Some(first), "cut={cut}");
        assert!(store.get(second.id()).unwrap().is_none(), "cut={cut}");
        drop(store);
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            committed,
            "cut={cut}"
        );
    }

    let first_entry = encoded_entry(&first);
    for cut in 0..first_entry.len() {
        let directory = TestDirectory::new("first-tail-cut");
        let mut visible = prefix(definition);
        visible.extend_from_slice(&first_entry[..cut]);
        directory.write_image(&visible);
        let store =
            ArtifactBlockCandidateStore::open(&directory.path, definition, limits(1)).unwrap();
        assert!(store.is_empty().unwrap(), "cut={cut}");
        drop(store);
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            prefix(definition)
        );
    }
}

#[test]
fn entry_limit_applies_after_validity_but_exact_duplicates_stay_idempotent() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let directory = TestDirectory::new("limits");
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, limits(1)).unwrap();
    assert_eq!(
        store.insert(&first).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let committed = fs::read(directory.store_path()).unwrap();
    assert_eq!(
        store.insert(&first).unwrap(),
        ArtifactBlockCandidateInsertOutcome::AlreadyPresent
    );
    assert!(matches!(
        store.insert(&second),
        Err(ArtifactBlockCandidateStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1,
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    drop(store);
}

#[test]
fn post_open_block_footer_and_truncation_changes_poison_the_handle() {
    let definition = chain_definition(0x11);
    let candidate = block(0x21, 0x31);
    let entry_offset = STORE_PREFIX_BYTES as usize;
    let block_offset = entry_offset;
    let footer_offset = block_offset + candidate.to_canonical_bytes().len();
    for (label, offset) in [("block", block_offset), ("footer", footer_offset)] {
        let directory = TestDirectory::new(label);
        let mut store =
            ArtifactBlockCandidateStore::create(&directory.path, definition, limits(1)).unwrap();
        assert_eq!(
            store.insert(&candidate).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
        let mut bytes = fs::read(directory.store_path()).unwrap();
        bytes[offset] ^= 0x01;
        fs::write(directory.store_path(), bytes).unwrap();
        assert!(matches!(
            store.get(candidate.id()),
            Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { .. })
                | Err(ArtifactBlockCandidateStoreError::Read { .. })
        ));
        assert_eq!(store.chain_id(), definition.id());
        assert!(matches!(
            store.len(),
            Err(ArtifactBlockCandidateStoreError::Poisoned)
        ));
    }

    let directory = TestDirectory::new("truncate");
    let mut store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, limits(1)).unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let file = OpenOptions::new()
        .write(true)
        .open(directory.store_path())
        .unwrap();
    file.set_len(STORE_PREFIX_BYTES + 4).unwrap();
    assert!(matches!(
        store.insert(&candidate),
        Err(ArtifactBlockCandidateStoreError::Read { .. })
    ));
    assert!(matches!(
        store.is_empty(),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
}

#[test]
fn new_insert_detects_post_open_truncation_and_extension_before_writing() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let policy = limits(2);

    for (label, extend) in [("new-insert-truncate", false), ("new-insert-extend", true)] {
        let directory = TestDirectory::new(label);
        let mut store =
            ArtifactBlockCandidateStore::create(&directory.path, definition, policy).unwrap();
        assert_eq!(
            store.insert(&first).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
        let expected = fs::read(directory.store_path()).unwrap();
        let expected_end = expected.len() as u64;
        let mutated = if extend {
            let mut bytes = expected;
            bytes.push(0xff);
            bytes
        } else {
            expected[..expected.len() - 1].to_vec()
        };
        fs::write(directory.store_path(), &mutated).unwrap();

        assert!(matches!(
            store.insert(&second),
            Err(ArtifactBlockCandidateStoreError::StoreLengthChanged {
                expected,
                actual,
            }) if expected == expected_end && actual == mutated.len() as u64
        ));
        assert_eq!(fs::read(directory.store_path()).unwrap(), mutated);
        assert!(matches!(
            store.contains(first.id()),
            Err(ArtifactBlockCandidateStoreError::Poisoned)
        ));
    }
}

fn scripted_io(definition: ArtifactChainDefinition, fault: Option<Fault>) -> ScriptedIo {
    ScriptedIo::new(prefix(definition), fault)
}

#[test]
fn append_barriers_and_every_ambiguous_failure_reopen_to_old_or_new() {
    let definition = chain_definition(0x11);
    let candidate = block(0x21, 0x31);
    let canonical_len = candidate.to_canonical_bytes().len();
    let policy = limits(1);
    let mut success = ArtifactBlockCandidateStoreCore::empty(
        scripted_io(definition, None),
        definition.id(),
        policy,
    );
    assert_eq!(
        success.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    assert_eq!(
        success.file.trace,
        [
            Trace::Write(AppendPhase::Body, canonical_len),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, BLOCK_ID_BYTES as usize),
            Trace::Sync(AppendPhase::Commit),
        ]
    );

    let body_bytes = canonical_len;
    let faults = all_append_faults(body_bytes, BLOCK_ID_BYTES as usize);

    for fault in faults {
        let mut core = ArtifactBlockCandidateStoreCore::empty(
            scripted_io(definition, Some(fault.clone())),
            definition.id(),
            policy,
        );
        assert!(
            matches!(
                core.insert(&candidate),
                Err(ArtifactBlockCandidateStoreError::Commit {
                    block_id,
                    block_bytes,
                    ..
                }) if block_id == candidate.id() && block_bytes == canonical_len
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert!(core.index.is_empty(), "fault={fault:?}");
        assert_eq!(core.committed_end, STORE_PREFIX_BYTES, "fault={fault:?}");

        let durable = core.file.durable.clone();
        let mut reopened = ArtifactBlockCandidateStoreCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            definition.id(),
            policy,
        )
        .unwrap();
        assert!(reopened.index.len() <= 1, "fault={fault:?}");
        if !reopened.index.is_empty() {
            assert_eq!(reopened.get(candidate.id()).unwrap(), Some(candidate));
        }
    }
}

#[test]
fn recovery_and_stabilization_failures_return_no_handle() {
    let definition = chain_definition(0x11);
    let mut incomplete = prefix(definition);
    incomplete.push(0xff);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        ArtifactBlockCandidateStoreCore::replay(recovery_io, definition.id(), limits(1)),
        Err(ArtifactBlockCandidateStoreError::Recovery {
            offset: STORE_PREFIX_BYTES,
            ..
        })
    ));

    let mut incomplete = prefix(definition);
    incomplete.push(0xff);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.plain_sync_failure = true;
    assert!(matches!(
        ArtifactBlockCandidateStoreCore::replay(recovery_io, definition.id(), limits(1)),
        Err(ArtifactBlockCandidateStoreError::Recovery { .. })
    ));

    let complete = prefix(definition);
    let mut stabilize_io = ScriptedIo::from_images(complete.clone(), complete);
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        ArtifactBlockCandidateStoreCore::replay(stabilize_io, definition.id(), limits(1)),
        Err(ArtifactBlockCandidateStoreError::Stabilize { .. })
    ));
}
