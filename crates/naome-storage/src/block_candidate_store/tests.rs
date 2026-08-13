use std::env;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::{ProofBlock, ProofBlockId, ProofChainDefinition, ProofSetRoot, ProofTransition};
use naome_proof::ProofId;

use super::*;
use crate::ProofChainJournal;
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
        self.path.join("proof-chain.journal")
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

fn chain_definition(byte: u8) -> ProofChainDefinition {
    ProofChainDefinition::new([byte; 32])
}

fn limits(max_entries: usize, max_total_block_bytes: u64) -> ProofBlockCandidateStoreLimits {
    ProofBlockCandidateStoreLimits::new(max_entries, max_total_block_bytes).unwrap()
}

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; ProofId::BYTE_LENGTH])
}

fn block(parent: u8, proof: u8) -> ProofBlock {
    ProofBlock::new(
        ProofBlockId::from_bytes([parent; ProofBlockId::BYTE_LENGTH]),
        ProofTransition::new(
            ProofSetRoot::from_bytes([proof.wrapping_add(1); ProofSetRoot::BYTE_LENGTH]),
            ProofSetRoot::from_bytes([proof.wrapping_add(2); ProofSetRoot::BYTE_LENGTH]),
            vec![proof_id(proof)],
        )
        .unwrap(),
    )
}

fn prefix(definition: ProofChainDefinition) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORE_PREFIX_BYTES as usize);
    bytes.extend_from_slice(STORE_HEADER);
    bytes.extend_from_slice(definition.id().as_bytes());
    bytes
}

fn encoded_entry(block: &ProofBlock) -> Vec<u8> {
    let canonical = block.to_canonical_bytes();
    let mut bytes = Vec::with_capacity(ENTRY_FIXED_BYTES as usize + canonical.len());
    bytes.extend_from_slice(&u16::try_from(canonical.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&canonical);
    bytes.extend_from_slice(block.id().as_bytes());
    bytes
}

fn image(definition: ProofChainDefinition, blocks: &[ProofBlock]) -> Vec<u8> {
    let mut bytes = prefix(definition);
    for block in blocks {
        bytes.extend_from_slice(&encoded_entry(block));
    }
    bytes
}

#[test]
fn limits_round_trip_idempotence_and_create_without_replacement_are_exact() {
    assert_eq!(
        ProofBlockCandidateStoreLimits::new(0, 0),
        Err(ProofBlockCandidateStoreLimitsError::ZeroMaxEntries)
    );
    assert_eq!(
        ProofBlockCandidateStoreLimits::new(0, 1),
        Err(ProofBlockCandidateStoreLimitsError::ZeroMaxEntries)
    );
    assert_eq!(
        ProofBlockCandidateStoreLimits::new(1, 0),
        Err(ProofBlockCandidateStoreLimitsError::ZeroMaxTotalBlockBytes)
    );

    let chain_definition = chain_definition(0x11);
    let candidate = block(0x22, 0x33);
    let candidate_len = candidate.to_canonical_bytes().len() as u64;
    let policy = limits(1, candidate_len);
    assert_eq!(policy.max_entries(), 1);
    assert_eq!(policy.max_total_block_bytes(), candidate_len);

    let directory = TestDirectory::new("basics");
    let mut store =
        ProofBlockCandidateStore::create(&directory.path, chain_definition, policy).unwrap();
    assert_eq!(store.chain_id(), chain_definition.id());
    assert_eq!(store.limits(), policy);
    assert!(store.is_empty().unwrap());
    assert!(
        store
            .get(ProofBlockId::from_bytes([0xff; 32]))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let committed = fs::read(directory.store_path()).unwrap();
    assert_eq!(store.get(candidate.id()).unwrap(), Some(candidate.clone()));
    assert!(store.contains(candidate.id()).unwrap());
    assert_eq!(store.len().unwrap(), 1);
    assert_eq!(store.total_block_bytes().unwrap(), candidate_len);
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    assert!(matches!(
        ProofBlockCandidateStore::create(&directory.path, chain_definition, policy),
        Err(ProofBlockCandidateStoreError::Locked)
    ));
    drop(store);
    assert!(matches!(
        ProofBlockCandidateStore::create(&directory.path, chain_definition, policy),
        Err(ProofBlockCandidateStoreError::Create { .. })
    ));

    let mut reopened =
        ProofBlockCandidateStore::open(&directory.path, chain_definition, limits(2, 1_000))
            .unwrap();
    assert_eq!(reopened.get(candidate.id()).unwrap(), Some(candidate));
    assert_eq!(reopened.len().unwrap(), 1);
}

#[test]
fn exact_format_golden_binds_chain_block_and_footer() {
    let definition = chain_definition(0x11);
    let candidate = ProofBlock::new(
        ProofBlockId::from_bytes([
            0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc,
            0x97, 0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10,
            0x34, 0xc5, 0xf6, 0x2d,
        ]),
        ProofTransition::new(
            ProofSetRoot::from_bytes([0x11; 32]),
            ProofSetRoot::from_bytes([0x22; 32]),
            vec![proof_id(0x33), proof_id(0x44)],
        )
        .unwrap(),
    );
    let expected_id = ProofBlockId::from_bytes([
        0x47, 0x49, 0x83, 0xa0, 0x16, 0xeb, 0xf4, 0x66, 0x48, 0x8b, 0x63, 0x44, 0x85, 0xb9, 0xe6,
        0xe9, 0x3f, 0x16, 0x29, 0xbf, 0x3d, 0x0a, 0xfa, 0x5a, 0xfa, 0x56, 0x18, 0xf2, 0xe0, 0x4a,
        0x70, 0xf4,
    ]);
    assert_eq!(candidate.id(), expected_id);

    let directory = TestDirectory::new("golden");
    let mut store = ProofBlockCandidateStore::create(
        &directory.path,
        definition,
        limits(1, PROOF_BLOCK_MAX_BYTES as u64),
    )
    .unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );

    let bytes = fs::read(directory.store_path()).unwrap();
    let mut expected = prefix(definition);
    expected.extend_from_slice(&0x00a1_u16.to_be_bytes());
    expected.extend_from_slice(&candidate.to_canonical_bytes());
    expected.extend_from_slice(expected_id.as_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), 66 + 2 + 161 + 32);
}

#[test]
fn maximum_canonical_block_round_trips_and_reopens() {
    let definition = chain_definition(0x11);
    let candidate = ProofBlock::new(
        ProofBlockId::from_bytes([0x22; ProofBlockId::BYTE_LENGTH]),
        ProofTransition::new(
            ProofSetRoot::from_bytes([0x31; ProofSetRoot::BYTE_LENGTH]),
            ProofSetRoot::from_bytes([0x32; ProofSetRoot::BYTE_LENGTH]),
            (0_u8..8).map(|offset| proof_id(0x40 + offset)).collect(),
        )
        .unwrap(),
    );
    assert_eq!(candidate.to_canonical_bytes().len(), PROOF_BLOCK_MAX_BYTES);

    let directory = TestDirectory::new("maximum-block");
    let policy = limits(1, PROOF_BLOCK_MAX_BYTES as u64);
    let mut store = ProofBlockCandidateStore::create(&directory.path, definition, policy).unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    assert_eq!(
        store.total_block_bytes().unwrap(),
        PROOF_BLOCK_MAX_BYTES as u64
    );
    assert_eq!(store.get(candidate.id()).unwrap(), Some(candidate.clone()));
    drop(store);

    let mut reopened = ProofBlockCandidateStore::open(&directory.path, definition, policy).unwrap();
    assert_eq!(reopened.get(candidate.id()).unwrap(), Some(candidate));
    assert_eq!(
        reopened.total_block_bytes().unwrap(),
        PROOF_BLOCK_MAX_BYTES as u64
    );
}

#[test]
fn siblings_and_orphans_are_retained_without_touching_selected_state() {
    let definition = chain_definition(0x11);
    let directory = TestDirectory::new("structural-only");
    let journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let selected_before = fs::read(directory.journal_path()).unwrap();
    let head_before = journal.head_block_id().unwrap();
    let root_before = journal.proof_set_root().unwrap();
    let len_before = journal.len().unwrap();

    let sibling_a = block(0x42, 0x51);
    let sibling_b = block(0x42, 0x52);
    let orphan = block(0xee, 0x53);
    let mut store = ProofBlockCandidateStore::create(
        &directory.path,
        definition,
        limits(3, 3 * PROOF_BLOCK_MAX_BYTES as u64),
    )
    .unwrap();
    for candidate in [&sibling_a, &sibling_b, &orphan] {
        assert_eq!(
            store.insert(candidate).unwrap(),
            ProofBlockCandidateInsertOutcome::Inserted
        );
        assert_eq!(store.get(candidate.id()).unwrap(), Some(candidate.clone()));
    }
    assert_eq!(store.len().unwrap(), 3);
    assert_eq!(journal.head_block_id().unwrap(), head_before);
    assert_eq!(journal.proof_set_root().unwrap(), root_before);
    assert_eq!(journal.len().unwrap(), len_before);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_before);
    assert!(matches!(journal.block(sibling_a.id()), Ok(None)));
}

#[test]
fn wrong_chain_and_complete_corruption_precede_recovery_and_local_capacity() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let first_len = first.to_canonical_bytes().len() as u64;
    let mut corrupt = image(definition, &[first.clone(), second]);
    *corrupt.last_mut().unwrap() ^= 0x01;
    corrupt.push(0xff);
    let directory = TestDirectory::new("precedence");
    directory.write_image(&corrupt);

    assert!(matches!(
        ProofBlockCandidateStore::open(
            &directory.path,
            chain_definition(0x12),
            limits(1, first_len)
        ),
        Err(ProofBlockCandidateStoreError::ChainIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), corrupt);
    assert!(matches!(
        ProofBlockCandidateStore::open(&directory.path, definition, limits(1, first_len)),
        Err(ProofBlockCandidateStoreError::BlockIdMismatch { entry: 1, .. })
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
            ProofBlockCandidateStore::open(&directory.path, definition, limits(2, 1_000)),
            Err(ProofBlockCandidateStoreError::InvalidHeader)
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
        ProofBlockCandidateStore::open(&directory.path, definition, limits(2, 1_000)),
        Err(ProofBlockCandidateStoreError::InvalidHeader)
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), wrong_magic);

    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let committed = image(definition, &[first, second]);
    let directory = TestDirectory::new("reopen-entry-limit");
    directory.write_image(&committed);
    assert!(matches!(
        ProofBlockCandidateStore::open(&directory.path, definition, limits(1, 1_000)),
        Err(ProofBlockCandidateStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1,
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
}

#[test]
fn invalid_lengths_blocks_footers_and_duplicate_entries_fail_closed() {
    let definition = chain_definition(0x11);
    for actual in [0_u16, 1, 128, 354, u16::MAX] {
        let directory = TestDirectory::new("invalid-length");
        let mut bytes = prefix(definition);
        bytes.extend_from_slice(&actual.to_be_bytes());
        bytes.extend_from_slice(&[0xaa; 4]);
        directory.write_image(&bytes);
        assert!(matches!(
            ProofBlockCandidateStore::open(
                &directory.path,
                definition,
                limits(2, 1_000),
            ),
            Err(ProofBlockCandidateStoreError::InvalidBlockLength {
                actual: found,
                minimum: 129,
                maximum: 353,
                ..
            }) if found == actual
        ));
        assert_eq!(fs::read(directory.store_path()).unwrap(), bytes);
    }

    let candidate = block(0x21, 0x31);
    let canonical_len = candidate.to_canonical_bytes().len();
    let mut malformed = prefix(definition);
    malformed.extend_from_slice(&u16::try_from(canonical_len).unwrap().to_be_bytes());
    malformed.extend_from_slice(&vec![0xff; canonical_len]);
    malformed.extend_from_slice(candidate.id().as_bytes());
    let directory = TestDirectory::new("invalid-block");
    directory.write_image(&malformed);
    assert!(matches!(
        ProofBlockCandidateStore::open(&directory.path, definition, limits(2, 1_000)),
        Err(ProofBlockCandidateStoreError::InvalidBlock { .. })
    ));

    let entry = encoded_entry(&candidate);
    let mut duplicate = prefix(definition);
    duplicate.extend_from_slice(&entry);
    duplicate.extend_from_slice(&entry);
    let directory = TestDirectory::new("duplicate");
    directory.write_image(&duplicate);
    assert!(matches!(
        ProofBlockCandidateStore::open(&directory.path, definition, limits(2, 1_000)),
        Err(ProofBlockCandidateStoreError::DuplicateBlockId { entry: 1, .. })
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
        let mut store = ProofBlockCandidateStore::open(
            &directory.path,
            definition,
            limits(2, 2 * PROOF_BLOCK_MAX_BYTES as u64),
        )
        .unwrap();
        assert_eq!(store.len().unwrap(), 1, "cut={cut}");
        assert_eq!(
            store.get(first.id()).unwrap(),
            Some(first.clone()),
            "cut={cut}"
        );
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
        let store = ProofBlockCandidateStore::open(
            &directory.path,
            definition,
            limits(1, PROOF_BLOCK_MAX_BYTES as u64),
        )
        .unwrap();
        assert!(store.is_empty().unwrap(), "cut={cut}");
        drop(store);
        assert_eq!(
            fs::read(directory.store_path()).unwrap(),
            prefix(definition)
        );
    }
}

#[test]
fn entry_and_byte_limits_apply_after_validity_but_exact_duplicates_stay_idempotent() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let first_len = first.to_canonical_bytes().len() as u64;
    let directory = TestDirectory::new("limits");
    let mut store =
        ProofBlockCandidateStore::create(&directory.path, definition, limits(1, first_len))
            .unwrap();
    assert_eq!(
        store.insert(&first).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let committed = fs::read(directory.store_path()).unwrap();
    assert_eq!(
        store.insert(&first).unwrap(),
        ProofBlockCandidateInsertOutcome::AlreadyPresent
    );
    assert!(matches!(
        store.insert(&second),
        Err(ProofBlockCandidateStoreError::EntryLimitExceeded {
            actual: 2,
            maximum: 1,
        })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
    drop(store);

    assert!(matches!(
        ProofBlockCandidateStore::open(&directory.path, definition, limits(2, first_len - 1)),
        Err(ProofBlockCandidateStoreError::BlockByteLimitExceeded { .. })
    ));
    assert_eq!(fs::read(directory.store_path()).unwrap(), committed);
}

#[test]
fn post_open_length_block_footer_and_truncation_changes_poison_the_handle() {
    let definition = chain_definition(0x11);
    let candidate = block(0x21, 0x31);
    let entry_offset = STORE_PREFIX_BYTES as usize;
    let block_offset = entry_offset + BLOCK_LENGTH_BYTES as usize;
    let footer_offset = block_offset + candidate.to_canonical_bytes().len();
    for (label, offset) in [
        ("length", entry_offset),
        ("block", block_offset),
        ("footer", footer_offset),
    ] {
        let directory = TestDirectory::new(label);
        let mut store = ProofBlockCandidateStore::create(
            &directory.path,
            definition,
            limits(1, PROOF_BLOCK_MAX_BYTES as u64),
        )
        .unwrap();
        assert_eq!(
            store.insert(&candidate).unwrap(),
            ProofBlockCandidateInsertOutcome::Inserted
        );
        let mut bytes = fs::read(directory.store_path()).unwrap();
        bytes[offset] ^= 0x01;
        fs::write(directory.store_path(), bytes).unwrap();
        assert!(matches!(
            store.get(candidate.id()),
            Err(ProofBlockCandidateStoreError::StoredEntryChanged { .. })
                | Err(ProofBlockCandidateStoreError::Read { .. })
        ));
        assert_eq!(store.chain_id(), definition.id());
        assert!(matches!(
            store.len(),
            Err(ProofBlockCandidateStoreError::Poisoned)
        ));
    }

    let directory = TestDirectory::new("truncate");
    let mut store = ProofBlockCandidateStore::create(
        &directory.path,
        definition,
        limits(1, PROOF_BLOCK_MAX_BYTES as u64),
    )
    .unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let file = OpenOptions::new()
        .write(true)
        .open(directory.store_path())
        .unwrap();
    file.set_len(STORE_PREFIX_BYTES + 4).unwrap();
    assert!(matches!(
        store.insert(&candidate),
        Err(ProofBlockCandidateStoreError::Read { .. })
    ));
    assert!(matches!(
        store.is_empty(),
        Err(ProofBlockCandidateStoreError::Poisoned)
    ));
}

#[test]
fn new_insert_detects_post_open_truncation_and_extension_before_writing() {
    let definition = chain_definition(0x11);
    let first = block(0x21, 0x31);
    let second = block(0x22, 0x32);
    let policy = limits(2, 2 * PROOF_BLOCK_MAX_BYTES as u64);

    for (label, extend) in [("new-insert-truncate", false), ("new-insert-extend", true)] {
        let directory = TestDirectory::new(label);
        let mut store =
            ProofBlockCandidateStore::create(&directory.path, definition, policy).unwrap();
        assert_eq!(
            store.insert(&first).unwrap(),
            ProofBlockCandidateInsertOutcome::Inserted
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
            Err(ProofBlockCandidateStoreError::StoreLengthChanged {
                expected,
                actual,
            }) if expected == expected_end && actual == mutated.len() as u64
        ));
        assert_eq!(fs::read(directory.store_path()).unwrap(), mutated);
        assert!(matches!(
            store.contains(first.id()),
            Err(ProofBlockCandidateStoreError::Poisoned)
        ));
    }
}

fn scripted_io(definition: ProofChainDefinition, fault: Option<Fault>) -> ScriptedIo {
    ScriptedIo::new(prefix(definition), fault)
}

#[test]
fn append_barriers_and_every_ambiguous_failure_reopen_to_old_or_new() {
    let definition = chain_definition(0x11);
    let candidate = block(0x21, 0x31);
    let canonical_len = candidate.to_canonical_bytes().len();
    let policy = limits(1, canonical_len as u64);
    let mut success =
        ProofBlockCandidateStoreCore::empty(scripted_io(definition, None), definition.id(), policy);
    assert_eq!(
        success.insert(&candidate).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    assert_eq!(
        success.file.trace,
        [
            Trace::Write(AppendPhase::Body, BLOCK_LENGTH_BYTES as usize),
            Trace::Write(AppendPhase::Body, canonical_len),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, BLOCK_ID_BYTES as usize),
            Trace::Sync(AppendPhase::Commit),
        ]
    );

    let body_bytes = BLOCK_LENGTH_BYTES as usize + canonical_len;
    let faults = all_append_faults(body_bytes, BLOCK_ID_BYTES as usize);

    for fault in faults {
        let mut core = ProofBlockCandidateStoreCore::empty(
            scripted_io(definition, Some(fault.clone())),
            definition.id(),
            policy,
        );
        assert!(
            matches!(
                core.insert(&candidate),
                Err(ProofBlockCandidateStoreError::Commit {
                    block_id,
                    block_bytes,
                    ..
                }) if block_id == candidate.id() && block_bytes == canonical_len
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert!(core.index.is_empty(), "fault={fault:?}");
        assert_eq!(core.total_block_bytes, 0, "fault={fault:?}");
        assert_eq!(core.committed_end, STORE_PREFIX_BYTES, "fault={fault:?}");

        let durable = core.file.durable.clone();
        let mut reopened = ProofBlockCandidateStoreCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            definition.id(),
            policy,
        )
        .unwrap();
        assert!(reopened.index.len() <= 1, "fault={fault:?}");
        if reopened.index.is_empty() {
            assert_eq!(reopened.total_block_bytes, 0, "fault={fault:?}");
        } else {
            assert_eq!(reopened.total_block_bytes, canonical_len as u64);
            assert_eq!(
                reopened.get(candidate.id()).unwrap(),
                Some(candidate.clone())
            );
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
        ProofBlockCandidateStoreCore::replay(recovery_io, definition.id(), limits(1, 1_000)),
        Err(ProofBlockCandidateStoreError::Recovery {
            offset: STORE_PREFIX_BYTES,
            ..
        })
    ));

    let mut incomplete = prefix(definition);
    incomplete.push(0xff);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.plain_sync_failure = true;
    assert!(matches!(
        ProofBlockCandidateStoreCore::replay(recovery_io, definition.id(), limits(1, 1_000)),
        Err(ProofBlockCandidateStoreError::Recovery { .. })
    ));

    let complete = prefix(definition);
    let mut stabilize_io = ScriptedIo::from_images(complete.clone(), complete);
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        ProofBlockCandidateStoreCore::replay(stabilize_io, definition.id(), limits(1, 1_000)),
        Err(ProofBlockCandidateStoreError::Stabilize { .. })
    ));
}
