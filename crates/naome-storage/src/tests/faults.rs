use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fault {
    Seek,
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
    set_len_failure: bool,
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
            set_len_failure: false,
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
            set_len_failure: false,
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
        if self.fault == Some(Fault::Seek) {
            self.fault = None;
            return Err(io::Error::other("injected append seek failure"));
        }
        self.volatile.seek(position)
    }
}

impl JournalIo for ScriptedIo {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        if self.set_len_failure {
            self.set_len_failure = false;
            return Err(io::Error::other("injected recovery truncation failure"));
        }
        self.volatile.get_mut().truncate(size as usize);
        if self.volatile.position() > size {
            self.volatile.set_position(size);
        }
        Ok(())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        if self.plain_sync_failure {
            self.plain_sync_failure = false;
            return Err(io::Error::other("injected plain sync failure"));
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
fn late_address_mismatch_in_rooted_batch_consumes_no_journal_io_or_fault() {
    let (payloads, proof_ids) = dependency_chain();
    let requested_root = *proof_ids.last().unwrap();
    let wrong_id = ProofId::from_bytes([0xa7; 32]);
    let mut wrong_ids = proof_ids.clone();
    wrong_ids[1] = wrong_id;
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
    let volatile_before = core.file.volatile.get_ref().clone();
    let committed_end_before = core.committed_end;
    let chain_digest_before = core.chain_digest;

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &wrong_ids),
        ),
        Err(JournalError::BatchAdmission { source })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 1,
                    expected: Some(expected),
                    source: LedgerError::ProofIdMismatch { actual, .. },
                } if *expected == wrong_id && *actual == proof_ids[1]
            )
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault, Some(fault));
    assert_eq!(core.file.volatile.get_ref(), &volatile_before);
    assert_eq!(core.file.durable, JOURNAL_HEADER);
    assert_eq!(core.committed_end, committed_end_before);
    assert_eq!(core.chain_digest, chain_digest_before);
    assert!(core.ensure_healthy().is_ok());
    assert!(core.dag.is_empty());

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &proof_ids),
        ),
        Err(JournalError::Commit {
            root_proof_id,
            proof_count: 3,
            ..
        }) if root_proof_id == requested_root
    ));
    assert!(core.file.fault.is_none());
    assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
}

#[test]
fn oversized_rooted_batch_fails_before_secondary_allocation_or_journal_io() {
    let requested_root = ProofId::from_bytes([0xf0; 32]);
    let candidates = (0..=PROOF_BATCH_MAX_CANDIDATES)
        .map(|index| {
            let expected = if index == PROOF_BATCH_MAX_CANDIDATES {
                requested_root
            } else {
                ProofId::from_bytes([u8::try_from(index).unwrap(); 32])
            };
            AddressedProofCandidate::new(expected, Vec::new())
        })
        .collect();
    let mut core = JournalCore::empty(ScriptedIo::new(Some(Fault::Seek)));

    assert!(matches!(
        core.apply_rooted_canonical_proof_batch(requested_root, candidates),
        Err(JournalError::BatchAdmission { source })
            if matches!(
                source.as_ref(),
                ProofBatchError::TooManyCandidates {
                    actual,
                    maximum: PROOF_BATCH_MAX_CANDIDATES,
                } if *actual == PROOF_BATCH_MAX_CANDIDATES + 1
            )
    ));
    assert_eq!(core.file.fault, Some(Fault::Seek));
    assert!(core.file.trace.is_empty());
    assert!(core.dag.is_empty());
    assert!(core.ensure_healthy().is_ok());
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
        Err(JournalError::Commit { root_proof_id, .. }) if root_proof_id == actual
    ));
    assert!(core.file.fault.is_none());
    assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
}

#[test]
fn batch_append_barriers_are_ordered_and_every_ambiguous_failure_is_all_or_none() {
    let (payloads, proof_ids) = dependency_chain();
    let root_id = *proof_ids.last().unwrap();
    let body_write_bytes = 4
        + 1
        + payloads
            .iter()
            .map(|payload| 4 + payload.len())
            .sum::<usize>();
    let mut faults = vec![Fault::Seek];
    faults.extend((0..=body_write_bytes).map(|after| Fault::Write {
        phase: AppendPhase::Body,
        after,
    }));
    faults.extend([
        Fault::SyncBefore {
            phase: AppendPhase::Body,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Body,
        },
    ]);
    faults.extend((0..=32).map(|after| Fault::Write {
        phase: AppendPhase::Commit,
        after,
    }));
    faults.extend([
        Fault::SyncBefore {
            phase: AppendPhase::Commit,
        },
        Fault::SyncAfter {
            phase: AppendPhase::Commit,
        },
    ]);

    for fault in faults {
        let mut core = JournalCore::empty(ScriptedIo::new(Some(fault.clone())));
        assert!(
            matches!(
                core.apply_rooted_canonical_proof_batch(
                    root_id,
                    addressed_candidates(&payloads, &proof_ids),
                ),
                Err(JournalError::Commit {
                    root_proof_id,
                    proof_count: 3,
                    ..
                }) if root_proof_id == root_id
            ),
            "fault={fault:?}"
        );
        assert!(
            core.file.fault.is_none(),
            "fault was not consumed: {fault:?}"
        );
        assert!(matches!(core.ensure_healthy(), Err(JournalError::Poisoned)));
        assert!(matches!(
            core.apply_rooted_canonical_proof_batch(
                root_id,
                addressed_candidates(&payloads, &proof_ids),
            ),
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
                usize::from(expected_present) * payloads.len(),
                "fault={fault:?} image={name}"
            );
            for proof_id in &proof_ids {
                assert_eq!(
                    replayed.dag.proof(*proof_id).is_some(),
                    expected_present,
                    "fault={fault:?} image={name} proof_id={proof_id:?}"
                );
            }
            let expected_image = if expected_present {
                journal_transaction_image(std::slice::from_ref(&payloads))
            } else {
                JOURNAL_HEADER.to_vec()
            };
            assert_eq!(
                replayed.file.durable, expected_image,
                "fault={fault:?} image={name} was not stabilized"
            );

            let retry = replayed.apply_rooted_canonical_proof_batch(
                root_id,
                addressed_candidates(&payloads, &proof_ids),
            );
            if expected_present {
                assert!(matches!(
                    retry,
                    Err(JournalError::BatchAdmission { source })
                        if matches!(
                            source.as_ref(),
                            ProofBatchError::Candidate {
                                index: 0,
                                source: LedgerError::State {
                                    source: ProofStateError::DuplicateProof { .. }
                                },
                                ..
                            }
                        )
                ));
            } else {
                assert!(retry.is_ok(), "fault={fault:?} image={name}");
            }
        }
    }

    let mut success = JournalCore::empty(ScriptedIo::new(None));
    success
        .apply_rooted_canonical_proof_batch(root_id, addressed_candidates(&payloads, &proof_ids))
        .unwrap();
    let mut expected_trace = vec![
        Trace::Write(AppendPhase::Body, 4),
        Trace::Write(AppendPhase::Body, 1),
    ];
    for payload in &payloads {
        expected_trace.push(Trace::Write(AppendPhase::Body, 4));
        expected_trace.push(Trace::Write(AppendPhase::Body, payload.len()));
    }
    expected_trace.extend([
        Trace::Sync(AppendPhase::Body),
        Trace::Write(AppendPhase::Commit, 32),
        Trace::Sync(AppendPhase::Commit),
    ]);
    assert_eq!(success.file.trace, expected_trace);
    assert_eq!(success.file.durable, journal_transaction_image(&[payloads]));
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
fn incomplete_tail_truncation_failure_returns_recovery_error_and_no_handle() {
    let committed_end = JOURNAL_HEADER.len() as u64;
    let mut visible = JOURNAL_HEADER.to_vec();
    visible.push(0xaa);
    let mut file = ScriptedIo::from_images(visible, JOURNAL_HEADER.to_vec());
    file.set_len_failure = true;

    assert!(matches!(
        JournalCore::replay(file),
        Err(JournalError::Recovery { offset, .. }) if offset == committed_end
    ));
}

#[test]
fn incomplete_tail_sync_failure_returns_recovery_error_and_no_handle() {
    let committed_end = JOURNAL_HEADER.len() as u64;
    let mut visible = JOURNAL_HEADER.to_vec();
    visible.push(0xaa);
    let mut file = ScriptedIo::from_images(visible, JOURNAL_HEADER.to_vec());
    file.plain_sync_failure = true;

    assert!(matches!(
        JournalCore::replay(file),
        Err(JournalError::Recovery { offset, .. }) if offset == committed_end
    ));
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
            Err(JournalError::TransactionDigestMismatch { transaction: 0, .. })
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
