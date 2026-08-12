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
    fn new(id: ProofChainId, fault: Option<Fault>) -> Self {
        let prefix = journal_prefix(id);
        Self {
            volatile: Cursor::new(prefix.clone()),
            durable: prefix,
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
        if let Some(Fault::Write {
            phase: fault_phase,
            after,
        }) = self.fault.clone()
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
fn block_rejection_consumes_no_journal_io_or_fault() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let state = ProofChainState::new(id);
    let block = prepared_block(&state, &proof_ids);
    let stale = ProofBlock::new(
        ProofBlockId::from_bytes([0xaa; 32]),
        block.transition().clone(),
    );
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(ScriptedIo::new(id, Some(fault.clone())), id);
    let before = core.file.volatile.get_ref().clone();

    assert!(matches!(
        core.apply_block(
            &stale,
            vec![AddressedProofCandidate::new(
                ProofId::from_bytes([0x99; 32]),
                vec![0x00],
            )],
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch { .. }
        })
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault, Some(fault));
    assert_eq!(core.file.volatile.get_ref(), &before);
    assert_eq!(core.committed_end, JOURNAL_PREFIX_BYTES as u64);
    assert!(core.chain.proof_dag().is_empty());
    assert!(core.blocks.is_empty());
    assert!(core.ensure_healthy().is_ok());

    core.apply_block(&block, addressed_candidates(&payloads, &proof_ids))
        .unwrap_err();
    assert!(core.file.fault.is_none());
    assert!(matches!(
        core.ensure_healthy(),
        Err(ProofChainJournalError::Poisoned)
    ));
}

#[test]
fn append_barriers_are_ordered_and_every_ambiguous_failure_replays_old_or_new() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let block_bytes = block.to_canonical_bytes();
    let body_write_bytes = 4 + 2 + block_bytes.len() + 4 + payloads[0].len();
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
        let mut core = JournalCore::empty(ScriptedIo::new(id, Some(fault.clone())), id);
        assert!(
            matches!(
                core.apply_block(&block, addressed_candidates(&payloads, &proof_ids)),
                Err(ProofChainJournalError::Commit {
                    block_id,
                    proof_count: 1,
                    ..
                }) if block_id == block.id()
            ),
            "fault={fault:?}"
        );
        assert!(core.file.fault.is_none(), "fault={fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(ProofChainJournalError::Poisoned)
        ));
        assert!(core.blocks.is_empty(), "fault={fault:?}");

        let durable = core.file.durable.clone();
        let replay =
            JournalCore::replay(ScriptedIo::from_images(durable.clone(), durable), id, None)
                .unwrap();
        let expected_new = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        assert_eq!(
            replay.chain.proof_dag().len(),
            usize::from(expected_new),
            "fault={fault:?}"
        );
        assert_eq!(
            replay.chain.head_block_id(),
            if expected_new {
                block.id()
            } else {
                ProofChainState::new(id).head_block_id()
            },
            "fault={fault:?}"
        );
        assert_eq!(
            replay.blocks.get(&block.id()),
            expected_new.then_some(&block),
            "fault={fault:?}"
        );
    }
}

#[test]
fn successful_commit_streams_body_then_two_sync_barriers_then_footer() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(2);
    let block = one_block(id, &payloads, &proof_ids);
    let block_len = block.to_canonical_bytes().len();
    let mut core = JournalCore::empty(ScriptedIo::new(id, None), id);

    core.apply_block(&block, addressed_candidates(&payloads, &proof_ids))
        .unwrap();
    assert_eq!(
        core.file.trace,
        vec![
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, 2),
            Trace::Write(AppendPhase::Body, block_len),
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, payloads[0].len()),
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, payloads[1].len()),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, 32),
            Trace::Sync(AppendPhase::Commit),
        ]
    );
    assert_eq!(
        core.file.durable,
        journal_image(id, &[(block.clone(), payloads, proof_ids)])
    );
    assert_eq!(core.chain.head_block_id(), block.id());
    assert_eq!(core.blocks.get(&block.id()), Some(&block));
}

#[test]
fn replay_recovery_and_stabilization_fail_without_returning_a_handle() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let complete = journal_image(id, &[(block, payloads, proof_ids)]);

    let mut stabilization = ScriptedIo::from_images(complete.clone(), complete.clone());
    stabilization.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(stabilization, id, None),
        Err(ProofChainJournalError::Stabilize { .. })
    ));

    let incomplete = complete[..complete.len() - 1].to_vec();
    let mut truncation = ScriptedIo::from_images(incomplete.clone(), incomplete.clone());
    truncation.set_len_failure = true;
    assert!(matches!(
        JournalCore::replay(truncation, id, None),
        Err(ProofChainJournalError::Recovery { .. })
    ));

    let mut recovery_sync = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_sync.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(recovery_sync, id, None),
        Err(ProofChainJournalError::Recovery { .. })
    ));
}

#[test]
fn complete_bad_footer_is_not_recovered_but_incomplete_footer_is() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let complete = journal_image(id, &[(block, payloads, proof_ids)]);

    let incomplete = complete[..complete.len() - 1].to_vec();
    let recovered = JournalCore::replay(
        ScriptedIo::from_images(incomplete.clone(), incomplete),
        id,
        None,
    )
    .unwrap();
    assert!(recovered.chain.proof_dag().is_empty());
    assert!(recovered.blocks.is_empty());
    assert_eq!(recovered.file.durable, journal_prefix(id));

    let mut corrupt = complete.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(matches!(
        JournalCore::replay(ScriptedIo::from_images(corrupt.clone(), corrupt), id, None,),
        Err(ProofChainJournalError::BlockIdMismatch { entry: 0, .. })
    ));
}

#[test]
fn poisoned_public_handle_exposes_only_chain_context_and_keeps_lock() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = ProofDag::new()
        .apply_canonical_proof_bytes(payload.clone())
        .unwrap()
        .proof_id();
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let block = journal.prepare_block(vec![proof_id]).unwrap();
    journal
        .apply_block(
            &block,
            vec![AddressedProofCandidate::new(proof_id, payload.clone())],
        )
        .unwrap();
    let block_id = block.id();
    assert_eq!(journal.block(block_id).unwrap(), Some(&block));
    journal.core.poisoned = true;

    assert_eq!(journal.chain_id(), id);
    assert!(matches!(
        journal.block(block_id),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.head_block_id(),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.proof(proof_id),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.len(),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.is_empty(),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.proof_set_root(),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.proof_set_proof(proof_id),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.prepare_block(vec![proof_id]),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_block(
            &block,
            vec![AddressedProofCandidate::new(proof_id, payload)],
        ),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::Locked)
    ));
}
