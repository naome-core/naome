use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use crate::{AppendPhase, StoreIo};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    Seek,
    Write { phase: AppendPhase, after: usize },
    SyncBefore { phase: AppendPhase },
    SyncAfter { phase: AppendPhase },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Trace {
    Write(AppendPhase, usize),
    Sync(AppendPhase),
}

pub(crate) fn all_append_faults(body_bytes: usize, commit_bytes: usize) -> Vec<Fault> {
    let mut faults = vec![Fault::Seek];
    faults.extend((0..=body_bytes).map(|after| Fault::Write {
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
    faults.extend((0..=commit_bytes).map(|after| Fault::Write {
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
    faults
}

pub(crate) struct ScriptedIo {
    pub(crate) volatile: Cursor<Vec<u8>>,
    pub(crate) durable: Vec<u8>,
    fault: Option<Fault>,
    pub(crate) set_len_failure: bool,
    pub(crate) plain_sync_failure: bool,
    body_written: usize,
    commit_written: usize,
    pub(crate) trace: Vec<Trace>,
}

impl ScriptedIo {
    pub(crate) fn new(prefix: Vec<u8>, fault: Option<Fault>) -> Self {
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

    pub(crate) fn from_images(visible: Vec<u8>, durable: Vec<u8>) -> Self {
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

    pub(crate) fn fault(&self) -> Option<&Fault> {
        self.fault.as_ref()
    }

    fn phase_written(&mut self, phase: AppendPhase) -> &mut usize {
        match phase {
            AppendPhase::Body => &mut self.body_written,
            AppendPhase::Commit => &mut self.commit_written,
        }
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.volatile.read(bytes)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.volatile.write(bytes)
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

impl StoreIo for ScriptedIo {
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
