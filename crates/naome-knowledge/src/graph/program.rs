//! The same checked graph and canonical catalog own incremental programs.
use super::*;
use crate::{
    proof_work::{CheckedWork, Work},
    resources::adaptive::{self, Snapshot},
};
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Chunk, Manifest};
use std::time::Duration;

pub(crate) struct ProgramBudget {
    snapshot: Option<Snapshot>,
    next: Instant,
}
impl Default for ProgramBudget {
    fn default() -> Self {
        Self {
            snapshot: None,
            next: Instant::now(),
        }
    }
}
impl ProgramBudget {
    pub(crate) fn refresh(&mut self, directory: &Path) -> Result<&Snapshot, crate::Error> {
        if let Some(active) = adaptive::current() {
            self.snapshot = Some(active);
            return Ok(self.snapshot.as_ref().expect("active node budget"));
        }
        if Instant::now() >= self.next {
            let snapshot = Snapshot::derive(
                adaptive::load(directory)?,
                adaptive::sample(directory)?,
                crate::resources::limits().memory_bytes as u64,
            )?;
            self.snapshot = Some(snapshot);
            self.next = Instant::now() + Duration::from_secs(1);
        }
        Ok(self.snapshot.as_ref().expect("initial program budget"))
    }
}

/// Input is restored in bounded groups before mathematical evaluation starts.
/// No saved result or incoming manifest creates checked graph membership.
pub(crate) struct ProgramCheck {
    manifest: Manifest,
    work: Option<Work>,
    budget: ProgramBudget,
}
impl ProgramCheck {
    pub(crate) fn open(graph: &Graph, manifest: Manifest) -> Result<Self, crate::Error> {
        let directory = graph.store.directory().join(".program-work");
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err("program work directory must be a real directory".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory).map_err(crate::Error::from)?
            }
            Err(error) => return Err(error.into()),
        }
        let work = Work::open(&directory.join(format!(
            "{}.sqlite3",
            crate::hex(manifest.proof_id().as_bytes())
        )))?;
        Ok(Self {
            manifest,
            work: Some(work),
            budget: ProgramBudget::default(),
        })
    }
    pub(crate) fn restrict_cache(&mut self, bytes: u64) -> Result<(), crate::Error> {
        if let Some(work) = &mut self.work {
            work.restrict_cache(bytes)?;
        }
        Ok(())
    }
    pub(crate) fn advance(&mut self, graph: &Graph) -> Result<Option<CheckedWork>, crate::Error> {
        let snapshot = self.budget.refresh(graph.store.directory())?;
        let work = self.work.as_mut().ok_or("program check already consumed")?;
        work.record_budget(snapshot)?;
        if snapshot.budget.paused.is_some() {
            work.advance(&snapshot.budget)?;
            return Ok(None);
        }
        let status = work.status()?;
        if status.commands < self.manifest.commands {
            let progress = graph.store.program_progress(&self.manifest)?;
            if status.commands > progress.commands {
                return Err("work input exceeds canonical received prefix".into());
            }
            if status.commands < progress.commands {
                let chunk = graph.store.program_chunk(
                    &self.manifest,
                    status.commands,
                    snapshot.budget.batch_steps.clamp(1, CHUNK_RECORDS),
                    CHUNK_BYTES,
                )?;
                if status.program_hash != crate::hex(&chunk.previous) {
                    return Err("work input differs from canonical received prefix".into());
                }
                work.append_group(&chunk.records)?;
            }
            return Ok(None);
        }
        if status.commands != self.manifest.commands
            || status.program_hash != crate::hex(&self.manifest.program_hash)
        {
            return Err("work input differs from complete manifest".into());
        }
        let progress = work.advance(&snapshot.budget)?;
        if work.status()?.fully_checked {
            if !work.prepare_export(&snapshot.budget)? {
                return Ok(None);
            }
            let checked = self.work.take().expect("program work").into_checked()?;
            if checked.proof()?.manifest() != &self.manifest {
                return Err("mathematically checked program differs from manifest".into());
            }
            return Ok(Some(checked));
        }
        if !progress {
            return Err("program ended without a completely checked seal".into());
        }
        Ok(None)
    }
}

pub(crate) struct ProgramAdmission {
    prefix: Option<CheckedBatch>,
    cursor: naome_checker::ProgramRegistration,
    base: [u8; 32],
    storage: Arc<CheckedStorage>,
    epoch: u64,
}
impl ProgramAdmission {
    fn current(&self, graph: &Graph) -> Result<(), crate::Error> {
        if self.base != graph.context.snapshot_id()
            || !Arc::ptr_eq(&self.storage, &graph.checked_storage)
            || self.epoch != graph.cold(graph.checked_storage.copy_epoch())?
        {
            return Err(STALE_COMMIT);
        }
        Ok(())
    }
    pub(crate) fn advance(
        &mut self,
        graph: &Graph,
        proof: &CheckedWork,
        records: usize,
    ) -> Result<bool, crate::Error> {
        self.current(graph)?;
        if records == 0 {
            return Ok(false);
        }
        crate::resources::require_work_admission()?;
        let _disk = crate::resources::DiskLease::acquire(
            graph.store.directory(),
            (records as u64).saturating_mul(128 * 1024),
        )?;
        let source = self.storage.clone();
        let phase = source
            .admission_phase()
            .map_err(crate::Error::CorruptStorage)?;
        let result = self
            .cursor
            .advance(proof.proof()?, records)
            .map_err(crate::Error::from);
        let mut gates = graph.cold(phase.finish(graph.checked_storage.as_ref()))?;
        phase.discarded(&mut gates);
        result?;
        Ok(self.cursor.complete())
    }
    pub(crate) fn finish(
        self,
        graph: &Graph,
        proof: &CheckedWork,
    ) -> Result<CheckedBatch, crate::Error> {
        self.current(graph)?;
        let checked = proof.proof()?;
        let growth = program_context_bytes(checked)?;
        let context = self.cursor.finish().map_err(crate::Error::from)?;
        CheckedBatch::from_program(
            graph,
            context,
            crate::object::BinaryProof::from_program(checked)?,
            self.epoch,
            growth,
            self.prefix,
        )
    }
}

impl Graph {
    pub(crate) fn description(
        &self,
        id: ProofId,
    ) -> Result<Option<crate::object::ProofDescription>, crate::Error> {
        if !self.contains(id)? {
            return Ok(None);
        }
        match self.cold(self.store.program_manifest(id))? {
            Some(manifest) => self
                .describe_program(id, manifest)
                .map(crate::object::ProofDescription::Program)
                .map(Some),
            None => self
                .describe(id)
                .map(|metadata| metadata.map(crate::object::ProofDescription::Certificate)),
        }
    }

    pub(crate) fn transfer(
        &self,
        id: ProofId,
    ) -> Result<Option<crate::object::ProofTransfer>, crate::Error> {
        let Some(record) = self.binary_object(id)? else {
            return Ok(None);
        };
        match record.program()? {
            Some(manifest) => self
                .describe_program(id, manifest)
                .map(crate::object::ProofTransfer::Program)
                .map(Some),
            None => Ok(Some(crate::object::ProofTransfer::Certificate(
                record.envelope(),
            ))),
        }
    }

    fn describe_program(
        &self,
        id: ProofId,
        manifest: Manifest,
    ) -> Result<crate::object::ProgramMetadata, crate::Error> {
        let question = if self
            .context
            .proof_header(id)
            .map_err(crate::Error::from)?
            .is_some_and(|header| header.canonical_length() != usize::MAX)
        {
            match self.describe(id) {
                Ok(metadata) => metadata.map(|metadata| metadata.question),
                Err(error) if !error.fatal() => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        Ok(crate::object::ProgramMetadata { manifest, question })
    }
    pub(crate) fn program_manifest(&self, id: ProofId) -> Result<Option<Manifest>, crate::Error> {
        if !self.contains(id)? {
            return Ok(None);
        }
        self.cold(self.store.program_manifest(id))
    }
    pub(crate) fn program_chunk(
        &self,
        id: ProofId,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<Option<Chunk>, crate::Error> {
        let Some(manifest) = self.program_manifest(id)? else {
            return Ok(None);
        };
        self.cold(self.store.program_chunk(&manifest, start, records, maximum))
            .map(Some)
    }
    pub(crate) fn begin_program_admission(
        &self,
        proof: &CheckedWork,
    ) -> Result<ProgramAdmission, crate::Error> {
        self.begin_program_admission_after(proof, None)
    }
    pub(crate) fn begin_program_admission_after(
        &self,
        proof: &CheckedWork,
        prefix: Option<CheckedBatch>,
    ) -> Result<ProgramAdmission, crate::Error> {
        self.ensure_live()?;
        if let Some(prefix) = &prefix
            && !self.batch_current(prefix)?
        {
            return Err(STALE_COMMIT);
        }
        let context = prefix
            .as_ref()
            .map_or(&self.context, |prefix| &prefix.context);
        let cursor = context
            .begin_program_registration(proof.proof()?)
            .map_err(crate::Error::from)?;
        Ok(ProgramAdmission {
            cursor,
            prefix,
            base: self.context.snapshot_id(),
            storage: self.checked_storage.clone(),
            epoch: self.cold(self.checked_storage.copy_epoch())?,
        })
    }
    pub(super) fn replay_program(&mut self, manifest: &Manifest) -> Result<(), crate::Error> {
        let mut check = ProgramCheck::open(self, manifest.clone())?;
        let proof = loop {
            if let Some(proof) = check.advance(self)? {
                break proof;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut cursor = self
            .context
            .begin_program_registration(proof.proof()?)
            .map_err(crate::Error::from)?;
        let mut budget = ProgramBudget::default();
        while !cursor.complete() {
            let snapshot = budget.refresh(self.store.directory())?;
            if snapshot.budget.paused.is_some() {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            cursor
                .advance(proof.proof()?, snapshot.budget.batch_steps.max(1))
                .map_err(crate::Error::from)?;
        }
        self.context = cursor.finish().map_err(crate::Error::from)?;
        self.context_bytes = self
            .context_bytes
            .checked_add(program_context_bytes(proof.proof()?)?)
            .ok_or("checked context byte overflow")?;
        Ok(())
    }
}

fn program_context_bytes(
    proof: &naome_checker::program::CheckedProgram,
) -> Result<usize, crate::Error> {
    match proof.conclusion() {
        Some(formula) => Ok(formula
            .encode_canonical()
            .map_err(crate::Error::from)?
            .len()),
        None => usize::try_from(proof.node_count()?)
            .ok()
            .and_then(|n| n.checked_mul(128))
            .ok_or_else(|| "program formula graph width".into()),
    }
}
