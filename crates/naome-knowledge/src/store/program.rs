use super::*;
use naome_proof::program::{Chunk, Manifest};

impl Store {
    fn read_program<R>(
        &self,
        read: impl FnOnce(&Catalog) -> Result<R, crate::Error>,
    ) -> Result<R, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        self.ensure_database()?;
        read(&catalog)
    }
    fn update_program<R>(
        &self,
        write: impl FnOnce(&Catalog) -> Result<R, crate::Error>,
    ) -> Result<R, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        self.ensure_database()?;
        let result = write(&catalog);
        match (result, self.record_generation()) {
            (Err(primary), Err(generation)) => Err(crate::Error::UncertainDurability(format!(
                "{primary}; generation observation failed: {generation}"
            ))),
            (_, Err(generation)) => Err(generation),
            (result, Ok(())) => result,
        }
    }
    pub(crate) fn start_program(
        &self,
        manifest: &Manifest,
    ) -> Result<ProgramProgress, crate::Error> {
        self.update_program(|catalog| catalog.start_program(manifest))
    }
    pub(crate) fn program_manifest(&self, id: ProofId) -> Result<Option<Manifest>, crate::Error> {
        self.read_program(|catalog| catalog.program_manifest(id))
    }
    pub(crate) fn program_progress(
        &self,
        manifest: &Manifest,
    ) -> Result<ProgramProgress, crate::Error> {
        self.read_program(|catalog| catalog.program_progress(manifest))
    }
    pub(crate) fn append_program(
        &self,
        manifest: &Manifest,
        chunk: &Chunk,
    ) -> Result<ProgramProgress, crate::Error> {
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (chunk.records.len() as u64).saturating_mul(8192),
        )?;
        self.update_program(|catalog| catalog.append_program(manifest, chunk))
    }
    pub(crate) fn program_chunk(
        &self,
        manifest: &Manifest,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<Chunk, crate::Error> {
        self.read_program(|catalog| catalog.program_chunk(manifest, start, records, maximum))
    }
}
