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
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
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
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        let result = write(&catalog);
        match (result, self.record_generation()) {
            (Err(primary @ crate::Error::UncertainDurability(_)), Err(_)) => Err(primary),
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
    pub(crate) fn program_manifest(
        &self,
        id: ArtifactId,
    ) -> Result<Option<Manifest>, crate::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_program_catalog_lock_keeps_its_machine_cause() {
        let directory = crate::checkpoint::tests::Directory::new();
        let store = Store::open(&directory.0).unwrap();
        std::thread::scope(|scope| {
            let _ = scope
                .spawn(|| {
                    let _guard = store.catalog.lock().unwrap();
                    panic!("poison test lock");
                })
                .join();
        });
        assert_eq!(
            store.read_program(|_| Ok(())),
            Err(crate::InputFault::CatalogLockPoisoned.into())
        );
        assert_eq!(
            store.update_program(|_| Ok(())),
            Err(crate::InputFault::CatalogLockPoisoned.into())
        );
    }
}
