use super::*;
use crate::model_exchange::{Bundle, Model, Registration};
use std::sync::Arc;

impl Disk {
    pub(in crate::jobs) fn solver_snapshot(&self, journal: &Journal) -> Result<Bundle, String> {
        let checkpoint = journal
            .learning
            .as_ref()
            .ok_or("native proof learning is disabled")?
            .exchange_model()
            .clone();
        let registration = Registration::new(Model::Solver { checkpoint });
        let memory = Bundle::reserve(&registration)?;
        let parts = registration
            .model
            .blobs()
            .map(|blob| {
                let mut bytes = Vec::with_capacity(blob.bytes);
                for index in 0..blob.chunks() {
                    let chunk = self
                        .checkpoint
                        .get_bytes("model", &blob.key(index), blob.chunk_len(index)?)?
                        .ok_or("selected solver model chunk missing")?;
                    if chunk.len() != blob.chunk_len(index)? {
                        return Err("selected solver chunk length differs".into());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(bytes)
            })
            .collect::<Result<_, String>>()?;
        Bundle::new(registration, parts, memory)
    }

    pub(in crate::jobs) fn select_solver(
        &mut self,
        journal: &mut Journal,
        expected: &str,
        candidate: Option<Arc<Bundle>>,
    ) -> Result<Registration, crate::Error> {
        let mut next = journal
            .learning
            .clone()
            .ok_or("native proof learning is disabled")?;
        let current = Registration::new(Model::Solver {
            checkpoint: next.exchange_model().clone(),
        });
        if current.id() != expected {
            return Err("selected solver changed since comparison".into());
        }
        let mut updates = Vec::new();
        let bytes = candidate.as_ref().map_or(0, |b| {
            b.registration.model.blobs().map(|p| p.bytes).sum::<usize>()
        });
        let _memory = crate::resources::MemoryLease::acquire(bytes)?;
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (bytes as u64).saturating_mul(4).saturating_add(512 * 1024),
        )?;
        if let Some(candidate) = candidate {
            candidate.registration.validate()?;
            let Model::Solver { checkpoint } = &candidate.registration.model else {
                return Err("solver adoption requires a solver checkpoint".into());
            };
            next.adopt_model(checkpoint.clone())?;
            let mut written = std::collections::BTreeSet::new();
            for blob in checkpoint.blobs() {
                if !written.insert(&blob.sha256) {
                    continue;
                }
                let data = candidate
                    .part(blob)
                    .ok_or("validated solver artifact missing")?;
                for (index, bytes) in data
                    .chunks(crate::resources::limits().native_model_chunk_bytes)
                    .enumerate()
                {
                    let key = blob.key(index);
                    if let Some(previous) = self.checkpoint.get_bytes("model", &key, bytes.len())? {
                        if previous != bytes {
                            return Err(crate::Error::CorruptStorage(
                                "immutable solver chunk differs".into(),
                            ));
                        }
                    } else {
                        updates.push(crate::checkpoint::Update::Put {
                            kind: "model",
                            key,
                            payload: bytes.to_vec(),
                        });
                    }
                }
            }
        } else {
            next.rollback_model()?;
        }
        updates.push(crate::checkpoint::Update::put(
            "learning",
            "current",
            &Some(&next),
        )?);
        self.update_model_refs(
            &mut updates,
            "global",
            next.retained_blobs().cloned().collect(),
        )?;
        self.checkpoint
            .commit(&journal.header(), updates)
            .map_err(crate::Error::from)?;
        let selection = Registration::new(Model::Solver {
            checkpoint: next.exchange_model().clone(),
        });
        journal.learning = Some(next);
        self.learning_hash = crate::learning::digest(&journal.learning);
        Ok(selection)
    }
}

/// Install one real, independently initialized native checkpoint for the
/// ordinary-process acceptance fixture. It only operates on a stopped, fresh
/// test node and uses the same paired checkpoint transaction as adoption.
#[cfg(all(feature = "developer-tools", feature = "system-tests"))]
pub(crate) fn model_fixture(
    directory: &std::path::Path,
    seed: u64,
    materialize: bool,
) -> Result<String, String> {
    use crate::learning::{ArtifactIo, Blob, Engine, model::Checkpoint};
    use std::{collections::BTreeMap, ops::Range};
    #[derive(Default)]
    struct Artifacts(BTreeMap<String, Vec<u8>>);

    impl ArtifactIo for Artifacts {
        fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
            let start = range.start * crate::resources::limits().native_model_chunk_bytes;
            let length = blob.range_len(&range)?;
            self.0
                .get(&blob.sha256)
                .and_then(|bytes| bytes.get(start..start + length))
                .map(<[u8]>::to_vec)
                .ok_or("fixture artifact missing".into())
        }

        fn write(
            &mut self,
            blob: &Blob,
            range: Range<usize>,
            bytes: Vec<u8>,
        ) -> Result<(), String> {
            let part = self.0.entry(blob.sha256.clone()).or_default();
            if part.len() != range.start * crate::resources::limits().native_model_chunk_bytes {
                return Err("fixture model chunk sequence differs".into());
            }
            part.extend(bytes);
            Ok(())
        }
    }

    let _graph = crate::Graph::open(directory).map_err(|e| e.to_string())?;
    let settings = Settings {
        native_proof_learning: true,
        ..Settings::default()
    }
    .validate()?;
    let (mut disk, mut journal) = Disk::open(directory, settings, 0)?;
    let original = disk.solver_snapshot(&journal)?;
    if original.registration.model
        != (Model::Solver {
            checkpoint: Checkpoint::fresh(),
        })
        || journal.next_id != 1
    {
        return Err("fixture requires a fresh stopped native node".into());
    }
    let mut checkpoint = Checkpoint {
        seed,
        ..Checkpoint::fresh()
    };
    let mut io = Artifacts::default();
    if materialize {
        let _memory = crate::resources::MemoryLease::acquire(
            crate::resources::limits().native_model_work_bytes,
        )
        .map_err(|e| e.to_string())?;
        checkpoint = Engine::default().snapshot(&checkpoint, &mut io)?;
    }
    let registration = Registration::new(Model::Solver { checkpoint });
    let memory = Bundle::reserve(&registration)?;
    let bytes = registration
        .model
        .blobs()
        .map(|blob| {
            io.0.remove(&blob.sha256)
                .ok_or("fixture model blob missing")
        })
        .collect::<Result<_, _>>()?;
    let candidate = Arc::new(Bundle::new(registration, bytes, memory)?);
    disk.select_solver(&mut journal, &original.registration.id(), Some(candidate))
        .map(|selected| selected.id())
        .map_err(|e| e.to_string())
}
