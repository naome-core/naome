//! Incremental consumption of a durable untrusted provider stream.
use super::*;
use crate::{
    graph::program::{ProgramAdmission, ProgramBudget},
    proof_work::{CheckedWork, Work},
};
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Command, command_hash};

pub(super) struct Generated {
    job: u64,
    units: u32,
    unit: u32,
    imported: u64,
    hash: [u8; 32],
    pending: Option<oneshot::Receiver<Result<Vec<Command>, String>>>,
    work: Option<Work>,
    checked: Option<CheckedWork>,
    admission: Option<ProgramAdmission>,
    budget: ProgramBudget,
}
impl Generated {
    pub(super) fn new(job: u64, units: u32) -> Self {
        Self {
            job,
            units,
            unit: 1,
            imported: 0,
            hash: [0; 32],
            pending: None,
            work: None,
            checked: None,
            admission: None,
            budget: ProgramBudget::default(),
        }
    }
    pub(super) fn restrict_cache(&mut self, graph: &Graph) -> Result<(), crate::Error> {
        let cache = self
            .budget
            .refresh(graph.ownership().directory())?
            .budget
            .cache_bytes;
        if let Some(work) = &mut self.work {
            work.restrict_cache(cache)?;
        }
        if let Some(proof) = &mut self.checked {
            proof.restrict_cache(cache)?;
        }
        Ok(())
    }
    pub(super) fn prepare(
        &mut self,
        graph: &Graph,
        client: &jobs::Client,
        question: &CompiledQuestion,
    ) -> Result<Option<(ProofId, crate::graph::CheckedBatch)>, crate::Error> {
        let snapshot = self.budget.refresh(graph.ownership().directory())?.clone();
        if snapshot.budget.paused.is_some() {
            return Ok(None);
        }
        if self.work.is_none() && self.checked.is_none() {
            let directory = graph.ownership().directory().join(".program-work");
            if let Ok(metadata) = std::fs::symlink_metadata(&directory)
                && (!metadata.is_dir() || metadata.file_type().is_symlink())
            {
                return Err("program work directory must be a real directory".into());
            }
            self.work = Some(Work::open(
                &directory.join(format!("candidate-{}.sqlite3", self.job)),
            )?);
        }
        if let Some(work) = self.work.as_mut() {
            work.record_budget(&snapshot)?;
            if self.unit <= self.units {
                if let Some(mut pending) = self.pending.take() {
                    match pending.try_recv() {
                        Ok(result) => {
                            let records = result?;
                            let before = self.imported;
                            for command in &records {
                                self.hash = command_hash(
                                    self.hash,
                                    &serde_json::to_vec(command).map_err(|e| e.to_string())?,
                                );
                                self.imported = self
                                    .imported
                                    .checked_add(1)
                                    .ok_or("program command address exhausted")?;
                            }
                            let status = work.status()?;
                            if status.commands == before {
                                work.append_group(&records)?;
                            } else if status.commands < self.imported {
                                return Err(
                                    "candidate checkpoint ends inside a provider group".into()
                                );
                            }
                            let status = work.status()?;
                            if status.commands == self.imported
                                && status.program_hash != crate::hex(&self.hash)
                            {
                                return Err(
                                    "candidate input differs from its retained provider stream"
                                        .into(),
                                );
                            }
                            self.unit = self
                                .unit
                                .checked_add(1)
                                .ok_or("provider unit address exhausted")?;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => self.pending = Some(pending),
                        Err(_) => return Err("provider candidate owner stopped".into()),
                    }
                } else {
                    self.pending = Some(client.program(self.job, self.unit)?);
                }
                return Ok(None);
            }
            let status = work.status()?;
            if status.commands != self.imported || status.program_hash != crate::hex(&self.hash) {
                return Err("candidate retained stream differs".into());
            }
            if !status.fully_checked {
                if !work.advance(&snapshot.budget)? && !work.status()?.fully_checked {
                    return Err("candidate has no completely checked seal".into());
                }
                return Ok(None);
            }
            if !work.prepare_export(&snapshot.budget)? {
                return Ok(None);
            }
            let checked = self.work.take().expect("candidate work").into_checked()?;
            question
                .classify_checked_program(checked.proof()?)
                .map_err(crate::Error::from)?;
            self.checked = Some(checked);
        }
        let checked = self.checked.as_ref().ok_or("checked candidate absent")?;
        let proof = checked.proof()?;
        let manifest = proof.manifest();
        let store = graph.ownership();
        let progress = store.start_program(manifest)?;
        if progress.commands < manifest.commands {
            let chunk = proof
                .input_chunk(
                    progress.commands,
                    snapshot.budget.batch_steps.clamp(1, CHUNK_RECORDS),
                    CHUNK_BYTES,
                )
                .map_err(crate::Error::from)?;
            store.append_program(manifest, &chunk)?;
            return Ok(None);
        }
        if self.admission.is_none() {
            self.admission = Some(graph.begin_program_admission(checked)?);
        }
        let admission = self.admission.as_mut().expect("candidate admission");
        match admission.advance(graph, checked, snapshot.budget.batch_steps.max(1)) {
            Ok(false) => Ok(None),
            Ok(true) => {
                let admission = self.admission.take().expect("candidate admission");
                Ok(Some((
                    manifest.proof_id(),
                    admission.finish(graph, checked)?,
                )))
            }
            Err(crate::Error::StaleAuthority) => {
                self.admission = Some(graph.begin_program_admission(checked)?);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_pressure_at_work_creation_retains_the_completed_provider_candidate() {
        const CASE: &str = "autonomous::program::tests::disk_pressure_at_work_creation_retains_the_completed_provider_candidate";
        if std::env::var_os("NAOME_PROGRAM_CREATION_CASE").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CASE, "--nocapture"])
                .env("NAOME_PROGRAM_CREATION_CASE", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let graph = Graph::default();
        let owner = jobs::tests::Manual::new();
        let question = CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
        let mut generated = Generated::new(17, 1);
        let path = graph
            .ownership()
            .directory()
            .join(".program-work/candidate-17.sqlite3");
        crate::resources::with_disk_available(0, || {
            let error = generated
                .prepare(&graph, &owner.client, &question)
                .err()
                .expect("work creation must defer");
            assert!(error.retryable());
            assert!(!path.exists());
        });
        assert_eq!((generated.job, generated.unit), (17, 1));
        assert!(
            generated
                .prepare(&graph, &owner.client, &question)
                .unwrap()
                .is_none()
        );
        assert!(path.exists() && generated.pending.is_some());
        assert_eq!((generated.job, generated.unit), (17, 1));
    }
}
