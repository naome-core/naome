//! Incremental consumption of a durable untrusted provider stream.
use super::*;
use crate::{
    graph::program::{PreparedProgram, ProgramBudget},
    proof_work::Work,
};
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Command, Prefix};

pub(super) struct Generated {
    job: u64,
    units: u32,
    unit: u32,
    prefix: Prefix,
    pending: Option<oneshot::Receiver<Result<Vec<Command>, String>>>,
    work: Option<Work>,
    checked: Option<PreparedProgram>,
    budget: ProgramBudget,
}
impl Generated {
    pub(super) fn new(job: u64, units: u32) -> Self {
        Self {
            job,
            units,
            unit: 1,
            prefix: Prefix::default(),
            pending: None,
            work: None,
            checked: None,
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
                            let before = self.prefix;
                            let mut prefix = before;
                            for command in &records {
                                prefix.append(&naome_proof::program::encode_command(command)?)?;
                            }
                            let status = work.status()?;
                            if status.commands == before.commands {
                                work.append_group(&records)?;
                            } else if status.commands < prefix.commands {
                                return Err(
                                    "candidate checkpoint ends inside a provider group".into()
                                );
                            }
                            let status = work.status()?;
                            if status.commands == prefix.commands
                                && status.program_hash != crate::hex(&prefix.hash)
                            {
                                return Err(
                                    "candidate input differs from its retained provider stream"
                                        .into(),
                                );
                            }
                            self.prefix = prefix;
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
            if status.commands != self.prefix.commands
                || status.program_hash != crate::hex(&self.prefix.hash)
            {
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
            self.checked = Some(PreparedProgram::new(checked));
        }
        let checked = self.checked.as_mut().ok_or("checked candidate absent")?;
        let proof = checked.proof()?;
        let manifest = proof.manifest().clone();
        let store = graph.ownership();
        let progress = store.start_program(&manifest)?;
        if progress.commands < manifest.commands {
            let chunk = proof
                .input_chunk(
                    progress.commands,
                    snapshot.budget.batch_steps.clamp(1, CHUNK_RECORDS),
                    CHUNK_BYTES,
                )
                .map_err(crate::Error::from)?;
            store.append_program(&manifest, &chunk)?;
            return Ok(None);
        }
        if checked.advance(graph, snapshot.budget.batch_steps.max(1))? {
            Ok(Some((
                manifest.proof_id(),
                checked.take_batch().expect("prepared candidate"),
            )))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate() {
        const CASE: &str = "autonomous::program::tests::disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate";
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

        let records = vec![Command::Equal { left: 0, right: 0 }];
        let respond = || {
            let (send, receive) = oneshot::channel();
            send.send(Ok(records.clone())).unwrap();
            receive
        };
        generated.pending = Some(respond());
        crate::resources::with_disk_available(0, || {
            let error = generated
                .prepare(&graph, &owner.client, &question)
                .err()
                .expect("import must defer before advancing its in-memory cursor");
            assert!(error.retryable());
        });
        assert_eq!(
            (
                generated.unit,
                generated.prefix.commands,
                generated.prefix.hash
            ),
            (1, 0, [0; 32])
        );
        assert_eq!(
            generated.work.as_ref().unwrap().status().unwrap().commands,
            0
        );
        generated.pending = Some(respond());
        assert!(
            generated
                .prepare(&graph, &owner.client, &question)
                .unwrap()
                .is_none()
        );
        assert_eq!((generated.unit, generated.prefix.commands), (2, 1));
        assert_eq!(
            generated.work.as_ref().unwrap().status().unwrap().commands,
            1
        );
    }
}
