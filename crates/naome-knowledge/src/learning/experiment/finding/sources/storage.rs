//! Restore complete frozen inputs for an independent arm, never a partial job.
use super::*;
use crate::learning::history::PAGE_BYTES;

#[derive(Default)]
struct Reads {
    bytes: u64,
    operations: u64,
}
impl Reads {
    fn read(&mut self, path: &Path, cap: usize) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        self.bytes += bytes.len() as u64;
        self.operations += 1;
        if bytes.len() > cap {
            return Err("frozen source file exceeds its existing capacity".into());
        }
        Ok(bytes)
    }
    fn json<T: serde::de::DeserializeOwned>(
        &mut self,
        path: &Path,
        cap: usize,
    ) -> Result<T, String> {
        serde_json::from_slice(&self.read(path, cap)?).map_err(|e| e.to_string())
    }
}

impl Frozen {
    pub(in crate::learning::experiment::finding) fn read(
        output: &Path,
        holdout: &lineage::Holdout,
    ) -> Result<(Self, Value), String> {
        let started = Instant::now();
        let cpu = meta::cpu_micros()?;
        let checking = proof::checking_work();
        let mut reads = Reads::default();
        let cost: Value = reads.json(&output.join("cost.json"), PAGE_BYTES)?;
        let count = cost["epochs"]
            .as_u64()
            .ok_or("frozen source epoch count absent")? as usize;
        if !(1..=MAX_EPOCHS).contains(&count)
            || cost["episodes"] != count * QUERIES
            || cost["complete"] != true
            || cost["optimizer_updates"] != 0
        {
            return Err("frozen source collection is incomplete or changed".into());
        }
        let initial: State = reads.json(&output.join("initial-state.json"), PAGE_BYTES)?;
        initial.validate()?;
        if initial.model.updates != 0
            || initial.model.model.is_none()
            || initial.examples().next().is_some()
            || !initial.knowledge.is_empty()
            || !initial.definitions.is_empty()
            || cost["initial_state_sha256"] != digest(&initial)
        {
            return Err("frozen acquisition initial source context differs".into());
        }
        let mut episodes = Vec::new();
        let mut ledgers = Vec::new();
        let mut epochs = Vec::new();
        let mut reconstructed = initial.clone();
        for epoch in 0..count {
            let ledger = lineage::Ledger::read(
                &reads.read(&output.join(format!("lineage-{epoch}.json")), PAGE_BYTES)?,
                holdout,
            )?;
            for index in epoch * QUERIES..(epoch + 1) * QUERIES {
                let job = 1 + index as u64;
                let episode: Episode = reads.json(
                    &output.join(format!("episode-{job}.json")),
                    crate::resources::limits().native_model_blob_bytes,
                )?;
                if episode.observation.summary.job != job {
                    return Err("frozen source order differs".into());
                }
                episode.validate(&initial, &ledger, holdout)?;
                if let Some(solution) = &episode.solution {
                    reconstructed.accept(Example {
                        origin: Origin::Local,
                        job,
                        question: episode.observation.question.clone(),
                        proof_id: solution.proof_id.clone(),
                        refuted: solution.refuted,
                        tree: solution.tree.clone(),
                    })?;
                }
                episodes.push(episode);
                let peak = crate::resources::feedback::Meter::start()
                    .finish(0, true)
                    .peak_rss_bytes
                    .ok_or("source restore lacks its memory observation")?;
                if peak > model::REQUIREMENTS.work_bytes as u64
                    || meta::cpu_micros()?.saturating_sub(cpu) > CPU
                    || started.elapsed().as_micros() > WALL
                    || reads.bytes > IO
                {
                    return Err(
                        "source restore exhausted its unchanged experiment allowance".into(),
                    );
                }
            }
            reconstructed.compact()?;
            reconstructed.compact_with_meta_headroom(
                super::super::super::adaptive::outer_metadata_headroom(&reconstructed),
            )?;
            let saved: State =
                reads.json(&output.join(format!("epoch-{epoch}.json")), PAGE_BYTES)?;
            saved.validate()?;
            if digest(&saved) != digest(&reconstructed) {
                return Err(
                    "frozen epoch cannot be reconstructed from its checked original sources".into(),
                );
            }
            ledgers.push(ledger);
            epochs.push(saved);
        }
        if cost["source_sha256"] != digest(&episodes) {
            return Err("frozen source collection digest differs".into());
        }
        // Only after every source and ancestor passed the split and native
        // checks are the exact original parameter/optimizer blobs imported.
        let (model, store) =
            super::super::confirmation::import_model(&output.join("initial-model"))?;
        if model != initial.model {
            return Err("frozen initial model or Adam differs".into());
        }
        for file in std::fs::read_dir(output.join("initial-model")).map_err(|e| e.to_string())? {
            reads.bytes += file
                .map_err(|e| e.to_string())?
                .metadata()
                .map_err(|e| e.to_string())?
                .len();
            reads.operations += 1;
        }
        let after = proof::checking_work();
        let rechecks = json!({"cpu_micros":meta::cpu_micros()?.saturating_sub(cpu),"wall_micros":started.elapsed().as_micros(),"source_read_bytes":reads.bytes,"source_reads":reads.operations,"checker_calls":after.calls-checking.calls,"checker_steps":after.steps-checking.steps,"optimizer_updates":0});
        Ok((
            Self {
                initial,
                store,
                epochs,
                episodes,
                ledgers,
                cost,
            },
            rechecks,
        ))
    }
}

#[test]
fn an_incomplete_collection_never_imports_model_parameters() {
    let directory = Directory::new();
    write(
        &directory.0.join("cost.json"),
        &json!({"epochs":1,"episodes":48,"complete":false,"optimizer_updates":0}),
    );
    let held = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let bytes=serde_json::to_vec(&json!({"cases":[{"source":held.source(),"resolution":crate::hex(held.resolution_id()),"family":curriculum::owned::family(held.proved_target()),"lineage":"held"}]})).unwrap();
    let holdout = lineage::Holdout::read(&bytes, &crate::hex(&Sha256::digest(&bytes))).unwrap();
    let error = Frozen::read(&directory.0, &holdout).err().unwrap();
    assert!(error.contains("incomplete"));
    assert!(!directory.0.join("initial-model").exists());
}
