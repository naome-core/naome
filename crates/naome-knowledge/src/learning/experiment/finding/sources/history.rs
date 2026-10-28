//! Scientific files implement the ordinary two-lane source-owner interface.
//! These IO measurements are separate from production SQLite operation costs.
use super::*;
use crate::learning::history::{Lane, PAGE_BYTES, Page, Receipt, Record, Request, SOURCES, Source};
use std::{io::Read, ops::Range};

pub(in crate::learning::experiment::finding) struct Io<'a> {
    pub(in crate::learning::experiment::finding) store: Store,
    frozen: &'a Frozen,
    directory: &'a Path,
    available: usize,
    pub(in crate::learning::experiment::finding) source_bytes: u64,
    pub(in crate::learning::experiment::finding) source_reads: u64,
    pub(in crate::learning::experiment::finding) pages: Vec<Value>,
}
impl<'a> Io<'a> {
    pub(in crate::learning::experiment::finding) fn new(
        frozen: &'a Frozen,
        directory: &'a Path,
    ) -> Self {
        Self {
            store: Store {
                inner: MemoryStore(frozen.store.0.clone()),
                ..Default::default()
            },
            frozen,
            directory,
            available: 0,
            source_bytes: 0,
            source_reads: 0,
            pages: Vec::new(),
        }
    }
    pub(in crate::learning::experiment::finding) fn epoch(
        &mut self,
        epoch: usize,
    ) -> Result<(), String> {
        if epoch >= self.frozen.epochs.len() || self.available != epoch * QUERIES {
            return Err("scientific source epoch skipped or repeated".into());
        }
        self.available = (epoch + 1) * QUERIES;
        Ok(())
    }
    fn episode(&mut self, job: u64, remaining: usize) -> Result<Episode, String> {
        let index = usize::try_from(job)
            .map_err(|_| "scientific source job range")?
            .checked_sub(1)
            .ok_or("scientific source job is zero")?;
        let expected = self
            .frozen
            .episodes
            .get(index)
            .filter(|_| index < self.available)
            .ok_or("scientific source is outside the available epoch")?;
        let path = self.directory.join(format!("episode-{job}.json"));
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(remaining as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        self.source_bytes += bytes.len() as u64;
        self.source_reads += 1;
        if bytes.len() > remaining {
            return Err("scientific history exhausted its original read allowance".into());
        }
        let episode: Episode = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if episode.observation.summary.job != job || digest(&episode) != digest(expected) {
            return Err("scientific source bytes or job differ from the frozen collection".into());
        }
        // Collection already checked the complete proof and ancestry. This
        // read binds exact frozen bytes; native Working rechecks proof sources
        // and Observation validates operational records before model loading.
        episode.observation.validate()?;
        Ok(episode)
    }
}
impl ArtifactIo for Io<'_> {
    fn history(&mut self, request: &Request) -> Result<Receipt, String> {
        request.validate()?;
        if self.available == 0 {
            return Err("scientific history has no opened source epoch".into());
        }
        let started = meta::cpu_micros()?;
        let before_bytes = self.source_bytes;
        let before_reads = self.source_reads;
        let mut entries = BTreeMap::new();
        for episode in self.frozen.episodes.iter().take(self.available) {
            let job = episode.observation.summary.job;
            match request.lane {
                Lane::Sources => {
                    if let Some(solution) = &episode.solution {
                        entries.entry(solution.proof_id.clone()).or_insert(job);
                    }
                }
                Lane::Records => {
                    entries.insert(job.to_string(), job);
                }
            }
        }
        let entries = entries
            .into_iter()
            .filter(|(key, _)| request.after.as_ref().is_none_or(|after| key > after))
            .take(SOURCES)
            .collect::<Vec<_>>();
        let at_end = entries.len() < SOURCES;
        let mut page = Page {
            request: request.clone(),
            next: None,
            examined: Vec::new(),
            sources: Vec::new(),
            records: Vec::new(),
        };
        let mut truncated = false;
        for (key, job) in entries {
            let remaining = crate::resources::limits()
                .native_model_blob_bytes
                .saturating_sub((self.source_bytes - before_bytes) as usize);
            if remaining == 0 {
                return Err("scientific history read allowance exhausted".into());
            }
            if request.lane == Lane::Records || job < request.horizon {
                let episode = self.episode(job, remaining)?;
                match request.lane {
                    Lane::Sources => {
                        let solution = episode
                            .solution
                            .ok_or("scientific admitted source lacks its complete proof")?;
                        if solution.proof_id != key {
                            return Err("scientific source proof index differs".into());
                        }
                        page.sources.push(Source {
                            job,
                            origin: Origin::Local,
                            question: episode.observation.question,
                            solution,
                            peer_certificate: None,
                        });
                    }
                    Lane::Records => page.records.push(Record {
                        job,
                        observation: (job < request.horizon).then_some(episode.observation),
                    }),
                }
            }
            page.examined.push((key.clone(), job));
            page.next = Some(key);
            if crate::checkpoint::encode(&page)?.len() > PAGE_BYTES {
                page.examined.pop();
                match request.lane {
                    Lane::Sources if job < request.horizon => {
                        page.sources.pop();
                    }
                    Lane::Records => {
                        page.records.pop();
                    }
                    _ => {}
                }
                page.next = page.examined.last().map(|(key, _)| key.clone());
                if page.examined.is_empty() {
                    return Err("scientific history record exceeds its existing page bound".into());
                }
                truncated = true;
                break;
            }
        }
        if at_end && !truncated {
            page.next = None;
        }
        let bytes = crate::checkpoint::encode(&page)?;
        let blob = artifact::save(self, &bytes)?;
        let receipt = Receipt {
            request: request.clone(),
            blob,
            next: page.next.clone(),
            read_bytes: (self.source_bytes - before_bytes)
                .try_into()
                .map_err(|_| "scientific history read counter overflow")?,
            read_operations: (self.source_reads - before_reads)
                .try_into()
                .map_err(|_| "scientific history operation counter overflow")?,
            read_cpu_micros: meta::cpu_micros()?.saturating_sub(started),
        };
        receipt.validate(request)?;
        self.pages.push(json!({"receipt":receipt,"available_episodes":self.available,"examined":page.examined,"checked_sources":page.sources.len(),"observations":page.records.iter().filter(|r|r.observation.is_some()).count()}));
        Ok(receipt)
    }
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
        self.store.read(blob, range)
    }
    fn write(&mut self, blob: &Blob, range: Range<usize>, bytes: Vec<u8>) -> Result<(), String> {
        self.store.write(blob, range, bytes)
    }
}

#[test]
fn terminal_records_keep_unknowns_horizon_and_original_read_bounds() {
    let directory = Directory::new();
    let common = State::fresh();
    let q = CompiledQuestion::compile(
        "goal=all(a,all(b,imp(not(eq(a,b)),imp(all(x,all(y,mem(x,y))),mem(b,a)))))",
    )
    .unwrap();
    let episodes = (1..=QUERIES as u64)
        .map(|job| {
            let summary = crate::frontier::evidence::observed_completion(
                &q,
                job,
                experience::TerminalEvidence::Unknown,
                0,
                None,
            )
            .experience
            .unwrap();
            let episode = Episode {
                lineage: "unit-fixture".into(),
                authored_lineage: "unit-fixture".into(),
                observation: experience::Observation {
                    question: q.source().into(),
                    summary,
                    frontier: None,
                    executions: Vec::new(),
                    knowledge: Vec::new(),
                },
                solution: None,
            };
            write(&directory.0.join(format!("episode-{job}.json")), &episode);
            episode
        })
        .collect::<Vec<_>>();
    // This fixture exercises file transport only and is never a proof source.
    let frozen = Frozen {
        initial: common.clone(),
        store: MemoryStore::default(),
        epochs: vec![common],
        episodes,
        ledgers: Vec::new(),
        cost: json!(null),
    };
    let mut io = Io::new(&frozen, &directory.0);
    let mut request = Request {
        lane: Lane::Sources,
        after: None,
        horizon: 20,
    };
    assert!(io.history(&request).is_err());
    io.epoch(0).unwrap();
    assert!(io.epoch(0).is_err());
    assert!(io.epoch(1).is_err());
    let receipt = io.history(&request).unwrap();
    let page: Page =
        crate::checkpoint::decode(&artifact::load(&mut io, &receipt.blob).unwrap()).unwrap();
    assert!(page.sources.is_empty() && page.records.is_empty());
    assert_eq!(io.source_reads, 0);
    request.lane = Lane::Records;
    let receipt = io.history(&request).unwrap();
    let page: Page =
        crate::checkpoint::decode(&artifact::load(&mut io, &receipt.blob).unwrap()).unwrap();
    assert_eq!(page.records.len(), SOURCES);
    assert_eq!(page.examined.len(), SOURCES);
    assert!(page.sources.is_empty());
    assert_eq!(io.source_reads, SOURCES as u64);
    for record in &page.records {
        assert_eq!(record.observation.is_some(), record.job < request.horizon);
        if let Some(observation) = &record.observation {
            assert_eq!(
                observation.summary.terminal,
                experience::TerminalEvidence::Unknown
            );
        }
    }
    assert!(page.examined.windows(2).all(|w| w[0].0 < w[1].0));
    let path = directory.0.join("episode-1.json");
    let original = std::fs::read(&path).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["authored_lineage"] = json!("substituted");
    write(&path, &changed);
    assert!(
        io.history(&request)
            .unwrap_err()
            .contains("frozen collection")
    );
    std::fs::write(&path, original).unwrap();
    request.after = receipt.next;
    let next = io.history(&request).unwrap();
    let next: Page =
        crate::checkpoint::decode(&artifact::load(&mut io, &next.blob).unwrap()).unwrap();
    assert_eq!(next.records.len(), QUERIES - SOURCES);
    assert!(next.next.is_none());
    assert!(
        next.examined
            .iter()
            .all(|(key, _)| key > request.after.as_ref().unwrap())
    );
}
