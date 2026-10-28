//! File-backed scientific source adapter; production SQLite costs are separate.
use super::*;
use crate::learning::history::{Page, Receipt, Request, SOURCES, Source};
use std::{ops::Range, path::PathBuf};

#[derive(Serialize, Deserialize)]
struct Entry {
    proof: String,
    job: u64,
    blob: Blob,
}
pub(super) fn persist(source: &super::super::Source, path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    let mut sources = BTreeMap::new();
    for row in &source.common.rows {
        if row["solution"].is_null() {
            continue;
        }
        let solution: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
        sources.entry(solution.proof_id.clone()).or_insert(Source {
            job: row["job"].as_u64().unwrap(),
            origin: Origin::Local,
            question: row["question"].as_str().unwrap().into(),
            solution,
            peer_certificate: None,
        });
    }
    let mut entries = Vec::new();
    for (proof, source) in sources {
        let bytes = crate::checkpoint::encode(&source).unwrap();
        entries.push(Entry {
            proof: proof.clone(),
            job: source.job,
            blob: Blob::of(&bytes),
        });
        std::fs::write(path.join(format!("{proof}.json")), bytes).unwrap();
    }
    write(&path.join("manifest.json"), &entries);
}

pub(super) struct Io {
    pub store: Store,
    pub directory: PathBuf,
    pub source_bytes: u64,
    pub source_reads: u64,
}
impl ArtifactIo for Io {
    fn history(&mut self, request: &Request) -> Result<Receipt, String> {
        request.validate()?;
        if request.lane != crate::learning::history::Lane::Sources {
            return Err("admitted-source fixture cannot supply operational job history".into());
        }
        let cpu = meta::cpu_micros()?;
        let bytes =
            std::fs::read(self.directory.join("manifest.json")).map_err(|e| e.to_string())?;
        let mut read_bytes = bytes.len();
        let mut read_operations = 1;
        let entries: Vec<Entry> = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if !entries.windows(2).all(|p| p[0].proof < p[1].proof) {
            return Err("scientific source manifest order differs".into());
        }
        let entries = entries
            .iter()
            .filter(|e| request.after.as_ref().is_none_or(|a| e.proof > *a))
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
        for entry in entries {
            crate::object::id_bytes(&entry.proof)?;
            entry.blob.validate()?;
            if entry.job < request.horizon {
                if read_bytes + entry.blob.bytes
                    > crate::resources::limits().native_model_blob_bytes
                {
                    return Err("scientific history read allowance".into());
                }
                let bytes = std::fs::read(self.directory.join(format!("{}.json", entry.proof)))
                    .map_err(|e| e.to_string())?;
                read_bytes += bytes.len();
                read_operations += 1;
                if Blob::of(&bytes) != entry.blob {
                    return Err("scientific source bytes differ".into());
                }
                let source: Source = crate::checkpoint::decode(&bytes)?;
                if source.job != entry.job || source.solution.proof_id != entry.proof {
                    return Err("scientific source identity differs".into());
                }
                page.sources.push(source);
            }
            page.examined.push((entry.proof.clone(), entry.job));
            page.next = Some(entry.proof.clone());
            if crate::checkpoint::encode(&page)?.len() > crate::learning::history::PAGE_BYTES {
                page.examined.pop();
                if entry.job < request.horizon {
                    page.sources.pop();
                }
                page.next = page.examined.last().map(|(key, _)| key.clone());
                if page.examined.is_empty() {
                    return Err("scientific history source exceeds page".into());
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
            next: page.next,
            read_bytes,
            read_operations,
            read_cpu_micros: meta::cpu_micros()?.saturating_sub(cpu),
        };
        receipt.validate(request)?;
        self.source_bytes += read_bytes as u64;
        self.source_reads += read_operations as u64;
        Ok(receipt)
    }
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
        self.store.read(blob, range)
    }
    fn write(&mut self, blob: &Blob, range: Range<usize>, bytes: Vec<u8>) -> Result<(), String> {
        self.store.write(blob, range, bytes)
    }
}
