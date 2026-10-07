use crate::{Envelope, MAX_ACCEPTED_BYTES, MAX_OBJECTS, MAX_PROOF_BYTES};
use naome_proof::ProofId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const MAX_ENVELOPE_BYTES: usize = 2 * MAX_PROOF_BYTES + 512;

pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
    #[cfg(test)]
    cut: std::cell::Cell<Option<BatchCut>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    root: String,
    members: BTreeMap<String, String>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchCut {
    BeforeWrite,
    DuringWrite,
    BeforeRename,
    AfterRename,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("knowledge.lock"))
            .map_err(|error| error.to_string())?;
        lock.try_lock()
            .map_err(|error| format!("knowledge directory already owned: {error}"))?;
        let objects = directory.join("objects");
        fs::create_dir_all(&objects).map_err(|error| error.to_string())?;
        Ok(Self {
            directory: objects,
            _lock: lock,
            #[cfg(test)]
            cut: std::cell::Cell::new(None),
        })
    }

    pub fn load(&self) -> Result<Vec<Envelope>, String> {
        let mut objects = Vec::new();
        let mut total = 0;
        for entry in fs::read_dir(&self.directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path
                .file_name()
                .is_some_and(|name| name == ".incoming" || name == ".incoming-batch")
            {
                continue;
            }
            if path.file_name().is_some_and(|name| name == "batches") {
                for entry in fs::read_dir(&path).map_err(|error| error.to_string())? {
                    let batch = entry.map_err(|error| error.to_string())?.path();
                    let manifest_bytes = read_bounded(&batch.join("manifest.json"), 32 * 1024)?;
                    if batch.file_name().and_then(|name| name.to_str())
                        != Some(&crate::hex(&Sha256::digest(&manifest_bytes)))
                    {
                        return Err("committed batch identity mismatch".into());
                    }
                    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
                        .map_err(|error| error.to_string())?;
                    if manifest.version != 1
                        || manifest.members.is_empty()
                        || manifest.members.len() > crate::intake::MAX_CLOSURE_OBJECTS
                        || !manifest.members.contains_key(&manifest.root)
                        || fs::read_dir(&batch)
                            .map_err(|error| error.to_string())?
                            .count()
                            != manifest.members.len() + 1
                    {
                        return Err("incomplete committed batch".into());
                    }
                    for (id, digest) in manifest.members {
                        crate::object::id_bytes(&id)?;
                        let bytes =
                            read_bounded(&batch.join(format!("{id}.json")), MAX_ENVELOPE_BYTES)?;
                        if crate::hex(&Sha256::digest(&bytes)) != digest {
                            return Err("committed batch member corruption".into());
                        }
                        let object: Envelope =
                            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                        if object.proof_id != id {
                            return Err("committed batch filename mismatch".into());
                        }
                        Self::retain(&mut objects, &mut total, object)?;
                    }
                }
                continue;
            }
            if objects.len() >= MAX_OBJECTS {
                return Err("durable object count limit".into());
            }
            let bytes = read_bounded(&path, MAX_ENVELOPE_BYTES)?;
            let object: Envelope =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if path.file_name().and_then(|name| name.to_str())
                != Some(&format!("{}.json", object.proof_id))
            {
                return Err("durable object filename mismatch".into());
            }
            Self::retain(&mut objects, &mut total, object)?;
        }
        Ok(objects)
    }

    fn retain(
        objects: &mut Vec<Envelope>,
        total: &mut usize,
        object: Envelope,
    ) -> Result<(), String> {
        if objects.len() >= MAX_OBJECTS {
            return Err("durable object count limit".into());
        }
        *total += object.proof.len() / 2;
        if *total > MAX_ACCEPTED_BYTES {
            return Err("durable byte capacity".into());
        }
        objects.push(object);
        Ok(())
    }

    pub fn persist_batch<'a>(
        &self,
        root: ProofId,
        objects: impl Iterator<Item = &'a Envelope>,
    ) -> Result<(), String> {
        let temporary = self.directory.join(".incoming-batch");
        if temporary.exists() {
            fs::remove_dir_all(&temporary).map_err(|error| error.to_string())?;
        }
        fs::create_dir(&temporary).map_err(|error| error.to_string())?;
        #[cfg(test)]
        self.fail_at(BatchCut::BeforeWrite)?;
        let mut manifest = Manifest {
            version: 1,
            root: crate::hex(root.as_bytes()),
            members: BTreeMap::new(),
        };
        for object in objects {
            crate::object::id_bytes(&object.proof_id)?;
            let bytes = serde_json::to_vec(object).map_err(|error| error.to_string())?;
            let mut file = File::create(temporary.join(format!("{}.json", object.proof_id)))
                .map_err(|error| error.to_string())?;
            #[cfg(test)]
            if self.cut.get() == Some(BatchCut::DuringWrite) {
                file.write_all(&bytes[..bytes.len() / 2])
                    .map_err(|error| error.to_string())?;
                return self.fail_at(BatchCut::DuringWrite);
            }
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| error.to_string())?;
            manifest
                .members
                .insert(object.proof_id.clone(), crate::hex(&Sha256::digest(&bytes)));
        }
        if !manifest.members.contains_key(&manifest.root) {
            return Err("batch root missing".into());
        }
        let bytes = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        let mut file =
            File::create(temporary.join("manifest.json")).map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        File::open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        let batches = self.directory.join("batches");
        fs::create_dir_all(&batches).map_err(|error| error.to_string())?;
        #[cfg(test)]
        self.fail_at(BatchCut::BeforeRename)?;
        fs::rename(
            &temporary,
            batches.join(crate::hex(&Sha256::digest(&bytes))),
        )
        .map_err(|error| error.to_string())?;
        // A failure from here is ambiguous durability. The owner halts; a
        // restart verifies the entire committed batch or fails startup.
        #[cfg(test)]
        self.fail_at(BatchCut::AfterRename)?;
        #[cfg(unix)]
        {
            File::open(&batches)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
            File::open(&self.directory)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_at(&self, cut: BatchCut) -> Result<(), String> {
        if self.cut.get() == Some(cut) {
            Err("injected batch persistence cut".into())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn set_cut(&self, cut: BatchCut) {
        self.cut.set(Some(cut));
    }

    pub fn persist(&self, object: &Envelope) -> Result<(), String> {
        let destination = self.directory.join(format!("{}.json", object.proof_id));
        let bytes = serde_json::to_vec(object).map_err(|error| error.to_string())?;
        if destination.exists() {
            if read_bounded(&destination, MAX_ENVELOPE_BYTES)? == bytes {
                return Ok(());
            }
            return Err("immutable durable object collision".into());
        }
        let temporary = self.directory.join(".incoming");
        let mut file = File::create(&temporary).map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, &destination).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("expected regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err("file byte limit".into());
    }
    Ok(bytes)
}
