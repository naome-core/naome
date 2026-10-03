use crate::{Envelope, MAX_ACCEPTED_BYTES, MAX_OBJECTS, MAX_PROOF_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const MAX_ENVELOPE_BYTES: usize = 2 * MAX_PROOF_BYTES + 512;

pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
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
        })
    }

    pub fn load(&self) -> Result<Vec<Envelope>, String> {
        let mut objects = Vec::new();
        let mut total = 0;
        for entry in fs::read_dir(&self.directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.file_name().is_some_and(|name| name == ".incoming") {
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
            total += object.proof.len() / 2;
            if total > MAX_ACCEPTED_BYTES {
                return Err("durable byte capacity".into());
            }
            objects.push(object);
        }
        Ok(objects)
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
