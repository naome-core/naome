//! Explicit source replacement; this metadata grants no signer authority.
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use naome_chain::ArtifactChainDefinition;
use rustix::fs::OFlags;

use super::{Mode, Result, stabilize};
use crate::app::files;

const LOCK: &str = "source-generation.lock";
const BINDING: &str = "source-generation-v0.json";
const CANDIDATES: &str = "candidates";
const PAYLOADS: &str = "payloads";

pub(super) struct Generation {
    directory: PathBuf,
    original_candidates: PathBuf,
    original_payloads: PathBuf,
}

pub(super) struct Owner {
    directory: PathBuf,
    binding: Vec<u8>,
    create: bool,
    _lock: File,
}

fn directory(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)
        .map_err(|_| "source_recovery_directory")?
        .is_dir()
    {
        return Err("source_recovery_directory");
    }
    path.canonicalize().map_err(|_| "source_recovery_directory")
}

impl Generation {
    pub(super) fn prepare(
        root: &Path,
        candidates: &Path,
        payloads: &Path,
        protected: &[&Path],
    ) -> Result<Self> {
        let root = directory(root)?;
        let original_candidates = directory(candidates)?;
        let original_payloads = directory(payloads)?;
        // A replacement may not add files inside a source or authority
        // directory, nor encompass one under its own generation tree.
        for other in [&original_candidates, &original_payloads]
            .into_iter()
            .map(PathBuf::as_path)
            .chain(protected.iter().copied())
        {
            let other = directory(other)?;
            if root.starts_with(&other) || other.starts_with(&root) {
                return Err("source_recovery_directory_overlap");
            }
        }
        Ok(Self {
            directory: root,
            original_candidates,
            original_payloads,
        })
    }

    pub(super) fn open(self, definition: ArtifactChainDefinition) -> Result<Owner> {
        let binding = serde_json::to_vec(&(
            0u8,
            definition.id().as_bytes(),
            &self.original_candidates,
            &self.original_payloads,
        ))
        .map_err(|_| "source_recovery_binding")?;
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
            .open(self.directory.join(LOCK))
            .map_err(|_| "source_recovery_lock")?;
        if !lock
            .metadata()
            .map_err(|_| "source_recovery_lock")?
            .is_file()
        {
            return Err("source_recovery_lock");
        }
        lock.try_lock().map_err(|_| "source_recovery_locked")?;

        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(|_| "source_recovery_directory")? {
            if entries.len() == 4 {
                return Err("source_recovery_directory_contents");
            }
            entries.push(entry.map_err(|_| "source_recovery_directory")?.file_name());
        }
        let create = entries.len() == 1 && entries[0] == LOCK;
        if !create {
            if entries.len() != 4
                || [LOCK, BINDING, CANDIDATES, PAYLOADS]
                    .iter()
                    .any(|name| !entries.iter().any(|entry| entry == name))
            {
                return Err("source_recovery_incomplete_generation");
            }
            if !files::match_and_sync(&self.directory.join(BINDING), &binding)? {
                return Err("source_recovery_binding");
            }
        }
        for name in [CANDIDATES, PAYLOADS] {
            let path = self.directory.join(name);
            if create {
                fs::create_dir(&path).map_err(|_| "source_recovery_create_directory")?;
            }
            directory(&path)?;
        }
        stabilize(&self.directory)?;
        Ok(Owner {
            directory: self.directory,
            binding,
            create,
            _lock: lock,
        })
    }
}

impl Owner {
    pub(super) fn mode(&self) -> Mode {
        if self.create {
            Mode::Create
        } else {
            Mode::Open
        }
    }

    pub(super) fn candidate_directory(&self) -> PathBuf {
        self.directory.join(CANDIDATES)
    }

    pub(super) fn payload_directory(&self) -> PathBuf {
        self.directory.join(PAYLOADS)
    }

    pub(super) fn seal(&self) -> Result<()> {
        if self.create {
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(self.directory.join(BINDING))
                .map_err(|_| "source_recovery_binding_create")?;
            file.write_all(&self.binding)
                .and_then(|()| file.sync_all())
                .map_err(|_| "source_recovery_binding_sync")?;
        }
        stabilize(&self.directory)
    }
}
