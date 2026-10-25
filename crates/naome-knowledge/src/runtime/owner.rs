//! Versioned local owner text; directory ownership and call serialization are required.
use super::*;

// Bound both worst-case JSON escaping and the small recovery metadata.
const CONFIG: &str = "owner.json";
const PENDING: &str = ".owner-pending";
const COMMIT: &str = ".owner-commit";
const INCOMING: &str = ".owner-incoming";

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u8,
    revision: u64,
    interest: String,
}

impl Configuration {
    fn empty() -> Self {
        Self {
            version: 1,
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("unsupported owner configuration version".into());
        }
        validate(&self.interest)
    }

    fn receipt(&self) -> Result<Receipt, String> {
        Ok(Receipt {
            version: 1,
            revision: self.revision,
            digest: crate::hex(&Sha256::digest(bytes(self)?)),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    previous: Configuration,
    next: Receipt,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    revision: u64,
    digest: String,
}

#[derive(Debug)]
pub(super) struct Failure {
    pub(super) message: String,
    pub(super) recovery_required: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            recovery_required: false,
        }
    }
}

pub(super) fn validate(text: &str) -> Result<(), String> {
    if text.len() > crate::resources::limits().owner_text_bytes {
        return Err(format!(
            "interest exceeds {} UTF-8 bytes",
            crate::resources::limits().owner_text_bytes
        ));
    }
    Ok(())
}

fn read<T: serde::de::DeserializeOwned>(directory: &Path, name: &str) -> Result<Option<T>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(directory.join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("owner configuration must be one owned regular file".into());
    }
    let mut data = Vec::new();
    file.take((6 * crate::resources::limits().owner_text_bytes + 512) as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > (6 * crate::resources::limits().owner_text_bytes + 512) {
        return Err("owner configuration byte limit".into());
    }
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn sync(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn remove_incoming(directory: &Path) -> Result<(), String> {
    let path = directory.join(INCOMING);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => {
            fs::remove_file(path).map_err(|error| error.to_string())
        }
        Ok(_) => Err("owner temporary path must be one regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn bytes(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn replace(directory: &Path, name: &str, value: &impl Serialize) -> Result<(), String> {
    remove_incoming(directory)?;
    write_new(&directory.join(INCOMING), &bytes(value)?)?;
    fs::rename(directory.join(INCOMING), directory.join(name))
        .map_err(|error| error.to_string())?;
    sync(directory)
}

fn load_state(directory: &Path) -> Result<Configuration, String> {
    remove_incoming(directory)?;
    let current: Option<Configuration> = read(directory, CONFIG)?;
    let receipt: Option<Receipt> = read(directory, COMMIT)?;
    let pending: Option<Pending> = read(directory, PENDING)?;
    if let Some(current) = &current {
        current.validate()?;
    }
    let Some(pending) = pending else {
        if receipt.is_some() || current.as_ref().is_some_and(|config| config.revision != 0) {
            return Err("owner recovery record is missing".into());
        }
        return Ok(current.unwrap_or_else(Configuration::empty));
    };
    pending.previous.validate()?;
    if pending.version != 1
        || pending.next.version != 1
        || pending.previous.revision.checked_add(1) != Some(pending.next.revision)
        || pending.next.digest.len() != 64
        || crate::unhex(&pending.next.digest)?.len() != 32
    {
        return Err("invalid owner recovery record".into());
    }
    if let Some(receipt) = &receipt {
        if receipt.version != 1
            || receipt.digest.len() != 64
            || crate::unhex(&receipt.digest)?.len() != 32
        {
            return Err("invalid owner commit receipt".into());
        }
        if receipt == &pending.next {
            let current = current.ok_or("committed owner configuration is missing")?;
            if current.receipt()? != *receipt {
                return Err("owner commit configuration mismatch".into());
            }
            return Ok(current);
        }
        if receipt != &pending.previous.receipt()? {
            return Err("owner commit recovery mismatch".into());
        }
    } else if pending.previous.revision != 0 {
        return Err("established owner commit receipt is missing".into());
    }
    if current.as_ref() == Some(&pending.previous) {
        return Ok(pending.previous);
    }
    if current
        .as_ref()
        .is_some_and(|config| config.receipt().ok().as_ref() != Some(&pending.next))
    {
        return Err("owner pending configuration mismatch".into());
    }
    // The durable old bytes survive every stage, including a failed recovery.
    // No cleanup after a successful commit discards this last recovery copy.
    replace(directory, CONFIG, &pending.previous)?;
    replace(directory, COMMIT, &pending.previous.receipt()?)?;
    Ok(pending.previous)
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Profile {
    pub(crate) version: u8,
    pub(crate) revision: u64,
    pub(crate) interest: String,
    pub(crate) digest: String,
}

pub(super) fn profile(directory: &Path) -> Result<Profile, String> {
    let config = load_state(directory)?;
    let receipt = config.receipt()?;
    Ok(Profile {
        version: config.version,
        revision: config.revision,
        interest: config.interest,
        digest: receipt.digest,
    })
}

pub(super) fn load(directory: &Path) -> Result<String, String> {
    Ok(load_state(directory)?.interest)
}

pub(super) fn update(directory: &Path, text: &str) -> Result<String, Failure> {
    update_at(directory, text, |_| Ok(()), || Ok(()))
}

fn update_at(
    directory: &Path,
    text: &str,
    mut checkpoint: impl FnMut(u8) -> Result<(), String>,
    mut recover: impl FnMut() -> Result<(), String>,
) -> Result<String, Failure> {
    validate(text)?;
    let previous = load_state(directory)?;
    if previous.interest == text {
        return Ok(text.into());
    }
    let next = Configuration {
        version: 1,
        revision: previous
            .revision
            .checked_add(1)
            .ok_or("owner configuration revision exhausted".to_string())?,
        interest: text.into(),
    };
    let pending = Pending {
        version: 1,
        previous: previous.clone(),
        next: next.receipt()?,
    };
    let result: Result<(), String> = (|| {
        replace(directory, PENDING, &pending)?;
        checkpoint(0)?;
        replace(directory, CONFIG, &next)?;
        checkpoint(1)?;
        replace(directory, COMMIT, &pending.next)?;
        checkpoint(2)?;
        Ok(())
    })();
    if let Err(error) = result {
        let unchanged = read::<Configuration>(directory, CONFIG)
            .map(|config| config.unwrap_or_else(Configuration::empty) == previous)
            .unwrap_or(false);
        let old_receipt = previous.receipt()?;
        let receipt_unchanged = read::<Receipt>(directory, COMMIT)
            .map(|receipt| {
                receipt.as_ref() == Some(&old_receipt)
                    || receipt.is_none() && previous.revision == 0
            })
            .unwrap_or(false);
        if unchanged && receipt_unchanged {
            remove_incoming(directory)?;
            return Err(error.into());
        }
        let rollback: Result<(), String> = (|| {
            recover()?;
            // Revoke the new receipt first so interrupted rollback cannot certify
            // the replacement. Keep PENDING and its complete old bytes intact.
            replace(directory, COMMIT, &previous.receipt()?)?;
            replace(directory, CONFIG, &previous)?;
            Ok(())
        })();
        return match rollback {
            Ok(()) => Err(error.into()),
            Err(rollback) => Err(Failure {
                message: format!("owner update failed: {error}; recovery required: {rollback}"),
                recovery_required: true,
            }),
        };
    }
    Ok(text.into())
}

#[cfg(test)]
mod tests;
