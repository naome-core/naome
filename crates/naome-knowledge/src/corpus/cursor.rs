//! Authenticated cursors are hints scoped to a frozen source, never authority.
use hmac::{Hmac, Mac};
use hmac_sha2::Sha256;
use sha2::Digest;
use std::{fs::File, io::Read, path::Path};

#[derive(Clone)]
pub(crate) struct Key([u8; 32]);
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeCursorKey(<private>)")
    }
}
impl Key {
    pub fn ephemeral() -> Result<Self, String> {
        let mut key = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut key))
            .map_err(|e| e.to_string())?;
        Ok(Self(key))
    }
    pub fn open(directory: &Path) -> Result<Self, String> {
        use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
        let path = directory.join("cursor.key");
        let marker = directory.join("cursor.initialized");
        let initialized = match std::fs::symlink_metadata(&marker) {
            Ok(_) => Some(super::snapshot::read_regular(&marker, 128)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        let key = match super::snapshot::read_regular(&path, 32) {
            Ok(bytes) => Self(
                bytes
                    .try_into()
                    .map_err(|_| "node cursor key length differs")?,
            ),
            Err(error) => {
                // Only genuine absence permits initial creation. Broken aliases,
                // corrupt bytes and an established missing key fail closed.
                if initialized.is_some() || std::fs::symlink_metadata(&path).is_ok() {
                    return Err(error);
                }
                match std::fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                    Ok(_) => return Err(error),
                }
                let key = Self::ephemeral()?;
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                file.write_all(&key.0)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
                File::open(directory)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| e.to_string())?;
                key
            }
        };
        let expected = format!(
            "naome-cursor-key-v2\n{}\n",
            crate::hex(&sha2::Sha256::digest(key.0))
        );
        match initialized {
            Some(bytes) if bytes != expected.as_bytes() => {
                return Err("node cursor key digest or marker version differs".into());
            }
            Some(_) => {}
            None => crate::jobs::write_marker(&marker, expected.as_bytes())?,
        }
        Ok(key)
    }
    pub fn sign(&self, value: &impl serde::Serialize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed HMAC key");
        mac.update(b"naome:retrieval-cursor:v1\0");
        mac.update(&bytes);
        Ok(crate::hex(&mac.finalize().into_bytes()))
    }
    pub fn verify(&self, value: &impl serde::Serialize, token: &str) -> Result<(), String> {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let token = crate::object::id_bytes(token)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed HMAC key");
        mac.update(b"naome:retrieval-cursor:v1\0");
        mac.update(&bytes);
        mac.verify_slice(&token)
            .map_err(|_| "retrieval cursor authentication differs".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_key_preserves_cursors_and_rejects_same_length_corruption() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
            "naome-cursor-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let key = Key::open(&directory.0).unwrap();
        let token = key.sign(&("request", "query", 10)).unwrap();
        Key::open(&directory.0)
            .unwrap()
            .verify(&("request", "query", 10), &token)
            .unwrap();
        let path = directory.0.join("cursor.key");
        let original = std::fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(Key::open(&directory.0).unwrap_err().contains("digest"));
        std::fs::write(&path, &original).unwrap();
        Key::open(&directory.0)
            .unwrap()
            .verify(&("request", "query", 10), &token)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(Key::open(&directory.0).is_err());
        assert!(!path.exists());
        std::fs::write(&path, &original).unwrap();
        std::fs::write(
            directory.0.join("cursor.initialized"),
            b"naome-cursor-key-v1\n",
        )
        .unwrap();
        assert!(Key::open(&directory.0).unwrap_err().contains("version"));
    }
}
