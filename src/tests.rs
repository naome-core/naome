use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use naome_foundation::ZfcAxiom;
use naome_proof::{ProofCertificate, ProofStep};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub(crate) fn new(label: &str) -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("naome-{label}-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

pub(crate) fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
        .unwrap()
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec()
}
