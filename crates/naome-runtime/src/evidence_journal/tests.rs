use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "naome-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.0.join(IMAGE)).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn replacement_faults_poison_owner_and_reopen_only_complete_old_or_new_raw_images() {
    for stage in [
        faults::Stage::Create,
        faults::Stage::Write,
        faults::Stage::FileSync,
        faults::Stage::Rename,
        faults::Stage::DirectorySync,
    ] {
        let dir = Directory::new();
        let old = vec![17; 96];
        let new = vec![29; 129];
        let mut owner = EvidenceJournal::open(&dir.0, true, old.clone(), 1024).unwrap();
        faults::FAIL.with(|f| f.set(Some(stage)));
        assert!(matches!(owner.save(new.clone()), Err(Failure::Io(_))));
        faults::FAIL.with(|f| assert!(f.get().is_none(), "injection must fire"));
        assert!(matches!(owner.save(old.clone()), Err(Failure::Poisoned)));
        drop(owner);
        let restored = EvidenceJournal::open(&dir.0, false, vec![], 1024).unwrap();
        assert_eq!(
            restored.image(),
            if stage == faults::Stage::DirectorySync {
                new.as_slice()
            } else {
                old.as_slice()
            }
        );
    }
}

#[test]
fn strict_image_reopen_checks_bounds_checksum_framing_missing_and_nonregular_sources_without_repair()
 {
    let dir = Directory::new();
    let image = (0..192).map(|i| i as u8).collect::<Vec<_>>();
    drop(EvidenceJournal::open(&dir.0, true, image.clone(), 256).unwrap());
    let original = dir.bytes();
    let mut cases = vec![
        vec![],
        original[..31].to_vec(),
        original[..original.len() - 1].to_vec(),
        vec![0; 289],
    ];
    for index in [0, original.len() / 2, original.len() - 1] {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        cases.push(bytes);
    }
    let mut trailing = original.clone();
    trailing.push(0);
    cases.push(trailing);
    for bytes in cases {
        fs::write(dir.0.join(IMAGE), &bytes).unwrap();
        assert!(EvidenceJournal::open(&dir.0, false, vec![], 256).is_err());
        assert_eq!(dir.bytes(), bytes);
    }
    fs::write(dir.0.join(IMAGE), &original).unwrap();
    assert!(matches!(
        EvidenceJournal::open(&dir.0, true, vec![], 256),
        Err(Failure::Io(_))
    ));
    assert_eq!(dir.bytes(), original);
    drop(EvidenceJournal::open(&dir.0, false, vec![], 256).unwrap());
    fs::remove_file(dir.0.join(IMAGE)).unwrap();
    assert!(EvidenceJournal::open(&dir.0, false, vec![], 256).is_err());
    let target = dir.0.join("target");
    fs::write(&target, &original).unwrap();
    std::os::unix::fs::symlink(&target, dir.0.join(IMAGE)).unwrap();
    assert!(EvidenceJournal::open(&dir.0, false, vec![], 256).is_err());
    assert_eq!(fs::read(target).unwrap(), original);
}

#[test]
fn image_owner_excludes_second_owner_and_releases_even_when_lock_descriptor_is_duplicated() {
    let dir = Directory::new();
    let owner = EvidenceJournal::open(&dir.0, true, vec![1; 32], 256).unwrap();
    assert!(matches!(
        EvidenceJournal::open(&dir.0, false, vec![], 256),
        Err(Failure::Locked)
    ));
    let duplicate = owner._lock.0.try_clone().unwrap();
    drop(owner);
    drop(EvidenceJournal::open(&dir.0, false, vec![], 256).unwrap());
    drop(duplicate);
}

#[test]
fn identical_raw_custody_skips_disk_replacement_and_capacity_refuses_before_mutation() {
    let dir = Directory::new();
    let image = vec![1; 32];
    let mut owner = EvidenceJournal::open(&dir.0, true, image.clone(), 32).unwrap();
    let before = dir.bytes();
    faults::FAIL.with(|f| f.set(Some(faults::Stage::Create)));
    owner.save(image).unwrap();
    faults::FAIL.with(|f| {
        assert_eq!(f.get(), Some(faults::Stage::Create));
        f.set(None);
    });
    assert!(matches!(owner.save(vec![2; 33]), Err(Failure::Invalid)));
    assert_eq!(dir.bytes(), before);
    assert!(!owner.poisoned);
}

#[test]
fn evidence_wrapper_has_an_independent_vector_and_mutation_corpus() {
    let directory = Directory::new();
    let raw = (0..192).map(|i| i as u8).collect::<Vec<_>>();
    let encode = |raw: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"naome:fixed-validator-retained-evidence-checksum:v0\0");
        hash.update(raw);
        let mut bytes = raw.to_vec();
        bytes.extend_from_slice(&hash.finalize());
        bytes
    };
    let expected = encode(&raw);
    drop(EvidenceJournal::open(&directory.0, true, raw, 256).unwrap());
    assert_eq!(directory.bytes(), expected);
    crate::codec_corpus::check(
        "raw evidence checksum wrapper",
        &[encode(&[]), expected],
        |bytes| {
            fs::write(directory.0.join(IMAGE), bytes).unwrap();
            let decoded = EvidenceJournal::open(&directory.0, false, vec![], 256).ok()?;
            Some(encode(decoded.image()))
        },
    );
}
