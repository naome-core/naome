use super::*;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-decision-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let model = root.join("model");
        let runtime = root.join("runtime");
        fs::create_dir(&model).unwrap();
        fs::create_dir(&runtime).unwrap();
        fs::write(
            root.join("python"),
            b"metadata-only fixture; never executed",
        )
        .unwrap();
        for (directory, assets) in [
            (&model, &manifest().model.files),
            (
                &runtime,
                &manifest().runtime.platforms[platform().unwrap()].files,
            ),
        ] {
            for asset in assets {
                let path = directory.join(&asset.file);
                if let Some(link) = &asset.link {
                    std::os::unix::fs::symlink(link, path).unwrap();
                } else {
                    // Sparse metadata fixtures exercise observation only.
                    // They are not valid weights and never start inference.
                    fs::File::create(path)
                        .unwrap()
                        .set_len(asset.bytes.unwrap())
                        .unwrap();
                }
            }
        }
        let configuration = Configuration {
            version: 1,
            python: root.join("python"),
            model_directory: model,
            runtime_directory: runtime,
            threads: 1,
            max_input_tokens: 1024,
            memory_bytes: 4 * 1024 * 1024 * 1024,
        };
        fs::write(
            root.join("decision.json"),
            serde_json::to_vec(&configuration).unwrap(),
        )
        .unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn adapter_initialization_preserves_the_complete_pinned_manifest() {
    let raw: serde_json::Value = serde_json::from_str(ASSETS).unwrap();
    assert_eq!(serde_json::to_value(manifest()).unwrap(), raw);
    assert_eq!(model().repository, raw["model"]["repository"]);
    assert_eq!(model().revision, raw["model"]["revision"]);
}

#[test]
fn installed_identity_stays_bound_to_its_original_observation() {
    let fixture = Fixture::new();
    assert!(!Installed::matches_current(&fixture.0, None).unwrap());
    let installed = Installed::load(&fixture.0).unwrap().unwrap();
    let identity = installed.identity();
    assert!(Installed::matches_current(&fixture.0, Some(&installed)).unwrap());
    let weights = installed
        .configuration()
        .model_directory
        .join(&model().files[0].file);
    fs::rename(&weights, weights.with_extension("original")).unwrap();
    fs::File::create(&weights)
        .unwrap()
        .set_len(model().files[0].bytes.unwrap())
        .unwrap();
    assert!(!Installed::matches_current(&fixture.0, Some(&installed)).unwrap());
    assert_eq!(
        installed.identity(),
        identity,
        "observation must not silently refresh a loaded backend"
    );
    assert_ne!(
        Installed::load(&fixture.0).unwrap().unwrap().identity(),
        identity
    );
}
