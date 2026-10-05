use std::path::{Path, PathBuf};
use std::process::Command;

fn git(directory: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(directory)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

fn watch_metadata(path: &str) {
    let mut path = PathBuf::from(path.trim());
    while !path.exists() {
        if !path.pop() {
            return;
        }
    }
    println!("cargo:rerun-if-changed={}", path.display());
}

fn source_identity(directory: &Path) -> (String, bool) {
    let Some(root) = git(directory, &["rev-parse", "--show-toplevel"]) else {
        return ("unavailable".into(), false);
    };
    let root = Path::new(root.trim());
    // Removing a watched untracked file must refresh a dirty build identity.
    if let Some(files) = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    ) {
        for file in files.split('\0').filter(|file| !file.is_empty()) {
            println!("cargo:rerun-if-changed={}", root.join(file).display());
        }
    }
    // Cargo must refresh an identity after commit, checkout, stage or restore,
    // even when the changed file is outside this private crate.
    let mut metadata = vec![
        "HEAD".to_owned(),
        "index".to_owned(),
        "packed-refs".to_owned(),
    ];
    if let Some(reference) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
        metadata.push(reference.trim().to_owned());
    }
    for item in metadata {
        if let Some(path) = git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", &item],
        ) {
            watch_metadata(&path);
        }
    }
    let tree = git(root, &["rev-parse", "HEAD^{tree}"])
        .map(|tree| tree.trim().to_owned())
        .unwrap_or_else(|| "unavailable".into());
    let clean = git(root, &["status", "--porcelain", "--untracked-files=all"])
        .is_some_and(|status| status.trim().is_empty());
    (tree, clean)
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    let compiler = std::env::var("RUSTC").expect("Cargo supplies its Rust compiler");
    let output = std::process::Command::new(compiler)
        .arg("--version")
        .output()
        .expect("compiler identity is available");
    assert!(output.status.success());
    let version = String::from_utf8(output.stdout).expect("Rust version is UTF-8");
    println!("cargo:rustc-env=NAOME_LAB_COMPILER={}", version.trim());
    let directory = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let (tree, clean) = source_identity(&directory);
    println!("cargo:rustc-env=NAOME_LAB_SOURCE_TREE={tree}");
    println!("cargo:rustc-env=NAOME_LAB_SOURCE_CLEAN={clean}");
}
