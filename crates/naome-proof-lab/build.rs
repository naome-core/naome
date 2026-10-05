fn main() {
    let compiler = std::env::var("RUSTC").expect("Cargo supplies its Rust compiler");
    let output = std::process::Command::new(compiler)
        .arg("--version")
        .output()
        .expect("compiler identity is available");
    assert!(output.status.success());
    let version = String::from_utf8(output.stdout).expect("Rust version is UTF-8");
    println!("cargo:rustc-env=NAOME_LAB_COMPILER={}", version.trim());
}
