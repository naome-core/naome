use super::*;
use crate::checkpoint::tests::Directory;

#[test]
fn profile_defaults_and_existing_json_limits_survive_shared_owned_reads() {
    let directory = Directory::new();
    assert_eq!(load(&directory.0).unwrap(), Selection::default());
    let path = directory.0.join("resource-profile.json");
    fs::write(&path, br#"{"profile":"light","custom":null}"#).unwrap();
    assert_eq!(load(&directory.0).unwrap().profile, Profile::Light);
    fs::write(&path, b" ".repeat(4097)).unwrap();
    assert!(load(&directory.0).is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(directory.0.join("absent"), &path).unwrap();
    assert!(load(&directory.0).is_err());
}

#[test]
fn profile_fifo_is_rejected_without_waiting_for_a_writer() {
    const TEST: &str =
        "resources::adaptive::tests::files::profile_fifo_is_rejected_without_waiting_for_a_writer";
    const INPUT: &str = "NAOME_PROFILE_FIFO_TEST_DIRECTORY";
    if let Some(directory) = std::env::var_os(INPUT) {
        assert!(load(Path::new(&directory)).is_err());
        return;
    }
    let directory = Directory::new();
    nix::unistd::mkfifo(
        &directory.0.join("resource-profile.json"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env(INPUT, &directory.0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(status.success(), "{output:?}");
            break;
        }
        if std::time::Instant::now() >= until {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("resource profile open waited for a FIFO writer");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
