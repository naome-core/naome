use super::*;
use crate::checkpoint::tests::Directory;

#[test]
fn profile_defaults_and_existing_json_limits_survive_shared_owned_reads() {
    let directory = Directory::new();
    assert_eq!(load(&directory.0).unwrap(), Selection::default());
    let path = directory.0.join("resource-profile.json");
    fs::write(
        &path,
        serde_json::to_vec(&Selection {
            profile: Profile::Light,
            custom: None,
        })
        .unwrap(),
    )
    .unwrap();
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

#[test]
fn invalid_resource_profile_retains_numeric_parse_and_limit_causes() {
    let directory = Directory::new();
    let path = directory.0.join("resource-profile.json");
    fs::write(&path, br#"{"profile":4980991,"custom":null}"#).unwrap();
    let error = load(&directory.0).unwrap_err();
    assert!(matches!(
        error,
        crate::Error::ResourceProfileDecode {
            reason: crate::JsonFault::Data,
            ..
        }
    ));
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(value["reason"], u32::from(crate::JsonFault::Data));
    let invalid = Selection {
        profile: Profile::Custom,
        custom: None,
    };
    fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    let error = load(&directory.0).unwrap_err();
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::ResourceCustomInvalid)
    );
    assert!(!error.retryable());
}
