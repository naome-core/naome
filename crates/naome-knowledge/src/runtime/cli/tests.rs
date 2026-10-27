mod computation;
use super::*;

#[test]
fn information_options_and_commands_are_exact() {
    for option in ["--version", "-V"] {
        assert_eq!(
            information(&[OsString::from(option)]),
            Some(format!("naome {}", env!("CARGO_PKG_VERSION")))
        );
    }
    for option in ["--help", "-h"] {
        let help = information(&[OsString::from(option)]).unwrap();
        let commands = help
            .lines()
            .filter_map(|line| line.strip_prefix("  naome "))
            .collect::<Vec<_>>();
        assert_eq!(commands, ["start", "stop", "status", "--help", "--version"]);
        assert!(help.contains("--json") && help.contains("adapt automatically"));
    }
    assert!(information(&["--help", "start"].map(OsString::from)).is_none());
}

#[test]
fn startup_handoff_is_explicit_and_bound_to_start() {
    let arguments = ["--json", "--startup-handoff", "start"].map(OsString::from);
    let parsed = Arguments::parse(&arguments).unwrap();
    assert!(parsed.json && parsed.startup_handoff);
    assert_eq!(parsed.command, "start");
    for command in ["stop", "status"] {
        assert!(
            Arguments::parse(&["--json", "--startup-handoff", command].map(OsString::from))
                .is_err()
        );
    }
    assert!(
        !Arguments::parse(&["--json", "start"].map(OsString::from))
            .unwrap()
            .startup_handoff
    );
}
