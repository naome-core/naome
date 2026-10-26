//! Operator presentation; runtime state and persisted owner text stay unchanged.
use super::{Status, owner};
use std::{
    ffi::OsString,
    fmt::Write as _,
    io::{self, IsTerminal, Write as _},
};

pub(super) fn information(arguments: &[OsString]) -> Option<String> {
    match arguments {
        [option] if option == "--version" || option == "-V" => {
            Some(format!("naome {}", env!("CARGO_PKG_VERSION")))
        }
        [option] if option == "--help" || option == "-h" => Some(
            "NAOME checked-knowledge node\n\n\
             Usage:\n  naome start\n  naome stop\n  naome status\n  \
             naome interest <text>\n  naome --help\n  naome --version\n\n\
             Place --json before a command for machine output.\n\
             \nData and configuration:\n\
             NAOME_NODE_DIR selects an isolated node directory. The default is\n\
             $XDG_DATA_HOME/naome, or $HOME/.local/share/naome. First start creates\n\
             config.json. Stop and back up the entire directory before updating.\n\
             Pre-release software supports current formats without legacy migration.\n\
             \nAutomatic computation:\n\
             Budgets adapt automatically. Status reports running, pausing, paused\n\
             or stopped computation and its reason. Pressure closes new computation;\n\
             admitted work drains without new time or work allowances. Bounded\n\
             discovery, checked-artifact serving and lifecycle control remain active.\n\
             No unchecked artifact is admitted. Network allocations retain memory limits.\n\
             \nNative proof learning (opt-in):\n\
             Set runtime.jobs.native_proof_learning=true in config.json while stopped.\n\
             A fresh 1,003,681-parameter CPU graph model learns from accepted local proofs.\n\
             Locally checked peer proofs can supply supported reconstructed traces.\n\
             Training uses fixed question-only curricula and excludes reserved groups.\n\
             Repeated structure can create checked relation definitions.\n\
             Checked definitions supply meaning and stable references for later proofs.\n\
             Model, optimizer and replay stay local; only checked mathematics is gossiped.\n\
             Candidate promotion is bounded; continued improvement is not established.\n\
             \nNetworking and privacy:\n\
             The checked graph is public to compatible peers: do not store secrets.\n\
             mDNS discovers LAN peers; the public IPFS Amino DHT discovers Internet\n\
             peers as a client. Discovery reveals identities and reachable addresses.\n\
             Noise authenticates transport; it does not hide addresses or timing.\n\
             config.json discovery.internet, discovery.dht and discovery.mdns control\n\
             discovery. Set internet=false for an isolated DHT with its own bootstrap\n\
             peers. Keep allow_private_addresses disabled for public operation."
                .into(),
        ),
        _ => None,
    }
}

pub(super) struct Arguments<'a> {
    pub command: &'a str,
    pub text: Option<&'a str>,
    pub json: bool,
    pub startup_handoff: bool,
}

impl<'a> Arguments<'a> {
    pub fn parse(arguments: &'a [OsString]) -> Result<Self, String> {
        // Only a leading option selects output, so `interest --json` is text.
        let (json, arguments) = match arguments.split_first() {
            Some((option, rest)) if option == "--json" => (true, rest),
            _ => (false, arguments),
        };
        let (startup_handoff, arguments) = match arguments.split_first() {
            Some((option, rest)) if json && option == "--startup-handoff" => (true, rest),
            _ => (false, arguments),
        };
        let (command, text) = match arguments {
            [command] if matches!(command.to_str(), Some("start" | "stop" | "status")) => {
                (command.to_str().expect("matched UTF-8 command"), None)
            }
            [command, text] if command == "interest" => {
                let text = text.to_str().ok_or("interest must be valid UTF-8")?;
                owner::validate(text)?;
                ("interest", Some(text))
            }
            _ => return Err("usage: naome [--json] start | stop | status | interest <text>\nplace --json before the command for machine output".into()),
        };
        if startup_handoff && command != "start" {
            return Err("startup handoff is only valid for --json start".into());
        }
        Ok(Self {
            command,
            text,
            json,
            startup_handoff,
        })
    }
}

pub(super) fn print(command: &str, json: bool, status: &Status) -> Result<(), String> {
    let stdout = io::stdout();
    let color = stdout.is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
    let output = if json {
        format!(
            "{}\n",
            serde_json::to_string(status).map_err(|error| error.to_string())?
        )
    } else {
        human(command, status, color)
    };
    stdout
        .lock()
        .write_all(output.as_bytes())
        .map_err(|error| error.to_string())
}

fn human(command: &str, status: &Status, color: bool) -> String {
    let green = if color { "\x1b[32m" } else { "" };
    let red = if color { "\x1b[31m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let action = match command {
        "start" => format!("{green}✓{reset} Start complete"),
        "stop" => format!("{green}✓{reset} Stop complete"),
        "interest" => format!("{green}✓{reset} Interest saved"),
        _ => "Node status".into(),
    };
    let state = if status.running {
        format!("{green}● Running{reset}")
    } else {
        format!("{red}○ Stopped{reset}")
    };
    let verification = match status.artifact_verification {
        super::ArtifactVerification::Checked => "checked in this run",
        super::ArtifactVerification::NotRun => "stored; verification not run",
    };
    let computation = match status.computation {
        crate::resources::ComputationState::Stopped => "Stopped",
        crate::resources::ComputationState::Running => "Running",
        crate::resources::ComputationState::Pausing => {
            "Pausing automatically (finishing current work)"
        }
        crate::resources::ComputationState::Paused => {
            "Paused automatically (network remains available)"
        }
    };
    let mut output = format!(
        "\n  NAOME  {action}\n\n  State            {state}\n  Computation      {computation}\n  Accepted artifacts {} ({verification})\n",
        status.accepted_artifacts,
    );
    if let Some(reason) = &status.computation_reason {
        let reason = reason
            .chars()
            .flat_map(char::escape_default)
            .collect::<String>();
        // The reason originates in the local resource policy; retain terminal
        // escaping so passive diagnostics cannot acquire display authority.
        writeln!(output, "    Computation reason: {reason}").expect("String write");
    }
    if matches!(
        status.computation,
        crate::resources::ComputationState::Pausing | crate::resources::ComputationState::Paused
    ) {
        let advice = match status.computation_reason.as_deref() {
            Some("disk pressure") => Some("Free disk space on the node's filesystem."),
            Some(
                "memory pressure"
                | "node process tree memory pressure"
                | "operating system memory pressure",
            ) => Some("Reduce memory use on this host if the pause persists."),
            Some("operating system power saving") => {
                Some("Check the host's power-saving setting if computation should resume.")
            }
            Some("operating system thermal pressure") => Some("Let the host cool down."),
            Some("sustained external CPU pressure") => Some("Let other CPU-intensive work finish."),
            Some("hardware observation unavailable") => {
                Some("Hardware observations are retried automatically.")
            }
            _ => None,
        };
        if let Some(advice) = advice {
            writeln!(output, "    {advice}").expect("String write");
        }
        output.push_str("    Computation resumes automatically after stable recovery.\n");
    }
    output.push_str("\n  Interest\n");
    if status.interest.is_empty() {
        output.push_str("    (none)\n");
    } else {
        for line in status.interest.split('\n') {
            output.push_str("    │ ");
            for character in line.chars() {
                // Escape C0/C1, carriage returns, terminal sequences and Unicode
                // direction/line controls. Newlines get owned, indented rows.
                if character.is_control()
                    || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                {
                    write!(output, "{}", character.escape_default()).expect("String write");
                } else {
                    output.push(character);
                }
            }
            output.push('\n');
        }
    }
    output.push('\n');
    output
}

#[cfg(test)]
mod tests;
