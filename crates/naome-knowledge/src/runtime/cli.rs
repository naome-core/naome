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
             naome interest <text>\n  naome resources [history [after]]\n  \
             naome wallet address\n  naome wallet challenge <audience>\n  \
             naome wallet prove <challenge.json>\n  \
             naome wallet verify <address> <challenge.json> <proof.json>\n  \
             naome wallet connect <ledger-dir> <wallet-address>\n  \
             naome wallet connection\n  naome wallet disconnect\n  \
             naome wallet test-coins init <ledger-dir> <units>\n  \
             naome wallet test-coins balance <ledger-dir> [address]\n  \
             naome wallet test-coins send|prepare <ledger-dir> <recipient> <units>\n  \
             naome wallet test-coins submit <ledger-dir> <transaction.json>\n  \
             naome wallet test-coins authorize|revoke <ledger-dir> <node-wallet-address>\n  \
             naome --version\n\n\
             Place --json before a command for machine output.\n\
             NAOME_NODE_DIR selects the local node directory.\n\
             Resource budgets adapt automatically."
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
    let verification = match status.proof_verification {
        super::ProofVerification::Checked => "checked in this run",
        super::ProofVerification::NotRun => "stored; verification not run",
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
        "\n  NAOME  {action}\n\n  State            {state}\n  Computation      {computation}\n  Accepted proofs  {} ({verification})\n",
        status.accepted_proofs,
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
