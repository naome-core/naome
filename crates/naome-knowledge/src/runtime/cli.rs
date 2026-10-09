//! Operator presentation; runtime state and persisted owner text stay unchanged.
use super::{Status, owner};
use std::{
    ffi::OsString,
    fmt::Write as _,
    io::{self, IsTerminal, Write as _},
};

pub(super) struct Arguments<'a> {
    pub command: &'a str,
    pub text: Option<&'a str>,
    pub json: bool,
}

impl<'a> Arguments<'a> {
    pub fn parse(arguments: &'a [OsString]) -> Result<Self, String> {
        // Only a leading option selects output, so `interest --json` is text.
        let (json, arguments) = match arguments.split_first() {
            Some((option, rest)) if option == "--json" => (true, rest),
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
        Ok(Self {
            command,
            text,
            json,
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
    let mut output = format!(
        "\n  NAOME  {action}\n\n  State            {state}\n  Accepted proofs  {}\n\n  Interest\n",
        status.accepted_proofs,
    );
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
mod tests {
    use super::*;

    #[test]
    fn output_option_does_not_consume_literal_interest() {
        for (args, json) in [
            (vec!["interest", "--json"], false),
            (vec!["--json", "interest", "--json"], true),
        ] {
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            let parsed = Arguments::parse(&args).unwrap();
            assert_eq!(parsed.text, Some("--json"));
            assert_eq!(parsed.json, json);
        }
        for args in [vec!["status", "--json"], vec!["--json"], vec!["interest"]] {
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert!(Arguments::parse(&args).is_err());
        }
    }

    #[test]
    fn untrusted_interest_cannot_style_or_rewrite_operator_rows() {
        let status = Status {
            running: false,
            accepted_proofs: 3,
            interest: "λ 🦀\n\r\t\x1b[32m\x1b]8;;link\x07\u{009b}2J\u{202e}x\n".into(),
        };
        let rendered = human("status", &status, false);
        assert!(rendered.contains("    │ λ 🦀\n"));
        assert!(
            rendered
                .contains("\\r\\t\\u{1b}[32m\\u{1b}]8;;link\\u{7}\\u{9b}2J\\u{202e}x\n    │ \n")
        );
        assert!(!rendered.chars().any(|c| c.is_control() && c != '\n'));
        assert_eq!(
            serde_json::from_str::<Status>(&serde_json::to_string(&status).unwrap())
                .unwrap()
                .interest,
            status.interest
        );
    }
}
