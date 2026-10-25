//! Developer-only program verification. Input is spooled on disk; neither its
//! total command count nor the constructed formula DAG is held in memory.
use super::*;
use naome_checker::{
    ArtifactState,
    program::{Engine, Error as CheckError},
};
use naome_proof::program::{Command, RECORD_BYTES};
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub(super) enum ProgramError {
    Check(CheckError),
    RecordLimit {
        line: u64,
        command: u64,
    },
    Syntax {
        line: u64,
        command: u64,
        column: usize,
        category: &'static str,
        message: String,
    },
    Incomplete {
        commands: u64,
        checked_commands: u64,
    },
}
impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check(error) => error.fmt(f),
            Self::RecordLimit { line, .. } => write!(
                f,
                "program line {line} exceeds the {RECORD_BYTES}-byte command limit"
            ),
            Self::Syntax {
                line,
                column,
                message,
                ..
            } => write!(f, "program line {line}, column {column}: {message}"),
            Self::Incomplete {
                checked_commands,
                commands,
            } => write!(
                f,
                "program has no completely checked final seal ({checked_commands}/{commands} commands checked)"
            ),
        }
    }
}
impl Error for ProgramError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Check(error) => Some(error),
            _ => None,
        }
    }
}
impl ProgramError {
    pub(super) fn json(&self) -> serde_json::Value {
        let proof = match self {
            Self::Check(error) => error.diagnostic(),
            _ => None,
        };
        let (code, phase, details) = match self {
            Self::Check(_) if proof.is_some() => ("NAO0010", "check", serde_json::Value::Null),
            Self::Check(error) => (
                "program.execution",
                "execution",
                serde_json::to_value(error).expect("program error serializes"),
            ),
            Self::RecordLimit { line, command } => (
                "program.command_byte_limit",
                "parse",
                serde_json::json!({"line":line,"command":command,"maximum":RECORD_BYTES}),
            ),
            Self::Syntax {
                line,
                command,
                column,
                category,
                ..
            } => (
                "program.syntax",
                "parse",
                serde_json::json!({"line":line,"command":command,"column":column,"category":category}),
            ),
            Self::Incomplete {
                commands,
                checked_commands,
            } => (
                "program.incomplete",
                "check",
                serde_json::json!({"commands":commands,"checked_commands":checked_commands,"requires_final_seal":true}),
            ),
        };
        serde_json::json!({"schema_version":1,"ok":false,"phase":phase,"diagnostic":{"code":code,"message":self.to_string(),"proof":proof,"details":details},"message":null})
    }
}

pub(super) fn run(path: &Path, json: bool, output: &mut impl Write) -> Result<(), CliError> {
    let program_error = |source| CliError::Program {
        path: path.to_owned(),
        source,
    };
    let check_error = |error| program_error(ProgramError::Check(error));
    let file = File::open(path).map_err(|source| CliError::Read {
        path: path.to_owned(),
        source,
    })?;
    // SQLite's empty filename creates a private temporary on-disk database and
    // deletes it on close. The engine still applies its ordinary cache bounds.
    let connection =
        rusqlite::Connection::open("").map_err(|error| check_error(CheckError::Storage(error)))?;
    let mut engine = Engine::open(connection).map_err(&check_error)?;
    let mut reader = BufReader::new(file);
    let mut line = 0;
    let mut commands = 0;
    let mut pending = Vec::new();
    loop {
        let mut bytes = Vec::new();
        let count = (&mut reader)
            .take((RECORD_BYTES + 3) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|source| CliError::Read {
                path: path.to_owned(),
                source,
            })?;
        if count == 0 {
            break;
        }
        line += 1;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.len() > RECORD_BYTES {
            return Err(program_error(ProgramError::RecordLimit {
                line,
                command: commands,
            }));
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let command: Command = serde_json::from_slice(&bytes).map_err(|error| {
            let category = match error.classify() {
                serde_json::error::Category::Io => "io",
                serde_json::error::Category::Syntax => "syntax",
                serde_json::error::Category::Data => "data",
                serde_json::error::Category::Eof => "eof",
            };
            program_error(ProgramError::Syntax {
                line,
                command: commands,
                column: error.column(),
                category,
                message: error.to_string(),
            })
        })?;
        pending.push(command);
        commands += 1;
        if pending.len() == 64 {
            engine.append_group(&pending).map_err(&check_error)?;
            pending.clear();
        }
    }
    engine.append_group(&pending).map_err(&check_error)?;
    let context = ArtifactState::new();
    while engine
        .advance(512, 1024 * 1024, &context)
        .map_err(&check_error)?
    {}
    let status = engine.status().map_err(&check_error)?;
    if !status.fully_checked {
        return Err(program_error(ProgramError::Incomplete {
            commands: status.commands,
            checked_commands: status.checked_commands,
        }));
    }
    while !engine.prepare_export(512).map_err(&check_error)? {}
    let checked = engine.checked().map_err(check_error)?;
    if json {
        writeln!(output,"{}",serde_json::json!({"schema_version":1,"ok":true,"kind":"program","proof_id":hex(checked.manifest().proof_id().as_bytes()),"statement_id":hex(checked.manifest().statement_id().as_bytes()),"derivation_id":hex(checked.manifest().derivation_id().as_bytes()),"manifest":checked.manifest()}))
    } else { (|| -> io::Result<()> {
        write_hex_line(output,"proof_id",checked.manifest().proof_id().as_bytes())?;
        write_hex_line(output,"statement_id",checked.manifest().statement_id().as_bytes())?;
        write_hex_line(output,"derivation_id",checked.manifest().derivation_id().as_bytes())
    })() }.map_err(|source|CliError::Output {source})
}
