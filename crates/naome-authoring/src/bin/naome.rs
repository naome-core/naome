use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use naome_authoring::{AUTHORING_SOURCE_MAX_BYTES, CompileError, CompiledProof, compile};

const USAGE: &str = "usage: naome proof compile <proof.nao>";

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match run(&arguments, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("naome: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(arguments: &[OsString], output: &mut impl Write) -> Result<(), CliError> {
    let [proof, compile_command, path] = arguments else {
        return Err(CliError::Usage);
    };
    if proof != OsStr::new("proof") || compile_command != OsStr::new("compile") {
        return Err(CliError::Usage);
    }

    let path = PathBuf::from(path);
    let source = read_source(&path)?;
    let proof = compile(&source).map_err(|source| CliError::Compile {
        path: path.clone(),
        source,
    })?;
    write_compiled(output, &proof).map_err(|source| CliError::Output { source })
}

fn read_source(path: &Path) -> Result<String, CliError> {
    let file = File::open(path).map_err(|source| CliError::Read {
        path: path.to_owned(),
        source,
    })?;
    let maximum_read =
        u64::try_from(AUTHORING_SOURCE_MAX_BYTES).expect("the authoring source limit fits u64") + 1;
    let mut bytes = Vec::new();
    file.take(maximum_read)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > AUTHORING_SOURCE_MAX_BYTES {
        return Err(CliError::SourceTooLong {
            path: path.to_owned(),
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        });
    }
    String::from_utf8(bytes).map_err(|error| CliError::Read {
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidData, error.utf8_error()),
    })
}

fn write_compiled(output: &mut impl Write, proof: &CompiledProof) -> io::Result<()> {
    write_hex_line(output, "statement_id", proof.statement_id().as_bytes())?;
    write_hex_line(output, "derivation_id", proof.derivation_id().as_bytes())?;
    write_hex_line(output, "proof_id", proof.proof_id().as_bytes())?;
    write_hex_line(output, "canonical_proof", proof.canonical_proof_bytes())
}

fn write_hex_line(output: &mut impl Write, label: &str, bytes: &[u8]) -> io::Result<()> {
    write!(output, "{label} ")?;
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output)
}

#[derive(Debug)]
enum CliError {
    Usage,
    Read { path: PathBuf, source: io::Error },
    SourceTooLong { path: PathBuf, maximum: usize },
    Compile { path: PathBuf, source: CompileError },
    Output { source: io::Error },
}

impl CliError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::Read { .. }
            | Self::SourceTooLong { .. }
            | Self::Compile { .. }
            | Self::Output { .. } => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::Read { path, source } => {
                write!(formatter, "failed to read {}: {source}", display_path(path))
            }
            Self::SourceTooLong { path, maximum } => write!(
                formatter,
                "{}: source exceeds the {maximum}-byte limit",
                display_path(path)
            ),
            Self::Compile { path, source } => {
                write!(formatter, "{}: {source}", display_path(path))
            }
            Self::Output { source } => write!(formatter, "failed to write output: {source}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::Output { source } => Some(source),
            Self::Compile { source, .. } => Some(source),
            Self::Usage | Self::SourceTooLong { .. } => None,
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_exact_and_distinct_from_compilation_failure() {
        let mut output = Vec::new();
        let error = run(&[], &mut output).unwrap_err();
        assert!(matches!(error, CliError::Usage));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.to_string(), USAGE);
        assert!(output.is_empty());
    }

    #[test]
    fn output_failure_retains_its_io_source() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("injected output failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/self-equality.nao");
        let arguments = [
            OsString::from("proof"),
            OsString::from("compile"),
            path.into_os_string(),
        ];
        let error = run(&arguments, &mut FailingWriter).unwrap_err();
        assert!(matches!(error, CliError::Output { .. }));
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn reader_bounds_bytes_before_utf8_decoding() {
        let path = std::env::temp_dir().join(format!(
            "naome-authoring-reader-limit-{}.nao",
            std::process::id()
        ));
        let mut bytes = vec![b' '; AUTHORING_SOURCE_MAX_BYTES];
        bytes.extend_from_slice(&[0xff, 0xff]);
        std::fs::write(&path, bytes).unwrap();
        let error = read_source(&path).unwrap_err();
        std::fs::remove_file(path).unwrap();

        assert!(matches!(
            &error,
            CliError::SourceTooLong {
                maximum: AUTHORING_SOURCE_MAX_BYTES,
                ..
            }
        ));
        assert!(
            !error
                .to_string()
                .contains(&(AUTHORING_SOURCE_MAX_BYTES + 1).to_string())
        );
    }
}
