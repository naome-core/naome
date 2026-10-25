use super::*;

#[test]
fn usage_is_exact_and_distinct_from_compilation_failure() {
    for arguments in [
        Vec::new(),
        vec![OsString::from("compile"), OsString::from("proof.nao")],
    ] {
        let mut output = Vec::new();
        let error = run(&arguments, &mut output).unwrap_err();
        assert!(matches!(error, CliError::Usage));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.to_string(), USAGE);
        assert!(output.is_empty());
    }
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

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/self-equality.nao");
    let arguments = [OsString::from("proof"), path.into_os_string()];
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
    let error = read_source(&path, AUTHORING_SOURCE_MAX_BYTES).unwrap_err();
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
