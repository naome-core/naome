use super::*;
#[test]
fn native_probe_bounds_output_and_time_then_reaps_before_reuse() {
    let now = Instant::now();
    assert!(
        run("/bin/sleep", &["10"], 64, now + Duration::from_millis(20))
            .unwrap_err()
            .contains("deadline")
    );
    assert!(now.elapsed() < Duration::from_secs(1));
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match run("/bin/echo", &["ready"], 64, deadline) {
            Ok(output) => {
                assert_eq!(output, "ready\n");
                break;
            }
            Err(error) if error.contains("cleanup pending") && Instant::now() < deadline => {
                std::thread::yield_now()
            }
            other => panic!("probe did not recover: {other:?}"),
        }
    }
    assert!(
        run(
            "/bin/echo",
            &["too much output"],
            1,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap_err()
        .contains("capacity")
    );
    assert!(
        run("/bin/echo", &["unused"], 64, Instant::now())
            .unwrap_err()
            .contains("deadline")
    );
}
