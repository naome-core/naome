use super::*;

#[tokio::test]
async fn cancelled_partial_result_remains_framed_and_large_output_drains_through_eof() {
    let (mut output, input) = tokio::io::duplex(64);
    let mut cleanup = serde_json::to_vec(&Frame::CleanupComplete { id: 1 }).unwrap();
    cleanup.push(b'\n');
    output.write_all(&cleanup).await.unwrap();
    let mut frames = FrameReader::new(input);
    assert_eq!(frames.next().await.unwrap().unwrap(), cleanup);
    // The pipe has insufficient capacity for the result. Consume a prefix,
    // cancel that read, then keep the prefix while draining the rest.
    let mut expected = serde_json::to_vec(&Frame::Result {
        id: 1,
        output: Output::Proof {
            proof: "x".repeat(64 * 1024),
            helpers: Vec::new(),
        },
    })
    .unwrap();
    expected.push(b'\n');
    let prefix = expected[..32].to_vec();
    output.write_all(&prefix).await.unwrap();
    let mut waiting = Box::pin(frames.next());
    assert!(libp2p::futures::poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    assert_eq!(frames.partial, prefix);
    let remainder = expected[32..].to_vec();
    let supplier = tokio::spawn(async move {
        output.write_all(&remainder).await.unwrap();
    });
    let result = tokio::time::timeout(Duration::from_secs(2), frames.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result, expected);
    assert!(frames.next().await.unwrap().is_none());
    supplier.await.unwrap();
}

#[test]
fn worker_frame_rejects_unknown_codes_and_noncanonical_payloads() {
    use crate::outcome::WorkerFrame;
    let code = u32::from(WorkerFrame::CleanupComplete);
    let valid = format!("[{code},{{\"id\":1}}]");
    assert!(matches!(
        serde_json::from_str::<Frame>(&valid),
        Ok(Frame::CleanupComplete { id: 1 })
    ));
    for invalid in [
        format!("[{},{{\"id\":1}}]", code + 100),
        format!("[{code},{{\"id\":1,\"extra\":0}}]"),
        format!("[{code},{{\"id\":1}},0]"),
        format!("[{code},{{}}]"),
    ] {
        assert!(
            serde_json::from_str::<Frame>(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn truncated_provider_frame_has_a_machine_readable_cause() {
    let (mut output, input) = tokio::io::duplex(64);
    output.write_all(b"[1,{\"id\":1}").await.unwrap();
    drop(output);
    let mut frames = FrameReader::new(input);
    assert_eq!(frames.next().await, Err(WorkerFailure::FrameTruncated));
}
