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

#[test]
fn worker_failure_frame_preserves_registered_cause() {
    let original = crate::Error::MemoryOverload {
        requested: 3,
        charged: 4,
        budget: 5,
    };
    let code = crate::outcome::JobFailureCode::from_owner(&original);
    let frame = Frame::Failed { id: 42, code };
    let bytes = serde_json::to_vec(&frame).unwrap();
    assert!(
        matches!(serde_json::from_slice::<Frame>(&bytes), Ok(Frame::Failed { id: 42, code: actual }) if u32::from(actual) == original.code())
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    invalid[1]["code"] = 0xffff_ffff_u32.into();
    assert!(serde_json::from_value::<Frame>(invalid).is_err());
}

#[test]
fn durable_grants_preserve_closed_invalid_and_identity_failures() {
    fn control(receiver: sync_channel::Receiver<Vec<u8>>) -> WorkerControl {
        WorkerControl {
            id: 7,
            current_unit: 0,
            receiver,
            descendants: Vec::new(),
            blocked_nanos: 0,
        }
    }
    let (sender, receiver) = sync_channel::sync_channel(1);
    drop(sender);
    assert_eq!(
        control(receiver).grant_data(1),
        Err(WorkerFailure::GrantClosed)
    );
    let (sender, receiver) = sync_channel::sync_channel(1);
    sender.send(b"invalid".to_vec()).unwrap();
    assert_eq!(
        control(receiver).grant_data(1),
        Err(WorkerFailure::GrantDecoding)
    );
    let (sender, receiver) = sync_channel::sync_channel(1);
    sender
        .send(
            serde_json::to_vec(&Grant {
                id: 7,
                next: 2,
                data: None,
            })
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        control(receiver).grant_data(1),
        Err(WorkerFailure::GrantIdentity)
    );
    let (sender, receiver) = sync_channel::sync_channel(1);
    sender
        .send(
            serde_json::to_vec(&Grant {
                id: 7,
                next: 1,
                data: None,
            })
            .unwrap(),
        )
        .unwrap();
    assert_eq!(control(receiver).grant_data(1), Ok(None));
}

#[test]
fn provider_lifeline_reports_truncation_and_capacity_with_codes() {
    let mut truncated = std::io::Cursor::new(b"partial".as_slice());
    assert_eq!(
        line(&mut truncated, 32).unwrap_err(),
        crate::Error::from(WorkerFailure::FrameTruncated)
    );
    let mut oversized = std::io::Cursor::new(b"abcd\n".as_slice());
    let error = line(&mut oversized, 3).unwrap_err();
    assert_eq!(
        error,
        crate::Error::ResearchMismatch {
            code: crate::ResearchFailure::ProviderPipeCapacity,
            expected: 3,
            actual: 5,
        }
    );
    let json = serde_json::to_value(error).unwrap();
    assert_eq!(
        json["code"],
        u32::from(crate::ResearchFailure::ProviderPipeCapacity)
    );
    assert_eq!(json["actual"], 5);
    let mut valid = std::io::Cursor::new(b"ok\nnext\n".as_slice());
    assert_eq!(line(&mut valid, 3).unwrap(), b"ok\n");
    assert_eq!(line(&mut valid, 5).unwrap(), b"next\n");
}

#[test]
fn cleanup_failure_retains_signal_stage_and_os_cause() {
    let signal = process_error(
        crate::ResearchFailure::ProviderTermSignal,
        std::io::Error::from_raw_os_error(nix::errno::Errno::EACCES as i32),
    );
    let failure = combine_cleanup(
        crate::ResearchFailure::ProviderReapDeadline.into(),
        &[signal],
    );
    let json = serde_json::to_value(&failure).unwrap();
    assert_eq!(
        json["code"],
        u32::from(crate::ResearchFailure::MultipleFailures)
    );
    assert_eq!(
        json["primary"]["code"],
        u32::from(crate::ResearchFailure::ProviderReapDeadline)
    );
    assert_eq!(
        json["cleanup"]["code"],
        u32::from(crate::ResearchFailure::ProviderTermSignal)
    );
    assert_eq!(
        json["cleanup"]["cause"]["kind"],
        u32::from(crate::IoFaultKind::PermissionDenied)
    );
    assert_eq!(
        json["cleanup"]["cause"]["os_code"],
        nix::errno::Errno::EACCES as i32
    );
    assert!(failure.fatal());
}

#[test]
fn cleanup_failure_frame_carries_a_registered_cause() {
    let cause = JobFailureCode::from_owner(&crate::Error::from(
        crate::ResearchFailure::ProviderReapDeadline,
    ));
    let bytes = serde_json::to_vec(&Frame::CleanupFailed { id: 42, cause }).unwrap();
    assert!(
        matches!(serde_json::from_slice::<Frame>(&bytes), Ok(Frame::CleanupFailed { id: 42, cause: actual }) if actual == cause)
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    invalid[1]["cause"] = 0xffff_ffff_u32.into();
    assert!(serde_json::from_value::<Frame>(invalid).is_err());
}
