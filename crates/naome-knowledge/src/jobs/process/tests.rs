use super::*;

#[tokio::test]
async fn cancelled_partial_result_remains_framed_and_large_output_drains_through_eof() {
    let (mut output, input) = tokio::io::duplex(64);
    let cleanup = b"{\"event\":\"cleanup_complete\",\"id\":1}\n";
    output.write_all(cleanup).await.unwrap();
    let mut frames = FrameReader::new(input);
    assert_eq!(frames.next().await.unwrap().unwrap(), cleanup);
    // The pipe has insufficient capacity for the result. Consume a prefix,
    // cancel that read, then keep the prefix while draining the rest.
    let prefix = b"{\"event\":\"result\",\"id\":1,\"output\":\"";
    output.write_all(prefix).await.unwrap();
    let mut waiting = Box::pin(frames.next());
    assert!(libp2p::futures::poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    assert_eq!(frames.partial, prefix);
    let mut remainder = vec![b'x'; 64 * 1024];
    remainder.extend_from_slice(b"\"}\n");
    let expected = [prefix.as_slice(), remainder.as_slice()].concat();
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
