use super::*;
#[test]
fn sparse_maps_are_charged_for_nodes_and_rejected_before_tree_allocation() {
    let source = format!("{}0{}", "{\"\":".repeat(100), "}".repeat(100));
    // Measured with the pinned Rust/serde_json allocator: this shape retains
    // 63,200 bytes, although its entire source is only 501 bytes.
    let bound = allocation_bound(source.as_bytes(), usize::MAX).unwrap();
    assert!(bound >= 63_200);
    assert_eq!(
        allocation_bound(source.as_bytes(), 63_199),
        Err(Error::InputLimit("CLI JSON allocation limit"))
    );
    let command = QueuedCommand::from_value(serde_json::from_str(&source).unwrap());
    let (parsed, memory) = command.parse().unwrap();
    assert_eq!(parsed, serde_json::from_str::<Value>(&source).unwrap());
    drop(memory);
}
#[test]
fn maximum_escaped_sources_remain_supported_and_syntax_stays_strict() {
    let value = serde_json::json!({"command":"produce","source":"\u{1}".repeat(crate::resources::limits().producer_bytes),"request":"escaped"});
    let command = QueuedCommand::from_value(value.clone());
    assert!(command.bytes.len() < crate::resources::limits().command_bytes);
    let (parsed, _memory) = command.parse().unwrap();
    assert_eq!(parsed, value);
    for bytes in [b"{} {}".as_slice(), b"{\"a\":", b"[1,]", b"NaN"] {
        assert!(matches!(
            allocation_bound(bytes, usize::MAX),
            Err(Error::InvalidInput(_))
        ));
    }
}
