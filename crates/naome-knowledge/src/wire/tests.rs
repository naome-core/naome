use super::*;
use libp2p::futures::io::Cursor;

fn encoded() -> Vec<u8> {
    let bytes = serde_json::to_vec(
        &Frame::new(Body::Inventory {
            known: None,
            after: None,
            limit: crate::resources::limits().inventory_page,
        })
        .message,
    )
    .unwrap();
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend(bytes);
    framed
}

#[test]
fn current_message_schema_requires_exact_fields_and_types() {
    for body in [
        serde_json::json!({"kind":"Inventory","after":null,"limit":"untrusted"}),
        serde_json::json!({"kind":"Inventory","after":null,"limit":1,"extra":true}),
    ] {
        assert!(
            serde_json::from_value::<Message>(
                serde_json::json!({"compatibility":crate::compatibility(),"body":body})
            )
            .is_err()
        );
    }
    assert_eq!(PROTOCOL.as_ref(), "/naome/knowledge/6");
}

#[tokio::test]
async fn strict_frames_reject_oversize_trailing_and_truncation() {
    let codec = Codec::default();
    assert!(codec.read(&mut Cursor::new(encoded())).await.is_ok());
    let mut trailing = encoded();
    trailing.push(0);
    assert!(
        codec
            .read(&mut Cursor::new(trailing))
            .await
            .unwrap_err()
            .to_string()
            .contains("trailing")
    );
    let mut truncated = encoded();
    truncated.pop();
    assert!(codec.read(&mut Cursor::new(truncated)).await.is_err());
    let header = (frame_limit() as u32 + 1).to_be_bytes().to_vec();
    assert!(
        codec
            .read(&mut Cursor::new(header))
            .await
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
}

#[tokio::test]
async fn frame_custody_is_shared_and_released_after_handling() {
    let codec = Codec::default();
    let other = codec.clone();
    let mut retained = Vec::new();
    for _ in 0..crate::resources::active_limits().inbound_frames {
        retained.push(codec.read(&mut Cursor::new(encoded())).await.unwrap());
    }
    assert!(
        other
            .read(&mut Cursor::new(encoded()))
            .await
            .unwrap_err()
            .to_string()
            .contains("capacity")
    );
    retained.pop();
    assert!(other.read(&mut Cursor::new(encoded())).await.is_ok());
}
