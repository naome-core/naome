use super::*;

#[tokio::test]
async fn prepared_control_is_unavailable_until_publication_and_failure_cleans_its_socket() {
    let directory = Directory::new();
    let control = Control::prepare(&directory.0, "ab".repeat(32)).unwrap();
    let socket = control.endpoint.socket.clone();
    assert!(socket.exists());
    assert!(
        request(&directory.0, Operation::Status, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!directory.0.join("control.json").exists());
    drop(control);
    assert!(!socket.exists());
}

#[tokio::test]
async fn dropping_a_prepared_listener_preserves_a_published_replacement() {
    let directory = Directory::new();
    let old = Control::prepare(&directory.0, "ab".repeat(32)).unwrap();
    let current = Control::prepare(&directory.0, "cd".repeat(32)).unwrap();
    current.publish().unwrap();
    drop(old);
    assert_eq!(
        endpoint(&directory.0).unwrap().unwrap().token,
        "cd".repeat(32)
    );
    let serve = async {
        let stream = current.accept().await.unwrap();
        current.respond(stream, 7, true).await.unwrap();
    };
    let (status, ()) = tokio::join!(request(&directory.0, Operation::Status, None), serve);
    let status = status.unwrap().unwrap();
    assert!(status.running);
    assert_eq!(status.accepted_proofs, 7);
}
