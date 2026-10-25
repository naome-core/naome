use super::*;
use std::io::Cursor;

fn check(bytes: Vec<u8>, ready: bool, expired: bool) -> Result<(), String> {
    let (send, receive) = mpsc::sync_channel(1);
    let token = "ab".repeat(32);
    let deadline = Instant::now()
        + if expired {
            Duration::ZERO
        } else {
            Duration::from_secs(1)
        };
    let result = observe(
        Cursor::new(bytes),
        &token,
        &AtomicBool::new(ready),
        deadline,
        None,
        send,
    );
    drop(receive);
    result
}

#[test]
fn startup_release_requires_begin_checked_readiness_and_exact_instance() {
    let token = "ab".repeat(32);
    let frames = [begin(&token), acknowledge(&token)].concat();
    assert!(check(frames.clone(), true, false).is_ok());
    assert!(
        check(frames, false, false)
            .unwrap_err()
            .contains("readiness mismatch")
    );
    assert!(check(acknowledge(&token), true, false).is_err());
    assert!(
        check(
            [begin(&token), acknowledge(&"cd".repeat(32))].concat(),
            true,
            false
        )
        .is_err()
    );
    assert!(check([begin(&token), begin(&token)].concat(), true, false).is_err());
}

#[test]
fn parent_eof_partial_frame_and_expiry_never_release_startup() {
    let token = "ab".repeat(32);
    assert!(
        check(Vec::new(), true, false)
            .unwrap_err()
            .contains("lifeline closed")
    );
    assert!(
        check(begin(&token), true, false)
            .unwrap_err()
            .contains("lifeline closed")
    );
    assert!(check(b"begin ab".to_vec(), true, false).is_err());
    assert!(
        check([begin(&token), acknowledge(&token)].concat(), true, true)
            .unwrap_err()
            .contains("deadline")
    );
    assert!(
        check(vec![b'x'; MAX_FRAME + 1], true, false)
            .unwrap_err()
            .contains("frame limit")
    );
}

#[test]
fn original_native_custody_cutoff_cannot_be_replaced_by_the_long_startup_clock() {
    let token = "ab".repeat(32);
    let (send, _receive) = mpsc::sync_channel(1);
    let result = observe(
        Cursor::new([begin(&token), acknowledge(&token)].concat()),
        &token,
        &AtomicBool::new(true),
        Instant::now() + crate::resources::limits().startup_timeout,
        Some(0),
        send,
    );
    assert!(result.unwrap_err().contains("lifeline deadline"));
}

#[tokio::test(start_paused = true)]
async fn checked_ready_can_arrive_after_the_control_lifecycle_timeout() {
    let directory = crate::runtime::tests::Directory::new();
    let token = "ab".repeat(32);
    let started = tokio::time::Instant::now();
    let deadline = started + crate::resources::limits().startup_timeout;
    let serve = async {
        // Virtual time tests the startup/RPC distinction. It supplies no
        // native replay, large-corpus, custody or resource qualification.
        tokio::time::sleep(crate::resources::limits().lifecycle_timeout + Duration::from_secs(1))
            .await;
        let control = super::super::Control::bind_token(&directory.0, token.clone()).unwrap();
        let (stream, _) = control.listener.accept().await.unwrap();
        control.respond(stream, 0, true).await.unwrap();
    };
    let (status, ()) = tokio::join!(wait(&directory.0, &token, deadline, || Ok(None)), serve);
    assert!(status.unwrap().running);
    assert!(
        tokio::time::Instant::now() - started
            >= crate::resources::limits().lifecycle_timeout + Duration::from_secs(1)
    );
}

#[tokio::test(start_paused = true)]
async fn startup_expiry_and_wrong_instance_never_reset_the_original_deadline() {
    let directory = crate::runtime::tests::Directory::new();
    let _other = super::super::Control::bind_token(&directory.0, "cd".repeat(32)).unwrap();
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_millis(75);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            wait(&directory.0, &"ab".repeat(32), deadline, || Ok(None))
        )
        .await
        .unwrap()
        .unwrap_err()
        .contains("startup deadline")
    );
    assert!(tokio::time::Instant::now() >= deadline);
    assert!(tokio::time::Instant::now() - started < Duration::from_millis(100));
}
