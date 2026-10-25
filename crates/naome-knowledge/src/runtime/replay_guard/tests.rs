use super::*;

fn descriptor() -> Descriptor {
    Descriptor {
        nonce: "ab".repeat(32),
        deadline: 100 * 1_000_000_000,
    }
}
fn frame(sequence: u64, sampled: u64) -> Vec<u8> {
    format!("grant {} {sequence} {sampled}\n", "ab".repeat(32)).into_bytes()
}
#[test]
fn descriptor_preserves_original_cutoff_and_rejects_invalid_windows() {
    let nonce = "ab".repeat(32);
    assert!(Descriptor::parse(&format!("{nonce}:{}", active_ns()), 1).is_ok());
    for value in [
        format!("{nonce}:1"),
        format!("{nonce}:{}", active_ns() + 2),
        format!("{nonce}:invalid"),
        "00:100".into(),
        format!("{}:100", "zz".repeat(32)),
    ] {
        assert!(Descriptor::parse(&value, 1).is_err());
    }
}
#[test]
fn grants_require_exact_nonce_order_and_fresh_sample_clocks() {
    let mut state = Grants::new(descriptor(), 1);
    assert!(state.push(&frame(1, 1), 2).unwrap());
    assert!(state.push(&frame(2, 2), 3).unwrap());
    for bad in [frame(2, 2), frame(4, 3), frame(3, 4), frame(3, 1)] {
        assert!(state.push(&bad, 3).is_err());
        state.frame.clear();
    }
    let wrong = format!("grant {} 3 3\n", "cd".repeat(32));
    assert!(state.push(wrong.as_bytes(), 3).is_err());
}
#[test]
fn partial_and_oversized_frames_never_admit_a_grant() {
    let mut state = Grants::new(descriptor(), 1);
    let value = frame(1, 1);
    assert!(!state.push(&value[..value.len() - 1], 2).unwrap());
    assert_eq!(state.sequence, 0);
    assert!(state.push(b"\n", 2).unwrap());
    assert_eq!(state.sequence, 1);
    assert!(state.push(&[b'x'; MAX_FRAME + 1], 3).is_err());
}
#[test]
fn silence_and_original_expiry_never_renew_admission() {
    let mut state = Grants::new(descriptor(), 1);
    assert!(state.check(fresh_ns() + 2, 1).is_err());
    assert!(state.push(&frame(1, 1), 2).unwrap());
    assert!(state.check(fresh_ns() + 2, 1).is_err());
    assert!(
        state
            .push(&frame(2, state.deadline), state.deadline)
            .is_err()
    );
}
#[test]
fn final_usage_and_both_reserves_preserve_total_rss_limit() {
    assert_eq!(own_rss_bytes() + 2 * 64 * 1024 * 1024, 512 * 1024 * 1024);
    assert!(check_usage(1, own_rss_bytes(), 2).is_ok());
    assert!(check_usage(1, own_rss_bytes() + 1, 2).is_err());
    assert!(check_usage(1, 0, 2).is_err());
    assert!(check_usage(2, own_rss_bytes(), 2).is_err());
}
