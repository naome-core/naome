use super::*;
use crate::AppendPhase;
use crate::fault_io::{ScriptedIo, Trace, all_append_faults};

const PREFIX: &[u8] = b"research-test-genesis-and-bound-limits-v1";
fn limits() -> Limits {
    Limits {
        payload_bytes: 128,
        frames: 10,
        file_bytes: 4096,
    }
}

#[derive(Clone)]
struct MemoryAnchor {
    position: Position,
    fail: Option<bool>,
}
impl Anchor for MemoryAnchor {
    fn position(&self) -> Position {
        self.position
    }
    fn advance(&mut self, prior: Position, next: Position) -> Result<(), Error> {
        assert_eq!(self.position, prior);
        if self.fail == Some(false) {
            return Err(Error::Io(std::io::Error::other("anchor before durability")));
        }
        self.position = next;
        if self.fail == Some(true) {
            return Err(Error::Io(std::io::Error::other("anchor response loss")));
        }
        Ok(())
    }
}
fn anchor() -> MemoryAnchor {
    MemoryAnchor {
        position: genesis_position(PREFIX),
        fail: None,
    }
}
fn empty() -> Log<ScriptedIo, MemoryAnchor> {
    Log::empty(
        ScriptedIo::new(PREFIX.to_vec(), None),
        anchor(),
        PREFIX,
        limits(),
    )
    .unwrap()
}

#[test]
fn every_append_fault_never_publishes_or_reuses_uncertain_owner() {
    let payload = b"complete public record";
    for fault in all_append_faults(4 + payload.len(), 32) {
        let io = ScriptedIo::new(PREFIX.to_vec(), Some(fault.clone()));
        let mut log = Log::empty(io, anchor(), PREFIX, limits()).unwrap();
        assert!(log.append(payload).is_err(), "{fault:?}");
        assert!(matches!(log.position(), Err(Error::Poisoned)));
        assert!(matches!(log.append(payload), Err(Error::Poisoned)));
        let durable = log.file.durable.clone();
        let anchor = log.anchor.clone();
        let complete_frame = PREFIX.len() + 4 + payload.len() + 32;
        let reopened = Log::replay(
            ScriptedIo::new(durable.clone(), None),
            anchor,
            PREFIX,
            limits(),
            |_| Ok(()),
        );
        if durable.len() == complete_frame {
            assert!(
                matches!(reopened, Err(Error::Invalid("journal/anchor mismatch"))),
                "{fault:?}"
            );
        } else {
            let log = reopened.unwrap();
            assert_eq!(log.position().unwrap().sequence, 0, "{fault:?}");
            assert_eq!(log.file.durable, PREFIX, "{fault:?}");
        }
    }
}

#[test]
fn append_orders_body_commit_then_anchor_and_replays_exact_payload() {
    let mut log = empty();
    let payload = b"finality with public evidence";
    let selected = log.append(payload).unwrap();
    assert_eq!(
        log.file.trace,
        vec![
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, payload.len()),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, 32),
            Trace::Sync(AppendPhase::Commit)
        ]
    );
    assert_eq!(log.anchor.position(), selected);
    assert_eq!(log.payload(0).unwrap(), payload);
    let mut count = 0;
    let mut reopened = Log::replay(
        ScriptedIo::new(log.file.durable.clone(), None),
        log.anchor.clone(),
        PREFIX,
        limits(),
        |body| {
            assert_eq!(body, payload);
            count += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(reopened.position().unwrap(), selected);
    assert_eq!(reopened.payload(0).unwrap(), payload);
}

#[test]
fn anchor_failure_gap_halts_but_lost_ack_can_recover_complete_new_state() {
    for after in [false, true] {
        let mut log = empty();
        log.anchor.fail = Some(after);
        assert!(log.append(b"intent").is_err());
        assert!(log.ensure().is_err());
        let durable = log.file.durable.clone();
        let mut anch = log.anchor.clone();
        anch.fail = None;
        let reopened = Log::replay(
            ScriptedIo::new(durable, None),
            anch,
            PREFIX,
            limits(),
            |_| Ok(()),
        );
        if after {
            assert_eq!(reopened.unwrap().position().unwrap().sequence, 1);
        } else {
            assert!(matches!(
                reopened,
                Err(Error::Invalid("journal/anchor mismatch"))
            ));
        }
    }
}

#[test]
fn complete_corruption_or_invalid_payload_never_truncates() {
    let mut log = empty();
    log.append(b"public record").unwrap();
    let bytes = log.file.durable.clone();
    for offset in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 1;
        assert!(
            Log::replay(
                ScriptedIo::new(corrupted, None),
                log.anchor.clone(),
                PREFIX,
                limits(),
                |_| Ok(())
            )
            .is_err(),
            "byte {offset}"
        );
    }
    let mut io = ScriptedIo::new(bytes.clone(), None);
    assert!(
        scan(&mut io, PREFIX, limits(), log.anchor.position(), |_| Err(
            Error::Invalid("application replay")
        ))
        .is_err()
    );
    assert_eq!(io.volatile.get_ref(), &bytes);
    assert_eq!(io.durable, bytes);
}

#[test]
fn only_incomplete_tail_after_exact_anchor_is_recoverable() {
    let mut log = empty();
    log.append(b"first").unwrap();
    let prefix = log.file.durable.clone();
    let mut second = empty();
    second.append(b"first").unwrap();
    second.append(b"second").unwrap();
    let complete = second.file.durable.clone();
    for length in prefix.len() + 1..complete.len() {
        let recovered = Log::replay(
            ScriptedIo::new(complete[..length].to_vec(), None),
            log.anchor.clone(),
            PREFIX,
            limits(),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(recovered.file.durable, prefix);
        assert_eq!(recovered.position().unwrap().sequence, 1);
    }
    assert!(
        Log::replay(
            ScriptedIo::new(complete, None),
            log.anchor.clone(),
            PREFIX,
            limits(),
            |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn declared_oversize_is_rejected_without_allocating_or_truncating() {
    let mut bytes = PREFIX.to_vec();
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut io = ScriptedIo::new(bytes.clone(), None);
    assert!(matches!(
        scan(&mut io, PREFIX, limits(), anchor().position(), |_| Ok(())),
        Err(Error::Invalid("frame length"))
    ));
    assert_eq!(io.durable, bytes);
    let mut log = empty();
    assert!(log.append(&[0; 129]).is_err());
    assert_eq!(log.position().unwrap().sequence, 0);
    assert_eq!(log.file.durable, PREFIX);
}

#[test]
fn observed_disk_changes_poison_owner_before_payload_release() {
    let mut log = empty();
    log.append(b"record").unwrap();
    log.file.volatile.get_mut()[PREFIX.len() + 4] ^= 1;
    assert!(log.payload(0).is_err());
    assert!(matches!(log.ensure(), Err(Error::Poisoned)));
}
