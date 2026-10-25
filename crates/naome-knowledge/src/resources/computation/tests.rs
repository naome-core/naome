use super::*;
use crate::resources::adaptive::{self, Observed, Selection, Snapshot};
use libp2p::futures::poll;

pub(crate) fn isolated(test: &str) -> bool {
    if std::env::var_os("NAOME_AUTOMATIC_GATE_TEST").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("NAOME_AUTOMATIC_GATE_TEST", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

pub(crate) fn budget(paused: bool) {
    let mut snapshot = Snapshot::derive(
        Selection::default(),
        Observed {
            memory_total: 8 << 30,
            memory_limit: 8 << 30,
            memory_available: 6 << 30,
            process_rss: 16 << 20,
            cpu_millis: 8000,
            disk_available: 1 << 30,
            ..Observed::default()
        },
        512 << 20,
    )
    .unwrap();
    if paused {
        snapshot.budget.paused = Some("sustained external CPU pressure".into());
        snapshot.budget.concurrency = 0;
        snapshot.budget.batch_steps = 0;
        snapshot.budget.network_requests = 1;
    }
    adaptive::publish(snapshot);
}

#[tokio::test]
async fn resource_pause_closes_admission_drains_work_and_wakes_waiting_providers() {
    if isolated(
        "resources::computation::tests::resource_pause_closes_admission_drains_work_and_wakes_waiting_providers",
    ) {
        return;
    }
    budget(false);
    let computation = Arc::new(Computation::default());
    let active = computation.try_enter().unwrap();
    budget(true);
    assert_eq!(computation.state(), ComputationState::Pausing);
    assert!(computation.try_enter().is_none());
    assert!(crate::resources::MemoryLease::acquire(4096).is_ok());
    assert_eq!(adaptive::network(4), 1);
    assert_eq!(adaptive::batch(4), 0);
    drop(active);
    assert_eq!(computation.state(), ComputationState::Paused);
    let mut waiting = Box::pin(computation.enter());
    assert!(poll!(waiting.as_mut()).is_pending());
    budget(true);
    assert!(poll!(waiting.as_mut()).is_pending());
    budget(false);
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .unwrap();
    budget(true);
    assert_eq!(computation.state(), ComputationState::Pausing);
    drop(resumed);
    assert_eq!(computation.state(), ComputationState::Paused);
}

#[tokio::test]
async fn cancelled_waiter_retains_no_work_and_concurrent_pause_cannot_report_false_quiescence() {
    if isolated(
        "resources::computation::tests::cancelled_waiter_retains_no_work_and_concurrent_pause_cannot_report_false_quiescence",
    ) {
        return;
    }
    budget(true);
    let computation = Arc::new(Computation::default());
    let mut waiting = Box::pin(computation.enter());
    assert!(poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    budget(false);
    let active = computation.try_enter().unwrap();
    let owner = computation.clone();
    std::thread::spawn(move || {
        budget(true);
        assert!(owner.try_enter().is_none());
        assert_eq!(owner.state(), ComputationState::Pausing);
    })
    .join()
    .unwrap();
    drop(active);
    assert_eq!(computation.state(), ComputationState::Paused);
}
