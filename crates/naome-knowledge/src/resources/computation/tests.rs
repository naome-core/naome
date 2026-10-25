use super::*;
use libp2p::futures::poll;

#[tokio::test]
async fn pause_closes_admission_drains_existing_work_and_resumes_waiting_providers() {
    let computation = Arc::new(Computation::default());
    let other_node = Arc::new(Computation::default());
    let active = computation.try_enter().unwrap();
    computation.set_paused(true);
    assert_eq!(computation.state(), ComputationState::Pausing);
    assert!(computation.try_enter().is_none());
    assert!(other_node.try_enter().is_some());
    drop(active);
    assert_eq!(computation.state(), ComputationState::Paused);

    let mut waiting = Box::pin(computation.enter());
    assert!(poll!(waiting.as_mut()).is_pending());
    computation.set_paused(true);
    assert!(poll!(waiting.as_mut()).is_pending());
    assert_eq!(computation.state(), ComputationState::Paused);
    computation.set_paused(false);
    let resumed = waiting.await;
    computation.set_paused(true);
    assert_eq!(computation.state(), ComputationState::Pausing);
    drop(resumed);
    assert_eq!(computation.state(), ComputationState::Paused);
}

#[tokio::test]
async fn cancelling_a_provider_at_a_paused_boundary_does_not_retain_active_work() {
    let computation = Arc::new(Computation::default());
    computation.set_paused(true);
    let mut waiting = Box::pin(computation.enter());
    assert!(poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    computation.set_paused(false);
    let active = computation.try_enter().unwrap();
    computation.set_paused(true);
    drop(active);
    assert_eq!(computation.state(), ComputationState::Paused);
}

#[test]
fn concurrent_pause_never_reports_quiescence_while_an_admitted_step_is_active() {
    let computation = Arc::new(Computation::default());
    let active = computation.try_enter().unwrap();
    let owner = computation.clone();
    std::thread::spawn(move || {
        owner.set_paused(true);
        assert!(owner.try_enter().is_none());
        assert_eq!(owner.state(), ComputationState::Pausing);
    })
    .join()
    .unwrap();
    drop(active);
    assert_eq!(computation.state(), ComputationState::Paused);
}
