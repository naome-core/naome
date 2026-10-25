use super::*;
use crate::resources::{
    ComputationState,
    adaptive::{self, Observed, Selection, Snapshot},
};

async fn exchange(control: &Control, operation: Operation) -> Status {
    let (response, served) = tokio::join!(request(&control.directory, operation, None), async {
        control
            .respond(control.accept().await.unwrap(), 3, true)
            .await
            .unwrap()
    });
    assert!(!served);
    response.unwrap().unwrap()
}

#[tokio::test]
async fn automatic_status_and_interest_preserve_identity_and_do_not_override_resource_policy() {
    const TEST: &str = "runtime::tests::computation::automatic_status_and_interest_preserve_identity_and_do_not_override_resource_policy";
    if std::env::var_os("NAOME_AUTOMATIC_STATUS_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_AUTOMATIC_STATUS_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = Directory::new();
    owner::update(&directory.0, "  logic\nλ  ").unwrap();
    let graph = Graph::open(&directory.0).unwrap();
    let control = Control::bind_test(&directory.0, graph.ownership()).unwrap();
    let endpoint = fs::read(directory.0.join("control.json")).unwrap();
    let active = control.computation.try_enter().unwrap();
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
    snapshot.budget.paused = Some("operating system power saving".into());
    snapshot.budget.concurrency = 0;
    snapshot.budget.batch_steps = 0;
    adaptive::publish(snapshot);
    let status = exchange(&control, Operation::Status).await;
    assert!(status.running);
    assert_eq!(status.computation, ComputationState::Pausing);
    assert_eq!(
        status.computation_reason.as_deref(),
        Some("operating system power saving")
    );
    assert_eq!(status.accepted_proofs, 3);
    assert_eq!(status.interest, "  logic\nλ  ");
    drop(active);
    assert_eq!(
        exchange(&control, Operation::Interest("new interest".into()))
            .await
            .computation,
        ComputationState::Paused
    );
    assert_eq!(
        fs::read(directory.0.join("control.json")).unwrap(),
        endpoint
    );
    assert!(!control.stopping());
}

#[tokio::test]
async fn invalid_control_token_cannot_mutate_owner_interest() {
    let directory = Directory::new();
    let graph = Graph::open(&directory.0).unwrap();
    let control = Control::bind_test(&directory.0, graph.ownership()).unwrap();
    let before = control.selection().unwrap();
    let client = async {
        let mut stream = UnixStream::connect(&control.endpoint.socket).await.unwrap();
        write_frame(
            &mut stream,
            &Request {
                version: 1,
                token: "02".repeat(32),
                operation: Operation::Interest("intruder".into()),
            },
        )
        .await
        .unwrap();
    };
    let server = async {
        control
            .respond(control.accept().await.unwrap(), 0, true)
            .await
            .unwrap_err()
    };
    let (_, error) = tokio::join!(client, server);
    assert_eq!(error, "local control instance mismatch");
    assert_eq!(control.selection().unwrap(), before);
}
